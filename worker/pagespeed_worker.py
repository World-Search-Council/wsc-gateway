#!/usr/bin/env python3
"""
pagespeed_worker.py - Asynchronous PageSpeed & Core Web Vitals audit worker.
Consumes audit requests from 'wsc_pagespeed_tasks', triggers the Headless SpeedSentinel cluster,
persists performance metrics in ClickHouse (wsc_pagespeed_daily & wsc_assembled_reports),
and dispatches real-time results via Webhook back to the CMS (WordPress).
"""

import os
import sys
import json
import time
import asyncio
import logging
from datetime import datetime

import aio_pika

import httpx

from common import (
    RABBITMQ_URL,
    _init_clickhouse,
    push_reports_via_gateway
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [pagespeed-worker] %(message)s")
logger = logging.getLogger("pagespeed_worker")

HEADLESS_API_KEY = os.getenv("WSC_HEADLESS_API_KEY", "wsc-headless-secret-key")


def get_headless_servers() -> list:
    raw = os.getenv("WSC_HEADLESS_SERVERS", "http://127.0.0.1:8081").strip()
    if raw.startswith("[") and raw.endswith("]"):
        try:
            items = json.loads(raw)
            return [str(s).rstrip("/") for s in items if s]
        except Exception:
            pass
    servers = [s.strip().rstrip("/") for s in raw.split(",") if s.strip()]
    return servers or ["http://127.0.0.1:8081"]


async def audit_pagespeed_cluster(url: str, strategy: str = "mobile", throttle_cpu: bool = True) -> dict | None:
    servers = get_headless_servers()
    payload = {
        "url": url,
        "strategy": strategy,
        "throttle_cpu": throttle_cpu
    }
    headers = {"X-API-KEY": HEADLESS_API_KEY}

    async with httpx.AsyncClient(timeout=45.0) as client:
        for server in servers:
            endpoint = f"{server}/v1/audit/speed"
            try:
                resp = await client.post(endpoint, json=payload, headers=headers)
                if resp.status_code == 200:
                    return resp.json()
                logger.warning(f"Headless server {server} returned HTTP {resp.status_code}")
            except Exception as e:
                logger.warning(f"Headless server {server} unreachable: {e}. Trying next in pool...")
    logger.error(f"All headless servers {servers} failed for {url}")
    return None


async def process_pagespeed_task(message: aio_pika.IncomingMessage, ch_client):
    async with message.process(ignore_processed=True):
        task_data = {}
        try:
            task_data = json.loads(message.body.decode("utf-8"))
            if not isinstance(task_data, dict):
                logger.error(f"Invalid message format in wsc_pagespeed_tasks: expected dict, got {type(task_data)}")
                return
        except Exception as e:
            logger.error(f"Invalid message format in wsc_pagespeed_tasks: {e}")
            return

        task_id = task_data.get("task_id", "unknown")
        project_id = task_data.get("project_id")
        url = task_data.get("url")
        strategy = task_data.get("strategy", "mobile")

        if not project_id or not url:
            logger.warning(f"Task {task_id} missing project_id or url: {task_data}")
            return

        logger.info(f"Processing PageSpeed audit {task_id} for {project_id} ({url}, {strategy})...")

        # 1. Execute live audit on Headless cluster (with round-robin & failover)
        start_time = time.time()
        audit_data = await audit_pagespeed_cluster(url, strategy=strategy, throttle_cpu=True)
        duration = round(time.time() - start_time, 2)

        if not audit_data:
            logger.error(f"Headless SpeedSentinel failed all clusters for {url} (task {task_id}) in {duration}s")
            return

        audit_data["project_id"] = project_id
        audit_data["task_id"] = task_id
        audit_data["report_type"] = "pagespeed_audit"

        logger.info(f"PageSpeed audit completed in {duration}s for {project_id}. Score: {audit_data.get('performance_score')}")

        # 2. Persist to ClickHouse: wsc_pagespeed_daily & wsc_assembled_reports
        if ch_client:
            try:
                metrics = audit_data.get("metrics", {})
                score = int(audit_data.get("performance_score", 0))
                lcp = int(round(float(metrics.get("lcp", {}).get("value", 0))))
                cls_score = float(metrics.get("cls", {}).get("value", 0.0))
                fcp = int(round(float(metrics.get("fcp", {}).get("value", 0))))
                ttfb = int(round(float(metrics.get("ttfb", {}).get("value", 0))))
                tbt = int(round(float(metrics.get("tbt", {}).get("value", 0))))
                today_date = datetime.utcnow().date()
                now_dt = datetime.utcnow()

                # Insert into daily time-series
                ch_client.insert(
                    "wsc_pagespeed_daily",
                    [[project_id, today_date, strategy, score, lcp, cls_score, fcp, ttfb, tbt]],
                    column_names=["project_id", "audited_date", "strategy", "performance_score", "lcp_ms", "cls_score", "fcp_ms", "ttfb_ms", "tbt_ms"]
                )

                # Insert full report snapshot into wsc_assembled_reports
                payload_json = json.dumps(audit_data)
                ch_client.insert(
                    "wsc_assembled_reports",
                    [[project_id, "pagespeed_audit", today_date, today_date, now_dt, payload_json, 1]],
                    column_names=["project_id", "report_type", "period_start", "period_end", "generated_at", "payload", "has_data"]
                )

                logger.info(f"Saved PageSpeed audit to ClickHouse tables (daily + snapshot) for {project_id}")
            except Exception as e:
                logger.error(f"ClickHouse insertion error for PageSpeed audit {task_id}: {e}")

        # 3. Dispatch to remote CMS via Gateway Webhook
        try:
            await push_reports_via_gateway(project_id, reports=[audit_data], pagespeed=audit_data)
            logger.info(f"Dispatched PageSpeed audit {task_id} to webhook for {project_id}")
        except Exception as e:
            logger.error(f"Error dispatching PageSpeed webhook for {project_id}: {e}")


async def run_pagespeed_worker():
    logger.info("Starting WSC PageSpeed & Core Web Vitals Worker...")

    ch_client = None
    try:
        ch_client = _init_clickhouse()
    except Exception as e:
        logger.warning(f"ClickHouse initial connect failed: {e}. Worker will continue and retry.")

    while True:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                # Prefetch 1 task at a time per worker process
                await channel.set_qos(prefetch_count=1)

                queue = await channel.declare_queue("wsc_pagespeed_tasks", durable=True)
                logger.info("Subscribed to queue 'wsc_pagespeed_tasks'. Waiting for tasks...")

                async for message in queue:
                    if not ch_client:
                        try:
                            ch_client = _init_clickhouse()
                        except Exception:
                            pass
                    await process_pagespeed_task(message, ch_client)

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("Pagespeed worker shutting down gracefully.")
            break
        except aio_pika.exceptions.AMQPConnectionError as e:
            logger.warning(f"RabbitMQ connection lost ({e}). Reconnecting in 5s...")
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Unexpected worker error: {e}. Restarting loop in 5s...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(run_pagespeed_worker())
