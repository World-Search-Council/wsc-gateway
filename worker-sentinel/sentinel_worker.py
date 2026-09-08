#!/usr/bin/env python3
"""
sentinel_worker.py - Asynchronous Domain & Tech Health Sentinel audit worker.
Consumes audit tasks from 'wsc_sentinel_tasks', triggers deep DNS, Mail, Web/SSL,
and Security Headers inspection via CZ.NIC dns-crawler (pure DNS, zero SMTP port 25 checks),
tracks infrastructure drift via DeepDiff, persists reports to Redis and ClickHouse,
supports synchronous RPC responses for gateway REST endpoints, and dispatches real-time
results via Webhook to CMS (WordPress).
"""

import os
import sys
import json
import time
import asyncio
import logging
from datetime import datetime

import aio_pika
import redis

from common import (
    RABBITMQ_URL,
    _init_clickhouse,
    push_reports_via_gateway
)
from sentinel_scanner import run_full_sentinel_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [sentinel-worker] %(message)s")
logger = logging.getLogger("sentinel_worker")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")


def get_redis_client():
    try:
        client = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=3.0)
        client.ping()
        return client
    except Exception as e:
        logger.warning(f"Redis connection unavailable: {e}")
        return None


async def process_sentinel_task(message: aio_pika.IncomingMessage, channel: aio_pika.Channel, ch_client, redis_client):
    async with message.process(ignore_processed=True):
        task_data = {}
        try:
            task_data = json.loads(message.body.decode("utf-8"))
        except Exception as e:
            logger.error(f"Invalid message format in wsc_sentinel_tasks: {e}")
            return

        task_id = task_data.get("task_id", f"sentinel_{int(time.time())}")
        project_id = task_data.get("project_id")
        domain = task_data.get("domain")
        previous_snapshot = task_data.get("previous_snapshot")

        if not project_id:
            logger.warning(f"Task {task_id} missing project_id: {task_data}")
            return

        # If previous_snapshot was not supplied in message, attempt to load from Redis
        if not previous_snapshot and redis_client:
            try:
                cached_prev = redis_client.get(f"sentinel:latest:{project_id}")
                if cached_prev:
                    previous_snapshot = json.loads(cached_prev)
            except Exception as e:
                logger.debug(f"Could not load previous snapshot from Redis for {project_id}: {e}")

        logger.info(f"Processing Sentinel audit {task_id} for {project_id} (domain: {domain or 'auto-resolve'})...")

        start_time = time.time()
        # Execute scan via threadpool
        report = await asyncio.to_thread(
            run_full_sentinel_scan,
            domain=domain or project_id,
            project_id=project_id,
            previous_snapshot=previous_snapshot
        )
        duration = round(time.time() - start_time, 2)

        report["task_id"] = task_id
        report["report_type"] = "domain_health"
        score = report.get("score", 0)
        rating = report.get("rating", "GOOD")
        drift = report.get("drift_status", "NO_CHANGE")
        logger.info(f"Sentinel audit finished for {project_id} in {duration}s. Score: {score}/100 ({rating}), Drift: {drift}")

        # 1. Persist to Redis Cache for instant UI reads
        if redis_client:
            try:
                report_json = json.dumps(report)
                redis_client.set(f"sentinel:latest:{project_id}", report_json, ex=86400 * 30)
                if report.get("domain"):
                    redis_client.set(f"sentinel:latest_domain:{report['domain']}", report_json, ex=86400 * 30)
                logger.info(f"Persisted latest Sentinel report in Redis for {project_id}")
            except Exception as e:
                logger.error(f"Failed to persist report in Redis for {project_id}: {e}")

        # 2. Persist to ClickHouse: wsc_assembled_reports
        if ch_client:
            try:
                today_date = datetime.utcnow().date()
                now_dt = datetime.utcnow()
                payload_json = json.dumps(report)

                ch_client.insert(
                    "wsc_assembled_reports",
                    [[project_id, "domain_health", today_date, today_date, now_dt, payload_json, 1]],
                    column_names=["project_id", "report_type", "period_start", "period_end", "generated_at", "payload", "has_data"]
                )
                logger.info(f"Saved Sentinel report snapshot to ClickHouse for {project_id}")
            except Exception as e:
                logger.error(f"ClickHouse insertion error for Sentinel task {task_id}: {e}")

        # 3. RPC reply (if requested by caller, e.g. synchronous REST API call)
        if message.reply_to and message.correlation_id:
            try:
                reply_body = json.dumps(report).encode("utf-8")
                await channel.default_exchange.publish(
                    aio_pika.Message(
                        body=reply_body,
                        correlation_id=message.correlation_id,
                        content_type="application/json"
                    ),
                    routing_key=message.reply_to
                )
                logger.info(f"Published RPC reply for task {task_id} (corr_id: {message.correlation_id})")
            except Exception as e:
                logger.error(f"Error publishing RPC reply for task {task_id}: {e}")

        # 4. Dispatch to remote CMS via Gateway Webhook
        try:
            await push_reports_via_gateway(project_id, reports=[report])
            logger.info(f"Dispatched Sentinel report webhook for {project_id}")
        except Exception as e:
            logger.error(f"Error dispatching Sentinel webhook for {project_id}: {e}")


async def run_sentinel_worker():
    logger.info("Starting WSC Sentinel Domain & Tech Health Worker...")

    ch_client = None
    try:
        ch_client = _init_clickhouse()
    except Exception as e:
        logger.warning(f"ClickHouse initial connect failed: {e}. Worker will continue and retry.")

    redis_client = get_redis_client()

    while True:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                await channel.set_qos(prefetch_count=1)

                queue = await channel.declare_queue("wsc_sentinel_tasks", durable=True)
                logger.info("Subscribed to queue 'wsc_sentinel_tasks'. Waiting for Sentinel tasks...")

                async for message in queue:
                    if not ch_client:
                        try:
                            ch_client = _init_clickhouse()
                        except Exception:
                            pass
                    if not redis_client:
                        redis_client = get_redis_client()

                    await process_sentinel_task(message, channel, ch_client, redis_client)

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("Sentinel worker shutting down gracefully.")
            break
        except aio_pika.exceptions.AMQPConnectionError as e:
            logger.warning(f"RabbitMQ connection lost ({e}). Reconnecting in 5s...")
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Unexpected worker error: {e}. Restarting loop in 5s...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(run_sentinel_worker())
