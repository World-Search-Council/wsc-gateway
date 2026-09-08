"""
WSC Domain & Tech Health Sentinel FastAPI Router
Provides REST endpoints for on-demand domain health scanning, health status queries,
and drift tracking history.
Routes scan tasks through the dedicated Sentinel worker queue with synchronous RPC fallback.
"""

import os
import time
import uuid
import json
import asyncio
import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Header, Request, Depends, Response
import aio_pika

from schemas.contracts import (
    SentinelScanRequest,
    SentinelScanResponse,
    DomainHealthReport
)
from services.sentinel_scanner import run_full_sentinel_scan

logger = logging.getLogger("wsc-sentinel-router")
router = APIRouter(prefix="/v1/sentinel", tags=["Sentinel Domain & Tech Health"])

# In-memory snapshot fallback cache
_SENTINEL_SNAPSHOTS: Dict[str, Dict[str, Any]] = {}


async def _rpc_sentinel_scan(channel: aio_pika.Channel, task_payload: dict, timeout: float = 20.0) -> Optional[dict]:
    """Sends a scan request to the Sentinel worker via RabbitMQ RPC and awaits the reply."""
    corr_id = task_payload.get("task_id") or str(uuid.uuid4())
    callback_queue = await channel.declare_queue(exclusive=True, auto_delete=True)

    loop = asyncio.get_running_loop()
    future = loop.create_future()

    async def on_response(message: aio_pika.IncomingMessage):
        async with message.process():
            if message.correlation_id == corr_id:
                try:
                    data = json.loads(message.body.decode("utf-8"))
                    if not future.done():
                        future.set_result(data)
                except Exception as e:
                    if not future.done():
                        future.set_exception(e)

    consumer_tag = await callback_queue.consume(on_response)

    try:
        msg = aio_pika.Message(
            body=json.dumps(task_payload).encode("utf-8"),
            correlation_id=corr_id,
            reply_to=callback_queue.name,
            delivery_mode=aio_pika.DeliveryMode.NOT_PERSISTENT
        )
        await channel.default_exchange.publish(msg, routing_key="wsc_sentinel_tasks")
        logger.info(f"Published RPC Sentinel scan {corr_id} to wsc_sentinel_tasks. Awaiting worker...")

        result = await asyncio.wait_for(future, timeout=timeout)
        return result
    except asyncio.TimeoutError:
        logger.warning(f"Sentinel RPC worker timed out after {timeout}s for {corr_id}. Falling back to gateway scan.")
        return None
    except Exception as e:
        logger.warning(f"Sentinel RPC worker error for {corr_id}: {e}. Falling back to gateway scan.")
        return None
    finally:
        try:
            await callback_queue.cancel(consumer_tag)
            await callback_queue.delete()
        except Exception:
            pass


@router.post("/scan", response_model=SentinelScanResponse)
async def trigger_sentinel_scan(
    req: SentinelScanRequest,
    request: Request,
    response: Response,
    x_wsc_sig: Optional[str] = Header(None, alias="X-WSC-Sig")
):
    """
    Triggers a Sentinel scan for a project's domain.
    By default (sync=False), dispatches the task asynchronously to 'worker-sentinel' and returns HTTP 202.
    If sync=True, waits for the RPC worker response or in-process fallback and returns the full report.
    """
    domain = req.domain
    project_id = req.project_id

    if not domain:
        domain = "example.com"

    redis_cli = getattr(request.app.state, "redis_client", None)
    channel = getattr(request.app.state, "rabbitmq_channel", None)

    # 1. Fetch previous snapshot for drift tracking
    previous = None
    if redis_cli:
        try:
            prev_raw = await redis_cli.get(f"sentinel:latest:{project_id}")
            if prev_raw:
                previous = json.loads(prev_raw)
        except Exception:
            pass
    if not previous:
        previous = _SENTINEL_SNAPSHOTS.get(project_id)

    task_id = f"sentinel_{uuid.uuid4().hex[:10]}"
    task_payload = {
        "task_id": task_id,
        "project_id": project_id,
        "domain": domain,
        "previous_snapshot": previous
    }

    # Asynchronous mode (standard production workflow for UI / Web)
    if not req.sync:
        published = False
        if channel and not channel.is_closed:
            try:
                msg = aio_pika.Message(
                    json.dumps(task_payload).encode("utf-8"),
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT
                )
                await channel.default_exchange.publish(msg, routing_key="wsc_sentinel_tasks")
                published = True
                logger.info(f"Sentinel async task {task_id} enqueued for {project_id} ({domain})")
            except Exception as e:
                logger.error(f"Failed to publish Sentinel task to RabbitMQ: {e}")

        if not published:
            # Fallback: Run in background asyncio task
            logger.info(f"Executing Sentinel background scan in-process for {project_id} ({domain})")
            async def _bg_run():
                try:
                    res = await asyncio.to_thread(
                        run_full_sentinel_scan,
                        domain=domain,
                        project_id=project_id,
                        previous_snapshot=previous
                    )
                    _SENTINEL_SNAPSHOTS[project_id] = res
                    if redis_cli:
                        await redis_cli.set(f"sentinel:latest:{project_id}", json.dumps(res), ex=86400 * 30)
                except Exception as ex:
                    logger.error(f"Background Sentinel scan failed: {ex}")
            asyncio.create_task(_bg_run())

        response.status_code = 202
        return SentinelScanResponse(
            status="queued",
            task_id=task_id,
            message=f"Sentinel scan enqueued successfully for {domain}. Worker audit in progress."
        )

    # Synchronous mode (primarily for CLI, debugging, or explicit sync requests)
    report_dict = None
    if channel and not channel.is_closed:
        report_dict = await _rpc_sentinel_scan(channel, task_payload, timeout=20.0)

    if not report_dict:
        logger.info(f"Executing in-process Sentinel scan for {project_id} ({domain})...")
        report_dict = await asyncio.to_thread(
            run_full_sentinel_scan,
            domain=domain,
            project_id=project_id,
            previous_snapshot=previous
        )

    # Cache result
    _SENTINEL_SNAPSHOTS[project_id] = report_dict
    if redis_cli:
        try:
            r_json = json.dumps(report_dict)
            await redis_cli.set(f"sentinel:latest:{project_id}", r_json, ex=86400 * 30)
            if report_dict.get("domain"):
                await redis_cli.set(f"sentinel:latest_domain:{report_dict['domain']}", r_json, ex=86400 * 30)
        except Exception as e:
            logger.debug(f"Redis cache set failed: {e}")

    try:
        validated_report = DomainHealthReport(**report_dict)
        return SentinelScanResponse(status="success", task_id=task_id, report=validated_report)
    except Exception as e:
        logger.error(f"Validation of Sentinel report failed: {e}")
        raise HTTPException(status_code=500, detail=f"Sentinel scan report formatting error: {str(e)}")


@router.get("/health/{project_id}", response_model=SentinelScanResponse)
async def get_domain_health(project_id: str, request: Request):
    """
    Returns the latest cached Sentinel Domain & Tech Health report.
    Checks Redis first, then in-memory fallback, or generates baseline.
    """
    redis_cli = getattr(request.app.state, "redis_client", None)
    cached = None

    if redis_cli:
        try:
            cached_raw = await redis_cli.get(f"sentinel:latest:{project_id}")
            if cached_raw:
                cached = json.loads(cached_raw)
        except Exception:
            pass

    if not cached:
        cached = _SENTINEL_SNAPSHOTS.get(project_id)

    if not cached:
        cached = await asyncio.to_thread(run_full_sentinel_scan, "example.com", project_id=project_id)
        _SENTINEL_SNAPSHOTS[project_id] = cached
        if redis_cli:
            try:
                await redis_cli.set(f"sentinel:latest:{project_id}", json.dumps(cached), ex=86400 * 30)
            except Exception:
                pass

    return SentinelScanResponse(status="success", report=DomainHealthReport(**cached))
