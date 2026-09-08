"""
WSC Gateway - PageSpeed & Core Web Vitals Router
Provides on-demand and cached lab performance audits powered by WSC SpeedSentinel.
Supports asynchronous processing via RabbitMQ worker queue and persistence in ClickHouse.
"""

import time
import uuid
import json
import logging
from typing import Dict, Any, Optional

from fastapi import APIRouter, HTTPException, Request, Depends, Response
import aio_pika

from schemas.contracts import (
    PageSpeedAuditRequest,
    PageSpeedAuditResponse,
    PageSpeedAuditReport,
    PageSpeedMetricContract,
    PageSpeedAssetSummaryContract,
    PageSpeedActionItemContract
)
from services.wsc_services_client import WSCServicesClient

logger = logging.getLogger("gateway.pagespeed")
pagespeed_router = APIRouter(prefix="/v1/pagespeed", tags=["PageSpeed & Core Web Vitals"])


def _get_ch_client(request: Request):
    """Retrieves ClickHouse client from app state or worker fallback."""
    ch = getattr(request.app.state, "clickhouse", None)
    if not ch:
        try:
            from worker.common import ch_client as worker_ch
            ch = worker_ch
        except Exception:
            pass
    return ch


@pagespeed_router.post("/audit", response_model=PageSpeedAuditResponse)
async def trigger_pagespeed_audit(req: PageSpeedAuditRequest, request: Request, response: Response):
    """
    Triggers a Core Web Vitals audit via WSC SpeedSentinel.
    By default, audits are processed asynchronously via RabbitMQ to avoid HTTP timeouts.
    If sync=True is passed, executes directly against the Headless cluster.
    """
    target_url = req.url
    if not target_url:
        target_url = "https://example.com"

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"https://{target_url}"

    # Synchronous mode (primarily for CLI/debugging)
    if req.sync:
        logger.info(f"Executing synchronous SpeedSentinel audit for project {req.project_id} on {target_url} ({req.strategy})")
        audit_data = await WSCServicesClient.audit_pagespeed(target_url, strategy=req.strategy)
        if not audit_data:
            raise HTTPException(
                status_code=502,
                detail="Headless SpeedSentinel cluster unavailable. Could not complete audit."
            )
        audit_data["project_id"] = req.project_id
        report = PageSpeedAuditReport(**audit_data)
        return PageSpeedAuditResponse(status="success", report=report)

    # Asynchronous mode (standard production workflow)
    task_id = f"ps_{uuid.uuid4().hex[:12]}"
    task_payload = {
        "task_id": task_id,
        "project_id": req.project_id,
        "url": target_url,
        "strategy": req.strategy,
        "requested_at": int(time.time())
    }

    published = False
    channel = getattr(request.app.state, "rabbitmq_channel", None)
    if channel:
        try:
            msg = aio_pika.Message(
                json.dumps(task_payload).encode("utf-8"),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT
            )
            await channel.default_exchange.publish(msg, routing_key="wsc_pagespeed_tasks")
            published = True
            logger.info(f"PageSpeed audit job {task_id} queued for {req.project_id} ({target_url})")
        except Exception as e:
            logger.error(f"Failed to publish PageSpeed task to RabbitMQ: {e}")

    if not published:
        # Fallback if RabbitMQ channel is temporarily unavailable: run in background or report error
        raise HTTPException(
            status_code=503,
            detail="Message queue temporarily unavailable to enqueue PageSpeed task. Please retry."
        )

    response.status_code = 202
    return PageSpeedAuditResponse(
        status="queued",
        task_id=task_id,
        message="PageSpeed audit queued. Results will be saved to ClickHouse and dispatched via webhook."
    )


@pagespeed_router.get("/{project_id}", response_model=PageSpeedAuditResponse)
async def get_pagespeed_health(project_id: str, request: Request, strategy: str = "mobile", url: Optional[str] = None):
    """
    Retrieves the latest real Core Web Vitals performance report for a project from ClickHouse.
    Optionally filters by specific target URL (for member multi-URL audits).
    No mock data is generated. If no audit exists, returns 404.
    """
    ch_client = _get_ch_client(request)
    if not ch_client:
        raise HTTPException(status_code=503, detail="ClickHouse storage unavailable")

    try:
        # 1. Check assembled reports for full JSON payload (optionally matching URL)
        params = {"pid": project_id}
        url_filter = ""
        if url:
            url_filter = "AND (JSONExtractString(payload, 'url') = %(target_url)s OR JSONExtractString(payload, 'url') = %(target_url_slash)s)"
            params["target_url"] = url.rstrip("/")
            params["target_url_slash"] = url.rstrip("/") + "/"

        query_assembled = f"""
            SELECT payload FROM wsc_assembled_reports
            WHERE project_id = %(pid)s AND report_type = 'pagespeed_audit' {url_filter}
            ORDER BY generated_at DESC
            LIMIT 1
        """
        rows = ch_client.query(query_assembled, parameters=params).result_rows
        if rows and rows[0][0]:
            payload_str = rows[0][0]
            report_data = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
            report_data["project_id"] = project_id
            return PageSpeedAuditResponse(
                status="success",
                report=PageSpeedAuditReport(**report_data)
            )

        # 2. Check wsc_pagespeed_daily for historical summary
        query_daily = """
            SELECT audited_date, strategy, performance_score, lcp_ms, cls_score, fcp_ms, ttfb_ms, tbt_ms
            FROM wsc_pagespeed_daily
            WHERE project_id = %(pid)s AND strategy = %(strat)s
            ORDER BY audited_date DESC
            LIMIT 1
        """
        daily_rows = ch_client.query(query_daily, parameters={"pid": project_id, "strat": strategy}).result_rows
        if daily_rows:
            row = daily_rows[0]
            score = int(row[2])
            lcp = float(row[3])
            cls_val = float(row[4])
            fcp = float(row[5])
            ttfb = float(row[6])
            tbt = float(row[7])

            report_data = {
                "status": "success",
                "project_id": project_id,
                "url": f"project-{project_id}",
                "strategy": strategy,
                "performance_score": score,
                "overall_rating": "GOOD" if score >= 85 else "NEEDS_IMPROVEMENT" if score >= 50 else "POOR",
                "metrics": {
                    "lcp": {"name": "Largest Contentful Paint", "value": lcp, "unit": "ms", "rating": "GOOD" if lcp <= 2500 else "POOR", "description": "LCP Messung"},
                    "cls": {"name": "Cumulative Layout Shift", "value": cls_val, "unit": "score", "rating": "GOOD" if cls_val <= 0.10 else "POOR", "description": "CLS Messung"},
                    "fcp": {"name": "First Contentful Paint", "value": fcp, "unit": "ms", "rating": "GOOD" if fcp <= 1800 else "POOR", "description": "FCP Messung"},
                    "ttfb": {"name": "Time to First Byte", "value": ttfb, "unit": "ms", "rating": "GOOD" if ttfb <= 600 else "POOR", "description": "TTFB Messung"},
                    "tbt": {"name": "Total Blocking Time", "value": tbt, "unit": "ms", "rating": "GOOD" if tbt <= 200 else "POOR", "description": "TBT Messung"}
                },
                "asset_summary": {"total_requests": 0, "total_weight_kb": 0.0, "breakdown_kb": {}, "dom_nodes": 0, "large_images": []},
                "action_items": [],
                "audited_at": int(time.time())
            }
            return PageSpeedAuditResponse(
                status="success",
                report=PageSpeedAuditReport(**report_data)
            )

    except Exception as e:
        logger.error(f"Error querying ClickHouse for pagespeed report {project_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Database query error: {str(e)}")

    raise HTTPException(
        status_code=404,
        detail=f"No PageSpeed audit recorded yet for project {project_id}. Please trigger an audit."
    )
