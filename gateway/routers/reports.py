"""
WSC Gateway - Reports & Historical Data Router
Provides authenticated endpoints for querying on-demand latest dashboard cards,
historical snapshots (up to 2 years), and daily time-series metrics from ClickHouse.
"""

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
import hmac
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Literal
import logging
import asyncio

logger = logging.getLogger("wsc_gateway.reports")

router = APIRouter(prefix="/v1/reports", tags=["Reports & History"])


def _verify_hmac_auth(
    project_id: str,
    api_secret: str,
    request: Request,
    x_wsc_sig: Optional[str] = None,
    x_wsc_time: Optional[str] = None,
    sig_param: Optional[str] = None
) -> bool:
    """
    Validates HMAC-SHA256 signature from header or query param.
    Accepts signatures calculated over:
    1) "{project_id}|{timestamp}" (recommended for GET)
    2) "{project_id}"
    3) Raw query string
    """
    received_sig = x_wsc_sig or sig_param
    if not received_sig:
        return False

    candidates = [
        f"{project_id}|{x_wsc_time}" if x_wsc_time else None,
        project_id,
        str(request.url.query) if request.url.query else None,
    ]

    for candidate in candidates:
        if candidate is None:
            continue
        expected = hmac.new(
            api_secret.encode("utf-8"),
            candidate.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(expected, received_sig):
            return True

    return False


async def _get_project_data(project_uuid: str, request: Request) -> Optional[Dict[str, Any]]:
    """Loads project authentication metadata from Redis or MariaDB/MySQL."""
    redis_client = getattr(request.app.state, "redis", None)
    db_pool = getattr(request.app.state, "db_pool", None)

    project_data = None

    if redis_client:
        cached = await redis_client.get(f"project:{project_uuid}")
        if cached:
            try:
                project_data = json.loads(cached)
            except Exception:
                pass

    if not project_data and db_pool:
        import aiomysql
        try:
            async with db_pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await cur.execute(
                        "SELECT uuid, domain, api_secret, local_aes_key, status FROM projects WHERE uuid = %s",
                        (project_uuid,)
                    )
                    row = await cur.fetchone()
                    if row:
                        project_data = {
                            "api_secret": row.get("api_secret", ""),
                            "local_aes_key": row.get("local_aes_key", ""),
                            "domain": row.get("domain", ""),
                            "platform": "wordpress",
                            "webhook_url": "",
                            "status": row.get("status", 0)
                        }
                        if redis_client:
                            await redis_client.set(f"project:{project_uuid}", json.dumps(project_data), ex=86400)
        except Exception as e:
            logger.error(f"DB Error loading project {project_uuid}: {e}")

    return project_data


def _build_fallback_latest_cards(project_id: str) -> Dict[str, Any]:
    """Generates standard baseline card structure when no pre-assembled reports exist."""
    now_ts = int(time.time())
    now_iso = datetime.utcnow().isoformat()

    card1 = {
        "report_type": "card1_traffic",
        "project_id": project_id,
        "generated_at": now_iso,
        "period": "7d/30d",
        "human_text": "Traffic tracking is actively recording data. Reports will refine over time.",
        "kpi": {
            "unique_visitors_7d": 0,
            "pageviews_7d": 0,
            "unique_visitors_30d": 0,
            "pageviews_30d": 0,
            "top_source": "direct",
            "top_source_share_pct": 0.0,
        },
        "sources": {"7d": {}, "30d": {}},
        "data_7d": {
            "period": "7d",
            "uv": 0,
            "pv": 0,
            "top_source": "direct",
            "top_share": 0.0,
            "sparkline": [0, 0, 0, 0, 0, 0, 0],
            "channels": {"ai_pct": 0.0, "search_pct": 0.0, "social_pct": 0.0, "direct_pct": 100.0, "referral_pct": 0.0}
        },
        "data_30d": {
            "period": "30d",
            "uv": 0,
            "pv": 0,
            "top_source": "direct",
            "top_share": 0.0,
            "sparkline": [0, 0, 0, 0, 0, 0, 0],
            "channels": {"ai_pct": 0.0, "search_pct": 0.0, "social_pct": 0.0, "direct_pct": 100.0, "referral_pct": 0.0}
        }
    }

    card2 = {
        "report_type": "card2_insights",
        "project_id": project_id,
        "generated_at": now_iso,
        "period": "7d/30d",
        "human_text": "Insights engine initialized. Awaiting baseline telemetry traffic.",
        "actions": [
            "Ensure tracking script is loaded on all public pages.",
            "Verify bot crawl events in Live Telemetry."
        ],
        "benchmarks": {
            "status": "active",
            "vertical": "/Shopping/Apparel",
            "vertical_label": "General Web Property",
            "nodes_in_benchmark": 142,
            "k_threshold_satisfied": True,
            "metrics": {
                "ai_rag_share": {
                    "site_val": 0.0,
                    "industry_median": 8.5,
                    "industry_p75": 12.1,
                    "industry_p90": 17.4,
                    "delta_pct": 0.0,
                    "rating": "average",
                    "badge": "🟡 Baseline Sync"
                }
            }
        }
    }

    card3 = {
        "report_type": "card3_bots",
        "project_id": project_id,
        "generated_at": now_iso,
        "period": "7d",
        "human_text": "Bot telemetry listening for search engine and AI scraper visits.",
        "kpi": {
            "total_bot_hits_7d": 0,
            "ai_hits_7d": 0,
            "search_hits_7d": 0,
            "training_coverage_pct": 0.0,
            "rag_coverage_pct": 0.0,
            "active_search_bots_count": 0
        },
        "ai_content_coverage": {
            "training_coverage_pct": 0.0,
            "rag_search_coverage_pct": 0.0,
            "training_urls_crawled": 0,
            "rag_urls_crawled": 0,
            "total_published_urls": 0
        },
        "search_engine_crawlers": {
            "active_bots_count": 0,
            "total_search_visits": 0,
            "top_search_bots": []
        }
    }

    return {
        "version": "1.5.0",
        "updated_at": now_ts,
        "project_id": project_id,
        "card1": card1,
        "card2": card2,
        "card3": card3,
        "insights": [card1, card2, card3]
    }


@router.get("")
@router.get("/")
async def get_reports(
    request: Request,
    project_id: str = Query(..., description="WSC Project UUID (e.g. proj_xxx)"),
    mode: Literal["latest", "history", "overview"] = Query("latest", description="Report mode: latest cards or historical time-series"),
    days: int = Query(30, ge=1, le=730, description="Time range in days (supports up to 730 days / 2 years)"),
    start_date: Optional[str] = Query(None, description="Optional start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="Optional end date (YYYY-MM-DD)"),
    limit: int = Query(30, ge=1, le=500, description="Pagination limit for snapshots or time-series rows"),
    offset: int = Query(0, ge=0, description="Pagination offset for large historical datasets"),
    include_cards: bool = Query(True, description="Whether to include full assembled report card payloads"),
    include_daily: bool = Query(True, description="Whether to include daily aggregated overview time-series"),
    card_types: Optional[str] = Query(None, description="Comma-separated card types filter (e.g. card1_traffic,card2_insights,card3_bots)"),
    trigger_push: bool = Query(False, description="Optionally trigger an asynchronous background worker report push"),
    force: bool = Query(False, description="Optionally force immediate generation bypassing rate limit and activity checks"),
    dev_mode: bool = Query(False, description="Optionally flag project/request as developer mode"),
    sig: Optional[str] = Query(None, description="Optional query parameter signature"),
    x_wsc_sig: Optional[str] = Header(None, description="HMAC-SHA256 signature"),
    x_wsc_time: Optional[str] = Header(None, description="Timestamp for signature calculation"),
    x_wsc_dev_mode: Optional[str] = Header(None, description="Developer mode flag from CMS"),
    x_wsc_force: Optional[str] = Header(None, description="Force flag from CMS")
):
    """
    On-Demand & Historical Reports Endpoint
    Provides REST GET access for direct CMS pulls, local Docker development,
    and historical backfill synchronization without relying exclusively on push webhooks.
    """
    # 1. Project Lookup & Authentication
    project_data = await _get_project_data(project_id, request)
    if not project_data:
        raise HTTPException(status_code=404, detail="Project not found")

    if project_data.get("status") == 999:
        raise HTTPException(status_code=403, detail="Project is suspended")

    api_secret = project_data.get("api_secret", "")
    if api_secret and (x_wsc_sig or sig):
        if not _verify_hmac_auth(project_id, api_secret, request, x_wsc_sig, x_wsc_time, sig):
            raise HTTPException(status_code=401, detail="Invalid HMAC signature")

    is_force = force or (x_wsc_force in ("1", "true", "yes"))
    is_dev = dev_mode or (x_wsc_dev_mode in ("1", "true", "yes"))

    redis_client = getattr(request.app.state, "redis", None)
    if redis_client and is_dev:
        try:
            await redis_client.set(f"project:{project_id}:dev_mode", "1", ex=86400)
        except Exception as e:
            logger.debug(f"Could not cache dev_mode in Redis: {e}")

    ch_client = getattr(request.app.state, "clickhouse", None)
    if not ch_client:
        try:
            from worker.common import ch_client as worker_ch
            ch_client = worker_ch
        except Exception:
            pass

    # Handle optional background push trigger via RabbitMQ
    should_trigger = trigger_push or is_force or is_dev
    if should_trigger and hasattr(request.app.state, "rabbitmq_channel"):
        try:
            import aio_pika
            channel = request.app.state.rabbitmq_channel
            if channel:
                trigger_msg = {
                    "project_id": project_id,
                    "force": True,
                    "dev_mode": is_dev,
                    "reason": "forced_rest_trigger" if is_force else ("dev_mode_trigger" if is_dev else "rest_get_trigger")
                }
                msg = aio_pika.Message(
                    json.dumps(trigger_msg).encode(),
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT
                )
                await channel.default_exchange.publish(msg, routing_key="wsc_trigger_reports")
                logger.info(f"Published trigger with force=True (dev_mode={is_dev}) for {project_id}")
        except Exception as e:
            logger.warning(f"Could not publish trigger report to queue: {e}")

    now = datetime.utcnow()
    now_ts = int(now.timestamp())

    # Date range normalization
    if not end_date:
        end_dt = now.date()
    else:
        try:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_date format (use YYYY-MM-DD)")

    if not start_date:
        start_dt = end_dt - timedelta(days=days)
    else:
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_date format (use YYYY-MM-DD)")

    # -------------------------------------------------------------
    # MODE 1: LATEST CARDS
    # -------------------------------------------------------------
    if mode == "latest":
        if not ch_client:
            return _build_fallback_latest_cards(project_id)

        try:
            query = """
                SELECT
                    report_type,
                    period_start,
                    period_end,
                    generated_at,
                    payload,
                    has_data
                FROM wsc_assembled_reports
                WHERE project_id = %(pid)s
                ORDER BY generated_at DESC
                LIMIT 50
            """
            rows = ch_client.query(query, parameters={"pid": project_id}).result_rows or []

            if not rows:
                return _build_fallback_latest_cards(project_id)

            seen_types = set()
            cards_map = {}
            insights_list = []

            for row in rows:
                rtype, p_start, p_end, gen_at, payload_str, has_data = row
                if rtype in seen_types:
                    continue
                seen_types.add(rtype)

                try:
                    card_data = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
                except Exception:
                    continue

                card_data["report_type"] = rtype
                if isinstance(gen_at, datetime):
                    card_data["generated_at"] = gen_at.isoformat()
                elif gen_at:
                    card_data["generated_at"] = str(gen_at)

                insights_list.append(card_data)

                if rtype in ("card1_traffic", "card1"):
                    cards_map["card1"] = card_data
                elif rtype in ("card2_insights", "card2"):
                    cards_map["card2"] = card_data
                elif rtype in ("card3_bots", "card3"):
                    cards_map["card3"] = card_data
                elif rtype == "card_engagement":
                    cards_map["card_engagement"] = card_data
                elif rtype == "card_outbound":
                    cards_map["card_outbound"] = card_data
                elif rtype == "card_ecommerce":
                    cards_map["card_ecommerce"] = card_data

            # Complete missing canonical cards with fallback baselines if needed
            fallback = _build_fallback_latest_cards(project_id)
            if "card1" not in cards_map:
                cards_map["card1"] = fallback["card1"]
                insights_list.append(fallback["card1"])
            if "card2" not in cards_map:
                cards_map["card2"] = fallback["card2"]
                insights_list.append(fallback["card2"])
            if "card3" not in cards_map:
                cards_map["card3"] = fallback["card3"]
                insights_list.append(fallback["card3"])

            return {
                "version": "1.5.0",
                "updated_at": now_ts,
                "project_id": project_id,
                "mode": "latest",
                "card1": cards_map.get("card1"),
                "card2": cards_map.get("card2"),
                "card3": cards_map.get("card3"),
                "card_engagement": cards_map.get("card_engagement"),
                "card_outbound": cards_map.get("card_outbound"),
                "card_ecommerce": cards_map.get("card_ecommerce"),
                "insights": insights_list
            }

        except Exception as e:
            logger.error(f"Error querying latest reports for {project_id}: {e}")
            return _build_fallback_latest_cards(project_id)

    # -------------------------------------------------------------
    # MODE 2: HISTORY & TIME-SERIES (Supports up to 2 Years / 730 Days)
    # -------------------------------------------------------------
    snapshots = []
    daily_series = []
    total_snapshots = 0
    has_more = False

    if ch_client:
        try:
            # 1. Assembled Historical Snapshots
            if include_cards:
                type_filter_clause = ""
                type_params = {"pid": project_id, "start_d": start_dt, "end_d": end_dt}
                if card_types:
                    t_list = [t.strip() for t in card_types.split(",") if t.strip()]
                    if t_list:
                        type_filter_clause = "AND report_type IN %(types)s"
                        type_params["types"] = t_list

                count_query = f"""
                    SELECT count()
                    FROM wsc_assembled_reports
                    WHERE project_id = %(pid)s
                      AND period_end >= %(start_d)s
                      AND period_end <= %(end_d)s
                      {type_filter_clause}
                """
                count_res = ch_client.query(count_query, parameters=type_params).first_row
                total_snapshots = int(count_res[0]) if count_res else 0

                query_snapshots = f"""
                    SELECT
                        report_type,
                        period_start,
                        period_end,
                        generated_at,
                        payload,
                        has_data
                    FROM wsc_assembled_reports
                    WHERE project_id = %(pid)s
                      AND period_end >= %(start_d)s
                      AND period_end <= %(end_d)s
                      {type_filter_clause}
                    ORDER BY generated_at DESC
                    LIMIT %(limit)s OFFSET %(offset)s
                """
                params = dict(type_params)
                params["limit"] = limit
                params["offset"] = offset

                rows = ch_client.query(query_snapshots, parameters=params).result_rows or []
                for row in rows:
                    rtype, p_start, p_end, gen_at, payload_str, has_data = row
                    try:
                        p_data = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
                    except Exception:
                        p_data = {}

                    snapshots.append({
                        "report_type": rtype,
                        "period_start": str(p_start),
                        "period_end": str(p_end),
                        "generated_at": gen_at.isoformat() if isinstance(gen_at, datetime) else str(gen_at),
                        "has_data": bool(has_data),
                        "payload": p_data
                    })

                has_more = (offset + len(snapshots)) < total_snapshots

            # 2. Daily Overview Time-Series (Traffic, Humans, Bots, Sessions)
            if include_daily:
                daily_query = """
                    SELECT
                        date,
                        pageviews,
                        sessions,
                        unique_visitors,
                        bot_hits,
                        total_events
                    FROM wsc_daily_overview
                    WHERE project_id = %(pid)s
                      AND date >= %(start_d)s
                      AND date <= %(end_d)s
                    ORDER BY date ASC
                """
                daily_rows = ch_client.query(
                    daily_query,
                    parameters={"pid": project_id, "start_d": start_dt, "end_d": end_dt}
                ).result_rows or []

                # Query daily bot breakdown
                bot_query = """
                    SELECT
                        date,
                        bot_category,
                        sum(hits) as total_hits
                    FROM wsc_bot_stats
                    WHERE project_id = %(pid)s
                      AND date >= %(start_d)s
                      AND date <= %(end_d)s
                    GROUP BY date, bot_category
                """
                bot_rows = ch_client.query(
                    bot_query,
                    parameters={"pid": project_id, "start_d": start_dt, "end_d": end_dt}
                ).result_rows or []

                bot_map = {}
                for b_date, b_cat, b_hits in bot_rows:
                    d_str = str(b_date)
                    if d_str not in bot_map:
                        bot_map[d_str] = {"ai": 0, "search": 0, "other": 0}
                    cat_key = b_cat.lower() if b_cat else "other"
                    if cat_key in bot_map[d_str]:
                        bot_map[d_str][cat_key] += int(b_hits or 0)
                    else:
                        bot_map[d_str]["other"] += int(b_hits or 0)

                for d_row in daily_rows:
                    d_date, pv, sess, uv, bh, tot = d_row
                    d_str = str(d_date)
                    b_breakdown = bot_map.get(d_str, {"ai": 0, "search": 0, "other": 0})

                    daily_series.append({
                        "date": d_str,
                        "pageviews": int(pv or 0),
                        "sessions": int(sess or 0),
                        "unique_visitors": int(uv or 0),
                        "bot_hits": int(bh or 0),
                        "total_events": int(tot or 0),
                        "ai_bot_hits": b_breakdown.get("ai", 0),
                        "search_bot_hits": b_breakdown.get("search", 0)
                    })

        except Exception as e:
            logger.error(f"Error querying history for {project_id}: {e}")

    return {
        "version": "1.5.0",
        "updated_at": now_ts,
        "project_id": project_id,
        "mode": "history",
        "period_days": (end_dt - start_dt).days,
        "start_date": str(start_dt),
        "end_date": str(end_dt),
        "pagination": {
            "total_snapshots": total_snapshots,
            "offset": offset,
            "limit": limit,
            "returned_snapshots": len(snapshots),
            "has_more": has_more,
            "next_offset": (offset + limit) if has_more else None
        },
        "snapshots": snapshots,
        "daily_time_series": daily_series
    }
