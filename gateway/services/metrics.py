"""
WSC Gateway — Prometheus & Grafana OpenMetrics Exporter (Prio 5.2)
Exposes HTTP request counters/histograms, telemetry ingestion throughput,
RabbitMQ queue depths (including DLX 5m/1h retry & DLQ queues),
and ClickHouse / MariaDB / Redis dependency health & query latency
in Prometheus text exposition format (`text/plain; version=0.0.4; charset=utf-8`).
"""

import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("wsc_gateway.metrics")

MONITORED_QUEUES: Tuple[str, ...] = (
    "wsc_raw_events",
    "wsc_raw_events_delay_5m",
    "wsc_raw_events_delay_1h",
    "wsc_raw_events.dlq",
    "wsc_trigger_reports",
    "wsc_report_tasks",
    "wsc_pagespeed_tasks",
    "wsc_sentinel_tasks",
)

HISTOGRAM_BUCKETS: Tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
)

_UUID_SEGMENT_RE = re.compile(r"/(proj_[a-zA-Z0-9_-]+|[0-9a-fA-F-]{16,}|\d+)(?=/|$)")


def normalize_route_label(path: str) -> str:
    """Normalizes dynamic path parameters to prevent label cardinality explosion."""
    if not path:
        return "/"
    cleaned = _UUID_SEGMENT_RE.sub("/{id}", path)
    if cleaned.startswith("/v1/sentinel/health/"):
        return "/v1/sentinel/health/{project_id}"
    if cleaned.startswith("/v1/pagespeed/") and cleaned != "/v1/pagespeed/audit":
        return "/v1/pagespeed/{project_id}"
    return cleaned[:80]


def _esc(val: Any) -> str:
    return str(val).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class WscPrometheusRegistry:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.http_requests_total: Dict[Tuple[str, str, int], int] = {}
        self.http_duration_buckets: Dict[Tuple[str, str], List[int]] = {}
        self.http_duration_sum: Dict[Tuple[str, str], float] = {}
        self.http_duration_count: Dict[Tuple[str, str], int] = {}

        self.ingest_batches_total: Dict[str, int] = {"queued": 0, "rejected": 0}
        self.ingest_events_total: int = 0
        self.webhook_dispatches_total: Dict[Tuple[str, str], int] = {}

        # Cached infrastructure probe snapshot (TTL 15s)
        self._infra_cache: Dict[str, Any] = {}
        self._infra_cached_at: float = 0.0
        self._infra_lock = asyncio.Lock()

    def observe_http(self, method: str, path: str, status_code: int, duration_sec: float) -> None:
        if status_code == 404 and not path.startswith("/v1/"):
            route = "/__unmatched_404__"
        else:
            route = normalize_route_label(path)
        m = method.upper()
        key = (m, route, int(status_code))
        self.http_requests_total[key] = self.http_requests_total.get(key, 0) + 1

        hkey = (m, route)
        if hkey not in self.http_duration_buckets:
            self.http_duration_buckets[hkey] = [0] * (len(HISTOGRAM_BUCKETS) + 1)
            self.http_duration_sum[hkey] = 0.0
            self.http_duration_count[hkey] = 0

        buckets = self.http_duration_buckets[hkey]
        for idx, bound in enumerate(HISTOGRAM_BUCKETS):
            if duration_sec <= bound:
                buckets[idx] += 1
        buckets[-1] += 1  # +Inf
        self.http_duration_sum[hkey] += duration_sec
        self.http_duration_count[hkey] += 1

    def record_ingest(self, status: str, events_count: int = 0) -> None:
        self.ingest_batches_total[status] = self.ingest_batches_total.get(status, 0) + 1
        if events_count > 0:
            self.ingest_events_total += int(events_count)

    def record_webhook(self, platform: str, status: str) -> None:
        key = (platform or "unknown", status)
        self.webhook_dispatches_total[key] = self.webhook_dispatches_total.get(key, 0) + 1

    async def _probe_infrastructure(self, app_state: Any) -> Dict[str, Any]:
        now_mono = time.monotonic()
        if self._infra_cache and (now_mono - self._infra_cached_at) < 15.0:
            return self._infra_cache

        async with self._infra_lock:
            now_mono = time.monotonic()
            if self._infra_cache and (now_mono - self._infra_cached_at) < 15.0:
                return self._infra_cache

            snap: Dict[str, Any] = {
                "up": {"redis": 0, "mariadb": 0, "clickhouse": 0, "rabbitmq": 0},
                "ch_ping_sec": 0.0,
                "redis_l1_entries": 0,
                "redis_mode": "standalone",
                "queues": {},
            }

            # 1. Redis probe
            redis_cli = getattr(app_state, "redis", None)
            if redis_cli is not None:
                snap["redis_mode"] = getattr(redis_cli, "mode_label", "standalone")
                snap["redis_l1_entries"] = getattr(redis_cli, "l1_size", 0)
                try:
                    ok = await redis_cli.ping()
                    snap["up"]["redis"] = 1 if ok else 0
                except Exception:
                    snap["up"]["redis"] = 0

            # 2. MariaDB probe
            db_pool = getattr(app_state, "db_pool", None)
            if db_pool is not None:
                try:
                    async with db_pool.acquire() as conn:
                        async with conn.cursor() as cur:
                            await cur.execute("SELECT 1")
                            await cur.fetchone()
                    snap["up"]["mariadb"] = 1
                except Exception:
                    snap["up"]["mariadb"] = 0

            # 3. ClickHouse probe & latency
            ch_client = getattr(app_state, "clickhouse", None)
            if ch_client is not None:
                t0 = time.perf_counter()
                try:
                    await asyncio.to_thread(ch_client.command, "SELECT 1")
                    snap["ch_ping_sec"] = round(time.perf_counter() - t0, 6)
                    snap["up"]["clickhouse"] = 1
                except Exception:
                    snap["up"]["clickhouse"] = 0

            # 4. RabbitMQ connection & passive queue depth inspection (isolated channel)
            rmq_conn = getattr(app_state, "rabbitmq_connection", None)
            if rmq_conn is not None and not rmq_conn.is_closed:
                snap["up"]["rabbitmq"] = 1
                insp_channel = None
                try:
                    insp_channel = await rmq_conn.channel()
                    for q_name in MONITORED_QUEUES:
                        try:
                            if insp_channel.is_closed:
                                insp_channel = await rmq_conn.channel()
                            q_obj = await insp_channel.declare_queue(q_name, passive=True)
                            res = q_obj.declaration_result
                            snap["queues"][q_name] = {
                                "messages": int(getattr(res, "message_count", 0) or 0),
                                "consumers": int(getattr(res, "consumer_count", 0) or 0),
                            }
                        except Exception:
                            snap["queues"][q_name] = {"messages": 0, "consumers": 0}
                except Exception as exc:
                    logger.debug(f"RabbitMQ queue metrics probe warning: {exc}")
                finally:
                    if insp_channel is not None and not insp_channel.is_closed:
                        try:
                            await insp_channel.close()
                        except Exception:
                            pass

            self._infra_cache = snap
            self._infra_cached_at = time.monotonic()
            return snap

    async def render_prometheus(self, app_state: Any, version: str = "2.3.0", spec: str = "1.5.0") -> str:
        infra = await self._probe_infrastructure(app_state)
        lines: List[str] = []

        # Gateway info & uptime
        lines.append("# HELP wsc_gateway_info Static build and topology metadata for the WSC Cloud Gateway.")
        lines.append("# TYPE wsc_gateway_info gauge")
        lines.append(
            f'wsc_gateway_info{{version="{_esc(version)}",standard_spec="{_esc(spec)}",redis_mode="{_esc(infra["redis_mode"])}"}} 1'
        )

        lines.append("# HELP wsc_gateway_uptime_seconds Seconds since the WSC Gateway process started.")
        lines.append("# TYPE wsc_gateway_uptime_seconds gauge")
        lines.append(f"wsc_gateway_uptime_seconds {round(time.time() - self.started_at, 2)}")

        # Dependency health
        lines.append("# HELP wsc_dependency_up Availability status of upstream WSC dependencies (1 = healthy, 0 = down).")
        lines.append("# TYPE wsc_dependency_up gauge")
        for comp, val in infra["up"].items():
            lines.append(f'wsc_dependency_up{{component="{_esc(comp)}"}} {val}')

        lines.append("# HELP wsc_clickhouse_ping_duration_seconds Round-trip latency of ClickHouse SELECT 1 health query.")
        lines.append("# TYPE wsc_clickhouse_ping_duration_seconds gauge")
        lines.append(f"wsc_clickhouse_ping_duration_seconds {infra['ch_ping_sec']}")

        lines.append("# HELP wsc_redis_l1_fallback_entries Active keys buffered in local L1 failover cache.")
        lines.append("# TYPE wsc_redis_l1_fallback_entries gauge")
        lines.append(f"wsc_redis_l1_fallback_entries {infra['redis_l1_entries']}")

        # RabbitMQ queues & DLX retry metrics
        lines.append("# HELP wsc_rabbitmq_queue_messages Ready messages waiting in WSC RabbitMQ & DLX retry queues.")
        lines.append("# TYPE wsc_rabbitmq_queue_messages gauge")
        for q_name, q_stats in infra["queues"].items():
            lines.append(f'wsc_rabbitmq_queue_messages{{queue="{_esc(q_name)}"}} {q_stats["messages"]}')

        lines.append("# HELP wsc_rabbitmq_queue_consumers Active worker consumers subscribed to WSC RabbitMQ queues.")
        lines.append("# TYPE wsc_rabbitmq_queue_consumers gauge")
        for q_name, q_stats in infra["queues"].items():
            lines.append(f'wsc_rabbitmq_queue_consumers{{queue="{_esc(q_name)}"}} {q_stats["consumers"]}')

        # Ingestion counters
        lines.append("# HELP wsc_ingest_batches_total Total /v1/ingest telemetry batches processed by status.")
        lines.append("# TYPE wsc_ingest_batches_total counter")
        for st, cnt in sorted(self.ingest_batches_total.items()):
            lines.append(f'wsc_ingest_batches_total{{status="{_esc(st)}"}} {cnt}')

        lines.append("# HELP wsc_ingest_events_total Total individual encrypted edge telemetry events enqueued.")
        lines.append("# TYPE wsc_ingest_events_total counter")
        lines.append(f"wsc_ingest_events_total {self.ingest_events_total}")

        # Webhook dispatches
        lines.append("# HELP wsc_webhook_dispatches_total Total push report webhook dispatches by CMS platform and status.")
        lines.append("# TYPE wsc_webhook_dispatches_total counter")
        for (plat, st), cnt in sorted(self.webhook_dispatches_total.items()):
            lines.append(f'wsc_webhook_dispatches_total{{platform="{_esc(plat)}",status="{_esc(st)}"}} {cnt}')

        # HTTP requests counter
        lines.append("# HELP wsc_http_requests_total Total HTTP requests handled by WSC Gateway.")
        lines.append("# TYPE wsc_http_requests_total counter")
        for (m, route, code), cnt in sorted(self.http_requests_total.items()):
            lines.append(f'wsc_http_requests_total{{method="{_esc(m)}",route="{_esc(route)}",status="{code}"}} {cnt}')

        # HTTP request duration histogram
        lines.append("# HELP wsc_http_request_duration_seconds HTTP request latency distribution in seconds.")
        lines.append("# TYPE wsc_http_request_duration_seconds histogram")
        for (m, route), buckets in sorted(self.http_duration_buckets.items()):
            for idx, bound in enumerate(HISTOGRAM_BUCKETS):
                lines.append(
                    f'wsc_http_request_duration_seconds_bucket{{method="{_esc(m)}",route="{_esc(route)}",le="{bound}"}} {buckets[idx]}'
                )
            lines.append(
                f'wsc_http_request_duration_seconds_bucket{{method="{_esc(m)}",route="{_esc(route)}",le="+Inf"}} {buckets[-1]}'
            )
            lines.append(
                f'wsc_http_request_duration_seconds_sum{{method="{_esc(m)}",route="{_esc(route)}"}} {round(self.http_duration_sum[(m, route)], 6)}'
            )
            lines.append(
                f'wsc_http_request_duration_seconds_count{{method="{_esc(m)}",route="{_esc(route)}"}} {self.http_duration_count[(m, route)]}'
            )

        return "\n".join(lines) + "\n"


METRICS = WscPrometheusRegistry()
