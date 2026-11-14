import asyncio
import os
import time
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
import hmac
import hashlib
import json
import uuid
import datetime
import httpx
import aio_pika
from aio_pika import ExchangeType
import aiomysql
from services.redis_cache import create_async_redis_client
from services.metrics import METRICS
from routers.shopify import router as shopify_router
from routers.ai_coverage import router as ai_coverage_router
from routers.benchmarks import router as benchmarks_router
from routers.sentinel import router as sentinel_router
from routers.pagespeed import pagespeed_router
from routers.intelligence import router as intelligence_router
from routers.reports import router as reports_router

GATEWAY_VERSION = "2.3.0"
STANDARD_SPEC_VERSION = "1.5.0"

app = FastAPI(title="WSC Analytics Gateway", version=GATEWAY_VERSION)
app.include_router(shopify_router)
app.include_router(ai_coverage_router)
app.include_router(benchmarks_router)
app.include_router(sentinel_router)
app.include_router(pagespeed_router)
app.include_router(intelligence_router)
app.include_router(reports_router)


# Common probe paths that scanners look for (return 404 quickly)
BLOCKED_PATH_PREFIXES = [
    "/wp-", "/xmlrpc", "/console", "/server", "/.env", "/.git",
    "/graphql", "/api/", "/actuator", "/telescope", "/debug",
    "/login", "/config.json", "/.vscode",
    "/favicon.ico", "/version", "/info.php", "/trace.axd",
    "/.DS_Store", "/ecp/", "/___proxy", "/v2/_catalog",
    "/s/", "/?rest_route", "/healthz", "/.well-known/security.txt"
]

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path.lower()
    # Quick block for obvious scanner probes (best practice to reduce noise)
    if any(path.startswith(prefix.lower()) or prefix.lower() in path for prefix in BLOCKED_PATH_PREFIXES):
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    t0 = time.perf_counter()
    response = await call_next(request)
    duration_sec = time.perf_counter() - t0
    if path != "/metrics":
        METRICS.observe_http(request.method, request.url.path, response.status_code, duration_sec)

    # Add basic security headers (Traefik also adds some)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

@app.get("/health")
async def liveness_check():
    """Simple health endpoint for monitoring / load balancers."""
    return {"status": "healthy"}

@app.get("/robots.txt")
async def robots_txt():
    """Tell bots to go away."""
    return PlainTextResponse("User-agent: *\nDisallow: /", media_type="text/plain")

@app.get("/metrics")
async def prometheus_metrics(request: Request, authorization: str = Header(None)):
    """Prometheus & Grafana OpenMetrics endpoint (Prio 5.2)."""
    expected_token = os.getenv("METRICS_BEARER_TOKEN", "").strip()
    if expected_token:
        supplied = ""
        if authorization and authorization.lower().startswith("bearer "):
            supplied = authorization[7:].strip()
        if not supplied or not hmac.compare_digest(supplied, expected_token):
            raise HTTPException(status_code=401, detail="Unauthorized metrics scrape")

    body = await METRICS.render_prometheus(
        request.app.state,
        version=GATEWAY_VERSION,
        spec=STANDARD_SPEC_VERSION,
    )
    return PlainTextResponse(body, media_type="text/plain; version=0.0.4; charset=utf-8")

# Globale Verbindungen
redis_client = None
rabbitmq_connection = None
rabbitmq_channel = None
db_pool = None

# --- KONFIGURATION ---
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'port': int(os.getenv('DB_PORT', 9006)),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'),
    'db': os.getenv('DB_NAME', 'wsc_analytics'),
    'autocommit': True
}

REDIS_URL = os.getenv('REDIS_URL')
RABBITMQ_URL = os.getenv('RABBITMQ_URL')

CLICKHOUSE_HOST = os.getenv('CLICKHOUSE_HOST')
CLICKHOUSE_PORT = int(os.getenv('CLICKHOUSE_PORT', 8443))
CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER')
CLICKHOUSE_PASS = os.getenv('CLICKHOUSE_PASS')
CLICKHOUSE_SECURE = os.getenv(
    'CLICKHOUSE_SECURE',
    'false' if CLICKHOUSE_PORT in (8123, 9000) else 'true'
).strip().lower() in ('1', 'true', 'yes')

# --- HILFSFUNKTION ---
def get_real_ip(request: Request) -> str:
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    x_real_ip = request.headers.get("X-Real-IP")
    if x_real_ip:
        return x_real_ip.strip()
    return request.client.host

# --- MODELS ---
class RegisterRequest(BaseModel):
    domain: str
    local_aes_key: str
    platform: str = "wordpress"
    webhook_url: str = ""

class IngestPayload(BaseModel):
    project_id: str
    timestamp: int
    data: list

class InsightPayload(BaseModel):
    project_id: str
    insights: list = []
    card1: dict = None
    card2: dict = None
    card3: dict = None
    card_engagement: dict = None
    card_outbound: dict = None
    card_ecommerce: dict = None
    domain_health: dict = None
    pagespeed: dict = None

# --- LIFECYCLE ---
@app.on_event("startup")
async def startup_event():
    global redis_client, rabbitmq_connection, rabbitmq_channel, db_pool
    redis_client = create_async_redis_client()

    try:
        rabbitmq_connection = await aio_pika.connect_robust(RABBITMQ_URL)
        rabbitmq_channel = await rabbitmq_connection.channel()
        await rabbitmq_channel.declare_exchange("wsc.dlx", ExchangeType.DIRECT, durable=True)

        # Main processing queue with dead-letter
        await rabbitmq_channel.declare_queue(
            "wsc_raw_events",
            durable=True,
            arguments={
                "x-dead-letter-exchange": "wsc.dlx",
                "x-dead-letter-routing-key": "retry"
            }
        )

        # Staged delay queues (TTL in ms)
        # 5 minutes for first 10 retries
        await rabbitmq_channel.declare_queue(
            "wsc_raw_events_delay_5m",
            durable=True,
            arguments={
                "x-message-ttl": 5 * 60 * 1000,
                "x-dead-letter-exchange": "",  # default exchange
                "x-dead-letter-routing-key": "wsc_raw_events"
            }
        )

        # Trigger & worker queues for report generation
        await rabbitmq_channel.declare_queue("wsc_trigger_reports", durable=True)
        await rabbitmq_channel.declare_queue("wsc_report_tasks", durable=True)

        # Queue for asynchronous PageSpeed & Core Web Vitals audits (consumed by pagespeed_worker)
        await rabbitmq_channel.declare_queue("wsc_pagespeed_tasks", durable=True)

        # Queue for asynchronous Sentinel audits (consumed by worker-sentinel)
        await rabbitmq_channel.declare_queue("wsc_sentinel_tasks", durable=True)

        # 1 hour for after 10 retries
        await rabbitmq_channel.declare_queue(
            "wsc_raw_events_delay_1h",
            durable=True,
            arguments={
                "x-message-ttl": 60 * 60 * 1000,
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": "wsc_raw_events"
            }
        )

        # Bind DLX
        dlq_queue = await rabbitmq_channel.declare_queue("wsc_raw_events.dlq", durable=True)
        await dlq_queue.bind("wsc.dlx", routing_key="retry")

    except Exception as e:
        print(f"⚠️ RabbitMQ noch nicht erreichbar: {e}")

    db_pool = await aiomysql.create_pool(**DB_CONFIG, minsize=1, maxsize=10)
    app.state.redis = redis_client
    app.state.redis_client = redis_client
    app.state.db_pool = db_pool
    app.state.rabbitmq_connection = rabbitmq_connection
    app.state.rabbitmq_channel = rabbitmq_channel

    # Initialize ClickHouse Client
    if CLICKHOUSE_HOST:
        try:
            import clickhouse_connect
            ch_client = clickhouse_connect.get_client(
                host=CLICKHOUSE_HOST,
                port=CLICKHOUSE_PORT,
                username=CLICKHOUSE_USER,
                password=CLICKHOUSE_PASS,
                connect_timeout=15,
                send_receive_timeout=30,
                secure=CLICKHOUSE_SECURE
            )
            ch_client.command("SELECT 1")
            app.state.clickhouse = ch_client
            print(f"🚀 ClickHouse Client verbunden ({CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}, secure={CLICKHOUSE_SECURE}).")
        except Exception as e:
            print(f"⚠️ ClickHouse Verbindungsfehler: {e}")
            app.state.clickhouse = None

    print(f"🚀 WSC Gateway v{GATEWAY_VERSION} gestartet (Redis mode: {getattr(redis_client, 'mode_label', 'standalone')}).")


@app.on_event("shutdown")
async def shutdown_event():
    if redis_client:
        await redis_client.close()
    if rabbitmq_connection and not rabbitmq_connection.is_closed:
        await rabbitmq_connection.close()
    if db_pool:
        db_pool.close()
        await db_pool.wait_closed()

@app.get("/")
@app.get("/v1/health")
async def health_check():
    return {
        "status": "active",
        "service": "WSC Gateway",
        "version": GATEWAY_VERSION,
        "standard_spec": STANDARD_SPEC_VERSION,
        "redis_mode": getattr(redis_client, "mode_label", "standalone"),
        "clickhouse_connected": getattr(app.state, "clickhouse", None) is not None,
        "rabbitmq_connected": rabbitmq_connection is not None and not rabbitmq_connection.is_closed,
        "timestamp": int(datetime.datetime.utcnow().timestamp())
    }

# --- ROUTE 1: REGISTRIERUNG ---
@app.post("/v1/register")
async def register_project(req: RegisterRequest, request: Request):
    client_ip = get_real_ip(request)

    wp_base_url = req.domain.rstrip('/')

    project_uuid = f"proj_{uuid.uuid4().hex[:16]}"
    api_secret = uuid.uuid4().hex
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        async with db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                # Mark any older project registrations for this domain as superseded (status=999)
                await cur.execute("UPDATE projects SET status = 999 WHERE domain = %s AND status = 0", (wp_base_url,))

                query = """
                    INSERT INTO projects 
                    (uuid, domain, api_secret, local_aes_key, registered_ip, platform, status, created, updated)
                    VALUES (%s, %s, %s, %s, %s, %s, 0, %s, %s)
                """
                await cur.execute(query, (
                    project_uuid, wp_base_url, api_secret, req.local_aes_key, client_ip, req.platform.lower(), now, now
                ))
    except Exception as e:
        print(f"DB Error: {e}")
        raise HTTPException(status_code=500, detail="Database error during registration")

    cache_data = {
        "api_secret": api_secret,
        "local_aes_key": req.local_aes_key,
        "domain": wp_base_url,
        "platform": req.platform.lower(),
        "webhook_url": req.webhook_url,
        "status": 0
    }
    await redis_client.set(f"project:{project_uuid}", json.dumps(cache_data), ex=86400)
    await redis_client.set(f"proj_sec:{project_uuid}", api_secret, ex=86400)

    return {"project_id": project_uuid, "api_secret": api_secret}

# --- ROUTE 2: INGESTION (Tracking Daten Empfang) ---
@app.post("/v1/ingest")
async def ingest_data(payload: IngestPayload, request: Request, x_wsc_sig: str = Header(None)):
    if not x_wsc_sig:
        METRICS.record_ingest("rejected")
        raise HTTPException(status_code=401, detail="Missing Signature")

    project_uuid = payload.project_id
    cached_project = await redis_client.get(f"project:{project_uuid}")

    if not cached_project:
        async with db_pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute("SELECT api_secret, local_aes_key, domain, platform, status FROM projects WHERE uuid = %s", (project_uuid,))
                row = await cur.fetchone()
                if not row:
                    METRICS.record_ingest("rejected")
                    raise HTTPException(status_code=404, detail="Project not found")

                project_data = {
                    "api_secret": row['api_secret'],
                    "local_aes_key": row['local_aes_key'],
                    "domain": row['domain'],
                    "platform": (row.get('platform') or "wordpress").lower(),
                    "webhook_url": "",
                    "status": row['status']
                }
                await redis_client.set(f"project:{project_uuid}", json.dumps(project_data), ex=86400)
                await redis_client.set(f"proj_sec:{project_uuid}", row['api_secret'], ex=86400)
    else:
        project_data = json.loads(cached_project)

    if project_data["status"] == 999:
        METRICS.record_ingest("rejected")
        raise HTTPException(status_code=403, detail="Project is blocked")

    raw_body = await request.body()
    expected_sig = hmac.new(project_data["api_secret"].encode('utf-8'), raw_body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, x_wsc_sig):
        METRICS.record_ingest("rejected")
        raise HTTPException(status_code=401, detail="Invalid Signature")

    # Normalize to list of dicts with "payload" key so workerV3 can consume uniformly
    if isinstance(payload.data, list):
        raw_events = [{"payload": item} for item in payload.data if item]
    else:
        raw_events = payload.data or []

    worker_message = {
        "project_id": project_uuid,
        "local_aes_key": project_data.get("local_aes_key", ""),
        "raw_events": raw_events
    }

    if rabbitmq_channel:
        message = aio_pika.Message(body=json.dumps(worker_message).encode(), delivery_mode=aio_pika.DeliveryMode.PERSISTENT)
        await rabbitmq_channel.default_exchange.publish(message, routing_key="wsc_raw_events")

    events_len = len(payload.data) if isinstance(payload.data, list) else 0
    METRICS.record_ingest("queued", events_count=events_len)
    return {"status": "ok", "queued_events": events_len}

# --- ROUTE 3: WEBHOOK DISPATCHER (Cross-Platform) ---
@app.post("/internal/dispatch-insights")
async def dispatch_insights(payload: InsightPayload):
    """
    Internal endpoint called by report generation workers to push fresh
    3-Card insights to remote CMS/Shop instances (WordPress, Drupal, Joomla, Shopware, Magento).
    """
    project_uuid = payload.project_id

    # 1. Projektdaten laden
    cached_project = await redis_client.get(f"project:{project_uuid}")
    if not cached_project:
        row = None
        for attempt in range(2):
            try:
                async with db_pool.acquire() as conn:
                    async with conn.cursor(aiomysql.DictCursor) as cur:
                        await cur.execute("SELECT api_secret, domain, platform, status FROM projects WHERE uuid = %s", (project_uuid,))
                        row = await cur.fetchone()
                break
            except Exception as e:
                print(f"MySQL query retry for {project_uuid}: {e}")
                if attempt == 1:
                    raise HTTPException(status_code=500, detail=f"Database query error: {e}")
                await asyncio.sleep(0.3)

        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
        project_data = {
            "api_secret": row['api_secret'],
            "domain": row['domain'],
            "platform": (row.get('platform') or "wordpress").lower(),
            "webhook_url": "",
            "status": row['status']
        }
        await redis_client.set(f"project:{project_uuid}", json.dumps(project_data), ex=86400)
        await redis_client.set(f"proj_sec:{project_uuid}", row['api_secret'], ex=86400)
    else:
        project_data = json.loads(cached_project)
        if "domain" not in project_data:
            raise HTTPException(status_code=500, detail="Domain missing in cache. Re-register needed.")

    if project_data["status"] == 999:
        raise HTTPException(status_code=403, detail="Project is blocked")

    # 2. Determine target webhook endpoint
    domain = project_data.get("domain", "").rstrip('/')
    platform = project_data.get("platform", "wordpress").lower()

    if project_data.get("webhook_url"):
        webhook_url = project_data["webhook_url"]
    elif platform in ("drupal", "drupal7", "drupal8", "drupal9", "drupal10", "drupal11", "shopware", "shopware6"):
        webhook_url = f"{domain}/api/wsc/webhook"
    elif platform in ("joomla", "joomla4", "joomla5"):
        webhook_url = f"{domain}/index.php?option=com_wsc_analytics&task=webhook.receive"
    elif platform in ("magento", "magento2"):
        webhook_url = f"{domain}/wsc/api/webhook"
    else:
        webhook_url = f"{domain}/wp-json/wsc/v1/webhook"

    # 3. Assemble canonical 3-card and legacy insights payload
    payload_dict = {
        "version": STANDARD_SPEC_VERSION,
        "updated_at": int(datetime.datetime.utcnow().timestamp()),
        "insights": payload.insights or []
    }

    if payload.card1:
        payload_dict["card1"] = payload.card1
    if payload.card2:
        payload_dict["card2"] = payload.card2
    if payload.card3:
        payload_dict["card3"] = payload.card3
    if payload.card_engagement:
        payload_dict["card_engagement"] = payload.card_engagement
    if payload.card_outbound:
        payload_dict["card_outbound"] = payload.card_outbound
    if payload.card_ecommerce:
        payload_dict["card_ecommerce"] = payload.card_ecommerce
    if payload.domain_health:
        payload_dict["domain_health"] = payload.domain_health
    if payload.pagespeed:
        payload_dict["pagespeed"] = payload.pagespeed

    # Extract 7-cards, sentinel and pagespeed from insight items if passed in list
    for item in payload.insights:
        if isinstance(item, dict):
            rtype = item.get("report_type") or item.get("type", "")
            if (rtype in ("card1_traffic", "card1") or rtype.startswith("card1")) and "card1" not in payload_dict:
                payload_dict["card1"] = item
            elif (rtype in ("card2_insights", "card2") or rtype.startswith("card2")) and "card2" not in payload_dict:
                payload_dict["card2"] = item
            elif (rtype in ("card3_bots", "card3") or rtype.startswith("card3")) and "card3" not in payload_dict:
                payload_dict["card3"] = item
            elif rtype in ("card_engagement", "card4") and "card_engagement" not in payload_dict:
                payload_dict["card_engagement"] = item
            elif rtype in ("card_outbound", "card5") and "card_outbound" not in payload_dict:
                payload_dict["card_outbound"] = item
            elif rtype in ("card_ecommerce", "card6") and "card_ecommerce" not in payload_dict:
                payload_dict["card_ecommerce"] = item
            elif rtype in ("domain_health", "sentinel", "card7") and "domain_health" not in payload_dict:
                payload_dict["domain_health"] = item
            elif (rtype in ("pagespeed_audit", "pagespeed", "card_pagespeed")) and "pagespeed" not in payload_dict:
                payload_dict["pagespeed"] = item

    request_body_str = json.dumps(payload_dict)

    # 4. Den HMAC-SHA256 für den Webhook-Empfänger berechnen
    signature = hmac.new(
        project_data["api_secret"].encode('utf-8'),
        request_body_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # 5. Asynchron an das CMS/Shop-System senden!
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                webhook_url,
                content=request_body_str,
                headers={
                    "Content-Type": "application/json",
                    "X-WSC-Sig": signature
                },
                timeout=10.0
            )
            response.raise_for_status()
            METRICS.record_webhook(platform, "success")
            return {"status": "success", "platform": platform, "target": webhook_url, "response": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text}
        except Exception as e:
            METRICS.record_webhook(platform, "failed")
            print(f"❌ Webhook dispatch failed to {webhook_url} ({platform}): {e}")
            raise HTTPException(status_code=500, detail=f"Webhook dispatch failed: {e}")
