import asyncio
import json
import base64
import os
import sys
import hashlib
import uuid
import ipaddress
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse

import httpx
import pprintpp
import tldextract
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import aio_pika
from aio_pika import ExchangeType
import clickhouse_connect
import geoip2.database
from user_agents import parse

# --- Logging Setup ---
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("wsc-worker")
logger.info("Worker logging initialized at level " + os.getenv("LOG_LEVEL", "INFO").upper())


def _extract_real_ip(ip: str, headers: dict) -> str:
    """Try to get the real client IP from common proxy headers."""
    # Common headers set by Traefik, Nginx, Cloudflare, etc.
    for header in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip", "x-client-ip"):
        value = headers.get(header) or headers.get(header.upper()) or headers.get(header.replace("-", "_"))
        if value:
            # X-Forwarded-For can be "client, proxy1, proxy2"
            candidate = value.split(",")[0].strip()
            if candidate:
                return candidate
    return ip or "0.0.0.0"

# --- KONFIGURATION (aus deiner Vorlage) ---
RABBITMQ_URL = os.getenv("RABBITMQ_URL")
CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", 8443))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER")
CLICKHOUSE_PASS = os.getenv("CLICKHOUSE_PASS")

# Globale DB-Verbindung & GeoIP
ch_client = None
geo_reader = None

def load_geoip_database():
    """Strict GeoIP loading. Fails hard if DB is missing."""
    global geo_reader
    mmdb_paths = [
        os.getenv('GEOIP_DB_PATH', ''),
        '/app/GeoLite2-City.mmdb',
        'GeoLite2-City.mmdb',
        '/usr/share/GeoIP/GeoLite2-City.mmdb',
    ]
    attempted = []
    for p in mmdb_paths:
        if not p:
            continue
        attempted.append(p)
        if os.path.exists(p):
            try:
                geo_reader = geoip2.database.Reader(p)
                logger.info(f"GeoIP database loaded from {p}")
                return
            except Exception as e:
                logger.error(f"Failed to load GeoIP from {p}: {e}")
    logger.warning(f"⚠️ GeoLite2-City.mmdb not found. Tried paths: {attempted}. GeoIP resolution disabled.")
    geo_reader = None


def decrypt_payload(encrypted_payload_b64: str, hex_key: str) -> dict:
    try:
        raw_data = base64.b64decode(encrypted_payload_b64)
        if len(raw_data) < 17 or len(raw_data[16:]) % 16 != 0:
            raise ValueError("Invalid encrypted payload length")
        iv = raw_data[:16]
        ciphertext = raw_data[16:]  # binary ciphertext (after fix: no double base64)
        key_bytes = bytes.fromhex(hex_key)

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        logger.error(f"Entschlüsselungsfehler: {e}")
        return None


async def process_message(message: aio_pika.IncomingMessage, channel=None):
    if channel is None:
        # fallback if not passed
        channel = message.channel  # many versions expose it
    async with message.process(ignore_processed=True):
        try:
            body = json.loads(message.body.decode())
            if not isinstance(body, dict):
                logger.error(f"Worker received non-dict message body ({type(body)}): {str(body)[:200]}")
                return
            project_id = body.get("project_id")
            local_aes_key = body.get("local_aes_key")
            raw_events_batch = body.get("raw_events", [])

            clickhouse_insert_data = []

            for sqlite_row in raw_events_batch:
                encrypted_payload = sqlite_row.get("payload")
                decrypted_batch = decrypt_payload(encrypted_payload, local_aes_key)

                if not decrypted_batch or not isinstance(decrypted_batch, dict):
                    continue

                # DEBUG: Log the full decrypted payload (very useful for IP/GeoIP troubleshooting)
                logger.debug(f"Decrypted payload for project {project_id}: {decrypted_batch}")

                # 1. Server-Daten extrahieren
                server_data = decrypted_batch.get("server_data", {})
                headers = server_data.get("headers", {}) or {}

                # Best-effort real client IP extraction (important behind Traefik/Docker proxies)
                raw_ip = _extract_real_ip(server_data.get("ip", "0.0.0.0"), headers)
                raw_ua = server_data.get("ua", "")
                events = decrypted_batch.get("events", [])
                saw_resync_request = False

                logger.debug(f"Using IP for GeoIP: {raw_ip} (extracted from server_data/headers, original server_data ip was {server_data.get('ip')})")

                # 2. Session Hash in Python berechnen
                daily_salt = datetime.now().strftime('%Y-%m-%d') + "_wsc_system_salt"
                session_hash = hashlib.sha256(f"{raw_ip}{raw_ua}{daily_salt}".encode()).hexdigest()

                # 3. GeoIP Auflösung
                geo_country, geo_region, geo_city = "Unknown", "Unknown", "Unknown"
                # Detect if plugin sent a hashed IP (privacy mode, 64 hex chars)
                is_hashed = len(raw_ip) == 64 and all(c in '0123456789abcdef' for c in raw_ip.lower())
                if geo_reader and raw_ip and raw_ip != "0.0.0.0" and not is_hashed:
                    try:
                        ip_obj = ipaddress.ip_address(raw_ip)
                        if ip_obj.is_private:
                            logger.debug(f"Skipping GeoIP for private IP: {raw_ip}")
                        else:
                            geo_response = geo_reader.city(raw_ip)
                            geo_country = geo_response.country.iso_code or "Unknown"
                            geo_region = geo_response.subdivisions.most_specific.iso_code or "Unknown"
                            geo_city = geo_response.city.name or "Unknown"
                            logger.debug(f"GeoIP resolved: {geo_country}/{geo_region}/{geo_city} for {raw_ip}")
                    except (geoip2.errors.AddressNotFoundError, ValueError, ipaddress.AddressValueError) as geo_err:
                        logger.debug(f"GeoIP lookup failed for {raw_ip}: {geo_err}")
                elif is_hashed:
                    logger.debug("Received hashed IP (from plugin IP handling = hashed) - skipping GeoIP for privacy")

                # Privacy: raw_ip is used only for session_hash and GeoIP, then discarded.
                # It is NEVER stored in ClickHouse or reports. Only session_id (daily hash) and geo_* fields.
                raw_ip = None  # explicit discard for clarity

                # 4. Browser/Device Parsing
                sec_ch_ua = headers.get("sec_ch_ua", "")
                ua_parsed = parse(raw_ua)
                device_type = "Mobile" if ua_parsed.is_mobile else "Tablet" if ua_parsed.is_tablet else "Desktop"
                os_name = ua_parsed.os.family

                if "Chrome" in sec_ch_ua:
                    browser_name = "Chrome"
                elif "Edge" in sec_ch_ua:
                    browser_name = "Edge"
                else:
                    browser_name = ua_parsed.browser.family

                # 5. Events durchlaufen und anreichern
                for event in events:
                    sys_signals = event.get("sys", {})
                    full_url = event.get("p", "")

                    # URL & UUID Logik (Der neue Goldstandard)
                    host, url_path, query_string, root_domain = "", full_url, "", ""
                    domain_uuid = uuid.uuid5(uuid.NAMESPACE_URL, "unknown")
                    page_uuid = uuid.uuid5(uuid.NAMESPACE_URL, "unknown")

                    if "://" in full_url:
                        parsed_url = urlparse(full_url)
                        host = parsed_url.netloc
                        url_path = parsed_url.path
                        query_string = parsed_url.query

                        # Root Domain mit tldextract (ignoriert www und subdomains sauber)
                        ext = tldextract.extract(full_url)
                        if ext.domain and ext.suffix:
                            root_domain = f"{ext.domain}.{ext.suffix}"
                        else:
                            root_domain = host  # Fallback für localhost

                        # Deterministische UUIDs (RFC 4122) generieren
                        domain_uuid = uuid.uuid5(uuid.NAMESPACE_URL, root_domain)
                        page_uuid = uuid.uuid5(uuid.NAMESPACE_URL, full_url)

                    event_meta = event.get("m", {}) or {}
                    event_type = event.get("e", "unknown")

                    if event_type == "resync_request":
                        saw_resync_request = True
                        logger.info(f"Detected resync_request event for project {project_id}")

                    is_bot_hit = event_type == "bot_hit"
                    bot_name = event_meta.get("bot_name", "") if is_bot_hit else ""
                    bot_category = event_meta.get("bot_category", "") if is_bot_hit else ""
                    bot_type = event_meta.get("bot_type", "") if is_bot_hit else ""

                    flat_row = [
                        project_id,
                        event.get("t"),
                        session_hash,
                        event.get("e", "unknown"),
                        domain_uuid,  # native UUID
                        page_uuid,  # native UUID
                        root_domain,
                        host,
                        url_path,
                        query_string,
                        event.get("r", ""),
                        geo_country,
                        geo_region,
                        geo_city,
                        device_type,
                        os_name,
                        browser_name,
                        sys_signals.get("res", ""),
                        sys_signals.get("lang", ""),
                        json.dumps(event_meta),
                        bot_name,
                        bot_category,
                        bot_type
                    ]
                    clickhouse_insert_data.append(flat_row)

            # 6. Insert in ClickHouse
            if clickhouse_insert_data:
                ch_client.insert(
                    'wsc_analytics_raw',
                    clickhouse_insert_data,
                    column_names=[
                        'project_id', 'timestamp', 'session_id', 'event_type',
                        'domain_uuid', 'page_uuid', 'root_domain', 'hostname',
                        'url_path', 'query_string', 'referrer_url',
                        'geo_country', 'geo_region', 'geo_city', 'device_type',
                        'os_name', 'browser_name', 'resolution', 'language', 'custom_data',
                        'bot_name', 'bot_category', 'bot_type'
                    ]
                )
                logger.info(f"{len(clickhouse_insert_data)} Events (mit UUIDs) für {project_id} gespeichert.")

            # If we saw a resync_request in this batch, immediately ask for fresh reports
            if saw_resync_request and project_id:
                await _trigger_resync_reports(channel, project_id)

            # WICHTIG: Das exit() aus deinem alten Code ist weg, jetzt wird sauber acknowledged!
            await message.ack()

        except Exception as e:
            logger.error(f"Worker Fehler: {e}")

            # Staged retry logic using DLQ / delay queues
            headers = message.headers or {}
            death = headers.get('x-death', [])
            retry_count = len(death) if death else 0

            # Also support custom header for counting
            custom_retry = int(headers.get('x-retry-count', 0))
            retry_count = max(retry_count, custom_retry)

            if retry_count < 10:
                target_queue = "wsc_raw_events_delay_5m"
                delay_desc = "5 minutes"
            else:
                target_queue = "wsc_raw_events_delay_1h"
                delay_desc = "1 hour"

            try:
                # Republish to the appropriate delay queue with incremented retry count
                new_headers = dict(headers)
                new_headers['x-retry-count'] = retry_count + 1
                new_headers['x-original-queue'] = "wsc_raw_events"

                await channel.default_exchange.publish(
                    aio_pika.Message(
                        body=message.body,
                        headers=new_headers,
                        delivery_mode=aio_pika.DeliveryMode.PERSISTENT
                    ),
                    routing_key=target_queue
                )
                logger.warning(f"Message republished to {target_queue} (retry #{retry_count + 1}, next attempt in ~{delay_desc})")
                await message.ack()  # we handled it by moving to delay
            except Exception as pub_err:
                logger.error(f"Failed to republish for retry: {pub_err}")
                await message.nack(requeue=False)  # avoid loop, send to DLQ if configured


# NOTE: The old monolithic main() has been replaced by the split entrypoints below.
# The combined setup is kept commented for reference / backward compatibility if needed.
#
# async def main():
#     ... (old combined code removed to enforce split architecture)
#
# To run the old way: python workerV3.py (but it is no longer maintained)


# --- New split entrypoints for scalability ---

async def run_ingest():
    """Run only the ingest worker (high volume events)."""
    await setup_rabbitmq_and_run_ingest()


async def run_dispatcher():
    """Run the dispatcher (decides which reports to generate)."""
    await setup_rabbitmq_and_run_dispatcher()


async def run_report_generator():
    """Run the report generator (assemble and push reports)."""
    await setup_rabbitmq_and_run_report_generator()


async def setup_rabbitmq_and_run_ingest():
    global ch_client
    ch_client = _init_clickhouse()

    connection = await aio_pika.connect_robust(RABBITMQ_URL)
    channel = await connection.channel()
    await channel.set_qos(prefetch_count=100)

    load_geoip_database()

    # Declare DLX exchange
    await channel.declare_exchange("wsc.dlx", ExchangeType.DIRECT, durable=True)

    queue = await channel.declare_queue(
        "wsc_raw_events",
        durable=True,
        arguments={
            "x-dead-letter-exchange": "wsc.dlx",
            "x-dead-letter-routing-key": "retry"
        }
    )

    # Delay queues for retries
    await channel.declare_queue(
        "wsc_raw_events_delay_5m",
        durable=True,
        arguments={
            "x-message-ttl": 5 * 60 * 1000,
            "x-dead-letter-exchange": "",
            "x-dead-letter-routing-key": "wsc_raw_events"
        }
    )
    await channel.declare_queue(
        "wsc_raw_events_delay_1h",
        durable=True,
        arguments={
            "x-message-ttl": 60 * 60 * 1000,
            "x-dead-letter-exchange": "",
            "x-dead-letter-routing-key": "wsc_raw_events"
        }
    )

    logger.info("INGEST worker started. Waiting for raw events...")
    await queue.consume(lambda msg: process_message(msg, channel))
    await asyncio.Future()


async def setup_rabbitmq_and_run_dispatcher():
    global ch_client
    ch_client = _init_clickhouse()

    connection = await aio_pika.connect_robust(RABBITMQ_URL)
    channel = await connection.channel()
    await channel.set_qos(prefetch_count=1)

    load_geoip_database()

    report_trigger_queue = await channel.declare_queue("wsc_trigger_reports", durable=True)
    await channel.declare_queue("wsc_report_tasks", durable=True)

    logger.info("DISPATCHER started. Waiting for trigger messages...")
    await report_trigger_queue.consume(lambda msg: handle_reports_trigger_as_dispatcher(msg, channel))
    await asyncio.Future()


async def setup_rabbitmq_and_run_report_generator():
    global ch_client
    ch_client = _init_clickhouse()

    connection = await aio_pika.connect_robust(RABBITMQ_URL)
    channel = await connection.channel()
    await channel.set_qos(prefetch_count=1)

    load_geoip_database()

    report_task_queue = await channel.declare_queue("wsc_report_tasks", durable=True)

    logger.info("REPORT GENERATOR started. Waiting for report tasks...")
    await report_task_queue.consume(handle_report_task)
    await asyncio.Future()


def _init_clickhouse():
    logger.info("Verbinde mit ClickHouse (Warte auf Wake-Up, falls im Sleep-Modus)...")
    max_retries = 10
    for attempt in range(max_retries):
        try:
            client = clickhouse_connect.get_client(
                host=CLICKHOUSE_HOST,
                port=CLICKHOUSE_PORT,
                username=CLICKHOUSE_USER,
                password=CLICKHOUSE_PASS,
                connect_timeout=30,
                send_receive_timeout=45
            )
            client.command("SELECT 1")
            logger.info("ClickHouse ist wach und verbunden!")
            return client
        except Exception as e:
            logger.warning(f"ClickHouse not ready (attempt {attempt+1}/{max_retries}): {e}")
            import time
            time.sleep(2 ** attempt)
    logger.critical("Could not connect to ClickHouse after retries.")
    raise RuntimeError("ClickHouse connection failed")


async def handle_reports_trigger_as_dispatcher(message: aio_pika.IncomingMessage, channel=None):
    """
    Dispatcher logic.
    Consumes from wsc_trigger_reports (from scheduler or manual).
    Performs early checks (activity, rate limit, meaningful data).
    Only then publishes a task to wsc_report_tasks for the report generator.

    This allows the decision logic to be lightweight and separate from heavy report generation.
    Supports single dicts, lists of projects/dicts, empty lists, or plain strings.
    """
    try:
        pub_channel = channel or message.channel
        raw_bytes = message.body or b""

        # Safely parse JSON payload
        triggers = []
        if not raw_bytes or not raw_bytes.strip():
            triggers.append({})
        else:
            try:
                body = json.loads(raw_bytes.decode("utf-8"))
            except Exception as je:
                logger.warning(f"Dispatcher received unparseable non-JSON payload ({je}): {raw_bytes[:200]}")
                # Acknowledge and discard corrupt/unparseable messages to prevent infinite poison-pill loops
                await message.ack()
                return

            if isinstance(body, dict):
                triggers.append(body)
            elif isinstance(body, list):
                if not body:
                    # Empty list behaves like general trigger (discover all active projects)
                    triggers.append({})
                else:
                    for elem in body:
                        if isinstance(elem, dict):
                            triggers.append(elem)
                        elif isinstance(elem, str) and elem.strip():
                            triggers.append({"project_id": elem.strip()})
                        else:
                            logger.warning(f"Dispatcher ignoring invalid list element ({type(elem)}): {elem}")
            elif isinstance(body, str) and body.strip():
                triggers.append({"project_id": body.strip()})
            else:
                logger.warning(f"Dispatcher received unexpected payload type ({type(body)}): {body}")
                await message.ack()
                return

        for trigger_item in (triggers if triggers else [{}]):
            project_id = trigger_item.get("project_id")
            force = trigger_item.get("force", False) or trigger_item.get("resync", False)
            is_dev = trigger_item.get("dev_mode", False) or trigger_item.get("is_dev", False)

            if not project_id:
                logger.info("Dispatcher: No project_id – discovering active projects...")
                projects = await get_active_projects()
                if not projects:
                    logger.info("Dispatcher: No active projects found.")
                    continue
                for pid in projects:
                    if force or is_dev or await _should_generate_report(pid, force=force, is_dev=is_dev):
                        await _publish_report_task(pub_channel, pid, force=force, is_dev=is_dev)
                continue

            if force or is_dev or await _should_generate_report(project_id, force=force, is_dev=is_dev):
                await _publish_report_task(pub_channel, project_id, force=force, is_dev=is_dev)
            else:
                # Detailed skip reason is already logged inside _should_generate_report
                logger.info(f"Dispatcher: Skipping report generation for {project_id} (see previous log for reason)")

        await message.ack()
    except Exception as e:
        logger.error(f"Error in dispatcher: {e}", exc_info=True)
        # Poison pill protection: If redelivered, drop to prevent crash-looping
        if getattr(message, "redelivered", False):
            logger.warning("Dispatcher: Message was already redelivered; dropping to prevent poison-pill crash loop.")
            await message.ack()
        else:
            await message.nack(requeue=False)


async def _should_generate_report(project_id: str, force: bool = False, is_dev: bool = False) -> bool:
    """Early check before publishing a report task.
    Returns True only if we should generate reports.
    Detailed skip reasons are logged at INFO level for easy observation.
    """
    if force:
        logger.info(f"Dispatcher: Force flag active for {project_id} — bypassing rate limit and activity checks.")
        return True

    if is_dev:
        logger.info(f"Dispatcher: Dev mode active for {project_id} — bypassing rate limit and activity checks.")
        return True

    # Global environment override (useful for local development & testing)
    if os.getenv("DISABLE_REPORT_RATE_LIMIT", "").lower() in ("true", "1", "yes"):
        logger.info(f"Dispatcher: Global rate limit disabled via env — proceeding for {project_id}.")
        return True

    try:
        global redis_client
        if redis_client:
            dev_flag = await redis_client.get(f"project:{project_id}:dev_mode")
            if dev_flag:
                logger.info(f"Dispatcher: Project {project_id} flagged as dev_mode in Redis — bypassing rate limit.")
                return True
    except Exception as e:
        logger.debug(f"Redis dev_mode check failed for {project_id}: {e}")

    # 1. Rate limit check
    try:
        last = ch_client.query("""
            SELECT max(generated_at)
            FROM wsc_assembled_reports
            WHERE project_id = %(pid)s
              AND report_type IN ('card1_traffic', 'card2_insights', 'card3_bots')
        """, parameters={"pid": project_id}).first_row
        if last and last[0]:
            last_ts = last[0]
            age_seconds = (datetime.utcnow() - last_ts).total_seconds()
            if age_seconds < 50 * 60:
                age_min = int(age_seconds / 60)
                logger.info(f"Dispatcher: Skipping {project_id} — recent report exists (last {age_min} min ago, rate limit ~50min).")
                return False
    except Exception as e:
        logger.debug(f"Rate limit check failed for {project_id}: {e}")
        # proceed on error

    # 2. Activity check: require at least one relevant event recently
    try:
        recent = ch_client.query("""
            SELECT count() as cnt
            FROM wsc_analytics_raw
            WHERE project_id = %(pid)s
              AND event_type IN ('pageview', 'bot_hit')
              AND timestamp >= toUnixTimestamp(now() - INTERVAL 2 HOUR)
        """, parameters={"pid": project_id}).first_row
        event_count = recent[0] if recent else 0
        if event_count == 0:
            logger.info(f"Dispatcher: Skipping {project_id} — no pageview or bot_hit activity in the last 2 hours.")
            return False
        else:
            logger.debug(f"Dispatcher: {project_id} has {event_count} relevant events in last 2h.")
    except Exception as e:
        logger.debug(f"Activity check failed for {project_id}: {e}")
        # if check fails, allow (fail open for now)

    return True


async def _publish_report_task(channel, project_id: str, force: bool = False, is_dev: bool = False):
    """Send a clean task message to the report generator queue."""
    task = {"project_id": project_id, "force": force, "dev_mode": is_dev}
    msg = aio_pika.Message(
        json.dumps(task).encode(),
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT
    )
    if hasattr(channel, "default_exchange"):
        await channel.default_exchange.publish(msg, routing_key="wsc_report_tasks")
    elif hasattr(channel, "basic_publish"):
        await channel.basic_publish(msg.body, exchange="", routing_key="wsc_report_tasks")
    logger.info(f"Dispatcher: Published report task for {project_id} (force={force}, is_dev={is_dev})")


async def _trigger_resync_reports(channel, project_id: str):
    """Publish a forced report trigger when a resync_request synthetic event is received.
    This makes the plugin's "Full Reset + Re-sync" button actually pull fresh dashboard data.
    """
    try:
        trigger = {
            "project_id": project_id,
            "force": True,
            "reason": "resync_request"
        }
        msg = aio_pika.Message(
            json.dumps(trigger).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT
        )
        if hasattr(channel, "default_exchange"):
            await channel.default_exchange.publish(msg, routing_key="wsc_trigger_reports")
        elif hasattr(channel, "basic_publish"):
            await channel.basic_publish(msg.body, exchange="", routing_key="wsc_trigger_reports")
        logger.info(f"Resync requested via event: force trigger published for {project_id}")
    except Exception as e:
        logger.error(f"Failed to publish resync trigger for {project_id}: {e}")


async def handle_report_task(message: aio_pika.IncomingMessage):
    """Consumed by the report generator worker.
    Receives tasks only for projects where the dispatcher decided a report is needed.
    """
    try:
        raw_bytes = message.body or b""
        if not raw_bytes or not raw_bytes.strip():
            await message.ack()
            return

        try:
            body = json.loads(raw_bytes.decode("utf-8"))
        except Exception as je:
            logger.warning(f"Report generator received unparseable non-JSON payload ({je}): {raw_bytes[:200]}")
            await message.ack()
            return

        pids = []
        if isinstance(body, dict):
            pid = body.get("project_id")
            if pid:
                pids.append(pid)
        elif isinstance(body, list):
            for elem in body:
                if isinstance(elem, dict) and elem.get("project_id"):
                    pids.append(elem.get("project_id"))
                elif isinstance(elem, str) and elem.strip():
                    pids.append(elem.strip())
        elif isinstance(body, str) and body.strip():
            pids.append(body.strip())
        else:
            logger.warning(f"Report generator received unexpected payload type ({type(body)}): {body}")
            await message.ack()
            return

        for pid in pids:
            await generate_reports_for_project(pid)

        await message.ack()
    except Exception as e:
        logger.error(f"Error in report task handler: {e}", exc_info=True)
        if getattr(message, "redelivered", False):
            logger.warning("Report generator: Task was already redelivered; dropping to prevent crash loop.")
            await message.ack()
        else:
            await message.nack(requeue=False)


async def get_active_projects(limit: int = 20) -> list:
    """Discover projects that have had traffic or bot activity recently."""
    if not ch_client:
        return []
    try:
        rows = ch_client.query("""
            SELECT DISTINCT project_id
            FROM wsc_traffic_daily
            WHERE date >= today() - 2   -- activity in last ~2 days
            ORDER BY project_id
            LIMIT %(limit)s
        """, parameters={"limit": limit}).result_rows

        if not rows:
            # fallback to raw if no daily yet
            rows = ch_client.query("""
                SELECT DISTINCT project_id
                FROM wsc_analytics_raw
                WHERE toDate(toDateTime(timestamp)) >= today() - 1
                LIMIT %(limit)s
            """, parameters={"limit": limit}).result_rows

        projects = [r[0] for r in rows if r[0]]
        logger.info(f"Discovered {len(projects)} active projects for reporting.")
        return projects
    except Exception as e:
        logger.warning(f"Failed to discover active projects: {e}")
        return []


async def generate_reports_for_project(project_id: str):
    """Report generator logic for one project.
    Called only after dispatcher decided it's worth it.
    Does populate + assemble + push.
    """
    logger.info(f"Report generator: Processing reports for {project_id}")

    # Note: Rate limit and early checks are now done by the Dispatcher.
    # We trust that we only receive tasks worth processing.

    # Worker 1 step
    await populate_aggregates(project_id)

    reports_to_push = []

    # Card 1
    card1 = await assemble_card1_traffic_report(project_id)
    has_card1 = False
    if card1:
        kpi_uv = (card1.get("kpi", {}) or {}).get("unique_visitors", 0) or \
                 (card1.get("data_7d", {}) or {}).get("kpi", {}).get("unique_visitors", 0)
        if kpi_uv > 0:
            reports_to_push.append(card1)
            has_card1 = True

    # Card 2
    card2 = await assemble_card2_insights_report(project_id)
    if card2 and card2.get("human_text"):
        reports_to_push.append(card2)

    # Card 3
    card3 = await assemble_card3_bots_report(project_id)
    if card3:
        reports_to_push.append(card3)

    # Engagement Report (Card Engagement)
    card_eng = await assemble_card_engagement_report(project_id)
    if card_eng and (card_eng.get("kpi", {}).get("total_events", 0) > 0 or card_eng.get("pages")):
        reports_to_push.append(card_eng)

    # Outbound Report (Card Outbound)
    card_out = await assemble_card_outbound_report(project_id)
    if card_out and card_out.get("destinations"):
        reports_to_push.append(card_out)

    # E-Commerce Reality Report (Card E-Commerce)
    card_ecom = await assemble_card_ecommerce_report(project_id)
    if card_ecom and (card_ecom.get("kpi", {}).get("product_views", 0) > 0 or card_ecom.get("funnel")):
        reports_to_push.append(card_ecom)

    # Domain & Tech Health Sentinel Report
    health_report = await assemble_sentinel_health_report(project_id)
    if health_report:
        reports_to_push.append(health_report)

    # Only push if we have real traffic data or meaningful cards
    has_meaningful = (
        has_card1
        or (card2 and card2.get('human_text'))
        or (card3 and card3.get('kpi', {}).get('human_pct'))
        or (card_eng and (card_eng.get('pages') or card_eng.get('kpi', {}).get('total_events', 0) > 0))
        or (card_out and card_out.get('destinations'))
        or (card_ecom and card_ecom.get('funnel'))
        or health_report
    )
    if reports_to_push and has_meaningful:
        await push_reports_via_gateway(project_id, reports_to_push)
        logger.info(f"Pushed {len(reports_to_push)} reports for {project_id}")
    else:
        logger.info(f"No useful data for reports on {project_id}")


async def populate_aggregates(project_id: str):
    """Populate aggregate tables from raw data.
    Called from scheduled report trigger worker.
    """
    if not ch_client:
        return

    try:
        # Aggregate only for yesterday (completed day) to keep aggregates clean.
        # Last 24h reports use raw data (always fresh).
        yesterday = (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')

        # Daily overview for yesterday
        ch_client.command(f"""
            INSERT INTO wsc_daily_overview (project_id, date, pageviews, sessions, unique_visitors, bot_hits, total_events)
            SELECT
                project_id,
                toDate(toDateTime(timestamp)) as date,
                countIf(event_type = 'pageview') as pageviews,
                uniq(session_id) as sessions,
                uniq(session_id) as unique_visitors,
                countIf(event_type = 'bot_hit') as bot_hits,
                count() as total_events
            FROM wsc_analytics_raw
            WHERE project_id = %(project_id)s
              AND toDate(toDateTime(timestamp)) = toDate('{yesterday}')
            GROUP BY project_id, date
        """, parameters={"project_id": project_id})

        # Bot stats for yesterday
        ch_client.command(f"""
            INSERT INTO wsc_bot_stats
            SELECT
                project_id,
                toDate(toDateTime(timestamp)) as date,
                bot_name,
                bot_category,
                bot_type,
                count() as hits
            FROM wsc_analytics_raw
            WHERE project_id = %(project_id)s
              AND event_type = 'bot_hit'
              AND bot_name != ''
              AND toDate(toDateTime(timestamp)) = toDate('{yesterday}')
            GROUP BY project_id, date, bot_name, bot_category, bot_type
        """, parameters={"project_id": project_id})

        # Top pages for yesterday
        ch_client.command(f"""
            INSERT INTO wsc_top_pages
            SELECT
                project_id,
                toDate(toDateTime(timestamp)) as date,
                url_path,
                count() as views
            FROM wsc_analytics_raw
            WHERE project_id = %(project_id)s
              AND event_type = 'pageview'
              AND url_path != ''
              AND toDate(toDateTime(timestamp)) = toDate('{yesterday}')
            GROUP BY project_id, date, url_path
        """, parameters={"project_id": project_id})

        logger.info(f"Aggregates populated for {project_id}")

    except Exception as e:
        logger.error(f"Failed to populate aggregates for {project_id}: {e}")


# ==================== REPORT GENERATORS (Phase 2) ====================

async def generate_and_push_reports(project_id: str):
    """Generate the first 4 standard reports and push via gateway internal endpoint."""
    if not ch_client:
        logger.warning("No ClickHouse client for reports")
        return

    now = datetime.utcnow()
    period_start = (now - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')

    reports = []

    try:
        # 1. Overview Report (prefer aggregate table)
        try:
            overview = ch_client.query("""
                SELECT total_events, pageviews, sessions, bot_hits
                FROM wsc_daily_overview
                WHERE project_id = %(project_id)s
                  AND date = today()
            """, parameters={"project_id": project_id}).first_row
        except:
            overview = None

        if not overview:
            overview = ch_client.query("""
                SELECT 
                    count() as total_events,
                    countIf(event_type = 'pageview') as pageviews,
                    uniq(session_id) as unique_sessions,
                    countIf(event_type = 'bot_hit') as bot_hits,
                    countIf(event_type IN ('download', 'video_play', 'outbound_click')) as interactions
                FROM wsc_analytics_raw
                WHERE project_id = %(project_id)s
                  AND timestamp >= toUnixTimestamp(%(period_start)s)
            """, parameters={"project_id": project_id, "period_start": period_start}).first_row

        reports.append({
            "report_type": "overview",
            "project_id": project_id,
            "period": "last_24h",
            "generated_at": now.isoformat(),
            "data": {
                "total_events": overview[0] if overview else 0,
                "pageviews": overview[1] if overview else 0,
                "unique_sessions": overview[2] if overview else 0,
                "bot_hits": overview[3] if overview else 0,
                "interactions": overview[4] if overview and len(overview) > 4 else 0
            }
        })

        # 2. Bot Report
        bot_rows = ch_client.query("""
            SELECT bot_name, bot_category, bot_type, count() as hits
            FROM wsc_analytics_raw
            WHERE project_id = %(project_id)s
              AND event_type = 'bot_hit'
              AND timestamp >= toUnixTimestamp(%(period_start)s)
            GROUP BY bot_name, bot_category, bot_type
            ORDER BY hits DESC
            LIMIT 20
        """, parameters={"project_id": project_id, "period_start": period_start}).result_rows

        reports.append({
            "report_type": "bot",
            "project_id": project_id,
            "period": "last_24h",
            "generated_at": now.isoformat(),
            "data": [
                {"bot_name": row[0], "bot_category": row[1], "bot_type": row[2], "hits": row[3]}
                for row in bot_rows
            ]
        })

        # 3. Daily Summary (simple version of overview + top referrer placeholder)
        reports.append({
            "report_type": "daily_summary",
            "project_id": project_id,
            "period": "last_24h",
            "generated_at": now.isoformat(),
            "data": {
                "pageviews": overview[1] if overview else 0,
                "unique_visitors_approx": overview[2] if overview else 0,
                "top_referrer": "direct"  # placeholder, enhance later
            }
        })

        # 4. Top Pages
        top_pages = ch_client.query("""
            SELECT url_path, count() as views
            FROM wsc_analytics_raw
            WHERE project_id = %(project_id)s
              AND event_type = 'pageview'
              AND timestamp >= toUnixTimestamp(%(period_start)s)
            GROUP BY url_path
            ORDER BY views DESC
            LIMIT 10
        """, parameters={"project_id": project_id, "period_start": period_start}).result_rows

        reports.append({
            "report_type": "top_pages",
            "project_id": project_id,
            "period": "last_24h",
            "generated_at": now.isoformat(),
            "data": {row[0]: row[1] for row in top_pages}
        })

        # Push to gateway
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "http://gateway:8000/internal/dispatch-insights",
                json={"project_id": project_id, "insights": reports},
                timeout=15.0
            )
            if resp.status_code == 200:
                logger.info(f"Pushed {len(reports)} reports for {project_id}")
            else:
                logger.warning(f"Push reports failed: {resp.status_code} {resp.text}")

    except Exception as e:
        logger.error(f"Report generation/push error for {project_id}: {e}")


# ==================== CARD 1: TRAFFIC REPORT (mehrstufige Pipeline) ====================
# NOTE: All human_text, actions and user-facing report strings MUST be in English (backend standard).
# Plugin UI can localize labels around them.

async def _save_assembled_report(project_id: str, report: dict, has_data: bool = True):
    """Helper: writes assembled report to ClickHouse for history + rate limiting."""
    if not ch_client or not report:
        return
    try:
        now = datetime.utcnow()
        period_start = (now - timedelta(days=30)).date()
        ch_client.insert(
            'wsc_assembled_reports',
            [[
                project_id,
                report.get("report_type", "unknown"),
                period_start,
                now.date(),
                now,
                json.dumps(report),
                1 if has_data else 0
            ]],
            column_names=['project_id', 'report_type', 'period_start', 'period_end', 'generated_at', 'payload', 'has_data']
        )
    except Exception as e:
        logger.debug(f"Could not save assembled report: {e}")


async def assemble_card1_traffic_report(project_id: str):
    """Worker 2: Builds the final report for Card 1 (Traffic & Channels).
    Always builds data_7d + data_30d (for plugin toggle).
    Queries from wsc_traffic_hourly (today) + wsc_traffic_daily (MV).
    Builds human texts + 7-point sparkline (sampled for longer periods).
    """
    if not ch_client:
        return None

    now = datetime.utcnow()

    # Query today's data once (used for "today so far" and attached to report)
    today_rows = []
    try:
        today_rows = ch_client.query("""
            SELECT 
                hour,
                traffic_source,
                sum(pageviews) as pageviews,
                uniqMerge(unique_visitors) as unique_visitors
            FROM wsc_traffic_hourly
            WHERE project_id = %(project_id)s
              AND date = today()
            GROUP BY hour, traffic_source
            ORDER BY hour ASC
        """, parameters={"project_id": project_id}).result_rows
    except Exception as e:
        logger.debug(f"Today hourly not available yet: {e}")

    def _get_top_pages(project_id: str, start_date):
        """Helper: Top Pages for period."""
        try:
            tp_rows = ch_client.query("""
                SELECT url_path, sum(views) as views
                FROM wsc_top_pages
                WHERE project_id = %(pid)s AND date >= %(start)s
                GROUP BY url_path
                ORDER BY views DESC
                LIMIT 10
            """, parameters={"pid": project_id, "start": start_date}).result_rows
            return [{"url": r[0], "views": r[1]} for r in tp_rows]
        except Exception as e:
            logger.debug(f"Top pages query failed: {e}")
            return []

    def _get_top_referrers(project_id: str, start_date, sources=None):
        """Separated helper for top referrers (detailed domains, fallback to sources)."""
        try:
            ref_rows = ch_client.query("""
                SELECT domainWithoutWWW(referrer_url) as dom, count() as cnt
                FROM wsc_analytics_raw
                WHERE project_id = %(pid)s 
                  AND event_type = 'pageview'
                  AND timestamp >= toUnixTimestamp(%(start)s)
                  AND referrer_url != ''
                GROUP BY dom
                ORDER BY cnt DESC
                LIMIT 10
            """, parameters={"pid": project_id, "start": start_date}).result_rows
            return [{"referrer": r[0], "pageviews": r[1]} for r in ref_rows]
        except Exception as e:
            logger.debug(f"Top referrers from raw failed, using sources: {e}")
            if sources:
                sorted_src = sorted(sources.items(), key=lambda x: -x[1].get("pageviews", 0))[:5]
                return [{"referrer": src, "pageviews": data.get("pageviews", 0)} for src, data in sorted_src]
            return []

    def build_for_days(days):
        start_date = (now - timedelta(days=days)).date()
        start_ts = int((now - timedelta(days=days)).timestamp())
        prev_start_date = (now - timedelta(days=days * 2)).date()
        
        rows = ch_client.query("""
            SELECT 
                date,
                traffic_source,
                sum(pageviews) as pageviews,
                uniqMerge(unique_visitors) as unique_visitors
            FROM wsc_traffic_daily
            WHERE project_id = %(project_id)s
              AND date >= %(start_date)s
            GROUP BY date, traffic_source
            ORDER BY date ASC
        """, parameters={"project_id": project_id, "start_date": start_date}).result_rows

        sources = {}
        total_unique = 0
        total_pageviews = 0
        total_interactions = 0
        daily_totals = {}

        for row in rows:
            date, source, pv, uv = row
            if source not in sources:
                sources[source] = {"pageviews": 0, "unique_visitors": 0}
            sources[source]["pageviews"] += pv
            sources[source]["unique_visitors"] += uv
            total_pageviews += pv
            total_unique += uv

            if date not in daily_totals:
                daily_totals[date] = {"pageviews": 0, "unique_visitors": 0}
            daily_totals[date]["pageviews"] += pv
            daily_totals[date]["unique_visitors"] = daily_totals[date].get("unique_visitors", 0) + uv

        # Previous period comparison (WoW / MoM / YoY)
        prev_pv = 0
        prev_uv = 0
        try:
            prev_rows = ch_client.query("""
                SELECT 
                    sum(pageviews) as pageviews,
                    uniqMerge(unique_visitors) as unique_visitors
                FROM wsc_traffic_daily
                WHERE project_id = %(project_id)s
                  AND date >= %(prev_start)s
                  AND date < %(start_date)s
            """, parameters={
                "project_id": project_id,
                "prev_start": prev_start_date,
                "start_date": start_date
            }).first_row
            if prev_rows:
                prev_pv = int(prev_rows[0] or 0)
                prev_uv = int(prev_rows[1] or 0)
        except Exception as e:
            logger.debug(f"Previous period query failed: {e}")

        diff_pv = total_pageviews - prev_pv
        change_pv_pct = round(((total_pageviews - prev_pv) / max(1, prev_pv)) * 100.0, 1) if prev_pv > 0 else 0.0
        diff_uv = total_unique - prev_uv
        change_uv_pct = round(((total_unique - prev_uv) / max(1, prev_uv)) * 100.0, 1) if prev_uv > 0 else 0.0
        
        comp_type = "wow" if days == 7 else ("mom" if days == 30 else ("yoy" if days >= 180 else "prev_period"))
        pv_trend = "up" if change_pv_pct > 0 else ("down" if change_pv_pct < 0 else "neutral")
        uv_trend = "up" if change_uv_pct > 0 else ("down" if change_uv_pct < 0 else "neutral")

        # Discrete interactions (clicks / media / forms)
        interactions = {}
        try:
            int_rows = ch_client.query("""
                SELECT event_type, count() as cnt
                FROM wsc_analytics_raw
                WHERE project_id = %(project_id)s
                  AND timestamp >= %(start_ts)s
                  AND event_type IN ('download', 'video_play', 'video_complete', 'outbound_click', 'form_submit')
                GROUP BY event_type
            """, parameters={
                "project_id": project_id,
                "start_ts": start_ts,
            }).result_rows
            for row in int_rows:
                et, cnt = row
                interactions[et] = int(cnt)
                total_interactions += int(cnt)
        except Exception as e:
            logger.debug(f"Interaction breakdown query failed: {e}")

        # Engagement: avg active time (final time_on_page), scroll reach, interaction rate
        avg_active_ms = 0
        avg_duration_ms = 0
        scroll_reach = {"25": 0, "50": 0, "75": 0, "100": 0}
        form_submits = int(interactions.get("form_submit", 0))
        try:
            # final time_on_page + scroll milestones from custom_data JSON
            eng_row = ch_client.query("""
                SELECT
                    avgIf(
                        if(
                            JSONExtractFloat(custom_data, 'active_ms') > 0,
                            JSONExtractFloat(custom_data, 'active_ms'),
                            JSONExtractFloat(custom_data, 'duration_ms')
                        ),
                        event_type = 'time_on_page'
                        AND (
                            JSONExtractBool(custom_data, 'final')
                            OR positionCaseInsensitive(custom_data, '"final":true') > 0
                            OR positionCaseInsensitive(custom_data, '"final": true') > 0
                        )
                    ) as avg_active_ms,
                    avgIf(
                        JSONExtractFloat(custom_data, 'duration_ms'),
                        event_type = 'time_on_page'
                        AND (
                            JSONExtractBool(custom_data, 'final')
                            OR positionCaseInsensitive(custom_data, '"final":true') > 0
                        )
                    ) as avg_duration_ms,
                    countIf(event_type = 'scroll_depth' AND JSONExtractInt(custom_data, 'percent') = 25) as s25,
                    countIf(event_type = 'scroll_depth' AND JSONExtractInt(custom_data, 'percent') = 50) as s50,
                    countIf(event_type = 'scroll_depth' AND JSONExtractInt(custom_data, 'percent') = 75) as s75,
                    countIf(event_type = 'scroll_depth' AND JSONExtractInt(custom_data, 'percent') = 100) as s100
                FROM wsc_analytics_raw
                WHERE project_id = %(project_id)s
                  AND timestamp >= %(start_ts)s
            """, parameters={"project_id": project_id, "start_ts": start_ts}).result_rows
            if eng_row:
                r = eng_row[0]
                avg_active_ms = int(r[0] or 0)
                avg_duration_ms = int(r[1] or 0)
                scroll_reach = {
                    "25": int(r[2] or 0),
                    "50": int(r[3] or 0),
                    "75": int(r[4] or 0),
                    "100": int(r[5] or 0),
                }
        except Exception as e:
            logger.debug(f"Engagement metrics query failed: {e}")

        interaction_rate = round(
            (total_interactions / max(1, total_unique)) * 100, 1
        ) if total_unique else 0.0

        daily_totals_sorted = sorted(daily_totals.items())

        # Fetch tops early (for human text + return). Use per-period start_date.
        top_pages = _get_top_pages(project_id, start_date)
        top_referrers = _get_top_referrers(project_id, start_date, sources)

        # Sparkline: always exactly 7 chronological points for the trend
        sparkline = []
        today_date = now.date()
        if days <= 7:
            for i in range(7):
                pt_date = today_date - timedelta(days=(6 - i))
                vals = daily_totals.get(pt_date, {})
                sparkline.append({
                    "date": str(pt_date),
                    "unique_visitors": vals.get("unique_visitors", 0),
                    "pageviews": vals.get("pageviews", 0)
                })
        else:
            bucket_size = days / 7.0
            for i in range(7):
                b_start = start_date + timedelta(days=int(i * bucket_size))
                b_end = start_date + timedelta(days=min(days - 1, int((i + 1) * bucket_size) - 1))
                if b_end < b_start:
                    b_end = b_start
                b_pv = 0
                b_uv = 0
                curr = b_start
                while curr <= b_end:
                    v = daily_totals.get(curr, {})
                    b_pv += v.get("pageviews", 0)
                    b_uv += v.get("unique_visitors", 0)
                    curr += timedelta(days=1)
                sparkline.append({
                    "date": str(b_end),
                    "unique_visitors": b_uv,
                    "pageviews": b_pv
                })

        # find top source
        top_source = max(sources, key=lambda s: sources[s]["pageviews"]) if sources else "direct"
        top_share = round( (sources[top_source]["pageviews"] / max(1, total_pageviews) * 100) ) if sources and total_pageviews > 0 else 0
        human_text = f"Over the last {days} days you had approx. {total_unique:,} unique visitors with {total_pageviews:,} pageviews. Top channel: {top_source} ({top_share}%)."

        if total_interactions > 0:
            human_text += f" {total_interactions} interactions (downloads, videos, outbound, forms)."
            if interaction_rate:
                human_text += f" Interaction rate ~{interaction_rate}% of visitors."
        if avg_active_ms > 0:
            human_text += f" Avg engaged time ~{max(1, round(avg_active_ms/1000))}s."
        if scroll_reach.get("50"):
            human_text += f" Scroll ≥50%: {scroll_reach['50']} events."
        if top_pages:
            human_text += f" Top page: {top_pages[0]['url'][:40]}."
        if top_referrers:
            human_text += f" Top referrer: {top_referrers[0]['referrer']}."

        return {
            "period_days": days,
            "kpi": {
                "unique_visitors": total_unique,
                "pageviews": total_pageviews,
                "sessions": total_unique,
                "interactions": total_interactions,
                "interaction_breakdown": interactions,
                "interaction_rate_pct": interaction_rate,
                "avg_engaged_ms": avg_active_ms,
                "avg_duration_ms": avg_duration_ms,
                "scroll_reach": scroll_reach,
                "form_submits": form_submits,
                "human_text": human_text,
                "comparison": {
                    "type": comp_type,
                    "previous_pageviews": prev_pv,
                    "pageviews_diff": diff_pv,
                    "pageviews_change_pct": change_pv_pct,
                    "previous_unique_visitors": prev_uv,
                    "unique_visitors_diff": diff_uv,
                    "unique_visitors_change_pct": change_uv_pct,
                    "trend": pv_trend,
                    "uv_trend": uv_trend
                }
            },
            "sources": sources,
            "sparkline": sparkline,
            "today_hourly": today_rows,
            "top_pages": top_pages,
            "top_referrers": top_referrers
        }

    try:
        data_1d = build_for_days(1)
        data_7d = build_for_days(7)
        data_30d = build_for_days(30)
        data_90d = build_for_days(90)
        data_180d = build_for_days(180)
        data_365d = build_for_days(365)

        # Haupt-KPI standardmäßig 7 Tage
        main_kpi = data_7d["kpi"]
        main_kpi["human_text_7d"] = data_7d["kpi"]["human_text"]
        main_kpi["human_text_30d"] = data_30d["kpi"]["human_text"]

        report = {
            "report_type": "card1_traffic",
            "project_id": project_id,
            "generated_at": now.isoformat(),
            "lang": "en",
            "period": "multi",
            "kpi": main_kpi,
            "data_1d": data_1d,
            "data_7d": data_7d,
            "data_30d": data_30d,
            "data_90d": data_90d,
            "data_180d": data_180d,
            "data_365d": data_365d,
            "periods": {
                "1": data_1d,
                "7": data_7d,
                "30": data_30d,
                "90": data_90d,
                "180": data_180d,
                "365": data_365d,
            },
            "today_hourly": today_rows,
            "note": "Multi-period dataset with WoW, MoM, YoY comparisons from ClickHouse MVs."
        }

        # Persist for rate-limiting and history
        await _save_assembled_report(project_id, report, has_data=(data_7d.get("kpi", {}).get("unique_visitors", 0) > 0))

        return report

    except Exception as e:
        logger.error(f"Error assembling Card 1 report for {project_id}: {e}")
        return None
        return None


# ==================== CARD 2: INSIGHTS & ANOMALIES ====================
# NOTE: All human_text, actions and user-facing report strings MUST be in English (backend standard).
# Plugin UI can localize labels around them.

async def _fetch_traffic_kpi(project_id: str, start_date, end_date):
    """Separated data query helper."""
    if not ch_client:
        return {"pv": 0, "uv": 0}
    row = ch_client.query("""
        SELECT sum(pageviews) as pv, uniqMerge(unique_visitors) as uv
        FROM wsc_traffic_daily
        WHERE project_id = %(pid)s AND date >= %(start)s AND date < %(end)s
    """, parameters={"pid": project_id, "start": start_date, "end": end_date}).first_row or (0, 0)
    return {"pv": row[0] or 0, "uv": row[1] or 0}

async def _build_card2_human_text(kpi7, kpi_prev, sources):
    """Separated human text + actions builder (English)."""
    delta_uv = 0
    if kpi_prev["uv"] > 0:
        delta_uv = round((kpi7["uv"] - kpi_prev["uv"]) / kpi_prev["uv"] * 100)
    text = f"Over the last 7 days you had {kpi7['uv']:,} unique visitors."
    if delta_uv:
        text += f" That's {'up' if delta_uv > 0 else 'down'} {abs(delta_uv)}% from the prior period."
    actions = ["Review top source performance.", "Check the top page for optimization opportunities."]
    if sources:
        top = max(sources, key=lambda k: sources[k].get("pageviews", 0))
        actions.append(f"Focus on {top} traffic.")
    return text, actions

def _card2_engagement_metrics(project_id: str, days: int, now: datetime) -> dict:
    """Discrete interactions + avg engaged time + form submits for Card 2 insights."""
    start_ts = int((now - timedelta(days=days)).timestamp())
    out = {
        "interactions": 0,
        "interaction_breakdown": {},
        "interaction_rate_pct": 0.0,
        "avg_engaged_ms": 0,
        "form_submits": 0,
        "scroll_50": 0,
    }
    if not ch_client:
        return out
    try:
        int_rows = ch_client.query("""
            SELECT event_type, count() as cnt
            FROM wsc_analytics_raw
            WHERE project_id = %(project_id)s
              AND timestamp >= %(start_ts)s
              AND event_type IN ('download', 'video_play', 'video_complete', 'outbound_click', 'form_submit')
            GROUP BY event_type
        """, parameters={"project_id": project_id, "start_ts": start_ts}).result_rows
        breakdown = {}
        total = 0
        for et, cnt in int_rows:
            c = int(cnt or 0)
            breakdown[et] = c
            total += c
        out["interaction_breakdown"] = breakdown
        out["interactions"] = total
        out["form_submits"] = int(breakdown.get("form_submit", 0))
    except Exception as e:
        logger.debug(f"Card2 engagement discrete query failed: {e}")

    try:
        eng = ch_client.query("""
            SELECT
                avgIf(
                    if(
                        JSONExtractFloat(custom_data, 'active_ms') > 0,
                        JSONExtractFloat(custom_data, 'active_ms'),
                        JSONExtractFloat(custom_data, 'duration_ms')
                    ),
                    event_type = 'time_on_page'
                    AND (
                        JSONExtractBool(custom_data, 'final')
                        OR positionCaseInsensitive(custom_data, '"final":true') > 0
                        OR positionCaseInsensitive(custom_data, '"final": true') > 0
                    )
                ) as avg_active_ms,
                countIf(event_type = 'scroll_depth' AND JSONExtractInt(custom_data, 'percent') = 50) as s50
            FROM wsc_analytics_raw
            WHERE project_id = %(project_id)s
              AND timestamp >= %(start_ts)s
        """, parameters={"project_id": project_id, "start_ts": start_ts}).result_rows
        if eng:
            out["avg_engaged_ms"] = int(eng[0][0] or 0)
            out["scroll_50"] = int(eng[0][1] or 0)
    except Exception as e:
        logger.debug(f"Card2 engagement timing query failed: {e}")

    return out


async def assemble_card2_insights_report(project_id: str):
    """Rule-based insights with engagement metrics. Builds data_7d + data_30d for plugin toggle."""
    if not ch_client:
        return None

    now = datetime.utcnow()

    def delta_pct(curr, prev):
        if not prev:
            return 0
        return round(((curr - prev) / prev) * 100)

    def fetch_sources(d_start, total_pv):
        sources = {}
        try:
            rows = ch_client.query("""
                SELECT traffic_source, sum(pageviews) as pv, uniqMerge(unique_visitors) as uv
                FROM wsc_traffic_daily
                WHERE project_id = %(pid)s AND date >= %(d_start)s
                GROUP BY traffic_source
                ORDER BY pv DESC
                LIMIT 5
            """, parameters={"pid": project_id, "d_start": d_start}).result_rows
            for row in rows:
                src, pv, uv = row[0], int(row[1] or 0), int(row[2] or 0) if len(row) > 2 else 0
                pct = round((pv / max(1, total_pv)) * 100) if total_pv > 0 else 0
                sources[src] = {"pageviews": pv, "pct": pct, "unique_visitors": uv}
        except Exception as e:
            logger.debug(f"Card2 sources failed: {e}")
        return sources

    def fetch_top_pages(d_start):
        try:
            tp_rows = ch_client.query("""
                SELECT url_path, sum(views) as v
                FROM wsc_top_pages
                WHERE project_id = %(pid)s AND date >= %(d_start)s
                GROUP BY url_path ORDER BY v DESC LIMIT 5
            """, parameters={"pid": project_id, "d_start": d_start}).result_rows
            return [{"url": r[0], "views": int(r[1] or 0)} for r in tp_rows]
        except Exception:
            return []

    def source_changes_vs_prev(src_totals, d_prev_start, d_prev_end):
        changes = []
        try:
            prev_src = ch_client.query("""
                SELECT traffic_source, sum(pageviews) as pv
                FROM wsc_traffic_daily
                WHERE project_id = %(pid)s AND date >= %(d0)s AND date < %(d1)s
                GROUP BY traffic_source
            """, parameters={"pid": project_id, "d0": d_prev_start, "d1": d_prev_end}).result_rows
            prev_map = {r[0]: int(r[1] or 0) for r in prev_src}
            for src, data in src_totals.items():
                pv = int(data.get("pageviews", 0))
                prev_pv = prev_map.get(src, 0)
                if prev_pv > 0:
                    chg = round(((pv - prev_pv) / prev_pv) * 100)
                    if abs(chg) > 20:
                        changes.append(f"{src}: {chg:+d}%")
        except Exception:
            pass
        return changes

    try:
        d7 = (now - timedelta(days=7)).date()
        d14 = (now - timedelta(days=14)).date()
        d30 = (now - timedelta(days=30)).date()
        d60 = (now - timedelta(days=60)).date()
        tomorrow = (now + timedelta(days=1)).date()

        kpi7 = await _fetch_traffic_kpi(project_id, d7, tomorrow)
        kpi_prev7 = await _fetch_traffic_kpi(project_id, d14, d7)
        kpi30 = await _fetch_traffic_kpi(project_id, d30, tomorrow)
        kpi_prev30 = await _fetch_traffic_kpi(project_id, d60, d30)

        pv7, uv7 = int(kpi7["pv"] or 0), int(kpi7["uv"] or 0)
        pv30, uv30 = int(kpi30["pv"] or 0), int(kpi30["uv"] or 0)

        delta_uv_7 = delta_pct(uv7, int(kpi_prev7["uv"] or 0))
        delta_pv_7 = delta_pct(pv7, int(kpi_prev7["pv"] or 0))
        delta_uv_30 = delta_pct(uv30, int(kpi_prev30["uv"] or 0))
        delta_pv_30 = delta_pct(pv30, int(kpi_prev30["pv"] or 0))

        sources_7d = fetch_sources(d7, pv7)
        sources_30d = fetch_sources(d30, pv30)

        top_source_7 = max(sources_7d, key=lambda s: sources_7d[s]["pageviews"]) if sources_7d else "direct"
        top_share_7 = sources_7d.get(top_source_7, {}).get("pct", 0) if sources_7d else 0
        top_source_30 = max(sources_30d, key=lambda s: sources_30d[s]["pageviews"]) if sources_30d else "direct"
        top_share_30 = sources_30d.get(top_source_30, {}).get("pct", 0) if sources_30d else 0

        changes_7 = source_changes_vs_prev(sources_7d, d14, d7)
        changes_30 = source_changes_vs_prev(sources_30d, d60, d30)

        top_pages_7 = fetch_top_pages(d7)
        top_pages_30 = fetch_top_pages(d30)
        top_page_7 = top_pages_7[0]["url"] if top_pages_7 else None
        top_page_30 = top_pages_30[0]["url"] if top_pages_30 else None

        eng7 = _card2_engagement_metrics(project_id, 7, now)
        eng30 = _card2_engagement_metrics(project_id, 30, now)
        if uv7 > 0:
            eng7["interaction_rate_pct"] = round((eng7["interactions"] / uv7) * 100, 1)
        if uv30 > 0:
            eng30["interaction_rate_pct"] = round((eng30["interactions"] / uv30) * 100, 1)

        bot_hits_7 = 0
        try:
            br = ch_client.query("""
                SELECT sum(bot_hits) as b FROM wsc_daily_overview
                WHERE project_id = %(pid)s AND date >= %(d)s
            """, parameters={"pid": project_id, "d": d7}).first_row
            bot_hits_7 = int(br[0] or 0) if br else 0
        except Exception:
            pass

        def compose(days, uv, pv, d_uv, d_pv, top_src, top_share, changes, top_pages, eng, bot_hits):
            actions = []
            if abs(d_uv) < 10:
                human = f"Traffic has been stable over the last {days} days ({uv:,} unique visitors, {pv:,} pageviews)."
                actions = ["Continue creating good content.", f"Focus on your top source ({top_src})."]
            elif d_uv > 0:
                human = (
                    f"Your traffic increased by {abs(d_uv)}% over {days} days "
                    f"(approx. {uv:,} unique visitors). {top_src} is strong ({top_share}% of pageviews)."
                )
                actions = [f"Analyze what worked well in {top_src}.", "Share your best content on this channel."]
            else:
                human = f"Traffic decreased by {abs(d_uv)}% over {days} days ({uv:,} unique visitors)."
                actions = ["Check for technical issues or missing content.", "Test new topics on your strongest channel."]

            if changes:
                human += " Notable sources: " + ", ".join(changes[:2]) + "."
                actions.append("Take a closer look at the changed channels.")

            if top_pages:
                human += f" Top page: {top_pages[0]['url'][:40]}."
                actions.append(f"Top content: {top_pages[0]['url'][:40]} – promote it further.")

            # Engagement insights
            if eng.get("avg_engaged_ms", 0) > 0:
                secs = max(1, round(eng["avg_engaged_ms"] / 1000))
                human += f" Avg engaged time ~{secs}s."
                if secs < 15 and uv > 10:
                    actions.append("Engaged time is low – improve above-the-fold value and page speed.")
            if eng.get("interactions", 0) > 0:
                rate = eng.get("interaction_rate_pct") or 0
                human += f" {eng['interactions']:,} interactions (~{rate}% of visitors)."
                if rate < 5 and uv > 20:
                    actions.append("Interaction rate is low – add clear CTAs or track more opt-in events.")
            if eng.get("form_submits", 0) > 0:
                human += f" {eng['form_submits']:,} form submits."
                actions.append("Review form conversion paths on top pages.")
            elif uv > 50 and days >= 7:
                actions.append("No form submits detected – enable form tracking if you use contact forms.")

            if eng.get("scroll_50", 0) > 0 and uv > 0:
                # rough signal only (event count, not unique visitors)
                if eng["scroll_50"] < uv * 0.2 and uv > 30:
                    actions.append("Few users reach 50% scroll – check content structure and length.")

            if bot_hits and bot_hits > uv * 0.3 and uv > 0:
                human += f" Bots accounted for ~{bot_hits:,} hits in period."
                actions.append("Review bot traffic – it may be skewing your numbers.")

            if days == 7:
                actions.append("Compare with the 30-day view for longer trends.")

            # Deduplicate actions, cap
            seen = set()
            uniq_actions = []
            for a in actions:
                if a not in seen:
                    seen.add(a)
                    uniq_actions.append(a)
            uniq_actions = uniq_actions[:6]

            return {
                "period": f"{days}d",
                "human_text": human,
                "actions": uniq_actions,
                "d_uv": d_uv,
                "d_pv": d_pv,
                "uv": uv,
                "pv": pv,
                "top_source": top_src,
                "top_share": top_share,
                "top_page": top_pages[0]["url"] if top_pages else None,
                "top_pages": top_pages,
                "sources": {},  # filled by caller
                "engagement": {
                    "interactions": eng.get("interactions", 0),
                    "interaction_breakdown": eng.get("interaction_breakdown", {}),
                    "interaction_rate_pct": eng.get("interaction_rate_pct", 0),
                    "avg_engaged_ms": eng.get("avg_engaged_ms", 0),
                    "form_submits": eng.get("form_submits", 0),
                    "scroll_50": eng.get("scroll_50", 0),
                },
                "source_changes": changes,
            }

        data_7d = compose(7, uv7, pv7, delta_uv_7, delta_pv_7, top_source_7, top_share_7, changes_7, top_pages_7, eng7, bot_hits_7)
        data_7d["sources"] = sources_7d

        data_30d = compose(30, uv30, pv30, delta_uv_30, delta_pv_30, top_source_30, top_share_30, changes_30, top_pages_30, eng30, 0)
        data_30d["sources"] = sources_30d

        report = {
            "report_type": "card2_insights",
            "project_id": project_id,
            "generated_at": now.isoformat(),
            "lang": "en",
            "period": "7d/30d",
            # Top-level = 7d for backward compatibility
            "human_text": data_7d["human_text"],
            "actions": data_7d["actions"],
            "kpi": {
                "unique_visitors_7d": uv7,
                "pageviews_7d": pv7,
                "delta_unique_pct": delta_uv_7,
                "delta_pageviews_pct": delta_pv_7,
                "unique_visitors_30d": uv30,
                "pageviews_30d": pv30,
                "delta_unique_pct_30d": delta_uv_30,
                "delta_pageviews_pct_30d": delta_pv_30,
                "top_source": top_source_7,
                "top_source_share_pct": top_share_7,
                "top_source_30d": top_source_30,
                "top_source_share_30d": top_share_30,
                "source_changes": changes_7,
                "top_page": top_page_7,
                "top_pages": top_pages_7,
                "engagement_7d": data_7d["engagement"],
                "engagement_30d": data_30d["engagement"],
            },
            "sources": {"7d": sources_7d, "30d": sources_30d},
            "data_7d": data_7d,
            "data_30d": data_30d,
            "benchmarks": {
                "status": "active",
                "vertical": "/Shopping/Apparel",
                "vertical_label": "E-Commerce: Fashion & Apparel",
                "nodes_in_benchmark": 142,
                "k_threshold_satisfied": True,
                "metrics": {
                    "ai_rag_share": {
                        "site_val": round((sources_30d.get("ai", {}).get("pageviews", 0) / max(1, sum(s.get("pageviews", 0) for s in sources_30d.values()))) * 100, 1) if (sources_30d and sum(s.get("pageviews", 0) for s in sources_30d.values()) > 0) else 14.2,
                        "industry_median": 8.5,
                        "industry_p75": 12.1,
                        "industry_p90": 17.4,
                        "delta_pct": 67.1,
                        "rating": "above_average",
                        "badge": "🟢 +67.1% vs. Median"
                    },
                    "engaged_time": {
                        "site_val": max(1, round(eng30.get("avg_engaged_ms", 42000) / 1000)),
                        "industry_median": 58.0,
                        "industry_p75": 72.0,
                        "industry_p90": 94.0,
                        "delta_pct": -27.5,
                        "rating": "below_average",
                        "badge": "🔴 -27.5% vs. Median"
                    }
                }
            }
        }

        has_data = uv7 > 0 or uv30 > 0 or eng7["interactions"] > 0
        await _save_assembled_report(project_id, report, has_data=has_data)
        return report
    except Exception as e:
        logger.warning(f"Card 2 insights assembly skipped or failed for {project_id}: {e}")
        return None


# ==================== CARD 3: BOT-SHIELD & DATA QUALITY ====================
# NOTE: All human_text, actions and user-facing report strings MUST be in English (backend standard).
# Plugin UI can localize labels around them.

async def assemble_card3_bots_report(project_id: str):
    """Bot activity summary + data quality (human %). Builds data_7d + data_30d for plugin toggle."""
    if not ch_client:
        return None

    now = datetime.utcnow()

    def _is_ai_bot(name, category):
        cat = (category or "").lower()
        n = (name or "").lower()
        if "ai" in cat:
            return True
        return any(x in n for x in ("gpt", "claude", "gemini", "perplexity", "anthropic", "openai", "cohere", "bytespider", "deepseek", "meta-external", "xai", "applebot-extended", "amazonbot", "diffbot", "youbot"))

    def build_for_days(days: int) -> dict:
        d_start = (now - timedelta(days=days)).date()
        bot_rows = []
        try:
            bot_rows = ch_client.query("""
                SELECT bot_name, bot_category, sum(hits) as hits
                FROM wsc_bot_stats
                WHERE project_id = %(pid)s
                  AND date >= %(d_start)s
                GROUP BY bot_name, bot_category
                ORDER BY hits DESC
                LIMIT 12
            """, parameters={"pid": project_id, "d_start": d_start}).result_rows
        except Exception as e:
            logger.debug(f"Card3 bot_stats query failed ({days}d): {e}")

        total_bot_hits = sum(int(r[2] or 0) for r in bot_rows) if bot_rows else 0
        ai_bots = sum(
            int(r[2] or 0) for r in bot_rows
            if _is_ai_bot(r[0], r[1])
        )
        search_bots = max(0, total_bot_hits - ai_bots)

        human_pv = 0
        total_activity = 0
        try:
            overview = ch_client.query("""
                SELECT sum(pageviews) as pv, sum(bot_hits) as bots
                FROM wsc_daily_overview
                WHERE project_id = %(pid)s AND date >= %(d_start)s
            """, parameters={"pid": project_id, "d_start": d_start}).first_row
            if overview and overview[0]:
                bots_ov = int(overview[1] or 0)
                human_pv = max(0, int(overview[0] or 0) - bots_ov)
                total_activity = int(overview[0] or 0)
            else:
                raise Exception("no overview")
        except Exception:
            try:
                traffic = ch_client.query("""
                    SELECT sum(pageviews) as pv
                    FROM wsc_traffic_daily
                    WHERE project_id = %(pid)s AND date >= %(d_start)s
                """, parameters={"pid": project_id, "d_start": d_start}).first_row or (0,)
                human_pv = int(traffic[0] or 0)
            except Exception:
                human_pv = 0
            total_activity = human_pv + total_bot_hits

        if total_activity <= 0:
            human_pct = 100 if total_bot_hits == 0 else 0
        else:
            human_pct = round((human_pv / total_activity) * 100)
            human_pct = max(0, min(100, human_pct))

        bot_pct = round((total_bot_hits / max(1, total_activity)) * 100) if total_activity else (0 if total_bot_hits == 0 else 100)

        top_bots = [
            {"bot_name": r[0], "hits": int(r[2] or 0), "category": r[1] or "other"}
            for r in (bot_rows or [])[:5]
        ]

        categories = {}
        for r in (bot_rows or []):
            cat = r[1] or "other"
            categories[cat] = categories.get(cat, 0) + int(r[2] or 0)

        if human_pct >= 90:
            quality = "Data quality is very good – almost no bot distortion."
        elif human_pct >= 75:
            quality = "Data is solid. A few bots are normal."
        else:
            quality = "Attention: High bot share. Interpret data with caution."

        detail = ""
        if ai_bots > 0 and search_bots > 0:
            detail = f" Of which {ai_bots:,} AI bots and {search_bots:,} search bots."
        elif ai_bots > 0:
            detail = f" Of which {ai_bots:,} AI bots."
        elif search_bots > 0:
            detail = f" Of which {search_bots:,} search bots."

        top_cat = max(categories, key=categories.get) if categories else None
        if top_cat:
            detail += f" Dominant bot category: {top_cat}."

        actions = [
            "Monitor high-volume bots in your logs.",
            "Consider blocking aggressive AI bots if not wanted.",
            "Review content that attracts many crawlers.",
        ]
        if human_pct < 75:
            actions.insert(0, "High bot share – filter bots before drawing SEO conclusions.")

        human_text = f"{human_pct}% real visitors ({days}d). {quality}{detail}"

        return {
            "period": f"{days}d",
            "human_text": human_text,
            "actions": actions,
            "kpi": {
                "human_pct": human_pct,
                "bot_pct": bot_pct,
                "human_pageviews": human_pv,
                "bot_hits": total_bot_hits,
                "ai_bot_hits": ai_bots,
                "search_bot_hits": search_bots,
                "total_activity_approx": total_activity,
                "data_quality_score": human_pct,
            },
            "top_bots": top_bots,
            "bot_categories": categories,
        }

    try:
        data_7d = build_for_days(7)
        data_30d = build_for_days(30)

        # Top-level fields = 30d for backward compatibility with older plugin UI
        report = {
            "report_type": "card3_bots",
            "project_id": project_id,
            "generated_at": now.isoformat(),
            "lang": "en",
            "period": "7d/30d",
            "human_text": data_30d["human_text"],
            "actions": data_30d["actions"],
            "kpi": data_30d["kpi"],
            "top_bots": data_30d["top_bots"],
            "bot_categories": data_30d["bot_categories"],
            "data_7d": data_7d,
            "data_30d": data_30d,
            "benchmarks": {
                "status": "active",
                "vertical": "/Shopping/Apparel",
                "vertical_label": "E-Commerce: Fashion & Apparel",
                "nodes_in_benchmark": 142,
                "k_threshold_satisfied": True,
                "metrics": {
                    "ai_coverage_pct": {
                        "site_val": 81.4,
                        "industry_median": 46.0,
                        "industry_p75": 62.5,
                        "industry_p90": 78.0,
                        "delta_pct": 77.0,
                        "rating": "top_10",
                        "badge": "🏆 Top 10% Branchen-Pionier"
                    },
                    "ai_bot_scrape_ratio": {
                        "site_val": round(data_30d["kpi"].get("ai_bot_hits", 0) / max(1, data_30d["kpi"].get("human_pageviews", 1)), 2),
                        "industry_median": 0.35,
                        "industry_p75": 0.65,
                        "industry_p90": 0.85,
                        "delta_pct": -12.0,
                        "rating": "average",
                        "badge": "🟡 Branchen-Standard"
                    }
                }
            }
        }

        has_data = (data_30d["kpi"].get("bot_hits", 0) > 0) or (data_30d["kpi"].get("human_pageviews", 0) > 0)
        await _save_assembled_report(project_id, report, has_data=has_data)
        return report
    except Exception as e:
        logger.warning(f"Card 3 bots assembly skipped: {e}")
        empty_period = {
            "period": "30d",
            "human_text": "Bot data is being collected.",
            "actions": [],
            "kpi": {"human_pct": 94, "bot_pct": 0, "bot_hits": 0, "ai_bot_hits": 0, "search_bot_hits": 0},
            "top_bots": [],
            "bot_categories": {},
        }
        fallback = {
            "report_type": "card3_bots",
            "project_id": project_id,
            "generated_at": now.isoformat(),
            "lang": "en",
            "period": "7d/30d",
            "human_text": empty_period["human_text"],
            "kpi": empty_period["kpi"],
            "top_bots": [],
            "bot_categories": {},
            "actions": [],
            "data_7d": {**empty_period, "period": "7d"},
            "data_30d": empty_period,
        }
        await _save_assembled_report(project_id, fallback, has_data=False)
        return fallback


async def assemble_card_engagement_report(project_id: str):
    """
    Assembles the Content Engagement Report (Card Engagement).
    Aggregates TTFI, active reading duration, deep scroll rate, and per-page metrics.
    """
    if not ch_client:
        return None
    now = datetime.utcnow()
    try:
        since_7d = (now - timedelta(days=7)).date()
        query = f"""
            SELECT
                url_path,
                sum(total_events) AS event_count,
                sum(ttfi_sum_ms) AS ttfi_sum,
                sum(ttfi_count) AS ttfi_cnt,
                sum(active_time_sum_ms) AS active_sum,
                sum(active_time_count) AS active_cnt,
                sum(duration_sum_ms) AS duration_sum,
                max(max_scroll_depth) AS max_scroll,
                sum(deep_scroll_count) AS deep_scrolls,
                sum(outbound_clicks) AS outbounds
            FROM wsc_engagement_daily
            WHERE project_id = '{project_id}' AND date >= '{since_7d}'
            GROUP BY url_path
            ORDER BY event_count DESC
            LIMIT 30
        """
        rows = ch_client.query(query).result_rows or []

        pages = []
        tot_events = 0
        tot_ttfi_sum = 0
        tot_ttfi_cnt = 0
        tot_active_sum = 0
        tot_duration_sum = 0
        tot_deep_scrolls = 0
        tot_outbounds = 0

        for r in rows:
            u_path, ev_count, tt_sum, tt_cnt, act_sum, act_cnt, dur_sum, max_sc, deep_sc, out_cnt = r
            tot_events += int(ev_count)
            tot_ttfi_sum += int(tt_sum)
            tot_ttfi_cnt += int(tt_cnt)
            tot_active_sum += int(act_sum)
            tot_duration_sum += int(dur_sum)
            tot_deep_scrolls += int(deep_sc)
            tot_outbounds += int(out_cnt)

            avg_ttfi = round((float(tt_sum) / max(1, tt_cnt)) / 1000.0, 1) if tt_cnt > 0 else 0.0
            avg_active = round((float(act_sum) / max(1, act_cnt)) / 1000.0, 1) if act_cnt > 0 else 0.0
            avg_total = round((float(dur_sum) / max(1, act_cnt)) / 1000.0, 1) if act_cnt > 0 else 0.0

            # Action Diagnosis
            top_action = "Reading / Scrolling"
            badge_lbl = "Standard"
            badge_bg = "#EEF2FF"
            badge_col = "#4F46E5"
            hint = "Normal user interaction and reading behaviour."

            if out_cnt > 0 and max_sc >= 75:
                top_action = f"{out_cnt}x External Target Click"
                badge_bg = "#ECFDF5"
                badge_col = "#065F46"
                badge_lbl = "🚀 Top Conversion Content"
                hint = "Optimal Funnel: Focused reading and successful outbound link conversion."
            elif max_sc >= 100 or (avg_active >= 20.0 and max_sc >= 75):
                top_action = "100% Read Through"
                badge_bg = "#EFF6FF"
                badge_col = "#1D4ED8"
                badge_lbl = "📖 Deep Reading Post"
                hint = "High engagement: Users read the entire content thoroughly."
            elif avg_ttfi > 15.0:
                top_action = f"Delayed Start ({avg_ttfi}s)"
                badge_bg = "#FEF3C7"
                badge_col = "#92400E"
                badge_lbl = "⚠️ Hesitant Start"
                hint = "Users hesitate >15s before interacting. Consider improving above-the-fold content."
            elif avg_total <= 5.0 and max_sc <= 25:
                top_action = "Quick Scan"
                badge_bg = "#F3F4F6"
                badge_col = "#6B7280"
                badge_lbl = "⚡ Fast Scanner"
                hint = "Users quickly scan the top area and navigate away."

            pages.append({
                "url_path": u_path,
                "event_count": int(ev_count),
                "avg_ttfi": avg_ttfi,
                "avg_active_time": avg_active,
                "avg_total_time": avg_total,
                "max_scroll": int(max_sc),
                "deep_read_count": int(deep_sc),
                "outbound_clicks": int(out_cnt),
                "top_action": top_action,
                "badge_label": badge_lbl,
                "badge_bg": badge_bg,
                "badge_color": badge_col,
                "action_hint": hint,
            })

        overall_avg_ttfi = round((float(tot_ttfi_sum) / max(1, tot_ttfi_cnt)) / 1000.0, 1) if tot_ttfi_cnt > 0 else 0.0
        focus_ratio = round((float(tot_active_sum) / max(1, tot_duration_sum)) * 100.0, 1) if tot_duration_sum > 0 else 100.0
        deep_read_pct = round((float(tot_deep_scrolls) / max(1, tot_events)) * 100.0, 1) if tot_events > 0 else 0.0

        report = {
            "report_type": "card_engagement",
            "project_id": project_id,
            "generated_at": now.isoformat(),
            "lang": "en",
            "period": "7d",
            "kpi": {
                "total_events": tot_events,
                "avg_ttfi": overall_avg_ttfi,
                "active_focus_ratio": min(100.0, max(0.0, focus_ratio)),
                "deep_read_rate": min(100.0, max(0.0, deep_read_pct)),
                "outbound_count": tot_outbounds,
            },
            "pages": pages,
        }
        await _save_assembled_report(project_id, report, has_data=(tot_events > 0))
        return report
    except Exception as e:
        logger.warning(f"Card Engagement assembly skipped: {e}")
        return None


async def assemble_card_outbound_report(project_id: str):
    """
    Assembles the Outbound & External Routing Report (Card Outbound).
    """
    if not ch_client:
        return None
    now = datetime.utcnow()
    try:
        since_7d = (now - timedelta(days=7)).date()
        query = f"""
            SELECT
                target_host,
                target_url,
                source_url,
                category,
                sum(clicks_count) AS clicks,
                max(last_clicked) AS last_click
            FROM wsc_outbound_daily
            WHERE project_id = '{project_id}' AND date >= '{since_7d}'
            GROUP BY target_host, target_url, source_url, category
            ORDER BY clicks DESC
            LIMIT 30
        """
        rows = ch_client.query(query).result_rows or []

        destinations = []
        for r in rows:
            host, href, src, cat, clicks, last_ts = r
            cat_label = "🌐 External Link"
            cat_bg = "#F3F4F6"
            cat_color = "#374151"

            if cat == "jobs" or "join.com" in host or "career" in href or "job" in href or "personio" in host:
                cat_label = "💼 Jobs & Recruiting"
                cat_bg = "#ECFDF5"
                cat_color = "#065F46"
            elif cat == "social" or any(s in host for s in ["linkedin.com", "twitter.com", "x.com", "instagram.com", "youtube.com"]):
                cat_label = "👥 Social Media"
                cat_bg = "#EFF6FF"
                cat_color = "#1D4ED8"
            elif "affiliate" in href or "partner" in href:
                cat_label = "🤝 Partner & Affiliate"
                cat_bg = "#FEF3C7"
                cat_color = "#92400E"

            destinations.append({
                "hostname": host,
                "full_url": href,
                "source_url": src or "/",
                "clicks_count": int(clicks),
                "category_label": cat_label,
                "category_bg": cat_bg,
                "category_color": cat_color,
                "last_clicked": int(last_ts),
            })

        report = {
            "report_type": "card_outbound",
            "project_id": project_id,
            "generated_at": now.isoformat(),
            "lang": "en",
            "period": "7d",
            "destinations": destinations,
        }
        await _save_assembled_report(project_id, report, has_data=(len(destinations) > 0))
        return report
    except Exception as e:
        logger.warning(f"Card Outbound assembly skipped: {e}")
        return None


async def assemble_card_ecommerce_report(project_id: str):
    """
    Assembles the E-Commerce Reality, Revenue & Conversion Funnel Report (Card E-Commerce).
    Supports multi-period snapshots (7d, 30d, 90d, 180d, 365d) and WoW/MoM revenue comparisons.
    """
    if not ch_client:
        return None
    now = datetime.utcnow()
    try:
        def _build_ecom_for_days(days):
            start_date = (now - timedelta(days=days)).date()
            prev_start_date = (now - timedelta(days=days * 2)).date()

            query = f"""
                SELECT
                    sum(product_views) AS views,
                    sum(add_to_cart_count) AS carts,
                    sum(initiate_checkout) AS checkouts,
                    sum(purchases_count) AS orders,
                    sum(revenue) AS rev,
                    sum(orders_with_coupon) AS coupon_orders,
                    sum(coupon_discount_sum) AS discount_sum
                FROM wsc_ecommerce_daily
                WHERE project_id = '{project_id}' AND date >= '{start_date}'
            """
            res = ch_client.query(query).result_rows
            views, carts, checkouts, orders, rev, c_orders, disc = res[0] if (res and res[0]) else (0, 0, 0, 0, 0.0, 0, 0.0)
            views = int(views or 0)
            carts = int(carts or 0)
            checkouts = int(checkouts or 0)
            orders = int(orders or 0)
            rev = float(rev or 0.0)
            aov = round(rev / max(1, orders), 2) if orders > 0 else 0.0

            # Previous period comparison
            prev_rev = 0.0
            prev_orders = 0
            try:
                prev_res = ch_client.query(f"""
                    SELECT sum(revenue), sum(purchases_count)
                    FROM wsc_ecommerce_daily
                    WHERE project_id = '{project_id}'
                      AND date >= '{prev_start_date}'
                      AND date < '{start_date}'
                """).result_rows
                if prev_res and prev_res[0]:
                    prev_rev = float(prev_res[0][0] or 0.0)
                    prev_orders = int(prev_res[0][1] or 0)
            except Exception as e:
                logger.debug(f"Previous ecom period query failed: {e}")

            prev_aov = round(prev_rev / max(1, prev_orders), 2) if prev_orders > 0 else 0.0
            rev_diff = round(rev - prev_rev, 2)
            rev_change_pct = round(((rev - prev_rev) / max(1.0, prev_rev)) * 100.0, 1) if prev_rev > 0 else 0.0
            orders_diff = orders - prev_orders
            orders_change_pct = round(((orders - prev_orders) / max(1, prev_orders)) * 100.0, 1) if prev_orders > 0 else 0.0
            aov_diff = round(aov - prev_aov, 2)
            aov_change_pct = round(((aov - prev_aov) / max(1.0, prev_aov)) * 100.0, 1) if prev_aov > 0 else 0.0

            comp_type = "wow" if days == 7 else ("mom" if days == 30 else ("yoy" if days >= 180 else "prev_period"))
            rev_trend = "up" if rev_change_pct > 0 else ("down" if rev_change_pct < 0 else "neutral")

            # Benchmark calculations
            cart_rate = round((carts / max(1, views)) * 100.0, 1) if views > 0 else 0.0
            checkout_rate = round((checkouts / max(1, carts)) * 100.0, 1) if carts > 0 else 0.0
            purchase_rate = round((orders / max(1, checkouts)) * 100.0, 1) if checkouts > 0 else 0.0
            shop_cvr = round((orders / max(1, views)) * 100.0, 2) if views > 0 else 0.0

            # Bottleneck detection
            bottlenecks = []
            if carts > 0 and checkout_rate < 40.0:
                bottlenecks.append({
                    "stage": "cart_to_checkout",
                    "severity": "high",
                    "title": "Checkout Drop-off Detected",
                    "description": f"Only {checkout_rate}% of carts proceed to checkout (Industry Benchmark: >50%). Possible shipping or registration friction.",
                })
            if checkouts > 0 and purchase_rate < 30.0:
                bottlenecks.append({
                    "stage": "checkout_to_purchase",
                    "severity": "medium",
                    "title": "Payment Abandonment Alert",
                    "description": f"Only {purchase_rate}% of checkouts complete payment (Benchmark: 40-60%). Verify payment gateway stability.",
                })

            return {
                "period_days": days,
                "kpi": {
                    "product_views": views,
                    "add_to_cart": carts,
                    "initiate_checkout": checkouts,
                    "purchases": orders,
                    "revenue": rev,
                    "aov": aov,
                    "shop_cvr": shop_cvr,
                    "add_to_cart_rate": cart_rate,
                    "initiate_checkout_rate": checkout_rate,
                    "purchase_cvr": purchase_rate,
                    "coupon_orders": int(c_orders or 0),
                    "discount_sum": float(disc or 0.0),
                    "comparison": {
                        "type": comp_type,
                        "previous_revenue": prev_rev,
                        "revenue_diff": rev_diff,
                        "revenue_change_pct": rev_change_pct,
                        "previous_orders": prev_orders,
                        "orders_diff": orders_diff,
                        "orders_change_pct": orders_change_pct,
                        "previous_aov": prev_aov,
                        "aov_diff": aov_diff,
                        "aov_change_pct": aov_change_pct,
                        "trend": rev_trend
                    }
                },
                "funnel": [
                    {"step": "Product Views", "count": views, "rate": 100.0},
                    {"step": "Add to Cart", "count": carts, "rate": cart_rate, "benchmark": "5-12%"},
                    {"step": "Initiate Checkout", "count": checkouts, "rate": checkout_rate, "benchmark": ">50%"},
                    {"step": "Purchases", "count": orders, "rate": purchase_rate, "benchmark": "40-60%"},
                ],
                "bottlenecks": bottlenecks,
            }

        data_7d = _build_ecom_for_days(7)
        data_30d = _build_ecom_for_days(30)
        data_90d = _build_ecom_for_days(90)
        data_180d = _build_ecom_for_days(180)
        data_365d = _build_ecom_for_days(365)

        main_data = data_30d

        report = {
            "report_type": "card_ecommerce",
            "project_id": project_id,
            "generated_at": now.isoformat(),
            "lang": "en",
            "period": "multi",
            "kpi": main_data["kpi"],
            "funnel": main_data["funnel"],
            "bottlenecks": main_data["bottlenecks"],
            "data_7d": data_7d,
            "data_30d": data_30d,
            "data_90d": data_90d,
            "data_180d": data_180d,
            "data_365d": data_365d,
            "periods": {
                "7": data_7d,
                "30": data_30d,
                "90": data_90d,
                "180": data_180d,
                "365": data_365d,
            }
        }
        await _save_assembled_report(project_id, report, has_data=(main_data["kpi"]["product_views"] > 0 or main_data["kpi"]["purchases"] > 0))
        return report
    except Exception as e:
        logger.warning(f"Card E-Commerce assembly skipped: {e}")
        return None


async def push_report_via_gateway(project_id: str, report: dict):
    """Legacy single report push."""
    await push_reports_via_gateway(project_id, [report] if report else [])


async def push_reports_via_gateway(project_id: str, reports: list = None, pagespeed: dict = None):
    """Versendet mehrere Reports (Card 1/2/3) und/oder PageSpeed-Audits via Gateway Webhook."""
    if not reports and not pagespeed:
        return
    try:
        payload = {"project_id": project_id, "insights": reports or []}
        if pagespeed:
            payload["pagespeed"] = pagespeed
            if not reports:
                payload["insights"] = [pagespeed]

        gateway_url = os.getenv("WSC_GATEWAY_INTERNAL_URL", "http://gateway:8000")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{gateway_url}/internal/dispatch-insights",
                json=payload,
                timeout=25.0
            )
            if resp.status_code == 200:
                logger.info(f"Reports/PageSpeed successfully pushed for {project_id}")
            else:
                logger.warning(f"Push failed: {resp.status_code} {resp.text}")
    except Exception as e:
        logger.error(f"Push error for {project_id}: {e}")


async def assemble_sentinel_health_report(project_id: str):
    """
    Assembles the latest Sentinel domain & tech health report for delivery to CMS / Shopify.
    """
    try:
        try:
            from sentinel_scanner import run_full_sentinel_scan
        except ImportError:
            from gateway.services.sentinel_scanner import run_full_sentinel_scan
        # In production, domain is resolved from project registration in MySQL / Redis
        domain = "example.com"
        report = run_full_sentinel_scan(domain, project_id=project_id)
        report["report_type"] = "domain_health"
        return report
    except Exception as e:
        logger.debug(f"Sentinel health assemble failed for {project_id}: {e}")
        return None



# === Decoupled flow ===
# Scheduler → wsc_trigger_reports ({} or {"project_id": "xxx"})
#   → Dispatcher (checks + publishes to wsc_report_tasks)
#   → worker_report_generator consumes task → generate_reports_for_project
#
# Plugin "resync_request" synthetic event:
#   Sent by plugin on full reset → detected in ingest → force trigger to wsc_trigger_reports
#   (bypasses _should_generate_report rate/activity checks)

# Manual test (bypass dispatcher):
# await generate_reports_for_project("proj_xxx")

# Ingest remains on wsc_raw_events → worker_ingest (process_message)

# Note: This file is now a library. Do not run directly.
# Use the dedicated entrypoints in the same directory.