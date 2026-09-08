# Tables & Data Model

## ClickHouse - Raw Events

**Table:** `wsc_analytics_raw`

This is the main raw event table. All decrypted and enriched events land here.

### Columns (current as of workerV3.py)

| Column          | Type      | Description |
|-----------------|-----------|-------------|
| project_id      | String    | Project UUID from registration |
| timestamp       | UInt32 / DateTime | Event time (from plugin) |
| session_id      | String    | Daily SHA256 hash (raw_ip + ua + daily_salt). Raw IP is **never stored**. Used only for daily session uniqueness. |
| event_type      | String    | e.g. "pageview", "bot_hit", "test_event" |
| domain_uuid     | UUID      | Deterministic UUID5 based on root domain |
| page_uuid       | UUID      | Deterministic UUID5 based on full URL |
| root_domain     | String    | e.g. "example.com" (tldextract) |
| hostname        | String    | Full host |
| url_path        | String    | Path part of URL |
| query_string    | String    | Query parameters |
| referrer_url    | String    | Referrer |
| geo_country     | String    | ISO code or "Unknown" |
| geo_region      | String    | ISO code or "Unknown" |
| geo_city        | String    | City name or "Unknown" |
| device_type     | String    | Desktop / Mobile / Tablet |
| os_name         | String    | OS family |
| browser_name    | String    | Browser family (with sec-ch-ua fallback) |
| resolution      | String    | From sys.res if present |
| language        | String    | From sys.lang or UA |
| custom_data     | String (JSON) | Original event.m + extra metadata |
| bot_name        | String        | For bot_hit events |
| bot_category    | String        | 'ai' or 'search' |
| bot_type        | String        | 'training', 'rag' or 'other' |

**Engine (recommended for raw):**
- MergeTree or ReplacingMergeTree on (project_id, timestamp, session_id)
- Partition by toYYYYMM(timestamp) or similar
- Order by (project_id, timestamp, page_uuid)

## IP Handling & Privacy (Current State)

**Important facts (as implemented):**

- The **raw client IP is never persisted** in ClickHouse `wsc_analytics_raw`.
- In the ingest worker:
  1. Real IP is extracted from `server_data.ip` + common proxy headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` etc.).
  2. This `raw_ip` is used **only** for two things:
     - Creating a **daily session hash**: `SHA256(raw_ip + user_agent + daily_salt)`
     - GeoIP lookup (country / region / city) using MaxMind GeoLite2-City (skipped for private IPs).
  3. After these two uses, the raw IP is discarded. Only `session_id` (hash) and the three `geo_*` columns are written.
- Session hash changes every day → sessions cannot be linked across days.
- Geo data is coarse (city level at best).
- In the WordPress plugin:
  - Raw IP is used for **local rate limiting** (transient-based, ~30 req/min per IP).
  - Raw IP is stored locally in the `wsc_bot_hits.ip_address` table (for the Bot Tracking feature only). This data stays in the site's `wp-content/uploads/wsc-analytics/` and is subject to the site's retention setting.
  - The IP sent to the gateway is controlled by the "IP-Handling" setting in the plugin:
    - "full": sends the real IP (best for geo + sessions)
    - "hashed": sends a SHA256 hash of the IP instead (more private, geo will be skipped in worker)
  - The payload (including IP or hash + headers) is sent **encrypted** (AES-256-CBC + HMAC) to the gateway.

**Anonymization status:**
- Server-side at ingest: Effectively anonymized for analytics (no raw IP in CH).
- This matches the design goal "IP-Adresse anonymisiert" described in the architecture.

**Current options:**
- Plugin setting "IP-Handling" provides "full" vs "hashed".
- Raw IP is never stored server-side in analytics DB regardless of setting.

See also:
- `workers.md` (Ingest enrichment step)
- Plugin `get_real_client_ip()` and rate limiting code
- `clickhouse_create_table.sql` for the actual stored columns

**Rate Limiting (current, genau dokumentiert):**

**Plugin (WSC-Core):**
- Endpoint: POST /wp-json/wsc/v1/track
- Implementation: Simple per-IP limit using WordPress transients.
- Code: `is_rate_limited($ip)` in class-wsc-core.php
  - Key: `wsc_rl_` + md5($ip)
  - Limit: hard-coded 30 requests
  - Window: 60 seconds (MINUTE_IN_SECONDS)
  - If >=30 → 429 "Too many requests"
- IP used: Currently `$_SERVER['REMOTE_ADDR']` (not the full get_real_client_ip logic in the rate limit call itself, though get_real_client_ip exists and is used for payload).
- Applies before decryption/queue.
- No per-project differentiation.
- Also basic payload size limit (50kB).

**Gateway side:**
- Traefik (in docker-compose.yml): `ratelimit.average=20`, `ratelimit.burst=40` (requests per second? Traefik default unit is per second for average).
- Applies to the public gateway endpoint.
- Worker itself has no additional per-project rate limit on ingest (the report dispatcher has its own 50min rate limit for reports).

**Known limitations (before improvements):**
- Hard-coded values (now configurable via "Rate Limit (Requests/Minute)" setting in plugin settings).
- Uses basic transient (not distributed if multiple PHP processes, but fine for most SMB).
- No sliding window, no exponential backoff, no distinction between human vs bot traffic.
- IP for rate limit now consistently uses get_real_client_ip() logic.
- Gateway has additional proxy-level limits (Traefik).

The setting was added as part of hardening rate limiting.

See also:
- Plugin: `handle_incoming_events()`, `is_rate_limited()`, `get_real_client_ip()`
- Gateway docker-compose for Traefik middleware
- This is part of the "security-rate-limiting" todo.

## Aggregate Tables & Reporting (Hybrid + Multi-Stage Pipeline)

**Vision:** 3-Card-Dashboard (Traffic / Insights / Bots) – SMB-freundlich, einfach verständlich. Card 1 (Traffic & Kanäle) zuerst.

**Technischer Ansatz (hybrid, wie abgestimmt):**
- **Materialized Views** (stündlich für aktuellen Tag, täglich für Historie) für Basis-Aggregate (effizient, auto-update).
- **Report-Tabellen** (vom Worker befüllt): Worker 1 aggregiert aus Raw + MVs und schreibt in dedizierte Report-Tabellen.
- **Worker 2 (Report Assembly):** Baut pro Project den finalen Report (inkl. menschlicher Texte), pusht max. 1×/Stunde via Gateway-Webhook ins Plugin (SQLite), nur wenn Daten vorhanden.
- Reports im Plugin: Grunddaten in SQLite, leichte Berechnungen im Frontend (PHP/JS).
- Kein manueller Trigger-Button (erstmal).

**Aktuelle Aggregate-Tables (SummingMergeTree / AggregatingMergeTree):**
- `wsc_daily_overview` (stündlich + täglich) – Pageviews, Sessions, Unique Visitors, nach traffic_source (search/social/direct/ai/referral), device.
- `wsc_bot_stats` – Bot-Hits nach bot_name, category, type.
- `wsc_top_pages` – Views pro url_path/Tag.

**Strategie:**
- MV wo sinnvoll für Auto-Aggregation.
- Worker-Pipeline für komplexere Reports und kontrollierten Versand (vermeidet Fluten des Plugins).
- Card 1 zuerst: Unique Visitors (7 Tage + Sparkline), Quellen-Aufschlüsselung, 7/30 Tage Toggle.

Siehe workers.md für Pipeline-Details und den aktuellen Split (dispatcher.py, ingest.py, report_generator.py, common.py).

## MySQL (Projects & Auth)

**Table:** `projects` (in `wsc_analytics` DB)

Columns (from gateway/main.py registration):
- uuid (project_id)
- domain (full WP base URL, used for webhook callbacks)
- api_secret (for HMAC signatures)
- local_aes_key (stored for worker decryption)
- registered_ip
- status (0 = active, 999 = blocked)
- created, updated

**Redis Cache:**
- Key: `project:{uuid}`
- Value: JSON with api_secret, local_aes_key, domain, status
- TTL: 86400s

## Other

- RabbitMQ: `wsc_raw_events` (durable)
- Future DLQ / retry queues (see retries.md)
- GeoIP: external `GeoLite2-City.mmdb` (not in DB)