# Configuration & Environment Variables

## Gateway (gateway/main.py)

Environment variables (with defaults):

- `DB_HOST` = 195.149.93.135
- `DB_PORT` = 9006
- `DB_USER` = fuxx
- `DB_PASS` = Wfuxx2020*
- `DB_NAME` = wsc_analytics
- `REDIS_URL` = redis://redis:6379
- `RABBITMQ_URL` = amqp://guest:guest@localhost/

**Notes:**
- MySQL is used for projects table and auth.
- Redis for project cache (with domain for webhook callbacks).
- RabbitMQ for queueing to workers.

## Worker (worker/workerV3.py)

- `RABBITMQ_URL` (can be CloudAMQP or local)
- `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASS`
- GeoIP database: expects `GeoLite2-City.mmdb` in working dir (mount as volume or bake into image)

**Important security:**
- Never commit real credentials.
- Use secrets / env files in Docker Compose / Kubernetes.

## RabbitMQ Queues & Exchanges (to be declared)

- `wsc_raw_events` (durable, main processing queue)
- Future:
  - `wsc_raw_events_delay_5m` (TTL 5min, dead-letter to main)
  - `wsc_raw_events_delay_1h` (for after 10 retries)
  - Dead letter exchange `wsc.dlx`

## ClickHouse

- Database: usually default or dedicated
- Main table: `wsc_analytics_raw`
- Recommended: MergeTree family, partitioned by month, ordered by (project_id, timestamp)

## MySQL

- Database: `wsc_analytics`
- Table: `projects` (see tables.md)

## Plugin Side (for reference)

The WordPress plugin (WSC-Core) uses:
- `wsc_local_secret_key` (hex, 64 chars) – for AES encryption of batches
- `wsc_project_id`
- `wsc_api_secret` – for signing webhooks and ingest
- `wsc_hybrid_enabled`

All sensitive keys are generated on plugin activation and only the local key is sent (encrypted in transit) during registration.

## Docker / Compose Tips

- Mount GeoIP db for worker
- Gateway is now behind Traefik (public HTTPS on 443, internal on http://gateway:8000)
- Use `TRAEFIK_DOMAIN` and `ACME_EMAIL` in .env for Let's Encrypt
- Internal services (e.g. worker) call gateway via Docker DNS: http://gateway:8000
- Worker needs access to ClickHouse (often over HTTPS 8443)

See docker-compose.yml for current Traefik setup.