# WSC Gateway & Asynchronous Worker Mesh (`v2.3.0`)

<p align="center">
  <strong>High-Throughput Encrypted Telemetry Ingestion, RabbitMQ + DLX Worker Mesh, ClickHouse OLAP & Sentinel Orchestrator</strong><br>
  Core cloud data plane of the <a href="https://www.worldsearchcouncil.org"><strong>World Search Council (WSC)</strong></a>
</p>

<p align="center">
  <a href="https://api.worldsearchcouncil.org/v1/health"><img src="https://img.shields.io/badge/API_Status-Live_v2.3.0-10B981.svg?style=flat-square" alt="Live API"></a>
  <a href="https://github.com/World-Search-Council/wsc-gateway"><img src="https://img.shields.io/badge/Gateway-FastAPI_Python_3.11-009688.svg?style=flat-square&logo=fastapi" alt="FastAPI"></a>
  <img src="https://img.shields.io/badge/Queue-RabbitMQ_%2B_DLX-FF6600.svg?style=flat-square&logo=rabbitmq" alt="RabbitMQ">
  <img src="https://img.shields.io/badge/OLAP-ClickHouse_Cloud-FFCC01.svg?style=flat-square&logo=clickhouse" alt="ClickHouse">
  <img src="https://img.shields.io/badge/Cache-Redis_%2F_Cluster-DC382D.svg?style=flat-square&logo=redis&logoColor=white" alt="Redis Cluster">
  <img src="https://img.shields.io/badge/Observability-Prometheus_OpenMetrics-E6522C.svg?style=flat-square&logo=prometheus&logoColor=white" alt="Prometheus">
  <img src="https://img.shields.io/badge/License-GPL--2.0--or--later-orange.svg?style=flat-square" alt="License">
</p>

---

## 🏗️ Architecture Overview

The **WSC Gateway (`https://api.worldsearchcouncil.org`)** is the central ingestion, enrichment, OLAP analytics, and diagnostic dispatch engine for all 7 WSC CMS & storefront connectors (WordPress, Shopware 6, Shopify, Magento 2, Drupal 8–11, Drupal 7, Joomla 4/5) as well as the [WSC Authority & Member Portal](https://www.worldsearchcouncil.org).

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │    7 WSC CMS/Shop Connectors & Member Portal (worldsearchcouncil.org)   │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       │
              AES-256-CBC Encrypted Batches + HMAC-SHA256 (X-WSC-Sig)
                                       │
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │       FastAPI Gateway v2.3.0 (Traefik TLS + Redis / Redis Cluster)      │
  └──────┬───────────────────┬─────────────────────┬────────────────────────┘
         │                   │                     │
  wsc_raw_events    wsc_pagespeed_tasks    wsc_sentinel_tasks   (RabbitMQ + DLX)
         │                   │                     │
         ▼                   ▼                     ▼
  ┌──────────────┐   ┌───────────────┐     ┌──────────────────┐
  │ worker-ingest│   │worker-pagespd │     │ worker-sentinel  │
  │ + dispatcher │   │ (Playwright   │     │ (CZ.NIC DNS, TLS,│
  │ + worker-rpt │   │  headless-v4) │     │  Port-25-Free MX)│
  └──────┬───────┘   └───────┬───────┘     └────────┬─────────┘
         │                   │                      │
         ▼                   ▼                      ▼
  ┌──────────────────────────────────┐     ┌────────────────────────────────┐
  │ ClickHouse OLAP (12 Tables/5 MVs)│     │ Signed HMAC-SHA256 Webhooks &  │
  │ + MariaDB Registry + Redis Cache │────▶│ Canonical 7-Card Bento Reports │
  └──────────────────────────────────┘     └────────────────────────────────┘
```

### Privacy & Security Guarantees
- **Zero Stored Client IPs:** Client IP addresses inside encrypted micro-batches are decrypted exclusively in worker RAM to compute daily-salted session hashes (`SHA256(IP + UA + DailySalt)`) and coarse local GeoIP (`GeoLite2-City.mmdb`), then discarded before ClickHouse insertion.
- **Port-25 Outbound Ban:** `worker-sentinel` evaluates MX, SPF, DKIM, and DMARC strictly via authoritative DNS lookups (`dns-crawler` / `checkdmarc`) — never opening direct TCP/SMTP connections on port 25.
- **Strict Domain & SSRF Isolation:** PageSpeed and Sentinel scans validate target hostnames against registered project domains and public non-reserved IP ranges.

---

## ⚙️ Technology Stack (`v2.3.0`)

- **Ingress & API Gateway:** Traefik v3 TLS + Python 3.11 (`FastAPI`, `Uvicorn`, `aiomysql`, `aio_pika`)
- **Message Broker & Resiliency:** RabbitMQ / CloudAMQP (`amqps://`) with Dead-Letter Exchange (`wsc.dlx`), staged retry queues (`5m` / `1h`), and poison-pill DLQ (`wsc_raw_events.dlq`)
- **Analytical Data Warehouse:** ClickHouse / ClickHouse Cloud TLS (`CLICKHOUSE_SECURE=true`) — 12 MergeTree/ReplacingMergeTree/SummingMergeTree tables & 5 real-time Materialized Views (`backend/clickhouse_schema.sql`)
- **Project & Benchmark Registry:** MariaDB / MySQL (`projects`, `wsc_verticals`, `wsc_benchmark_snapshots` — `backend/wsc_analytics.sql`)
- **Distributed Cache:** `WscRedisCache` (`gateway/services/redis_cache.py`) supporting both standalone Redis and multi-node **Redis Cluster** (`REDIS_CLUSTER_MODE=true`, `REDIS_CLUSTER_NODES`) with bounded in-memory L1 TTL failover
- **Observability:** Built-in OpenMetrics / Prometheus exporter (`GET /metrics`, `gateway/services/metrics.py`) with scanner 404 cardinality protection, passive RabbitMQ queue depth gauges across all 8 queues, ClickHouse latency probes, and optional `METRICS_BEARER_TOKEN` protection

---

## 📡 Canonical API Endpoints

| Method | Endpoint | Auth | Description |
| :--- | :--- | :---: | :--- |
| `GET` | `/v1/health` (and `/health`) | Public | Liveness & upstream dependency probe (`mysql`, `redis`, `clickhouse`, `version`). |
| `GET` | `/metrics` | Bearer (opt.) | Prometheus / OpenMetrics exporter (HTTP histograms, ingest counters, 8 RabbitMQ queue depths, ClickHouse latency). |
| `POST` | `/v1/register` | Public | Pairs a CMS/storefront instance, registers `local_aes_key`, and returns `project_id` (`proj_...`) + `api_secret`. |
| `POST` | `/v1/ingest` | `X-WSC-Sig` | Enqueues AES-256-CBC encrypted telemetry micro-batches into `wsc_raw_events`. |
| `GET` | `/v1/reports` | `X-WSC-Sig` | Paginated pull of assembled 7-Card Bento snapshots (`latest`, `history`, `overview` up to 730 days). |
| `POST` | `/v1/sentinel/scan` | `X-WSC-Sig` | Triggers Port-25-free Domain Sentinel diagnostics (`sync=false` async queue `202` or `sync=true` RPC `200`). |
| `GET` | `/v1/sentinel/health/{project_id}` | Public/Token | Retrieves latest cached Domain Health snapshot (`domain-health.schema.json`). |
| `POST` | `/v1/pagespeed/audit` | `X-WSC-Sig` | Enqueues a Dual-Thermometer SpeedSentinel lab audit (**🤖 RAG Readiness** + **👤 Human CWV**). |
| `GET` | `/v1/pagespeed/{project_id}` | Public/Token | Queries latest mobile/desktop/subpage SpeedSentinel scorecard from ClickHouse. |
| `POST` | `/v1/ai-coverage/query` | `X-WSC-Sig` | Queries ClickHouse sensor telemetry for URL & root-domain AI RAG vs. Training bot visibility. |
| `GET` | `/v1/benchmarks/verticals` | Public | Lists Google NLP industry verticals and $k \ge 25$ anonymity status. |
| `POST` | `/v1/benchmarks/classify` | Public/Token | Classifies site metadata into canonical industry verticals. |
| `POST` | `/v1/benchmarks/query` | `X-WSC-Sig` | Returns $p_{50}, p_{75}, p_{90}$ vertical benchmark percentiles. |
| `POST` | `/v1/shopify/pixel` & `/webhook` | Project/HMAC | Sandboxed Shopify Web Pixel intake & server-side order conversion webhooks. |
| `POST` | `/internal/dispatch-insights` | Internal Mesh | Internal worker fan-out signing and pushing 7-Card Bento, Sentinel & PageSpeed webhooks to remote CMS nodes. |

Full payload contracts are documented in the **[WSC Developer Portal](https://world-search-council.github.io/wsc-docs/gateway/api/)** and **[RFC-0006](https://www.worldsearchcouncil.org/standards/RFC-0006)**.

---

## 🚀 Quick Start (Docker Compose)

### 1. Configure Environment & Schemas

```bash
cp .env.example .env
# Edit .env with your MariaDB, Redis, RabbitMQ (AMQP/AMQPS), and ClickHouse credentials
```

Initialize the relational and analytical schemas:
- **MariaDB / MySQL:** `mysql -u wsc_user -p wsc_analytics < backend/wsc_analytics.sql`
- **ClickHouse:** Execute `backend/clickhouse_schema.sql` against your ClickHouse database.
- **GeoIP (Optional):** Place MaxMind `GeoLite2-City.mmdb` in the project root (mounted read-only into `worker-ingest`).

### 2. Launch the 10-Container Stack

```bash
docker compose up -d --build
```

Services started by `docker-compose.yml`:
- `traefik` (HTTPS/ACME ingress proxy)
- `gateway` (FastAPI `v2.3.0`)
- `redis` (Cache & deduplication state)
- `dispatcher` (Scheduled report orchestrator)
- `worker-ingest` (2 replicas — AES-256 decryption & ClickHouse bulk writer)
- `worker-report` (2 replicas — 7-Card Bento OLAP assembler)
- `worker-pagespeed` (Headless Playwright CWV & RAG Readiness worker)
- `worker-sentinel` (Authoritative DNSSEC, SSL, Security Header & Mail DNS scanner)

### 3. Verify Health & Metrics

```bash
curl -sS http://localhost:8000/v1/health
curl -sS http://localhost:8000/metrics | head -n 25
```

---

## 📄 License

Licensed under the [GNU General Public License v2.0 or later (GPL-2.0-or-later)](LICENSE).  
Part of the **[World Search Council](https://www.worldsearchcouncil.org)** ([GitHub Organization](https://github.com/World-Search-Council)) open standards ecosystem.
