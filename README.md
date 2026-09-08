# WSC Gateway

<p align="center">
  <strong>High-Throughput Encrypted Telemetry Ingestion, Mesh Queue & Report Dispatcher</strong><br>
  Core synchronization backend of the <strong>World Search Council (WSC) Standard</strong>
</p>

<p align="center">
  <a href="https://github.com/World-Search-Council/wsc-gateway"><img src="https://img.shields.io/badge/Gateway-FastAPI-009688.svg?style=flat-square&logo=fastapi" alt="FastAPI"></a>
  <img src="https://img.shields.io/badge/Queue-RabbitMQ-FF6600.svg?style=flat-square&logo=rabbitmq" alt="RabbitMQ">
  <img src="https://img.shields.io/badge/Analytics-ClickHouse-FFCC01.svg?style=flat-square&logo=clickhouse" alt="ClickHouse">
  <img src="https://img.shields.io/badge/License-GPL--2.0--or--later-orange.svg?style=flat-square" alt="License">
</p>

---

## 🏗️ Architecture Overview

The **WSC Gateway** is the central orchestration and telemetry ingestion service for the World Search Council ecosystem. It receives end-to-end encrypted micro-batches from CMS client instances, ingests them into high-throughput message queues, and pushes aggregated reports back to client plugins via authenticated webhooks.

```
  ┌──────────────────────────────────────────────────────────────┐
  │         Client Edge Plugins (WordPress, Shopware, etc.)      │
  └──────────────────────────────┬───────────────────────────────┘
                                 │
                   (AES-256 Batch Ingestion / Webhook Push)
                                 │
                                 ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                 WSC Ingestion Gateway (FastAPI)              │
  └──────────────────────────────┬───────────────────────────────┘
                                 │
                           (AMQP Message Queue)
                                 │
                                 ▼
  ┌──────────────────────────────────────────────────────────────┐
  │               Asynchronous Ingestion & Sentinel Workers      │
  └───────────────┬──────────────────────────────┬───────────────┘
                  │                              │
         (Analytics Ingestion)           (Push Webhook Reports)
                  ▼                              ▼
  ┌──────────────────────────────┐ ┌─────────────────────────────┐
  │   ClickHouse (OLAP Engine)   │ │  WSC Client Edge Webhooks   │
  └──────────────────────────────┘ └─────────────────────────────┘
```

---

## ⚙️ Technology Stack

- **API Gateway:** Python (FastAPI / Uvicorn)
- **Message Broker:** RabbitMQ (`aio_pika`)
- **Telemetry Storage:** ClickHouse (Optimized column-oriented storage for billions of events)
- **Metadata & Auth:** MySQL / MariaDB (Project tokens & client encryption keys)
- **Sentinel Workers:** Async worker pool with Headless Chrome mesh integration for Core Web Vitals and PageSpeed audits
- **Push Mechanism:** Signed HMAC-SHA256 (`X-WSC-Sig`) webhooks back to connected CMS instances

---

## 🚀 Quick Start (Docker Compose)

### 1. Configuration

Copy the example environment template and configure your connection strings:

```bash
cp .env.example .env
```

### 2. Launch Services

```bash
docker compose up -d --build
```

### 3. Verify Health

```bash
curl http://localhost:8000/health
```

---

## 📡 Core API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/v1/ingest` | Receives AES-256 encrypted telemetry batches from client plugins. |
| `POST` | `/v1/projects/register` | Project pairing and shared secret exchange. |
| `POST` | `/v1/sentinel/audit` | Triggers an on-demand SpeedSentinel audit on headless worker nodes. |
| `GET` | `/v1/intelligence/benchmarks`| Provides cross-industry conversion and bot benchmark indices. |

---

## 📄 License

Licensed under the [GNU General Public License v2.0 or later (GPL-2.0-or-later)](LICENSE).  
Part of the **[World Search Council](https://github.com/World-Search-Council)** ecosystem.
