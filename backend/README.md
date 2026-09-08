# WSC Gateway - Backend Documentation

This folder serves as living documentation for the backend architecture, data model, workers, and configuration of WSC Core.

## Overview

WSC Core uses a **push-based architecture**:
- Plugin sends encrypted events → Gateway → RabbitMQ → Worker → ClickHouse
- Aggregates / Reports are pushed back via Webhook to the Plugin

Components:
- **gateway/**: FastAPI service (auth, ingest, dispatch)
- **worker/**: Processing & enrichment (decryption, GeoIP, UA parsing, UUIDs, ClickHouse insert)
- **backend/**: This documentation (tables, workers, configs)

## Key Principles
- All raw data is stored encrypted until the Worker.
- Local AES key stays with the project (plugin side).
- Gateway only forwards + signs webhooks.
- Retention and privacy are handled in the data layer.

See also:
- [tables.md](tables.md) – ClickHouse + MySQL schema
- [workers.md](workers.md) – responsibilities of current and future workers
- [configs.md](configs.md) – environment variables and infrastructure
- [retries.md](retries.md) – staged Dead Letter Queue & retry strategy
- [../roadmap.md](../roadmap.md)
- [../readme.md](../readme.md)
- Plugin side (WSC-Core) for the WordPress integration.