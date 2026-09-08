# WSC Gateway & Backend – Roadmap (Gateway + Worker + Pipeline)

**Modul:** WSC Gateway & Analytical Worker Pipeline  
**Aktuelle Version:** 1.5.1  
**Status:** Release-Bereit / 7-Card Suite & Pure Push-Report Pipeline Live  
**Letztes Update:** 1. September 2026 (Pure Gateway Push-Report Paradigm, ClickHouse MVs, E-Commerce & Engagement Assembler)  
**Strategie:** Push-basiert (Zentrale ClickHouse-Aggregation → Python-Worker Report Assembly → HMAC Webhook Push)

---

## Vision

WSC Core liefert **High-Speed Analytics, Bot Shield & E-Commerce Reality Intelligence**.  
Alle Rohdaten werden in ClickHouse aggregiert. Die fertigen Reports werden per **Push (HMAC-SHA256 Webhooks)** direkt an die CMS/Shop-Instanzen geliefert, wodurch lokale Serverlast und Daten-Inkonsistenzen vollständig eliminiert werden.

---

## Aktueller Stand

### Gateway & Backend
- FastAPI Gateway mit `/v1/register`, `/v1/ingest`, `/v1/shopify/*` und `/internal/dispatch-insights`.
- RabbitMQ Queue mit DLX (Dead Letter Exchange) und gestaffelten Delay-Wiederholungen (`wsc_raw_events_delay_5m`, `wsc_raw_events_delay_1h`, `wsc_raw_events_dlq`).
- Events werden entschlüsselt, angereichert (GeoIP, RFC 4122 UUIDs, Salted Session Hashing) und ohne PII/IP-Speicherung in ClickHouse geschrieben.

### ClickHouse & Aggregations-Pipeline
- **Materialized Views**:
  - `mv_wsc_engagement_daily`: Verweildauer, TTFI, Scroll-Meilensteine, Focus Ratio.
  - `mv_wsc_outbound_daily`: Externe Linkziele nach Kategorien (Jobs, Social, Affiliate, Reference).
  - `mv_wsc_ecommerce_daily`: 4-Stufen Funnel (`product_view`, `add_to_cart`, `initiate_checkout`, `purchase`), Revenue, AOV.
  - `wsc_daily_overview`, `wsc_bot_stats`, `wsc_top_pages`, `wsc_traffic_daily`.
- **7-Card Report Assemblers (`worker/common.py`)**:
  - `card1_traffic`: Traffic, Unique Visitors, Kanäle (Search, Social, Direct, AI RAG), Sparkline.
  - `card2_insights`: Proaktive strategische Handlungsempfehlungen & Anomalie-Erkennung.
  - `card3_bots`: Bot-Shield, Suchmaschinen-Crawls vs. AI-RAG & AI-Training.
  - `card_engagement`: Verweildauer, TTFI, Scroll-Meilensteine, UX-Badges.
  - `card_outbound`: Externe Linkziele nach Kategorien.
  - `card_ecommerce`: 4-Stufen Checkout-Ampel, Product Velocity Matrix, Coupon & Margen-Intelligence.
  - `domain_health`: DNS, SSL, Security-Header, Mail-Security (SPF/DMARC).

---

## Meilensteine

### Phase 1: Foundation & Push-Mechanismus (Abgeschlossen)
- [x] Gateway + Worker Grundgerüst (FastAPI + Pydantic v2 Contracts)
- [x] RabbitMQ + ClickHouse Integration
- [x] Webhook-Route im Gateway (`/internal/dispatch-insights`)
- [x] Webhook-Endpoint im Plugin mit HMAC-SHA256 Validierung
- [x] Retry-Logik & Dead-Letter-Exchanges für unzustellbare Nachrichten

### Phase 2: 7-Card Canonical Report Suite & Multi-Period Engine (Abgeschlossen)
- [x] **`card1_traffic`**: Multi-Period Snapshots (1d, 7d, 30d, 90d, 180d, 365d), Sparklines, WoW/MoM/YoY Vorperioden-Vergleiche & Deltas
- [x] **`card2_insights`**: Trend-Algorithmen & Empfehlungen
- [x] **`card3_bots`**: AI vs. Search vs. Scraper Analytics
- [x] **`card_engagement`**: UX-Diagnose (Deep Reader, Intent Mismatch)
- [x] **`card_outbound`**: Externe Link-Kategorisierung
- [x] **`card_ecommerce`**: Multi-Period Funnel, Umsatz- & Wachstumsmetriken, Checkout-Ampel & Product-Velocity
- [x] **`domain_health`**: Sentinel Security Scoring
- [x] Automatisierte Push-Generierung via `generate_reports_for_project()`

### Phase 3: ClickHouse Aggregation & Data Governance (Abgeschlossen)
- [x] Aggregierte Tabellen in ClickHouse angelegt (`wsc_daily_overview`, `wsc_bot_stats`, `wsc_top_pages`)
- [x] Materialized Views für Realtime-Rollups (`mv_wsc_engagement_daily`, `mv_wsc_outbound_daily`, `mv_wsc_ecommerce_daily`)
- [x] Multi-Period Rollups (180d & 365d) für Langzeit-Trends und historische Vergleiche
- [x] Strikte Zero-Local-Aggregation im CMS (WordPress) durch reine SQLite-Report-Reader
- [x] Datenschutz-Standard 1.5.0 (Zero-IP-Persistence, Daily Rotating Salt)

### Phase 4: Stabilität & Skalierung (Laufend)
- [x] Gestaffelte Retry-Queues (5m / 1h)
- [x] Multi-Worker Orchestrierung (`ingest.py`, `dispatcher.py`, `report_generator.py`)
- [ ] Redis Cluster Support für High-Scale Deployments
- [ ] Prometheus / Grafana Metrik-Exporte für Queue-Latenzen

### Phase 5: Microservice Mesh, SpeedSentinel & Cross-Domain Intelligence (Abgeschlossen)
- [x] **SpeedSentinel Playwright Engine (`/v1/pagespeed`)**:
  - Headless CDP Microservice Mesh mit 4G Mobile Throttling & Core Web Vitals (LCP, TBT, CLS, FCP, TTFB).
  - Pydantic Response Contracts & In-Memory Project Cache.
- [x] **AI Coverage & Cross-Domain Rollup Router (`/v1/ai-coverage/query`)**:
  - HMAC-SHA256 Authentifizierung, Multi-Domain ClickHouse Abfrage für RAG vs. Training Scraper.
- [x] **WSC Membership & Partner Verification (`/v1/license` & `/v1/partners`)**:
  - Validierung von Founding-, Partner- und Mitglieds-Lizenzen sowie Bereitstellung des Partner-Feeds.

---

## Architektur-Garantie (Pure Push)

- **Kein Polling**: Das Plugin fragt keine Rohdaten per API ab.
- **Keine lokale Aggregation**: Sämtliche Auswertungen, mathematischen Durchschnitte und Benchmarks werden zentral in ClickHouse berechnet und als fertige Reports per Push bereitgestellt.

---

**Ende der Roadmap**