# Workers

## Current Implementation (Split Workers)

The worker has been split for scalability:

### Entry points (in `worker/`)

- `dispatcher.py` – lightweight decision maker (checks if report generation is needed, supports force/resync)
- `ingest.py` – high-volume event ingestion into ClickHouse (scale this for load)
- `report_generator.py` – assembles and pushes the dashboard reports (Card 1/2/3)

All three import shared logic from `common.py` (former workerV3.py, now library).

`workerV3.py` is a thin deprecation shim.

See docker-compose.yml for how replicas are configured (worker-ingest and worker-report have `deploy.replicas`).

### How to run locally

```bash
# Ingest (multiple replicas possible)
python ingest.py

# Dispatcher (usually 1)
python dispatcher.py

# Report generator (scale as needed)
python report_generator.py
```

### Manual / forced resync

To force a report (e.g. after a full reset):
```json
{"project_id": "your-project-id", "force": true}
```
Send this message to the `wsc_trigger_reports` queue. The dispatcher will bypass rate/activity checks.

**Automatic resync from plugin:**
When the plugin performs "Full Reset + Re-sync", it sends a lightweight synthetic event `e: "resync_request"`.
The ingest worker detects this and automatically publishes a force trigger to `wsc_trigger_reports`.
No manual intervention needed.

**Recommended scheduler**
See `scripts/trigger-reports.py` for a simple periodic trigger script.
Run it with the same `RABBITMQ_URL` as the workers, e.g.:
```
python scripts/trigger-reports.py --interval 45
```

In Docker:
```bash
docker compose up --scale worker-ingest=4 --scale worker-report=2
```

### Legacy / Backward

`workerV3.py` still exists as shim for old scripts (emits deprecation warning). Avoid in new code.

**Responsibilities:**
- Consume from `wsc_raw_events` RabbitMQ queue
- Decrypt each payload using the project's `local_aes_key` (AES-256-CBC)
- Enrich events:
  - Real IP extraction (from `server_data.ip` + proxy headers)
  - **Daily session hash** (raw_ip + UA + daily_salt) — raw IP is discarded after this
  - GeoIP (country, region, city) via geoip2 (only for public IPs)
  - Device / OS / Browser parsing (user-agents + sec-ch-ua)
  - Deterministic UUIDs for domain and full page URL (uuid5)
  - Clean URL parsing (host, path, query)
- Insert enriched rows into ClickHouse `wsc_analytics_raw`
- Acknowledge messages (or nack + requeue on error)

**Input format (after gateway normalization):**
List of `{"payload": "<base64-encrypted-batch>"}`

**Output:**
Rows in ClickHouse + logs

**Error handling (current):**
- On exception: print + `nack(requeue=True)`
- (To be replaced by proper staged DLQ)

**Deployment:**
- Separate container (see worker/Dockerfile)
- Needs: RabbitMQ, ClickHouse, GeoIP db file

## Recommended Architecture (Scalable Dispatcher + Split Workers)

### Ziel-Architektur (für volle Skalierbarkeit)

Um Ingest und Reporting unabhängig skalieren zu können, wird der Worker in drei klare Komponenten aufgeteilt:

1. **Dispatcher** (leichtgewichtiges Script / Service)
   - Empfängt Trigger-Nachrichten (von externem Scheduler oder manuellem Resync).
   - Führt **frühe, günstige Checks** durch, bevor teure Arbeit entsteht:
     - Hat das Projekt in den letzten Stunden relevante Aktivität (Traffic oder Bots)?
     - Ist bereits ein frischer Report vorhanden (Rate-Limit)?
     - Gibt es überhaupt sinnvolle Daten für einen Report?
   - Nur bei positivem Ergebnis publiziert er eine gezielte Nachricht in die Report-Queue:
     ```json
     { "project_id": "proj_cef36dd667c34396" }
     ```
   - Bei leerer Nachricht oder ohne `project_id` kann der Dispatcher selbst eine kurze Discovery machen (oder diese Logik später komplett hier zentralisieren).
   - Vorteil: Der Dispatcher ist der **smarte Gatekeeper** und verhindert unnötige Last auf den Report-Workern.

2. **worker_ingest**
   - Nur zuständig für die Verarbeitung eingehender Events.
   - RabbitMQ `wsc_raw_events` konsumieren
   - Entschlüsseln, Anreichern (GeoIP, Device, UUIDs, Session-Hash, URL-Parsing)
   - Schreiben in `wsc_analytics_raw` + Materialized Views
   - Hoher Durchsatz, kann separat skaliert werden (viele Replicas bei Traffic-Spikes)

3. **worker_report_generator**
   - Nur zuständig für die Report-Erzeugung.
   - Konsumiert Nachrichten aus der Report-Queue (meist vom Dispatcher)
   - Führt aus:
     - `populate_aggregates` (yesterday + ggf. weitere)
     - `assemble_card1_traffic_report`
     - `assemble_card2_insights_report`
     - `assemble_card3_bots_report`
   - Push via `push_reports_via_gateway` (nur wenn `has_meaningful`)
   - Kann unabhängig skaliert, priorisiert oder sogar pro Projekt-Tier betrieben werden

### Queue-Aufteilung (Ziel)

| Queue                    | Producer                  | Consumer                  | Inhalt                              |
|--------------------------|---------------------------|---------------------------|-------------------------------------|
| `wsc_raw_events`         | Gateway                   | worker_ingest             | Rohe (verschlüsselte) Events        |
| `wsc_report_triggers`    | Externer Scheduler / Dispatcher | Dispatcher            | Trigger (leer oder mit project_id)  |
| `wsc_report_tasks`       | Dispatcher                | worker_report_generator   | `{ "project_id": "..." }`           |

Zusätzlich bleiben die bestehenden Delay-/DLQ-Queues für Fehlerbehandlung.

### Vorteile der Aufteilung

- **Unabhängige Skalierung**: Ingest braucht bei hohem Traffic viele Instanzen, Report-Generierung läuft meist periodisch und ressourcenschonend.
- **Frühe Filterung**: Der Dispatcher spart teure ClickHouse-Queries und Report-Assembly.
- **Entkopplung**: Die beiden Worker können in unterschiedlichen Deployments, Containern oder sogar Clustern laufen.
- **Bessere Observability**: Separate Logs, Metriken und Ressourcen-Limits pro Komponente.
- **Zukünftige Erweiterungen**: Einfach Prioritäts-Queues, dedizierte Report-Worker für große Projekte oder Cost-based Throttling hinzufügen.

### Aktueller Stand (Juli 2026) → Migration

Derzeit läuft noch ein kombinierter `workerV3.py`, der sowohl Ingest als auch Report-Logik enthält. Die Trennung über `wsc_trigger_reports` ist bereits ein erster Schritt in die richtige Richtung.

**Geplante Migrationsschritte:**

1. Dispatcher als separates Script/Deployment einführen (konsumiert `wsc_report_triggers`, publiziert nach Checks in `wsc_report_tasks`).
2. `worker_ingest` extrahieren (nur `process_message` + Insert-Logik).
3. `worker_report_generator` extrahieren (nur `process_project_reports`, `populate_aggregates`, `assemble_*` und `push`).
4. Bestehende `handle_reports_trigger` und `process_project_reports` in den Report-Generator verschieben.
5. Scheduler anpassen: Statt direkt in die alte Queue, in die neue `wsc_report_triggers` senden (leere oder gezielte Nachrichten).
6. Resync-Requests aus dem Plugin ebenfalls über den Dispatcher routen.
7. Monitoring & Alerting pro Worker-Typ aufbauen.

Bis zur vollständigen Trennung kann der kombinierte Worker weiterlaufen (Rückwärtskompatibilität).

Siehe auch `architecture.md` (Abschnitt "Scalable Worker & Reporting Pipeline") für die übergeordnete Begründung.

## ClickHouse Strategy

- Raw: `MergeTree`
- Aggregates: `SummingMergeTree` / `AggregatingMergeTree`
- **Hybrid**: Stündliche Materialized Views (for current day, fine granularity) where useful for auto-agg. Worker queries Raw/MVs to fill Report-Tabellen where more flexibility or human text assembly needed.
- Report data: Assembled by worker, pushed to plugin.

See tables.md for table definitions and workerV3.py for implementation.

See updated tables.md and workers.md for details.

## Queue Responsibilities

- Main queue: `wsc_raw_events` – raw encrypted events from all projects
- (Future) Delay / retry queues for DLQ strategy
- Dead letter exchange for failed messages

Workers should be idempotent where possible (use UUIDs and timestamps for dedup).