# WSC Gateway Workers (Split Architecture)

This directory contains the split worker components for better scalability.

## Components

- **dispatcher.py**: Lightweight service that receives triggers from `wsc_trigger_reports` and decides whether to generate reports. Publishes tasks to `wsc_report_tasks`.

- **ingest.py**: High-throughput worker that consumes raw events from `wsc_raw_events`, enriches them (GeoIP, device, etc.) and writes to ClickHouse.

- **report_generator.py**: Worker that consumes report tasks, populates aggregates, assembles the three dashboard cards and pushes them via the gateway.

All components share common logic from `common.py`.

## Running

```bash
# Ingest (can scale)
python ingest.py

# Dispatcher (typically 1)
python dispatcher.py

# Report generator (can scale independently)
python report_generator.py
```

## Docker / Compose

See root `docker-compose.yml`:

- `worker-ingest` with `deploy.replicas`
- `worker-report` with `deploy.replicas`
- `dispatcher` (single)

Scale at runtime:
```bash
docker compose up --scale worker-ingest=5 --scale worker-report=3
```

## Trigger Messages

- `{}` or empty: dispatcher discovers active projects
- `{"project_id": "proj_xxx"}`: specific project
- `{"project_id": "proj_xxx", "force": true}`: bypass rate/activity checks (for manual resync after reset)

## Notes

- `workerV3.py` is a deprecated shim for backward compatibility.
- The split enables independent scaling of ingestion vs. analytics workloads.
- Rate limiting and activity checks are centralized in the dispatcher.