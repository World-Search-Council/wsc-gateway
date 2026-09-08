# Retry & Dead Letter Queue Strategy

## Goal
Make message processing reliable without infinite loops or losing data.

## Current Staged DLQ Design

### Queues
- `wsc_raw_events` : main queue (declared with x-dead-letter-exchange = wsc.dlx)
- `wsc_raw_events_delay_5m` : 5 minute delay, dead-letters back to main queue
- `wsc_raw_events_delay_1h` : 1 hour delay for high retry count
- `wsc_raw_events.dlq` : final dead letter (for manual inspection)

### Retry Flow
1. Message fails in worker → republished to appropriate delay queue.
2. Delay queue has `x-message-ttl`.
3. After TTL expires, message is dead-lettered back to `wsc_raw_events`.
4. RabbitMQ adds `x-death` header with count + reason.
5. Worker reads the death count (or `x-retry-count` custom header).
6. If retry_count < 10 → use 5m delay.
7. If >= 10 → use 1h delay.

After many failures the message will eventually land in the .dlq queue.

## Implementation Notes
- Gateway declares the queues and DLX on startup.
- Worker handles the logic in the exception path (no simple requeue=True).
- Custom header `x-retry-count` is used as fallback.
- Messages are published with `delivery_mode=PERSISTENT`.

## Future Improvements
- Add a small admin tool or script to inspect / reprocess DLQ.
- Configurable retry counts and delays via env.
- Metrics / alerts on high DLQ volume.
- Separate queue per project if needed for isolation.

## How to inspect DLQ
```bash
rabbitmqadmin get queue=wsc_raw_events.dlq count=10
# or via management UI
```
