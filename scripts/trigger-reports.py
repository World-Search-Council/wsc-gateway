#!/usr/bin/env python3
"""
Simple periodic trigger for WSC reports.

This script publishes (empty) messages to the wsc_trigger_reports queue
at a regular interval. The dispatcher then decides whether to generate
fresh Card 1/2/3 reports for active projects.

Usage:
    python trigger-reports.py --interval 45

Recommended deployment:
- As a sidecar container alongside the workers
- Via cron: */45 * * * * cd /path/to/wsc-gateway && python scripts/trigger-reports.py --interval 45
- Or systemd timer

Environment:
    RABBITMQ_URL  (required, same as used by ingest/dispatcher/report workers)

Last polished: 18.07.2026 (observation phase)
"""

import os
import sys
import json
import time
import argparse
import asyncio

import aio_pika


async def send_trigger(interval_minutes: int):
    rabbit_url = os.environ.get("RABBITMQ_URL")
    if not rabbit_url:
        print("ERROR: RABBITMQ_URL environment variable is required.")
        sys.exit(1)

    print(f"Starting report trigger (every {interval_minutes} minutes)...")

    connection = await aio_pika.connect_robust(rabbit_url)
    channel = await connection.channel()

    while True:
        try:
            # Empty message = dispatcher will discover active projects automatically.
            # For a specific project you can send: {"project_id": "proj_xxx", "force": true}
            message = aio_pika.Message(
                b"{}",
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            )
            await channel.default_exchange.publish(message, routing_key="wsc_trigger_reports")
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Trigger sent to wsc_trigger_reports")
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ERROR sending trigger: {e}")

        await asyncio.sleep(interval_minutes * 60)


def main():
    parser = argparse.ArgumentParser(description="WSC Report Trigger Scheduler")
    parser.add_argument("--interval", type=int, default=45, help="Minutes between triggers (default: 45)")
    args = parser.parse_args()

    try:
        asyncio.run(send_trigger(args.interval))
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()