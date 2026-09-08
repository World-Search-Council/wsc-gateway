#!/usr/bin/env python3
"""
worker_ingest.py - high throughput event ingestion into ClickHouse.
Scale this service with multiple replicas for high load.
"""
import asyncio
import os
import sys

# Ensure sibling workerV3.py (shared functions) is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import run_ingest

if __name__ == "__main__":
    print("Starting INGEST worker (high volume events)...")
    asyncio.run(run_ingest())