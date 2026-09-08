#!/usr/bin/env python3
"""
report_generator.py - assembles dashboard reports and pushes them via gateway.
Scale this independently from ingest.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import run_report_generator

if __name__ == "__main__":
    print("Starting REPORT GENERATOR...")
    asyncio.run(run_report_generator())