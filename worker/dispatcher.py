#!/usr/bin/env python3
"""
dispatcher.py - lightweight dispatcher.
Checks whether a report should be generated and publishes tasks.
Usually run with 1 replica.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import run_dispatcher

if __name__ == "__main__":
    print("Starting DISPATCHER...")
    asyncio.run(run_dispatcher())