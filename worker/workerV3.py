"""
workerV3.py - DEPRECATED shim for backward compatibility.

The worker has been split:
- Use dispatcher.py
- Use ingest.py
- Use report_generator.py

This file re-exports from common.py for old scripts/tests.
It will be removed in future versions.
"""
import warnings
from common import *  # re-export everything

warnings.warn(
    "workerV3.py is deprecated. Use the split entrypoints: dispatcher.py, ingest.py, report_generator.py. "
    "See worker/README.md and workers.md for details.",
    DeprecationWarning,
    stacklevel=2
)

if __name__ == "__main__":
    import os
    import asyncio
    mode = os.getenv("WORKER_MODE", "monolith").lower()
    if mode == "ingest":
        asyncio.run(run_ingest())
    elif mode == "dispatcher":
        asyncio.run(run_dispatcher())
    elif mode == "report":
        asyncio.run(run_report_generator())
    else:
        print("Monolith mode is deprecated. Prefer split workers.")
        # Fallback to ingest for now
        asyncio.run(run_ingest())