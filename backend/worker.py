"""
Section 45: Dedicated Background Job Worker CLI Process Entrypoint.
Runs independently or alongside FastAPI using shared database models and configuration.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

from backend.db.session import init_db
from backend.services.log_sanitizer import configure_production_logging
from backend.services.background_job_worker import BackgroundJobWorker

# Configure redacted structured logging
configure_production_logging()
logger = logging.getLogger("cyberguard.worker")


async def main():
    logger.info("Initializing CyberGuard Background Job Worker...")

    # Ensure database schema is ready
    init_db(max_retries=10, retry_delay=2.0)

    concurrency = int(os.getenv("WORKER_CONCURRENCY", "4"))
    poll_interval = float(os.getenv("WORKER_POLL_INTERVAL", "1.0"))

    worker = BackgroundJobWorker(
        max_concurrency=concurrency,
        poll_interval=poll_interval,
    )

    loop = asyncio.get_running_loop()

    def _handle_shutdown(sig):
        logger.info("Received termination signal %s. Initiating graceful worker shutdown...", sig.name)
        worker.stop()

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, lambda sig=s: _handle_shutdown(sig))
        except NotImplementedError:
            # Fallback for environments where add_signal_handler is not implemented (e.g. Windows)
            pass

    logger.info("Background Worker running with ID '%s' (concurrency=%s)", worker.worker_id, concurrency)
    await worker.run_loop()
    logger.info("Background Worker process terminated cleanly.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)
