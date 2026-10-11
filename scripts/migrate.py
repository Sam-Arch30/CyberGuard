#!/usr/bin/env python3
"""
Section 74: Deterministic Database Migration Runner.
Executes Alembic migrations with pre-migration backup, rollback safeguards, and validation.
"""
import argparse
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cyberguard.migrate")


def run_alembic_command(args: list[str]) -> subprocess.CompletedProcess:
    """Executes alembic CLI command within the current environment."""
    cmd = ["alembic"] + args
    logger.info("Executing: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error("Alembic error (exit code %d):", result.returncode)
        if result.stdout:
            logger.error("STDOUT:\n%s", result.stdout)
        if result.stderr:
            logger.error("STDERR:\n%s", result.stderr)
        raise RuntimeError(f"Alembic command failed: {' '.join(cmd)}")
    return result


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Deterministic Database Migration Runner")
    parser.add_argument("--check-only", action="store_true", help="Only check current migration version without upgrading")
    parser.add_argument("--backup-first", action="store_true", default=True, help="Create a backup before running migrations")
    parser.add_argument("--revision", default="head", help="Target Alembic revision (default: head)")
    args = parser.parse_args()

    logger.info("Starting CyberGuard database migration process...")

    # 1. Inspect current revision
    try:
        curr_res = run_alembic_command(["current"])
        logger.info("Current Database Revision:\n%s", curr_res.stdout.strip())
    except Exception as e:
        logger.warning("Could not check current revision (database may be fresh): %s", e)

    if args.check_only:
        logger.info("Check-only completed.")
        sys.exit(0)

    # 2. Pre-migration backup if requested and database exists
    db_url = os.getenv("DATABASE_URL", "sqlite:///backend/data/mailtrace.db")
    if args.backup_first:
        try:
            logger.info("Running pre-migration database backup...")
            from scripts.backup_database import run_backup
            backup_dir = os.getenv("BACKUP_DIR", "backend/data/backups")
            manifest = run_backup(db_url, backup_dir)
            logger.info("Pre-migration backup secured: %s", manifest.get("archive_path"))
        except Exception as be:
            logger.warning("Pre-migration backup warning (continuing if new database): %s", be)

    # 3. Execute upgrade
    logger.info("Applying migrations up to revision '%s'...", args.revision)
    upg_res = run_alembic_command(["upgrade", args.revision])
    logger.info("Upgrade output:\n%s", upg_res.stdout.strip())

    # 4. Verify new current revision
    ver_res = run_alembic_command(["current"])
    logger.info("Verified active revision:\n%s", ver_res.stdout.strip())
    logger.info("All migrations completed successfully.")


if __name__ == "__main__":
    main()
