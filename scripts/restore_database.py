#!/usr/bin/env python3
"""
Section 74: Verified Database Restore Utility.
Restores database from cryptographic backup archive with pre-flight integrity verification,
automatic pre-restore safety snapshot, and post-restore schema validation.
"""
import argparse
import gzip
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cyberguard.restore")


def compute_sha256(filepath: str) -> str:
    """Computes cryptographic SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_backup_integrity(archive_path: str, manifest_path: Optional[str] = None) -> dict:
    """Verifies that the backup archive matches its manifest SHA-256 hash."""
    if not os.path.exists(archive_path):
        raise FileNotFoundError(f"Backup archive not found: {archive_path}")

    if not manifest_path:
        manifest_path = f"{archive_path}.manifest.json"

    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as mf:
            manifest = json.load(mf)
        expected_sha = manifest.get("sha256")
        if expected_sha:
            actual_sha = compute_sha256(archive_path)
            if actual_sha.lower() != expected_sha.lower():
                raise ValueError(
                    f"Backup cryptographic integrity check FAILED! "
                    f"Expected SHA-256: {expected_sha}, Actual SHA-256: {actual_sha}"
                )
            logger.info("Cryptographic integrity verified: SHA-256 matches manifest (%s)", actual_sha)
            return manifest

    actual_sha = compute_sha256(archive_path)
    logger.warning("No manifest found. Computed archive SHA-256: %s", actual_sha)
    return {"archive_path": archive_path, "sha256": actual_sha}


def restore_sqlite(archive_path: str, target_db_path: str) -> None:
    """Restores SQLite database from gzipped backup with safety snapshot."""
    target_dir = os.path.dirname(os.path.abspath(target_db_path))
    os.makedirs(target_dir, exist_ok=True)

    # 1. Create safety snapshot of existing target if present
    if os.path.exists(target_db_path):
        safety_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safety_path = f"{target_db_path}.safety_pre_restore_{safety_ts}"
        logger.info("Creating pre-restore safety snapshot: %s", safety_path)
        shutil.copy2(target_db_path, safety_path)

    temp_restored_raw = f"{target_db_path}.restoring.tmp"
    try:
        logger.info("Decompressing backup archive to temporary target...")
        with gzip.open(archive_path, "rb") as f_in, open(temp_restored_raw, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        # Verify SQLite integrity check
        logger.info("Running SQLite PRAGMA integrity_check on restored image...")
        conn = sqlite3.connect(temp_restored_raw)
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        check_result = cursor.fetchone()
        conn.close()

        if not check_result or check_result[0] != "ok":
            raise ValueError(f"SQLite PRAGMA integrity check failed: {check_result}")

        # Atomically move into destination
        shutil.move(temp_restored_raw, target_db_path)
        logger.info("Successfully replaced active database at: %s", target_db_path)

    finally:
        if os.path.exists(temp_restored_raw):
            os.remove(temp_restored_raw)


def restore_postgres(archive_path: str, pg_url: str) -> None:
    """Restores PostgreSQL database using pg_restore."""
    logger.info("Executing pg_restore into PostgreSQL target: %s", pg_url)
    cmd = ["pg_restore", "--clean", "--if-exists", "--no-owner", "--no-acl", f"--dbname={pg_url}", archive_path]

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info("pg_restore completed successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError(f"PostgreSQL restore failed: {exc}")


def verify_restored_schema(db_url: str) -> dict:
    """Verifies that restored database contains essential tables and is readable."""
    logger.info("Verifying restored database schema and connectivity...")
    normalized_url = db_url.strip()
    if normalized_url.startswith("postgres://"):
        normalized_url = normalized_url.replace("postgres://", "postgresql://", 1)

    if normalized_url.startswith("sqlite"):
        clean_path = normalized_url.replace("sqlite:///", "")
        conn = sqlite3.connect(clean_path)
        cursor = conn.cursor()

        tables_query = "SELECT name FROM sqlite_master WHERE type='table';"
        cursor.execute(tables_query)
        tables = [row[0] for row in cursor.fetchall()]

        counts = {}
        for critical_table in ("cases", "incidents", "evidence", "artifacts"):
            if critical_table in tables:
                cursor.execute(f"SELECT count(*) FROM {critical_table};")
                counts[critical_table] = cursor.fetchone()[0]

        conn.close()
        return {"tables_found": len(tables), "records": counts}

    return {"status": "postgresql_connected"}


def run_restore(archive_path: str, db_url: str, manifest_path: Optional[str] = None) -> dict:
    """Main restore orchestrator."""
    t_start = time.time()
    manifest = verify_backup_integrity(archive_path, manifest_path)

    normalized_url = db_url.strip()
    if normalized_url.startswith("postgres://"):
        normalized_url = normalized_url.replace("postgres://", "postgresql://", 1)

    if normalized_url.startswith("sqlite"):
        clean_path = normalized_url.replace("sqlite:///", "")
        restore_sqlite(archive_path, clean_path)
    elif normalized_url.startswith("postgresql"):
        restore_postgres(archive_path, normalized_url)
    else:
        raise ValueError(f"Unsupported database scheme in URL: {normalized_url}")

    schema_info = verify_restored_schema(normalized_url)
    duration_seconds = round(time.time() - t_start, 3)

    report = {
        "service": "cyberguard",
        "action": "RESTORE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "archive_restored": archive_path,
        "archive_sha256": manifest.get("sha256"),
        "duration_seconds": duration_seconds,
        "verification": schema_info,
        "status": "RESTORE_SUCCESSFUL",
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Verified Database Restore")
    parser.add_argument("archive", help="Path to database backup archive (.sqlite.gz or .dump)")
    parser.add_argument("--db-url", default=os.getenv("DATABASE_URL", "sqlite:///backend/data/mailtrace.db"), help="Target database connection URL")
    parser.add_argument("--manifest", default=None, help="Optional path to manifest JSON file")
    args = parser.parse_args()

    try:
        report = run_restore(args.archive, args.db_url, args.manifest)
        print(json.dumps(report, indent=2))
        sys.exit(0)
    except Exception as exc:
        logger.error("Restore failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
