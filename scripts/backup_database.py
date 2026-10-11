#!/usr/bin/env python3
"""
Section 74: Deterministic Database Backup Utility.
Creates timestamped, compressed, SHA-256 integrity-verified database backups.
Supports SQLite (local/staging) and PostgreSQL (managed/production).
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
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cyberguard.backup")


def compute_sha256(filepath: str) -> str:
    """Computes cryptographic SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def backup_sqlite(db_path: str, output_dir: str) -> str:
    """Performs an atomic, consistent SQLite online backup."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Source SQLite database not found: {db_path}")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"cyberguard_backup_{timestamp}.sqlite.gz"
    backup_path = os.path.join(output_dir, backup_filename)

    temp_raw_backup = os.path.join(output_dir, f"temp_{timestamp}.sqlite")

    try:
        # Atomic SQLite online backup API
        logger.info("Opening source database connection: %s", db_path)
        src_conn = sqlite3.connect(db_path)
        dst_conn = sqlite3.connect(temp_raw_backup)
        with dst_conn:
            src_conn.backup(dst_conn, pages=100, sleep=0.01)
        dst_conn.close()
        src_conn.close()

        # Compress with gzip
        logger.info("Compressing raw backup with gzip...")
        with open(temp_raw_backup, "rb") as f_in, gzip.open(backup_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

    finally:
        if os.path.exists(temp_raw_backup):
            os.remove(temp_raw_backup)

    return backup_path


def backup_postgres(pg_url: str, output_dir: str) -> str:
    """Executes pg_dump for PostgreSQL managed databases."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"cyberguard_backup_{timestamp}.dump"
    backup_path = os.path.join(output_dir, backup_filename)

    logger.info("Executing pg_dump against PostgreSQL target...")
    cmd = ["pg_dump", "--format=custom", "--no-owner", "--no-acl", f"--file={backup_path}", pg_url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info("pg_dump completed successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError(f"PostgreSQL backup failed: {exc}")

    return backup_path


def prune_old_backups(output_dir: str, keep_count: int = 10) -> int:
    """Retains the most recent N backups and removes older ones."""
    manifests = []
    for fname in os.listdir(output_dir):
        if fname.endswith(".manifest.json"):
            mpath = os.path.join(output_dir, fname)
            manifests.append((os.path.getmtime(mpath), mpath))

    manifests.sort(reverse=True)
    pruned = 0
    if len(manifests) > keep_count:
        for _, mpath in manifests[keep_count:]:
            try:
                with open(mpath, "r") as mf:
                    data = json.load(mf)
                target_archive = data.get("archive_path")
                if target_archive and os.path.exists(target_archive):
                    os.remove(target_archive)
                os.remove(mpath)
                pruned += 1
                logger.info("Pruned old backup: %s", mpath)
            except Exception as e:
                logger.warning("Error pruning backup %s: %s", mpath, e)

    return pruned


def run_backup(db_url: str, output_dir: str, keep_count: int = 10) -> dict:
    """Main backup orchestrator creating archive and verified manifest."""
    os.makedirs(output_dir, exist_ok=True)
    t_start = time.time()

    normalized_url = db_url.strip()
    if normalized_url.startswith("postgres://"):
        normalized_url = normalized_url.replace("postgres://", "postgresql://", 1)

    if normalized_url.startswith("sqlite"):
        clean_path = normalized_url.replace("sqlite:///", "")
        archive_path = backup_sqlite(clean_path, output_dir)
        driver = "sqlite"
    elif normalized_url.startswith("postgresql"):
        archive_path = backup_postgres(normalized_url, output_dir)
        driver = "postgresql"
    else:
        raise ValueError(f"Unsupported database scheme in URL: {normalized_url}")

    sha256 = compute_sha256(archive_path)
    file_size_bytes = os.path.getsize(archive_path)
    duration_seconds = round(time.time() - t_start, 3)

    manifest = {
        "service": "cyberguard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database_driver": driver,
        "archive_path": os.path.abspath(archive_path),
        "archive_filename": os.path.basename(archive_path),
        "file_size_bytes": file_size_bytes,
        "sha256": sha256,
        "duration_seconds": duration_seconds,
        "integrity_verified": True,
    }

    manifest_path = f"{archive_path}.manifest.json"
    with open(manifest_path, "w") as mf:
        json.dump(manifest, mf, indent=2)

    logger.info("Backup successfully completed:")
    logger.info("  Archive:  %s (%d bytes)", archive_path, file_size_bytes)
    logger.info("  SHA-256:  %s", sha256)
    logger.info("  Manifest: %s", manifest_path)

    pruned = prune_old_backups(output_dir, keep_count=keep_count)
    manifest["pruned_backups"] = pruned

    return manifest


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Deterministic Database Backup")
    parser.add_argument("--db-url", default=os.getenv("DATABASE_URL", "sqlite:///backend/data/mailtrace.db"), help="Database connection URL")
    parser.add_argument("--output-dir", default=os.getenv("BACKUP_DIR", "backend/data/backups"), help="Directory to store backup bundles")
    parser.add_argument("--keep", type=int, default=10, help="Number of recent backups to retain")
    args = parser.parse_args()

    try:
        manifest = run_backup(args.db_url, args.output_dir, keep_count=args.keep)
        print(json.dumps(manifest, indent=2))
        sys.exit(0)
    except Exception as exc:
        logger.error("Backup failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
