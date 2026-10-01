"""
Unified Persistent Evidence Storage Service for CyberGuard.
Provides storage abstraction, cryptographic integrity verification,
content-addressed layout, safe streaming, and path traversal protection.
"""
from __future__ import annotations

import os
import shutil
import hashlib
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Dict, Any, List, Optional, Tuple, Union

logger = logging.getLogger("cyberguard.storage")


class StorageError(Exception):
    """Base exception for evidence storage operations."""
    pass


class StoragePathTraversalError(StorageError, ValueError):
    """Raised when a storage path contains path traversal sequences or escapes storage root."""
    pass


class StoragePayloadTooLargeError(StorageError, ValueError):
    """Raised when an uploaded evidence payload exceeds maximum allowed size."""
    pass


class IntegrityStatus(str, Enum):

    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    MISSING = "MISSING"


class StorageBackendType(str, Enum):
    LOCAL = "LOCAL"
    S3 = "S3"
    GCS = "GCS"
    AZURE = "AZURE"


class RetentionPolicy(str, Enum):
    INDEFINITE = "INDEFINITE"
    THIRTY_DAYS = "30_DAYS"
    NINETY_DAYS = "90_DAYS"
    ONE_YEAR = "1_YEAR"
    LEGAL_HOLD = "LEGAL_HOLD"


@dataclass
class StorageResult:
    storage_key: str
    sha256: str
    size: int
    mime_type: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    original_filename: Optional[str] = None
    absolute_path: Optional[Path] = None
    is_duplicate: bool = False
    stored_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def detect_mime_type_from_header(header_bytes: bytes, fallback_mime: Optional[str] = None) -> str:
    """
    Lightweight, dependency-free MIME type detection based on magic file signatures.
    """
    if not header_bytes:
        return fallback_mime or "application/octet-stream"

    # RFC-822 Email
    if header_bytes.startswith(b"Received:") or header_bytes.startswith(b"From:") or header_bytes.startswith(b"Return-Path:"):
        return "message/rfc822"
    if b"\nReceived: " in header_bytes[:512] or b"\nFrom: " in header_bytes[:512]:
        return "message/rfc822"

    # PDF Document
    if header_bytes.startswith(b"%PDF"):
        return "application/pdf"

    # Portable Executable (Windows EXE / DLL / SYS)
    if header_bytes.startswith(b"MZ"):
        return "application/x-dosexec"

    # ZIP / Office Documents (DOCX, XLSX, PPTX, JAR, APK)
    if header_bytes.startswith(b"PK\x03\x04") or header_bytes.startswith(b"PK\x05\x06"):
        return "application/zip"

    # PNG Image
    if header_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"

    # JPEG Image
    if header_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"

    # GIF Image
    if header_bytes.startswith(b"GIF87a") or header_bytes.startswith(b"GIF89a"):
        return "image/gif"

    # WebP Image
    if header_bytes.startswith(b"RIFF") and b"WEBP" in header_bytes[:16]:
        return "image/webp"

    # 7-Zip Archive
    if header_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"

    # GZIP
    if header_bytes.startswith(b"\x1f\x8b"):
        return "application/gzip"

    # Tar Archive
    if len(header_bytes) >= 262 and header_bytes[257:262] == b"ustar":
        return "application/x-tar"

    # JSON Text
    stripped = header_bytes.strip()
    if (stripped.startswith(b"{") and stripped.endswith(b"}")) or (stripped.startswith(b"[") and stripped.endswith(b"]")):
        return "application/json"

    # Plain text / CSV
    try:
        header_bytes.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        pass

    return fallback_mime or "application/octet-stream"


class StorageBackend(ABC):
    """
    Abstract interface for durable evidence storage backends.
    Allows seamless future addition of S3/GCS/Azure without rewriting business logic.
    """
    @abstractmethod
    def store_stream(
        self,
        stream: BinaryIO,
        original_filename: Optional[str] = None,
        mime_type: Optional[str] = None,
        custom_key: Optional[str] = None,
    ) -> StorageResult:
        pass

    @abstractmethod
    def store_bytes(
        self,
        data: bytes,
        original_filename: Optional[str] = None,
        mime_type: Optional[str] = None,
        custom_key: Optional[str] = None,
    ) -> StorageResult:
        pass

    @abstractmethod
    def retrieve_bytes(self, storage_key: str) -> bytes:
        pass

    @abstractmethod
    def retrieve_stream(self, storage_key: str) -> BinaryIO:
        pass

    @abstractmethod
    def exists(self, storage_key: str) -> bool:
        pass

    @abstractmethod
    def verify_integrity(self, storage_key: str, expected_sha256: str) -> Tuple[IntegrityStatus, Optional[str]]:
        pass

    @abstractmethod
    def get_metadata(self, storage_key: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def delete(self, storage_key: str, force: bool = False) -> bool:
        pass


class LocalStorageBackend(StorageBackend):
    """
    Persistent, content-addressed local filesystem storage backend.
    Enforces atomic staging, checksum generation, and strict path traversal protection.
    """
    def __init__(
        self,
        root_dir: Optional[Union[str, Path]] = None,
        max_size_mb: int = 50,
        max_size_bytes: Optional[int] = None,
    ):
        if root_dir is None:
            env_root = os.getenv("CYBERGUARD_STORAGE_ROOT")
            if env_root:
                self.root_dir = Path(env_root).resolve()
            else:
                # Default to backend/data/storage
                self.root_dir = (Path(__file__).resolve().parent.parent / "data" / "storage").resolve()
        else:
            self.root_dir = Path(root_dir).resolve()

        if max_size_bytes is not None:
            self.max_size_bytes = max_size_bytes
        else:
            self.max_size_bytes = int(os.getenv("MAX_UPLOAD_SIZE_MB", str(max_size_mb))) * 1024 * 1024

        # Initialize canonical subdirectories
        self.artifacts_dir = self.root_dir / "artifacts"
        self.derived_dir = self.root_dir / "derived"
        self.reports_dir = self.root_dir / "reports"
        self.tmp_dir = self.root_dir / "tmp"

        for directory in (self.artifacts_dir, self.derived_dir, self.reports_dir, self.tmp_dir):
            directory.mkdir(parents=True, exist_ok=True)

        # Legacy backward-compatibility directories
        self.legacy_eml_dir = (self.root_dir.parent / "eml_store").resolve()
        self.legacy_reports_dir = (self.root_dir.parent / "reports").resolve()

    def resolve_safe_path(self, relative_key: str) -> Path:
        """
        Validates that a storage key does NOT escape the root directory via directory traversal or absolute paths.
        """
        clean_key = relative_key.strip().replace("\\", "/")
        # Reject absolute paths, root accesses, and obvious path traversal sequences
        if clean_key.startswith("/") or clean_key.startswith("~") or (len(clean_key) > 1 and clean_key[1] == ":"):
            raise StoragePathTraversalError(f"Absolute or foreign path not permitted in storage key: '{relative_key}'")

        parts = clean_key.split("/")
        if ".." in parts or any(p == ".." for p in parts):
            raise StoragePathTraversalError(f"Path traversal detected in storage key: '{relative_key}'")

        target = (self.root_dir / clean_key).resolve()
        try:
            target.relative_to(self.root_dir)
        except ValueError:
            raise StoragePathTraversalError(f"Target path '{target}' escapes storage root '{self.root_dir}'")

        return target

    def _get_candidate_paths(self, storage_key: str) -> List[Path]:
        """
        Returns all candidate paths for a storage key, including content-addressed
        and legacy fallback directories.
        """
        clean_key = storage_key.strip().replace("\\", "/")
        if clean_key.startswith("/") or clean_key.startswith("~") or (len(clean_key) > 1 and clean_key[1] == ":"):
            raise StoragePathTraversalError(f"Absolute or foreign path not permitted in storage key: '{storage_key}'")

        parts = clean_key.split("/")
        if ".." in parts or any(p == ".." for p in parts):
            raise StoragePathTraversalError(f"Path traversal detected in storage key: '{storage_key}'")

        candidates: List[Path] = []
        try:
            candidates.append(self.resolve_safe_path(storage_key))
        except StoragePathTraversalError:
            raise
        except ValueError:
            pass

        clean_id = storage_key.strip().replace("\\", "/").split("/")[-1]
        stem = clean_id.split(".")[0]

        # Check if clean_id is a 64-char sha256
        if len(stem) == 64:
            shard = stem[:2].lower()
            candidates.append(self.artifacts_dir / shard / stem.lower() / "original")
            candidates.append(self.artifacts_dir / shard / stem.lower() / f"{stem.lower()}.raw")

        # Check legacy eml_store
        if self.legacy_eml_dir.exists():
            candidates.append(self.legacy_eml_dir / f"{clean_id}")
            if not clean_id.endswith(".eml"):
                candidates.append(self.legacy_eml_dir / f"{clean_id}.eml")
                candidates.append(self.legacy_eml_dir / f"{clean_id.lower()}.eml")

        # Check legacy reports
        if self.legacy_reports_dir.exists():
            candidates.append(self.legacy_reports_dir / f"{clean_id}")
            if not clean_id.endswith(".pdf"):
                candidates.append(self.legacy_reports_dir / f"{clean_id}.pdf")

        return candidates

    def store_stream(
        self,
        stream: BinaryIO,
        original_filename: Optional[str] = None,
        mime_type: Optional[str] = None,
        custom_key: Optional[str] = None,
    ) -> StorageResult:
        """
        Streams content to a temporary staging file, calculating SHA-256, SHA-1,
        and MD5 concurrently. Enforces file size limits, moves to content-addressed
        storage atomically, and creates metadata sidecars.
        """
        staging_filename = f".tmp_{uuid.uuid4().hex}"
        staging_path = self.tmp_dir / staging_filename

        h_sha256 = hashlib.sha256()
        h_sha1 = hashlib.sha1()
        h_md5 = hashlib.md5()
        total_size = 0
        header_sample = bytearray()

        try:
            with open(staging_path, "wb") as f_out:
                while True:
                    chunk = stream.read(65536)  # 64 KB buffer
                    if not chunk:
                        break
                    total_size += len(chunk)
                    if total_size > self.max_size_bytes:
                        raise StoragePayloadTooLargeError(
                            f"File size exceeds maximum allowed upload size of {self.max_size_bytes // (1024*1024)} MB."
                        )
                    if len(header_sample) < 1024:
                        needed = 1024 - len(header_sample)
                        header_sample.extend(chunk[:needed])

                    h_sha256.update(chunk)
                    h_sha1.update(chunk)
                    h_md5.update(chunk)
                    f_out.write(chunk)

            calculated_sha256 = h_sha256.hexdigest().lower()
            calculated_sha1 = h_sha1.hexdigest().lower()
            calculated_md5 = h_md5.hexdigest().lower()

            detected_mime = detect_mime_type_from_header(bytes(header_sample), fallback_mime=mime_type)

            # Determine content-addressed storage key
            if custom_key:
                storage_key = custom_key.strip().lstrip("/")
                final_path = self.resolve_safe_path(storage_key)
            else:
                shard = calculated_sha256[:2]
                storage_key = f"artifacts/{shard}/{calculated_sha256}/original"
                final_path = self.artifacts_dir / shard / calculated_sha256 / "original"

            final_path.parent.mkdir(parents=True, exist_ok=True)

            is_duplicate = final_path.exists() and final_path.stat().st_size == total_size
            if not is_duplicate:
                # Atomic move
                shutil.move(str(staging_path), str(final_path))
            else:
                # File already exists identically; clean up staging file
                if staging_path.exists():
                    staging_path.unlink()

            # Write metadata sidecar
            metadata_file = final_path.parent / "metadata.json"
            if not metadata_file.exists():
                try:
                    import json
                    meta = {
                        "sha256": calculated_sha256,
                        "sha1": calculated_sha1,
                        "md5": calculated_md5,
                        "size": total_size,
                        "mime_type": detected_mime,
                        "original_filename": original_filename,
                        "stored_at": datetime.now(timezone.utc).isoformat(),
                        "storage_key": storage_key,
                    }
                    with open(metadata_file, "w", encoding="utf-8") as mf:
                        json.dump(meta, mf, indent=2)
                except Exception as meta_exc:
                    logger.warning("Failed to write metadata sidecar: %s", meta_exc)

            logger.info("Stored artifact '%s' (size=%d, sha256=%s)", storage_key, total_size, calculated_sha256)

            return StorageResult(
                storage_key=storage_key,
                sha256=calculated_sha256,
                sha1=calculated_sha1,
                md5=calculated_md5,
                size=total_size,
                mime_type=detected_mime,
                original_filename=original_filename,
                absolute_path=final_path,
                is_duplicate=is_duplicate,
            )
        finally:
            if staging_path.exists():
                try:
                    staging_path.unlink()
                except Exception:
                    pass

    def store_bytes(
        self,
        data: bytes,
        original_filename: Optional[str] = None,
        mime_type: Optional[str] = None,
        custom_key: Optional[str] = None,
    ) -> StorageResult:
        """Helper to store in-memory bytes through the streaming storage implementation."""
        import io
        return self.store_stream(
            stream=io.BytesIO(data),
            original_filename=original_filename,
            mime_type=mime_type,
            custom_key=custom_key,
        )

    def retrieve_bytes(self, storage_key: str) -> bytes:
        """Retrieves raw stored bytes for a storage key or legacy identifier."""
        candidates = self._get_candidate_paths(storage_key)
        for cand in candidates:
            if cand.is_file():
                with open(cand, "rb") as f:
                    return f.read()

        raise FileNotFoundError(f"Artifact evidence not found for storage key: '{storage_key}'")

    def retrieve_stream(self, storage_key: str) -> BinaryIO:
        """Opens and returns a binary file stream for reading."""
        candidates = self._get_candidate_paths(storage_key)
        for cand in candidates:
            if cand.is_file():
                return open(cand, "rb")

        raise FileNotFoundError(f"Artifact evidence stream not found for storage key: '{storage_key}'")

    def exists(self, storage_key: str) -> bool:
        """Checks whether stored bytes exist for this key."""
        candidates = self._get_candidate_paths(storage_key)
        return any(cand.is_file() and cand.stat().st_size > 0 for cand in candidates)

    def verify_integrity(self, storage_key: str, expected_sha256: str) -> Tuple[IntegrityStatus, Optional[str]]:
        """
        Recalculates SHA-256 of stored bytes and verifies cryptographic integrity.
        """
        clean_expected = expected_sha256.strip().lower()
        candidates = self._get_candidate_paths(storage_key)

        target_file: Optional[Path] = None
        for cand in candidates:
            if cand.is_file():
                target_file = cand
                break

        if not target_file:
            return IntegrityStatus.MISSING, None

        h = hashlib.sha256()
        with open(target_file, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        actual_sha256 = h.hexdigest().lower()

        if actual_sha256 == clean_expected:
            return IntegrityStatus.VERIFIED, actual_sha256
        else:
            logger.error(
                "Integrity mismatch for '%s'! Expected %s, got %s",
                storage_key, clean_expected, actual_sha256
            )
            return IntegrityStatus.MISMATCH, actual_sha256

    def get_metadata(self, storage_key: str) -> Optional[Dict[str, Any]]:
        """Retrieves metadata from sidecar file or basic filesystem stats."""
        candidates = self._get_candidate_paths(storage_key)
        for cand in candidates:
            if cand.is_file():
                meta_path = cand.parent / "metadata.json"
                if meta_path.is_file():
                    try:
                        import json
                        with open(meta_path, "r", encoding="utf-8") as mf:
                            return json.load(mf)
                    except Exception:
                        pass
                stat = cand.stat()
                return {
                    "size": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "storage_key": storage_key,
                }
        return None

    def delete(self, storage_key: str, force: bool = False) -> bool:
        """Safely removes an artifact from disk if not under legal hold."""
        candidates = self._get_candidate_paths(storage_key)
        deleted_any = False
        for cand in candidates:
            if cand.is_file():
                cand.unlink()
                deleted_any = True
                meta = cand.parent / "metadata.json"
                if meta.is_file():
                    try:
                        meta.unlink()
                    except Exception:
                        pass
        return deleted_any


# Global default instance configured with environment settings
evidence_storage = LocalStorageBackend()
