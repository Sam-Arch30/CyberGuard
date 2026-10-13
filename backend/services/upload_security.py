import os
import re
import uuid
from typing import Optional
from fastapi import HTTPException, status

# Configurable maximum upload size (Default 10 MB)
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".py", ".js",
    ".vbs", ".ps1", ".scr", ".pif", ".msi", ".jar", ".com"
}

ALLOWED_EXTENSIONS = {".eml", ".msg", ".txt"}

# Common RFC-822 email header tokens to detect genuine email format
RFC822_HEADER_TOKENS = [
    re.compile(
        r'^(from|to|subject|received|date|mime-version|return-path|message-id|content-type|delivered-to|'
        r'dkim-signature|arc-[a-z-]+|received-spf|authentication-results|reply-to|cc|bcc|sender|x-[a-z0-9-]+|'
        r'content-transfer-encoding|precedence|auto-submitted|references|in-reply-to):',
        re.IGNORECASE | re.MULTILINE
    ),
]


class UploadSecurityService:
    """Service to enforce upload file security, sanitize filenames, and validate MIME/content."""

    @classmethod
    def sanitize_filename(cls, filename: Optional[str]) -> str:
        """
        Sanitizes user-supplied filenames:
        - Prevents directory traversal attacks (../, ..\\, absolute paths).
        - Strips null bytes (\x00) and control characters.
        - Truncates long filenames to avoid buffer issues.
        - Returns a safe basename string.
        """
        if not filename or not isinstance(filename, str):
            return f"upload_{uuid.uuid4().hex[:8]}.eml"

        # 1. Remove null bytes and non-printable control characters
        clean = filename.replace("\x00", "").strip()
        clean = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', clean)

        # 2. Normalize Windows and Unix path separators to extract base name
        clean = clean.replace("\\", "/")
        clean = os.path.basename(clean)

        # 3. Strip leading/trailing dots and traversal sequences
        clean = re.sub(r'\.{2,}', '.', clean)
        clean = clean.strip(". ")

        # 4. Filter characters: allow alphanumeric, dots, underscores, hyphens
        # Replace dangerous characters with underscores
        clean = re.sub(r'[^a-zA-Z0-9._\-]', '_', clean)

        # 5. Length limit (max 128 chars)
        if len(clean) > 128:
            base, ext = os.path.splitext(clean)
            clean = f"{base[:120]}{ext}"

        if not clean or clean == ".eml":
            return f"upload_{uuid.uuid4().hex[:8]}.eml"

        # Ensure it has an extension
        if not os.path.splitext(clean)[1]:
            clean = f"{clean}.eml"

        return clean

    @classmethod
    def generate_secure_internal_filename(cls) -> str:
        """Generates a random UUID-based internal filename."""
        return f"eml_{uuid.uuid4().hex}.eml"

    @classmethod
    def validate_email_upload(
        cls,
        filename: str,
        content_type: Optional[str],
        content_bytes: bytes
    ) -> None:
        """
        Validates email file upload:
        - Rejects files exceeding MAX_UPLOAD_SIZE_BYTES (HTTP 413).
        - Rejects empty uploads (HTTP 400).
        - Rejects executable and dangerous binary magic headers (HTTP 400).
        - Rejects blocked extensions (HTTP 400).
        - Checks conservative RFC-822 structure.
        """
        # 1. Size check
        if len(content_bytes) > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE if hasattr(status, "HTTP_413_CONTENT_TOO_LARGE") else 413,
                detail=f"Uploaded file exceeds maximum allowed size of {MAX_UPLOAD_SIZE_MB} MB."
            )

        # 2. Empty check
        if not content_bytes or len(content_bytes.strip()) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded email file is empty."
            )

        # 3. Executable binary magic bytes rejection
        if content_bytes.startswith(b"MZ"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Executable binary files (Windows PE) are strictly prohibited."
            )
        if content_bytes.startswith(b"\x7fELF"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Executable binary files (Linux ELF) are strictly prohibited."
            )
        if content_bytes.startswith((b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Executable binary files (Mach-O) are strictly prohibited."
            )

        # 4. Prohibited file extension rejection
        _, ext = os.path.splitext(filename.lower())
        if ext in BLOCKED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File extension '{ext}' is prohibited for email analysis."
            )

        # 5. Conservative RFC-822 syntax validation
        # Examine the first 16KB of text for standard email headers or valid parsed headers
        sample_bytes = content_bytes[:16384]
        if sample_bytes.startswith(b"\xef\xbb\xbf"):
            sample_bytes = sample_bytes[3:]
        sample = sample_bytes.decode("utf-8", errors="ignore").lstrip()
        has_rfc_header = any(pattern.search(sample) for pattern in RFC822_HEADER_TOKENS)

        # Also permit mbox format starting with "From "
        is_mbox = sample.startswith("From ")

        if not (has_rfc_header or is_mbox):
            # Fallback to standard Python email parser
            try:
                import email
                from email import policy
                parsed_msg = email.message_from_bytes(content_bytes[:16384], policy=policy.default)
                if parsed_msg and len(parsed_msg.keys()) > 0:
                    has_rfc_header = True
            except Exception:
                pass

        if not (has_rfc_header or is_mbox):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file does not appear to be a valid RFC-822 email format. Standard email headers were not detected."
            )

    @staticmethod
    async def read_bounded_upload(file, max_bytes=MAX_UPLOAD_SIZE_BYTES, chunk_size=65536):
        payload = bytearray()
        while True:
            chunk = await file.read(min(chunk_size, max_bytes - len(payload) + 1))
            if not chunk:
                return bytes(payload)
            payload.extend(chunk)
            if len(payload) > max_bytes:
                raise HTTPException(413, "Uploaded file exceeds the allowed size.")
