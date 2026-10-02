import io
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.upload_security import UploadSecurityService, MAX_UPLOAD_SIZE_BYTES
from backend.services.html_sanitizer import HTMLSanitizerService
from backend.services.ssrf_protector import SSRFProtector
from backend.services.log_sanitizer import sanitize_log_text, SensitiveLogFilter
from backend.api.middleware.rate_limiter import global_rate_limiter
import logging

client = TestClient(app)


# =====================================================================
# 1. Filename & Path Traversal Sanitization Tests
# =====================================================================

def test_malicious_filename_sanitization():
    """Verify path traversal sequences, null bytes, and malicious characters are sanitized."""
    cases = [
        ("../../../../etc/passwd", "passwd.eml"),
        ("..\\..\\windows\\system32\\cmd.exe", "cmd.exe"),
        ("payload.eml\x00.exe", "payload.eml.exe"),
        ("/root/.ssh/id_rsa", "id_rsa.eml"),
        ("normal_email.eml", "normal_email.eml"),
        ("", lambda res: res.startswith("upload_") and res.endswith(".eml")),
        ("a" * 300 + ".eml", lambda res: len(res) <= 128 and res.endswith(".eml")),
    ]

    for raw, expected in cases:
        sanitized = UploadSecurityService.sanitize_filename(raw)
        assert "/" not in sanitized
        assert "\\" not in sanitized
        assert "\x00" not in sanitized
        assert not sanitized.startswith("..")

        if callable(expected):
            assert expected(sanitized)
        else:
            assert sanitized == expected


# =====================================================================
# 2. Oversized Upload & Executable Binary Validation Tests
# =====================================================================

def test_oversized_upload_rejection():
    """Verify uploads exceeding size limit are rejected with HTTP 413."""
    # 11 MB payload (exceeds default 10 MB limit)
    oversized_data = b"From: test@example.com\r\nSubject: Test\r\n\r\n" + (b"X" * (MAX_UPLOAD_SIZE_BYTES + 1024))
    files = {"file": ("oversized.eml", io.BytesIO(oversized_data), "message/rfc822")}

    response = client.post("/api/emails/analyze", files=files)
    assert response.status_code == 413
    assert "exceeds maximum allowed size" in response.json()["detail"]


def test_prohibited_executable_upload_rejection():
    """Verify binary executables and blocked extensions are rejected with HTTP 400."""
    # 1. Windows PE executable (starts with MZ)
    exe_content = b"MZ\x90\x00\x03\x00\x00\x00"
    files_exe = {"file": ("malware.exe", io.BytesIO(exe_content), "application/octet-stream")}
    res_exe = client.post("/api/emails/analyze", files=files_exe)
    assert res_exe.status_code == 400
    assert "Executable" in res_exe.json()["detail"] or "prohibited" in res_exe.json()["detail"]

    # 2. Linux ELF executable (starts with \x7fELF)
    elf_content = b"\x7fELF\x02\x01\x01\x00"
    files_elf = {"file": ("malware.eml", io.BytesIO(elf_content), "message/rfc822")}
    res_elf = client.post("/api/emails/analyze", files=files_elf)
    assert res_elf.status_code == 400
    assert "Executable" in res_elf.json()["detail"]


def test_invalid_rfc822_rejection():
    """Verify non-email random data is rejected."""
    random_binary = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 50
    files = {"file": ("garbage.eml", io.BytesIO(random_binary), "message/rfc822")}
    res = client.post("/api/emails/analyze", files=files)
    assert res.status_code == 400
    assert "valid RFC-822 email format" in res.json()["detail"]


def test_valid_rfc822_with_utf8_bom():
    """Verify emails starting with UTF-8 BOM are accepted and parsed."""
    bom_eml = b"\xef\xbb\xbfFrom: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test BOM\r\n\r\nHello world"
    files = {"file": ("bom_email.eml", io.BytesIO(bom_eml), "message/rfc822")}
    res = client.post("/api/emails/analyze", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["subject"] == "Test BOM"


def test_valid_rfc822_with_modern_auth_headers_first():
    """Verify emails starting with Delivered-To, ARC, DKIM, or Received-SPF are accepted."""
    modern_eml = (
        b"Delivered-To: recipient@corp.com\r\n"
        b"Received-SPF: pass (google.com: domain of sender@example.com designates 1.2.3.4 as permitted sender)\r\n"
        b"Authentication-Results: mx.google.com; dkim=pass header.i=@example.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com\r\n"
        b"From: sender@example.com\r\n"
        b"To: recipient@corp.com\r\n"
        b"Subject: Modern Email Auth\r\n\r\n"
        b"Body content here"
    )
    files = {"file": ("auth_headers.eml", io.BytesIO(modern_eml), "message/rfc822")}
    res = client.post("/api/emails/analyze", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["subject"] == "Modern Email Auth"



# =====================================================================
# 3. HTML Sanitization & Script Injection Tests
# =====================================================================

def test_html_email_sanitization():
    """Verify active scripts, iframes, objects, forms, and event handlers are neutralized."""
    dirty_html = """
    <html>
      <head>
        <script>alert('malicious XSS');</script>
      </head>
      <body onload="alert('body onload')">
        <h1>Welcome</h1>
        <iframe src="http://attacker.com/steal-cookies"></iframe>
        <object data="http://attacker.com/exploit.swf"></object>
        <embed src="http://attacker.com/flash.swf">
        <form action="http://phish.com/login" method="POST">
          <input type="password" name="pwd">
          <button type="submit">Submit</button>
        </form>
        <a href="javascript:alert('link xss')">Click Here</a>
        <img src="https://tracker.com/pixel.png" onerror="alert('img onerror')">
      </body>
    </html>
    """
    clean_html = HTMLSanitizerService.sanitize_html(dirty_html, block_remote_images=True)

    # Assert dangerous elements are completely removed
    assert "<script" not in clean_html.lower()
    assert "</script>" not in clean_html.lower()
    assert "<iframe" not in clean_html.lower()
    assert "<object" not in clean_html.lower()
    assert "<embed" not in clean_html.lower()
    assert "<form" not in clean_html.lower()

    # Assert event handlers are stripped
    assert "onload" not in clean_html.lower()
    assert "onerror" not in clean_html.lower()

    # Assert javascript: link is neutralized
    assert "javascript:" not in clean_html.lower()

    # Assert remote image is neutralized
    assert 'data-blocked-src="https://tracker.com/pixel.png"' in clean_html


# =====================================================================
# 4. SSRF Protections Tests
# =====================================================================

def test_ssrf_protections_ip():
    """Verify private, loopback, and cloud metadata IPs are rejected."""
    blocked_ips = [
        "127.0.0.1",
        "127.0.0.2",
        "10.0.0.1",
        "172.16.0.5",
        "192.168.1.1",
        "169.254.169.254",  # AWS/Cloud metadata
        "0.0.0.0",
        "::1",
        "invalid-ip",
        "../../internal"
    ]
    for ip in blocked_ips:
        assert SSRFProtector.is_safe_public_ip(ip) is False

    # Routable public IPs should be allowed
    assert SSRFProtector.is_safe_public_ip("8.8.8.8") is True
    assert SSRFProtector.is_safe_public_ip("1.1.1.1") is True


def test_ssrf_protections_domain():
    """Verify internal hostnames, metadata services, and injection strings are blocked."""
    blocked_domains = [
        "localhost",
        "127.0.0.1",
        "metadata.google.internal",
        "instance-data",
        "server.local",
        "internal.corp",
        "http://attacker.com",
        "evil.com@127.0.0.1",
        "evil.com/path",
        "evil.com:8080",
        "../../etc/passwd"
    ]
    for dom in blocked_domains:
        assert SSRFProtector.is_safe_public_domain(dom) is False

    # Legitimate public domain names should be allowed
    assert SSRFProtector.is_safe_public_domain("google.com") is True
    assert SSRFProtector.is_safe_public_domain("sub.example.co.uk") is True


# =====================================================================
# 5. Security Headers Tests
# =====================================================================

def test_http_security_headers():
    """Verify defense-in-depth security headers are injected in all responses."""
    response = client.get("/health")
    assert response.status_code == 200

    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "Strict-Transport-Security" in headers
    assert "Referrer-Policy" in headers
    assert "Content-Security-Policy" in headers


# =====================================================================
# 6. Rate Limiting Tests
# =====================================================================

def test_rate_limiting_enforcement():
    """Verify requests beyond category threshold receive HTTP 429 Too Many Requests."""
    test_ip = "192.0.2.199"

    # Exhaust the upload_analysis bucket (limit 20)
    for _ in range(20):
        allowed, _ = global_rate_limiter.is_allowed(test_ip, "test_cat", max_requests=20, window_seconds=60.0)
        assert allowed is True

    # 21st request should be rejected
    allowed, remaining = global_rate_limiter.is_allowed(test_ip, "test_cat", max_requests=20, window_seconds=60.0)
    assert allowed is False
    assert remaining == 0


# =====================================================================
# 7. Secret Exposure & Logging Privacy Tests
# =====================================================================

def test_logging_sanitizer():
    """Verify secrets, passwords, Bearer tokens, and API keys are redacted from logs."""
    sample_log = "User logged in with password='MySecretPassword123' and Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    sanitized = sanitize_log_text(sample_log)

    assert "MySecretPassword123" not in sanitized
    assert "password=[REDACTED]" in sanitized
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
    assert "Authorization: [REDACTED]" in sanitized

    bearer_log = "Processing request with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 token"
    sanitized_bearer = sanitize_log_text(bearer_log)
    assert "Bearer [REDACTED]" in sanitized_bearer

    api_key_log = "Contacting LLM with api_key='AIzaSyD-1234567890ABCDEF' at url https://api.openai.com/v1?key=sk-1234567890"
    sanitized_key = sanitize_log_text(api_key_log)
    assert "AIzaSyD-1234567890ABCDEF" not in sanitized_key
    assert "sk-1234567890" not in sanitized_key
    assert "[REDACTED]" in sanitized_key
