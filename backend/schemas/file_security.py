"""
File Security and Static Malware Analysis Schemas (Section 8).
Provides standardized, explainable models for static file analysis,
document inspection, script heuristics, archive security, and hash reputation.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PESectionInfo(BaseModel):
    name: str = Field(..., description="Section header name e.g. .text, .data, .rsrc")
    virtual_size: int = Field(0, description="Virtual size of section in memory")
    virtual_address: str = Field("0x0", description="Virtual address hex offset")
    raw_size: int = Field(0, description="Size of raw data on disk")
    entropy: float = Field(0.0, description="Shannon entropy of the section bytes (0.0 to 8.0)")
    characteristics: str = Field("", description="Hex characteristics or permissions flags")
    is_suspicious: bool = Field(False, description="True if section name is unusual or entropy is abnormal")


class PEImportInfo(BaseModel):
    dll: str = Field(..., description="Imported dynamic link library name (e.g. KERNEL32.dll)")
    functions: List[str] = Field(default_factory=list, description="Imported API function names")


class PEMetadata(BaseModel):
    is_pe: bool = Field(True, description="True if file is a valid Portable Executable")
    architecture: Optional[str] = Field(None, description="Architecture: x86, x64 (AMD64), ARM64")
    compile_timestamp: Optional[str] = Field(None, description="COFF compile timestamp string")
    subsystem: Optional[str] = Field(None, description="PE subsystem: Windows GUI, Windows CUI, etc.")
    entry_point: Optional[str] = Field(None, description="Entry point RVA address")
    number_of_sections: int = Field(0, description="Total number of sections")
    sections: List[PESectionInfo] = Field(default_factory=list, description="Section headers")
    imported_dlls: List[str] = Field(default_factory=list, description="Names of imported libraries")
    imports: List[PEImportInfo] = Field(default_factory=list, description="Grouped DLL imports and functions")
    suspicious_imports: List[str] = Field(default_factory=list, description="High-risk API functions detected")
    has_authenticode: bool = Field(False, description="True if certificate table entry is present")
    signature_status: str = Field("Unsigned", description="Authenticode status: Signed, Unsigned, or N/A")
    warnings: List[str] = Field(default_factory=list, description="Parsing anomalies or security warnings")


class PDFStaticMetadata(BaseModel):
    is_pdf: bool = Field(True, description="True if file matches PDF header signature")
    pdf_version: Optional[str] = Field(None, description="PDF specification version e.g. 1.4, 1.7")
    has_javascript: bool = Field(False, description="True if /JavaScript or /JS objects are present")
    javascript_snippets: List[str] = Field(default_factory=list, description="Extracted harmless script snippets")
    has_open_action: bool = Field(False, description="True if /OpenAction or /AA auto-executes upon document open")
    has_launch_action: bool = Field(False, description="True if /Launch action triggers external programs")
    has_embedded_files: bool = Field(False, description="True if /EmbeddedFiles or /EF attachments exist inside PDF")
    embedded_file_names: List[str] = Field(default_factory=list, description="Names of embedded payload files")
    has_submit_form: bool = Field(False, description="True if /SubmitForm exfiltration action is present")
    has_external_uri: bool = Field(False, description="True if external /URI hyperlinks exist")
    external_uris: List[str] = Field(default_factory=list, description="Extracted hyperlinks from PDF dictionary")
    is_encrypted: bool = Field(False, description="True if /Encrypt dictionary exists")
    suspicious_elements: List[str] = Field(default_factory=list, description="Discovered high-risk PDF operators")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Document metadata: Title, Author, Producer, Creator")
    warnings: List[str] = Field(default_factory=list, description="PDF structure or malformed warnings")


class OfficeStaticMetadata(BaseModel):
    is_office: bool = Field(True, description="True if file is an Office OpenXML or OLE compound file")
    office_format: Optional[str] = Field(None, description="Format e.g. OpenXML (DOCX), Macro-Enabled (DOCM), OLE")
    has_macros: bool = Field(False, description="True if VBA macros or vbaProject.bin are detected")
    vba_project_present: bool = Field(False, description="True if vbaProject.bin is present in archive")
    macro_names: List[str] = Field(default_factory=list, description="Extracted macro project names or modules")
    has_external_relationships: bool = Field(False, description="True if external template injection relationships exist")
    external_relationships: List[str] = Field(default_factory=list, description="Target URLs of external relationships")
    has_embedded_objects: bool = Field(False, description="True if embedded OLE objects or binary packages exist")
    suspicious_keywords: List[str] = Field(default_factory=list, description="Discovered keywords: AutoOpen, Shell, Environ, etc.")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Office document properties e.g. creator, modified")
    warnings: List[str] = Field(default_factory=list, description="Office parsing warnings")


class ScriptStaticMetadata(BaseModel):
    is_script: bool = Field(True, description="True if file is an executable or shell script")
    script_type: str = Field(..., description="Script format: PowerShell, Bash/Shell, Batch, VBScript, JavaScript, Python")
    has_encoded_commands: bool = Field(False, description="True if base64 or encoded command executions detected")
    has_download_commands: bool = Field(False, description="True if remote payload downloader commands found")
    has_execution_chains: bool = Field(False, description="True if shell invocation chains detected (IEX, cmd /c, etc.)")
    has_credential_access: bool = Field(False, description="True if credential harvesting or LSASS dump keywords found")
    has_persistence_commands: bool = Field(False, description="True if registry run keys or scheduled tasks referenced")
    matched_patterns: List[str] = Field(default_factory=list, description="Catalog of matched suspicious static patterns")
    snippets: List[str] = Field(default_factory=list, description="Safe truncated code snippets illustrating findings")
    warnings: List[str] = Field(default_factory=list, description="Script parsing warnings")


class ArchiveEntryInfo(BaseModel):
    filename: str = Field(..., description="Path/filename of inner entry")
    uncompressed_size: int = Field(0, description="Uncompressed byte size")
    compressed_size: int = Field(0, description="Compressed byte size in archive")
    is_encrypted: bool = Field(False, description="True if entry is password-protected/encrypted")
    is_suspicious_extension: bool = Field(False, description="True if entry has executable/script extension")
    is_nested_archive: bool = Field(False, description="True if entry is itself an archive")
    is_path_traversal: bool = Field(False, description="True if entry attempts path traversal (e.g. ../)")


class ArchiveStaticMetadata(BaseModel):
    is_archive: bool = Field(True, description="True if file is a recognized archive (ZIP/TAR/GZ/7z/RAR)")
    archive_type: Optional[str] = Field("ZIP", description="Archive format")
    total_files: int = Field(0, description="Total entries enumerated safely")
    uncompressed_size: int = Field(0, description="Sum of uncompressed bytes across all entries")
    compression_ratio: float = Field(0.0, description="Ratio of uncompressed size to compressed size")
    is_encrypted: bool = Field(False, description="True if any entry is password-protected")
    has_nested_archives: bool = Field(False, description="True if nested zip/rar/tar archives are found")
    has_path_traversal: bool = Field(False, description="True if path traversal vulnerability detected")
    has_hidden_executables: bool = Field(False, description="True if archive packages dangerous executable payloads")
    suspicious_entries: List[str] = Field(default_factory=list, description="Flagged filenames inside archive")
    entries: List[ArchiveEntryInfo] = Field(default_factory=list, description="Enumerated entries within safety limits")
    safety_violations: List[str] = Field(default_factory=list, description="Safety guard violations (bomb, traversal, etc.)")


class ImageStaticMetadata(BaseModel):
    is_image: bool = Field(True, description="True if file is a supported image")
    image_format: str = Field(..., description="Image format: PNG, JPEG, GIF, WEBP, BMP, TIFF")
    width: Optional[int] = Field(None, description="Width in pixels")
    height: Optional[int] = Field(None, description="Height in pixels")
    color_mode: Optional[str] = Field(None, description="Color mode: RGB, RGBA, L, CMYK")
    has_exif: bool = Field(False, description="True if EXIF metadata headers exist")
    exif_fields: Dict[str, str] = Field(default_factory=dict, description="Safe observable EXIF properties")
    warnings: List[str] = Field(default_factory=list, description="Image inspection warnings")


class FileIdentityInfo(BaseModel):
    sha256: str = Field(..., description="Primary SHA-256 cryptographic identity hash")
    sha1: str = Field(..., description="SHA-1 hash for interoperability")
    md5: str = Field(..., description="MD5 hash for legacy IOC matching")
    size_bytes: int = Field(..., description="Exact byte size of file")
    original_filename: str = Field(..., description="Original raw filename submitted")
    safe_display_name: str = Field(..., description="Sanitized, path-safe, non-executable display name")
    claimed_extension: str = Field(..., description="Extension inferred from filename")
    reported_mime: Optional[str] = Field(None, description="Client-reported Content-Type")
    detected_mime: str = Field(..., description="Deterministically detected MIME type from magic bytes")
    detected_file_type: str = Field(..., description="Human-readable detected file type description")
    is_polyglot: bool = Field(False, description="True if file contains valid overlapping format headers")


class FilenameSecurityInfo(BaseModel):
    is_double_extension: bool = Field(False, description="True if filename uses double extension evasion (e.g. .pdf.exe)")
    is_deceptive: bool = Field(False, description="True if filename contains misleading spacing or extension chains")
    has_unicode_deception: bool = Field(False, description="True if Right-To-Left Override or invisible control characters exist")
    detected_control_characters: List[str] = Field(default_factory=list, description="List of suspicious Unicode codepoints detected")
    signals: List[str] = Field(default_factory=list, description="Filename security anomalies and explanations")


class EntropyEvaluation(BaseModel):
    entropy: float = Field(..., description="Shannon entropy from 0.00 to 8.00")
    level: str = Field(..., description="Entropy tier: low, normal, high, very_high")
    description: str = Field(..., description="Explainable description of entropy level")
    is_high_entropy: bool = Field(False, description="True if entropy exceeds 7.2")


class ThreatIntelHashInfo(BaseModel):
    provider: str = Field(..., description="Threat intelligence provider name")
    sha256_queried: str = Field(..., description="SHA-256 queried")
    verdict: str = Field(..., description="Verdict: MALICIOUS, SUSPICIOUS, UNKNOWN, RATE_LIMITED")
    is_malicious: bool = Field(False, description="True if provider explicitly classifies hash as malicious")
    threat_types: List[str] = Field(default_factory=list, description="Associated malware families or tags")
    confidence: float = Field(0.0, description="Provider confidence score")
    details: Optional[str] = Field(None, description="Provider details or explanation")
    retrieved_at: str = Field(..., description="Timestamp of lookup")


class DerivedChildArtifact(BaseModel):
    artifact_id: str = Field(..., description="UUID of derived child artifact")
    name: str = Field(..., description="Sanitized filename of child artifact")
    artifact_type: str = Field(..., description="Artifact type (FILE, ATTACHMENT, URL)")
    mime_type: Optional[str] = Field(None, description="Detected MIME type")
    size_bytes: int = Field(0, description="Byte size of child artifact")
    sha256: str = Field(..., description="SHA-256 hash of child content")
    source: str = Field(..., description="Extraction source (e.g. ARCHIVE_EXTRACTION, PDF_EMBEDDED)")
    relationship_type: str = Field("CONTAINS", description="Knowledge graph relationship type")


class FileSecurityAnalysisResponse(BaseModel):
    """Canonical unified response model for Section 8 File Security Analyzer."""
    artifact_id: str = Field(..., description="Durable Artifact UUID")
    analysis_run_id: str = Field(..., description="AnalysisRun execution UUID")
    pipeline_version: str = Field("2.0.0", description="Analyzer pipeline version")
    classification: str = Field(..., description="Classification: KNOWN_MALICIOUS, MALWARE_SUSPECTED, SUSPICIOUS, BENIGN_LIKELY, UNKNOWN")
    risk_score: float = Field(..., description="Calculated threat score (0.0 - 100.0)")
    severity: str = Field(..., description="Overall severity: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(..., description="Confidence score (0.0 - 1.0)")
    summary: str = Field(..., description="Executive analytical summary")
    
    # Core Components
    identity: FileIdentityInfo = Field(..., description="Cryptographic identity and format verification")
    filename_analysis: FilenameSecurityInfo = Field(..., description="Filename deception and extension analysis")
    entropy: EntropyEvaluation = Field(..., description="Shannon entropy evaluation")
    
    # Format-Specific Metadata
    pe_metadata: Optional[PEMetadata] = Field(None, description="PE executable static metadata if applicable")
    pdf_metadata: Optional[PDFStaticMetadata] = Field(None, description="PDF static metadata if applicable")
    office_metadata: Optional[OfficeStaticMetadata] = Field(None, description="Office document static metadata if applicable")
    script_metadata: Optional[ScriptStaticMetadata] = Field(None, description="Script static metadata if applicable")
    archive_metadata: Optional[ArchiveStaticMetadata] = Field(None, description="Archive inspection metadata if applicable")
    image_metadata: Optional[ImageStaticMetadata] = Field(None, description="Image container metadata if applicable")
    
    # Intelligence & Observables
    reputation: ThreatIntelHashInfo = Field(..., description="Threat intelligence hash reputation lookup")
    extracted_urls: List[str] = Field(default_factory=list, description="Discovered URLs")
    extracted_domains: List[str] = Field(default_factory=list, description="Discovered domain names")
    extracted_ips: List[str] = Field(default_factory=list, description="Discovered IP addresses")
    extracted_emails: List[str] = Field(default_factory=list, description="Discovered email addresses")
    extracted_hashes: List[str] = Field(default_factory=list, description="Discovered file hashes")
    
    # Graph & Hierarchy
    derived_artifacts: List[DerivedChildArtifact] = Field(default_factory=list, description="Child artifacts extracted from archive/doc")
    findings_count: int = Field(0, description="Total normalized findings persisted")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="List of persisted analytical findings")
    indicators_count: int = Field(0, description="Total indicators registered")
    relationships_count: int = Field(0, description="Total knowledge graph edges registered")
    
    # Timing & Status
    status: str = Field("COMPLETED", description="Analysis status")
    created_at: str = Field(..., description="ISO-8601 execution timestamp")


class FileSecurityConfigResponse(BaseModel):
    max_file_size_bytes: int
    max_archive_uncompressed_bytes: int
    max_archive_entries: int
    max_archive_depth: int
    max_compression_ratio: float
    max_extracted_strings: int
    threat_intel_provider: str
    reputation_cache_ttl_seconds: int
    supported_formats: Dict[str, Dict[str, bool]]
