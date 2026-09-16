from typing import List, Dict, Any, Optional
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


class ArchiveEntryInfo(BaseModel):
    filename: str = Field(..., description="Path/filename of inner entry")
    uncompressed_size: int = Field(0, description="Uncompressed byte size")
    compressed_size: int = Field(0, description="Compressed byte size in archive")
    is_encrypted: bool = Field(False, description="True if entry is password-protected/encrypted")
    is_suspicious_extension: bool = Field(False, description="True if entry has executable/script extension")
    is_nested_archive: bool = Field(False, description="True if entry is itself an archive")
    is_path_traversal: bool = Field(False, description="True if entry attempts path traversal (e.g. ../)")


class ArchiveStaticMetadata(BaseModel):
    is_archive: bool = Field(True, description="True if file is a recognized archive (ZIP/RAR/7z)")
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


class AttachmentStaticAnalysisResult(BaseModel):
    """
    Comprehensive safe static malware analysis and forensic intelligence result for an email attachment.
    No code execution is ever performed.
    """
    # File identification
    original_filename: str = Field(..., description="Original filename of attachment")
    extension: str = Field(..., description="Normalized file extension including leading dot")
    claimed_type: str = Field("Unknown", description="Claimed file type inferred from filename or headers")
    mime_type: str = Field("application/octet-stream", description="MIME content type from email headers")
    detected_mime_type: str = Field("application/octet-stream", description="Forensically detected MIME type via magic bytes")
    detected_type: str = Field("Unknown binary", description="Forensically determined file category")
    magic_bytes_hex: str = Field("", description="First 16 bytes of payload represented in hex")
    size: int = Field(0, description="Raw attachment byte size")
    extension_mismatch: bool = Field(False, description="True if filename extension conflicts with magic byte signature")
    mismatch_details: Optional[str] = Field(None, description="Detailed explanation of detected mismatch")
    double_extension: bool = Field(False, description="True if filename utilizes disguised double extensions")

    # Cryptographic hashes
    sha256: str = Field(..., description="SHA-256 hash (primary forensic identifier)")
    sha1: str = Field(..., description="SHA-1 hash")
    md5: str = Field(..., description="MD5 hash")

    # Entropy
    entropy: float = Field(0.0, description="Shannon entropy (0.0 to 8.0)")
    entropy_level: str = Field("normal", description="Entropy categorization: low, normal, high, very_high")
    entropy_analysis: str = Field("", description="Forensic evaluation of entropy (high entropy alone != malware)")

    # Authenticode / Signature
    signature_status: str = Field("N/A", description="Authenticode status: Signed, Unsigned, or N/A")
    signer_info: Optional[str] = Field(None, description="Signer certificate summary if available")

    # Deep format inspection (only populated when relevant)
    pe_metadata: Optional[PEMetadata] = Field(None, description="Portable Executable binary header inspection")
    pdf_metadata: Optional[PDFStaticMetadata] = Field(None, description="Static PDF syntax and action analysis")
    office_metadata: Optional[OfficeStaticMetadata] = Field(None, description="Office document and macro analysis")
    archive_metadata: Optional[ArchiveStaticMetadata] = Field(None, description="Safe archive inspection and traversal")

    # Extracted embedded IOC indicators
    embedded_urls: List[str] = Field(default_factory=list, description="Extracted URLs found within attachment payload")
    embedded_domains: List[str] = Field(default_factory=list, description="Extracted domains found within attachment payload")
    embedded_ips: List[str] = Field(default_factory=list, description="Extracted IP addresses found within attachment payload")
    embedded_hashes: List[str] = Field(default_factory=list, description="Extracted or computed hashes")
    embedded_indicators_count: int = Field(0, description="Total count of unique embedded IOCs")

    # Threat Scoring & Risk Signals
    threat_level: str = Field("BENIGN", description="Categorical threat severity: CRITICAL, HIGH, MEDIUM, LOW, BENIGN")
    threat_score: int = Field(0, description="Deterministic attachment threat score (0 to 100)")
    risk_signals: List[str] = Field(default_factory=list, description="Specific explainable risk signals detected")
    analysis_summary: str = Field("", description="Executive forensic summary of static analysis findings")

    # Reputation
    reputation_status: str = Field("Reputation unavailable", description="Threat intel status or 'Reputation unavailable'")
    reputation_provider: Optional[str] = Field(None, description="External TI provider name if configured")
    reputation_details: Optional[str] = Field(None, description="Contextual reputation intelligence")

    # Evidence Chain of Custody
    evidence_id: str = Field(..., description="Forensic evidence token e.g. EVD-ATT-1A2B3C4D")
    integrity_status: str = Field("Verified Authentic", description="Chain of custody integrity verification")
    storage_guard: str = Field("Non-executable forensic vault - execution permissions stripped", description="Forensic storage policy")
    timestamp: str = Field(..., description="Forensic analysis timestamp in UTC")
