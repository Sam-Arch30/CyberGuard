export interface PESectionInfo {
  name: string;
  virtual_size: number;
  virtual_address: string;
  raw_size: number;
  entropy: number;
  characteristics: string;
  is_suspicious: boolean;
}

export interface PEImportInfo {
  dll: string;
  functions: string[];
}

export interface PEMetadata {
  is_pe: boolean;
  architecture?: string | null;
  compile_timestamp?: string | null;
  subsystem?: string | null;
  entry_point?: string | null;
  number_of_sections: number;
  sections: PESectionInfo[];
  imported_dlls: string[];
  imports: PEImportInfo[];
  suspicious_imports: string[];
  has_authenticode: boolean;
  signature_status: 'Signed' | 'Unsigned' | 'N/A';
  warnings: string[];
}

export interface PDFStaticMetadata {
  is_pdf: boolean;
  pdf_version?: string | null;
  has_javascript: boolean;
  javascript_snippets: string[];
  has_open_action: boolean;
  has_launch_action: boolean;
  has_embedded_files: boolean;
  embedded_file_names: string[];
  has_submit_form: boolean;
  has_external_uri: boolean;
  external_uris: string[];
  suspicious_elements: string[];
  metadata: Record<string, string>;
  warnings: string[];
}

export interface OfficeStaticMetadata {
  is_office: boolean;
  office_format?: string | null;
  has_macros: boolean;
  vba_project_present: boolean;
  macro_names: string[];
  has_external_relationships: boolean;
  external_relationships: string[];
  has_embedded_objects: boolean;
  suspicious_keywords: string[];
  metadata: Record<string, string>;
  warnings: string[];
}

export interface ArchiveEntryInfo {
  filename: string;
  uncompressed_size: number;
  compressed_size: number;
  is_encrypted: boolean;
  is_suspicious_extension: boolean;
  is_nested_archive: boolean;
  is_path_traversal: boolean;
}

export interface ArchiveStaticMetadata {
  is_archive: boolean;
  archive_type?: string | null;
  total_files: number;
  uncompressed_size: number;
  compression_ratio: number;
  is_encrypted: boolean;
  has_nested_archives: boolean;
  has_path_traversal: boolean;
  has_hidden_executables: boolean;
  suspicious_entries: string[];
  entries: ArchiveEntryInfo[];
  safety_violations: string[];
}

export interface AttachmentStaticAnalysisResult {
  original_filename: string;
  extension: string;
  claimed_type: string;
  mime_type: string;
  detected_mime_type: string;
  detected_type: string;
  magic_bytes_hex: string;
  size: number;
  extension_mismatch: boolean;
  mismatch_details?: string | null;
  double_extension: boolean;

  sha256: string;
  sha1: string;
  md5: string;

  entropy: number;
  entropy_level: 'low' | 'normal' | 'high' | 'very_high';
  entropy_analysis: string;

  signature_status: 'Signed' | 'Unsigned' | 'N/A';
  signer_info?: string | null;

  pe_metadata?: PEMetadata | null;
  pdf_metadata?: PDFStaticMetadata | null;
  office_metadata?: OfficeStaticMetadata | null;
  archive_metadata?: ArchiveStaticMetadata | null;

  embedded_urls: string[];
  embedded_domains: string[];
  embedded_ips: string[];
  embedded_hashes: string[];
  embedded_indicators_count: number;

  threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'BENIGN';
  threat_score: number;
  risk_signals: string[];
  analysis_summary: string;

  reputation_status: string;
  reputation_provider?: string | null;
  reputation_details?: string | null;

  evidence_id: string;
  integrity_status?: string;
  storage_guard?: string;
  timestamp: string;
}
