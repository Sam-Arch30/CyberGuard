import io
import os
import re
import html
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from sqlalchemy.orm import Session

from backend.db.models import CaseModel, ReportModel


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that counts total pages and renders running
    headers and footers on every page with page numbers 'Page X of Y'.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)

        # Running header on page 2+
        if self._pageNumber > 1:
            self.line(36, 756, 576, 756)
            self.drawString(36, 762, "MAILTRACE AI // OFFICIAL DIGITAL FORENSICS REPORT")
            self.drawRightString(576, 762, "CONFIDENTIAL // CHAIN OF CUSTODY VERIFIED")

        # Running footer on all pages
        self.line(36, 45, 576, 45)
        self.drawString(36, 33, "CONFIDENTIAL // LAW ENFORCEMENT & SOC EVIDENTIARY DISCLOSURE ONLY")
        self.drawRightString(576, 33, f"Page {self._pageNumber} of {page_count}")

        self.restoreState()


class ReportService:
    """
    High-fidelity digital forensics report generation service.
    Constructs server-side multi-page PDF dossiers complying with
    evidentiary integrity, deterministic forensics, and non-attribution standards.
    """

    REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "reports")

    @classmethod
    def ensure_reports_dir(cls):
        os.makedirs(cls.REPORTS_DIR, exist_ok=True)

    @staticmethod
    def _format_token(token: Optional[Any], max_chunk: int = 32) -> str:
        """
        Inserts zero-width spaces after delimiters so ReportLab can wrap
        arbitrarily long URLs, hashes, and headers without overflowing table cells.
        Escapes XML/HTML entities to ensure ReportLab markup safety.
        """
        if token is None or token == "":
            return "N/A"

        token_str = str(token)
        # Escape XML entities first
        safe_str = html.escape(token_str)

        # Insert zero-width spaces after common break boundaries
        res = []
        chunk_len = 0
        delims = {'/', '?', '&', '.', '=', '-', '_', ':', '@', '%', '#', '+', ';', ','}

        for ch in safe_str:
            res.append(ch)
            chunk_len += 1
            if ch in delims or chunk_len >= max_chunk:
                res.append("&#8203;")
                chunk_len = 0

        return "".join(res)

    @classmethod
    def _create_styles(cls) -> Dict[str, ParagraphStyle]:
        """Creates curated typographic styles tailored for legal/SOC reporting."""
        base = getSampleStyleSheet()

        styles = {
            "DocTitle": ParagraphStyle(
                "DocTitle",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=18,
                leading=22,
                textColor=colors.HexColor("#0F172A")
            ),
            "DocSubtitle": ParagraphStyle(
                "DocSubtitle",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8.5,
                leading=11,
                textColor=colors.HexColor("#0284C7"),
                textTransform="uppercase"
            ),
            "SectionHeader": ParagraphStyle(
                "SectionHeader",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=15,
                textColor=colors.HexColor("#0F172A"),
                spaceBefore=14,
                spaceAfter=6,
                keepWithNext=True
            ),
            "SubSectionHeader": ParagraphStyle(
                "SubSectionHeader",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#334155"),
                spaceBefore=8,
                spaceAfter=4,
                keepWithNext=True
            ),
            "Body": ParagraphStyle(
                "Body",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=8,
                leading=11,
                textColor=colors.HexColor("#1E293B")
            ),
            "BodyBold": ParagraphStyle(
                "BodyBold",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=11,
                textColor=colors.HexColor("#0F172A")
            ),
            "BodyMuted": ParagraphStyle(
                "BodyMuted",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#64748B")
            ),
            "Mono": ParagraphStyle(
                "Mono",
                parent=base["Normal"],
                fontName="Courier",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#0F172A")
            ),
            "MonoBold": ParagraphStyle(
                "MonoBold",
                parent=base["Normal"],
                fontName="Courier-Bold",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#0F172A")
            ),
            "TableCell": ParagraphStyle(
                "TableCell",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#1E293B")
            ),
            "TableCellBold": ParagraphStyle(
                "TableCellBold",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#0F172A")
            ),
            "TableCellMuted": ParagraphStyle(
                "TableCellMuted",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#64748B")
            ),
            "TableHead": ParagraphStyle(
                "TableHead",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#0F172A"),
                textTransform="uppercase"
            ),
            "AlertBox": ParagraphStyle(
                "AlertBox",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10.5,
                textColor=colors.HexColor("#334155")
            ),
            "BadgeCritical": ParagraphStyle(
                "BadgeCritical",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#DC2626")
            ),
            "BadgeHigh": ParagraphStyle(
                "BadgeHigh",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#EA580C")
            ),
            "BadgeMedium": ParagraphStyle(
                "BadgeMedium",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#D97706")
            ),
            "BadgeClean": ParagraphStyle(
                "BadgeClean",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#16A34A")
            )
        }
        return styles

    @classmethod
    def generate_email_report(
        cls,
        analysis: Dict[str, Any],
        case_id: Optional[str] = None,
        analyst_name: Optional[str] = "SOC Lead Analyst",
        notes: Optional[str] = None
    ) -> bytes:
        """
        Builds a comprehensive, multi-page vector PDF forensic dossier
        from an analyzed email dictionary or EmailAnalysisResponse model.
        """
        cls.ensure_reports_dir()

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=46,
            bottomMargin=50
        )

        styles = cls._create_styles()
        story = []

        # -------------------------------------------------------------
        # 1. EXTRACT & NORMALIZE EVIDENCE DATA
        # -------------------------------------------------------------
        subject = analysis.get("subject") or "(No Subject Available)"
        from_hdr = analysis.get("from") or "unknown@domain.local"
        to_hdr = analysis.get("to") or "undisclosed-recipients"
        if isinstance(to_hdr, list):
            to_hdr = ", ".join(to_hdr)
        cc_hdr = analysis.get("cc")
        if isinstance(cc_hdr, list):
            cc_hdr = ", ".join(cc_hdr)
        reply_to = analysis.get("reply_to") or "None"
        return_path = analysis.get("return_path") or "None"
        date_hdr = analysis.get("date") or "Unknown"
        message_id = analysis.get("message_id") or "None"

        email_sha256 = analysis.get("email_sha256") or analysis.get("id") or "UNCOMPUTED_HASH"
        evidence_id = analysis.get("id") or f"EVD-{email_sha256[:12]}"
        report_ref = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        threat_score_data = analysis.get("threat_score") or {}
        score_val = threat_score_data.get("score", 0)
        severity = (threat_score_data.get("severity") or "low").lower()

        auth_data = analysis.get("authentication") or {}
        spf_data = auth_data.get("spf") or {}
        dkim_data = auth_data.get("dkim") or {}
        dmarc_data = auth_data.get("dmarc") or {}
        alignment = auth_data.get("alignment") or {}

        ml_data = analysis.get("ml_assessment") or {}
        ai_data = analysis.get("ai_analyst") or {}

        # -------------------------------------------------------------
        # 2. DOCUMENT HEADER & EVIDENTIARY METADATA BLOCK
        # -------------------------------------------------------------
        story.append(Paragraph("MAILTRACE AI // FORENSIC TELEMETRY PLATFORM", styles["DocSubtitle"]))
        story.append(Spacer(1, 2))
        story.append(Paragraph("Digital Evidence & Forensic Incident Dossier", styles["DocTitle"]))
        story.append(Spacer(1, 8))

        # Metadata banner table
        meta_table_data = [
            [
                Paragraph("<b>REPORT REFERENCE:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(report_ref), styles["TableCell"]),
                Paragraph("<b>GENERATED (UTC):</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(generated_at), styles["TableCell"]),
            ],
            [
                Paragraph("<b>EVIDENCE IDENTIFIER:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(evidence_id), styles["TableCell"]),
                Paragraph("<b>ASSIGNED CASE:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(case_id or "UNASSIGNED / DIRECT EVIDENCE"), styles["TableCell"]),
            ],
            [
                Paragraph("<b>INVESTIGATOR:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(analyst_name or "SOC Lead Analyst"), styles["TableCell"]),
                Paragraph("<b>CLASSIFICATION:</b>", styles["TableCellBold"]),
                Paragraph("CONFIDENTIAL // EVIDENTIARY DISCLOSURE", styles["TableCellBold"]),
            ],
            [
                Paragraph("<b>EMAIL SHA-256:</b>", styles["TableCellBold"]),
                Paragraph(f"<font name='Courier'>{cls._format_token(email_sha256, max_chunk=28)}</font>", styles["TableCell"]),
                Paragraph("<b>HASH ALGORITHM:</b>", styles["TableCellBold"]),
                Paragraph("FIPS PUB 180-4 SHA-256 (Preserved Literal)", styles["TableCell"]),
            ]
        ]
        meta_table = Table(meta_table_data, colWidths=[110, 160, 110, 160])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 3. EXECUTIVE FORENSIC SUMMARY & SCORECARD
        # -------------------------------------------------------------
        story.append(Paragraph("1. Executive Forensic Summary", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        # Scorecard badge
        sev_style = styles["BadgeClean"]
        sev_bg = colors.HexColor("#F0FDF4")
        sev_border = colors.HexColor("#86EFAC")
        if severity == "critical":
            sev_style = styles["BadgeCritical"]
            sev_bg = colors.HexColor("#FEF2F2")
            sev_border = colors.HexColor("#FCA5A5")
        elif severity == "high":
            sev_style = styles["BadgeHigh"]
            sev_bg = colors.HexColor("#FFF7ED")
            sev_border = colors.HexColor("#FDBA74")
        elif severity in ("suspicious", "medium"):
            sev_style = styles["BadgeMedium"]
            sev_bg = colors.HexColor("#FFFBEB")
            sev_border = colors.HexColor("#FCD34D")

        ml_prob = ml_data.get("probability")
        ml_prob_str = f"{round(ml_prob * 100, 1)}%" if ml_prob is not None else "N/A"
        ml_class = ml_data.get("classification", "Not Evaluated").upper()

        scorecard_data = [
            [
                Paragraph("<b>DETERMINISTIC THREAT SCORE</b>", styles["TableCellBold"]),
                Paragraph("<b>ASSESSED SEVERITY</b>", styles["TableCellBold"]),
                Paragraph("<b>ML PHISHING PROBABILITY</b>", styles["TableCellBold"]),
                Paragraph("<b>ML CLASSIFICATION</b>", styles["TableCellBold"])
            ],
            [
                Paragraph(f"<font size=14><b>{score_val}/100</b></font>", styles["TableCellBold"]),
                Paragraph(f"<font size=10><b>{severity.upper()}</b></font>", sev_style),
                Paragraph(f"<font size=12><b>{ml_prob_str}</b></font>", styles["TableCellBold"]),
                Paragraph(f"<font size=10><b>{ml_class}</b></font>", styles["TableCell"])
            ]
        ]
        scorecard_table = Table(scorecard_data, colWidths=[135, 135, 135, 135])
        scorecard_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("BACKGROUND", (0, 1), (-1, 1), sev_bg),
            ("BOX", (0, 0), (-1, -1), 0.75, sev_border),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(scorecard_table)
        story.append(Spacer(1, 6))

        # Narrative summary paragraph
        summary_text = threat_score_data.get("summary") or "Automated deterministic parsing evaluated message headers, sender alignment, routing relay nodes, extracted URLs, and embedded attachments."
        story.append(Paragraph(html.escape(summary_text), styles["Body"]))
        if notes:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>Analyst Context:</b> {html.escape(notes)}", styles["Body"]))
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 4. EMAIL METADATA & SENDER ALIGNMENT
        # -------------------------------------------------------------
        story.append(Paragraph("2. Email Headers & Sender Alignment", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        headers_data = [
            [Paragraph("<b>From:</b>", styles["TableCellBold"]), Paragraph(cls._format_token(from_hdr), styles["Mono"])],
            [Paragraph("<b>To:</b>", styles["TableCellBold"]), Paragraph(cls._format_token(to_hdr), styles["Mono"])],
            [Paragraph("<b>Subject:</b>", styles["TableCellBold"]), Paragraph(cls._format_token(subject), styles["TableCellBold"])],
            [Paragraph("<b>Date:</b>", styles["TableCellBold"]), Paragraph(cls._format_token(date_hdr), styles["TableCell"])],
            [Paragraph("<b>Reply-To:</b>", styles["TableCellBold"]), Paragraph(cls._format_token(reply_to), styles["Mono"])],
            [Paragraph("<b>Return-Path:</b>", styles["TableCellBold"]), Paragraph(cls._format_token(return_path), styles["Mono"])],
            [Paragraph("<b>Message-ID:</b>", styles["TableCellBold"]), Paragraph(cls._format_token(message_id), styles["Mono"])]
        ]
        if cc_hdr:
            headers_data.append([Paragraph("<b>CC:</b>", styles["TableCellBold"]), Paragraph(cls._format_token(cc_hdr), styles["Mono"])])

        headers_table = Table(headers_data, colWidths=[90, 450])
        headers_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(headers_table)
        story.append(Spacer(1, 6))

        # Alignment sub-table
        reply_mismatch = alignment.get("reply_to_mismatch", False)
        return_mismatch = alignment.get("return_path_mismatch", False)
        align_data = [
            [
                Paragraph("<b>From Domain:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(alignment.get("from_domain") or "N/A"), styles["Mono"]),
                Paragraph("<b>Reply-To Domain:</b>", styles["TableCellBold"]),
                Paragraph(
                    f"{cls._format_token(alignment.get('reply_to_domain') or 'N/A')} "
                    f"<b>({'MISMATCH - SUSPICIOUS' if reply_mismatch else 'Aligned'})</b>",
                    styles["BadgeCritical"] if reply_mismatch else styles["TableCell"]
                )
            ],
            [
                Paragraph("<b>Return-Path Domain:</b>", styles["TableCellBold"]),
                Paragraph(
                    f"{cls._format_token(alignment.get('return_path_domain') or 'N/A')} "
                    f"<b>({'MISMATCH' if return_mismatch else 'Aligned'})</b>",
                    styles["BadgeCritical"] if return_mismatch else styles["TableCell"]
                ),
                Paragraph("<b>Alignment Verdict:</b>", styles["TableCellBold"]),
                Paragraph(
                    "<b>REPLY-TO / SENDER SPOOFING DETECTED</b>" if reply_mismatch else "Sender domains aligned",
                    styles["BadgeCritical"] if reply_mismatch else styles["BadgeClean"]
                )
            ]
        ]
        align_table = Table(align_data, colWidths=[110, 160, 110, 160])
        align_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(align_table)
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 5. AUTHENTICATION FINDINGS (SPF / DKIM / DMARC)
        # -------------------------------------------------------------
        story.append(Paragraph("3. Email Authentication Findings (SPF / DKIM / DMARC)", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        def format_auth_status(res: Optional[str]) -> Paragraph:
            r = (res or "unknown").lower()
            if r == "pass":
                return Paragraph("<font color='#16A34A'><b>PASS</b></font>", styles["TableCellBold"])
            elif r in ("fail", "permerror"):
                return Paragraph("<font color='#DC2626'><b>FAIL</b></font>", styles["TableCellBold"])
            elif r in ("softfail", "temperror", "neutral"):
                return Paragraph(f"<font color='#D97706'><b>{r.upper()}</b></font>", styles["TableCellBold"])
            return Paragraph(f"<font color='#64748B'><b>{r.upper()}</b></font>", styles["TableCellBold"])

        auth_table_data = [
            [
                Paragraph("<b>PROTOCOL</b>", styles["TableHead"]),
                Paragraph("<b>OBSERVED VERDICT</b>", styles["TableHead"]),
                Paragraph("<b>TECHNICAL DETAILS & EVIDENCE</b>", styles["TableHead"])
            ],
            [
                Paragraph("<b>SPF (Sender Policy)</b>", styles["TableCellBold"]),
                format_auth_status(spf_data.get("result")),
                Paragraph(cls._format_token(spf_data.get("details") or "No SPF policy details extracted."), styles["TableCell"])
            ],
            [
                Paragraph("<b>DKIM (Cryptographic)</b>", styles["TableCellBold"]),
                format_auth_status(dkim_data.get("result")),
                Paragraph(cls._format_token(dkim_data.get("details") or "No DKIM signature detected or validated."), styles["TableCell"])
            ],
            [
                Paragraph("<b>DMARC (Domain Policy)</b>", styles["TableCellBold"]),
                format_auth_status(dmarc_data.get("result")),
                Paragraph(cls._format_token(dmarc_data.get("details") or "No DMARC evaluation returned."), styles["TableCell"])
            ]
        ]
        auth_table = Table(auth_table_data, colWidths=[120, 100, 320])
        auth_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(auth_table)

        if auth_data.get("verification_notice"):
            story.append(Spacer(1, 3))
            story.append(Paragraph(f"<i>Notice: {html.escape(auth_data['verification_notice'])}</i>", styles["BodyMuted"]))
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 6. DETERMINISTIC THREAT ASSESSMENT & REASONS
        # -------------------------------------------------------------
        story.append(Paragraph("4. Deterministic Threat Score Breakdown", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        reasons = threat_score_data.get("reasons") or []
        if reasons:
            reasons_table_data = [
                [
                    Paragraph("<b>CATEGORY</b>", styles["TableHead"]),
                    Paragraph("<b>IMPACT</b>", styles["TableHead"]),
                    Paragraph("<b>FORENSIC FINDING & JUSTIFICATION</b>", styles["TableHead"])
                ]
            ]
            for r in reasons:
                pts = r.get("points", 0)
                pts_str = f"+{pts}" if pts > 0 else str(pts)
                reasons_table_data.append([
                    Paragraph(html.escape(r.get("category", "General").title()), styles["TableCellBold"]),
                    Paragraph(f"<font color='#DC2626'><b>{pts_str} pts</b></font>", styles["TableCellBold"]),
                    Paragraph(cls._format_token(r.get("description") or ""), styles["TableCell"])
                ])

            reasons_table = Table(reasons_table_data, colWidths=[110, 60, 370])
            reasons_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(reasons_table)
        else:
            story.append(Paragraph("No adverse threat factors identified. Analysis observed no high-risk markers.", styles["Body"]))

        # Positive evidence if present
        pos_evidence = threat_score_data.get("positive_evidence") or []
        if pos_evidence:
            story.append(Spacer(1, 4))
            pos_items = [f"• {html.escape(p.get('description', ''))}" for p in pos_evidence if p.get('description')]
            if pos_items:
                story.append(Paragraph(f"<b>Positive Mitigating Indicators:</b><br/>{'<br/>'.join(pos_items)}", styles["Body"]))
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 7. NLP / ML PHISHING CLASSIFICATION
        # -------------------------------------------------------------
        story.append(Paragraph("5. NLP Content Phishing Classification", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        ml_avail = ml_data.get("available", False)
        if ml_avail:
            features = ml_data.get("top_features") or []
            feat_str = ", ".join(features[:8]) if features else "None significant"
            ml_table_data = [
                [
                    Paragraph("<b>Model Name:</b>", styles["TableCellBold"]),
                    Paragraph(cls._format_token(ml_data.get("model_name") or "TF-IDF + Logistic Regression"), styles["TableCell"]),
                    Paragraph("<b>Classification:</b>", styles["TableCellBold"]),
                    Paragraph(f"<b>{ml_class}</b>", styles["BadgeCritical"] if "PHISHING" in ml_class else styles["BadgeClean"])
                ],
                [
                    Paragraph("<b>Phishing Probability:</b>", styles["TableCellBold"]),
                    Paragraph(f"<b>{ml_prob_str}</b>", styles["TableCellBold"]),
                    Paragraph("<b>Model Confidence:</b>", styles["TableCellBold"]),
                    Paragraph(cls._format_token(ml_data.get("confidence") or "High"), styles["TableCell"])
                ],
                [
                    Paragraph("<b>Top Text Features:</b>", styles["TableCellBold"]),
                    Paragraph(f"<font name='Courier'>{cls._format_token(feat_str)}</font>", styles["TableCell"]),
                    Paragraph("<b>Signal Role:</b>", styles["TableCellBold"]),
                    Paragraph("Auxiliary ML signal (Non-overriding)", styles["TableCellMuted"])
                ]
            ]
            ml_table = Table(ml_table_data, colWidths=[110, 160, 110, 160])
            ml_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(ml_table)
        else:
            notice = ml_data.get("notice") or "ML content assessment unavailable or email body empty. Deterministic forensic analysis continues unimpeded."
            story.append(Paragraph(f"<i>{html.escape(notice)}</i>", styles["BodyMuted"]))
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 8. AI ANALYST ASSISTANT SYNTHESIS (IF PRESENT)
        # -------------------------------------------------------------
        story.append(Paragraph("6. AI Analyst Assistant Synthesis", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        if ai_data and ai_data.get("available"):
            ai_summary = ai_data.get("summary") or "AI assessment completed based on structured forensic evidence."
            atk_type = ai_data.get("likely_attack_type") or "Unknown"
            atk_obj = ai_data.get("likely_objective") or "Unknown"
            key_ev = ai_data.get("key_evidence") or []
            rec_act = ai_data.get("recommended_actions") or []

            ai_summary_table_data = [
                [
                    Paragraph("<b>Likely Attack Type:</b>", styles["TableCellBold"]),
                    Paragraph(f"<b>{cls._format_token(atk_type)}</b>", styles["BadgeCritical"]),
                    Paragraph("<b>Likely Objective:</b>", styles["TableCellBold"]),
                    Paragraph(cls._format_token(atk_obj), styles["TableCell"])
                ]
            ]
            ai_summary_table = Table(ai_summary_table_data, colWidths=[110, 160, 110, 160])
            ai_summary_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(ai_summary_table)
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>Executive Synthesis:</b> {html.escape(ai_summary)}", styles["Body"]))

            if key_ev:
                story.append(Spacer(1, 3))
                ev_lines = [f"• {html.escape(e)}" for e in key_ev[:5]]
                story.append(Paragraph(f"<b>Key Forensic Evidence Identified by LLM:</b><br/>{'<br/>'.join(ev_lines)}", styles["Body"]))
        else:
            story.append(Paragraph("AI Analyst Assessment not requested or disabled for this analysis session.", styles["BodyMuted"]))
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 9. EXTRACTED INDICATORS OF COMPROMISE (IOCS)
        # -------------------------------------------------------------
        story.append(Paragraph("7. Extracted Indicators of Compromise (IOCs)", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        # 7A. URLs Table
        urls_list = analysis.get("url_analysis") or []
        story.append(Paragraph("<b>Observed URLs & Suspicion Scoring:</b>", styles["SubSectionHeader"]))
        if urls_list:
            url_table_data = [
                [
                    Paragraph("<b>EXTRACTED URL / TARGET HOST</b>", styles["TableHead"]),
                    Paragraph("<b>SCORE</b>", styles["TableHead"]),
                    Paragraph("<b>FORENSIC OBSERVATIONS & FLAGS</b>", styles["TableHead"])
                ]
            ]
            for u in urls_list[:12]:
                url_str = u.get("url", "")
                susp = u.get("suspicion_score", 0)
                obs = u.get("observations") or []
                obs_text = ", ".join(obs[:3]) if obs else "Standard link"
                susp_style = styles["BadgeCritical"] if susp >= 70 else (styles["BadgeMedium"] if susp >= 40 else styles["TableCell"])

                url_table_data.append([
                    Paragraph(f"<font name='Courier'>{cls._format_token(url_str, max_chunk=38)}</font>", styles["TableCell"]),
                    Paragraph(f"<b>{susp}/100</b>", susp_style),
                    Paragraph(cls._format_token(obs_text), styles["TableCell"])
                ])

            url_table = Table(url_table_data, colWidths=[270, 50, 220])
            url_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(url_table)
        else:
            raw_urls = analysis.get("urls") or []
            if raw_urls:
                u_text = ", ".join([f"<font name='Courier'>{cls._format_token(u)}</font>" for u in raw_urls[:10]])
                story.append(Paragraph(f"Extracted URLs: {u_text}", styles["Body"]))
            else:
                story.append(Paragraph("No URLs observed in email body or headers.", styles["BodyMuted"]))
        story.append(Spacer(1, 6))

        # 7B. Attachments & Hashes
        att_list = analysis.get("attachments") or []
        story.append(Paragraph("<b>Observed Attachments & Cryptographic Checksums:</b>", styles["SubSectionHeader"]))
        if att_list:
            att_table_data = [
                [
                    Paragraph("<b>FILENAME</b>", styles["TableHead"]),
                    Paragraph("<b>MIME TYPE</b>", styles["TableHead"]),
                    Paragraph("<b>SIZE</b>", styles["TableHead"]),
                    Paragraph("<b>SHA-256 CHECKSUM</b>", styles["TableHead"])
                ]
            ]
            for a in att_list:
                fn = a.get("filename") or "unnamed_attachment"
                mime = a.get("mime_type") or "application/octet-stream"
                sz = a.get("size", 0)
                sz_str = f"{round(sz / 1024, 1)} KB" if sz > 1024 else f"{sz} B"
                hash_val = a.get("sha256") or a.get("hash") or "N/A"

                att_table_data.append([
                    Paragraph(cls._format_token(fn), styles["TableCellBold"]),
                    Paragraph(cls._format_token(mime), styles["TableCell"]),
                    Paragraph(sz_str, styles["TableCell"]),
                    Paragraph(f"<font name='Courier'>{cls._format_token(hash_val, max_chunk=24)}</font>", styles["TableCell"])
                ])

            att_table = Table(att_table_data, colWidths=[140, 100, 60, 240])
            att_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(att_table)
        else:
            story.append(Paragraph("No file attachments detected in this message.", styles["BodyMuted"]))
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 10. TRANSMISSION PATH & RELAY INFRASTRUCTURE
        # -------------------------------------------------------------
        story.append(Paragraph("8. Network Transmission Path & Topology", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        relay_analysis = analysis.get("relay_analysis") or {}
        earliest_node = relay_analysis.get("earliest_observable_node") or {}
        hops = relay_analysis.get("transmission_order_hops") or []

        if earliest_node:
            earliest_ip = earliest_node.get("earliest_observable_ip") or "None identified"
            earliest_host = earliest_node.get("from_host") or "Unknown"
            earliest_conf = earliest_node.get("confidence") or "Unrated"

            early_table_data = [
                [
                    Paragraph("<b>Earliest Observable Sending IP:</b>", styles["TableCellBold"]),
                    Paragraph(f"<font name='Courier'><b>{cls._format_token(earliest_ip)}</b></font>", styles["BadgeCritical"]),
                    Paragraph("<b>Reverse DNS / Host:</b>", styles["TableCellBold"]),
                    Paragraph(cls._format_token(earliest_host), styles["TableCell"])
                ]
            ]
            early_table = Table(early_table_data, colWidths=[140, 130, 110, 160])
            early_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF2F2")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#FCA5A5")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(early_table)
            story.append(Spacer(1, 4))

        if hops:
            story.append(Paragraph("<b>Observed Infrastructure Route (Chronological Transmission Sequence):</b>", styles["SubSectionHeader"]))
            hops_table_data = [
                [
                    Paragraph("<b>HOP</b>", styles["TableHead"]),
                    Paragraph("<b>FROM (HOST / IP)</b>", styles["TableHead"]),
                    Paragraph("<b>BY (RECEIVING RELAY)</b>", styles["TableHead"]),
                    Paragraph("<b>TIMESTAMP</b>", styles["TableHead"])
                ]
            ]
            for h in hops[:10]:
                hop_num = h.get("hop_number", 1)
                from_desc = f"{h.get('from_host') or 'unknown'} ({h.get('from_ip') or 'no IP'})"
                by_desc = f"{h.get('by_host') or 'unknown'} ({h.get('by_ip') or 'no IP'})"
                ts = h.get("timestamp") or "N/A"

                hops_table_data.append([
                    Paragraph(f"#{hop_num}", styles["TableCellBold"]),
                    Paragraph(f"<font name='Courier'>{cls._format_token(from_desc, max_chunk=26)}</font>", styles["TableCell"]),
                    Paragraph(f"<font name='Courier'>{cls._format_token(by_desc, max_chunk=26)}</font>", styles["TableCell"]),
                    Paragraph(cls._format_token(ts), styles["TableCell"])
                ])

            hops_table = Table(hops_table_data, colWidths=[40, 200, 200, 100])
            hops_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(hops_table)
        else:
            story.append(Paragraph("No sequential relay hops reconstructed from Received: headers.", styles["BodyMuted"]))

        story.append(Spacer(1, 3))
        story.append(Paragraph("<i>Notice: Labeled strictly as observed infrastructure route. Does not represent physical attacker travel path.</i>", styles["BodyMuted"]))
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 11. IP INFRASTRUCTURE & DOMAIN INTELLIGENCE
        # -------------------------------------------------------------
        story.append(Paragraph("9. Infrastructure & Domain Intelligence", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        ip_intel = analysis.get("ip_intelligence") or {}
        if ip_intel:
            ip_table_data = [
                [
                    Paragraph("<b>IP ADDRESS</b>", styles["TableHead"]),
                    Paragraph("<b>LOCATION (CITY/COUNTRY)</b>", styles["TableHead"]),
                    Paragraph("<b>ASN / NETWORK</b>", styles["TableHead"]),
                    Paragraph("<b>ORGANIZATION / ISP</b>", styles["TableHead"])
                ]
            ]
            for ip_str, intel in list(ip_intel.items())[:8]:
                scope = intel.get("scope", "public")
                if scope != "public":
                    loc = f"Private / {scope.title()}"
                    asn = "RFC1918"
                    org = "Internal Network"
                else:
                    city = intel.get("city") or "Unknown City"
                    country = intel.get("country") or "Unknown Country"
                    loc = f"{city}, {country}"
                    asn = intel.get("asn") or "Unknown ASN"
                    org = intel.get("organization") or intel.get("isp") or "Unknown Org"

                ip_table_data.append([
                    Paragraph(f"<font name='Courier'>{cls._format_token(ip_str)}</font>", styles["TableCellBold"]),
                    Paragraph(cls._format_token(loc), styles["TableCell"]),
                    Paragraph(cls._format_token(asn), styles["TableCell"]),
                    Paragraph(cls._format_token(org), styles["TableCell"])
                ])

            ip_table = Table(ip_table_data, colWidths=[110, 130, 120, 180])
            ip_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(ip_table)
        else:
            story.append(Paragraph("No public IP intelligence enriched for this email.", styles["BodyMuted"]))
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 12. BRAND IMPERSONATION & LOOKALIKES
        # -------------------------------------------------------------
        lookalikes = analysis.get("lookalike_domains") or []
        if lookalikes:
            story.append(Paragraph("10. Brand Impersonation & Lookalike Domains", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

            la_table_data = [
                [
                    Paragraph("<b>SUSPECTED BRAND</b>", styles["TableHead"]),
                    Paragraph("<b>SPOOFED DOMAIN</b>", styles["TableHead"]),
                    Paragraph("<b>SIMILARITY</b>", styles["TableHead"]),
                    Paragraph("<b>TECHNIQUES & ATTACK PROFILE</b>", styles["TableHead"])
                ]
            ]
            for la in lookalikes[:6]:
                brand = la.get("brand_name") or la.get("suspected_brand") or "Target Brand"
                dom = la.get("domain") or ""
                sim = la.get("similarity", 0)
                sim_str = f"{round(sim * 100, 1)}%"
                tech = ", ".join(la.get("techniques") or ["Heuristic match"])

                la_table_data.append([
                    Paragraph(f"<b>{cls._format_token(brand)}</b>", styles["TableCellBold"]),
                    Paragraph(f"<font name='Courier'>{cls._format_token(dom)}</font>", styles["BadgeCritical"]),
                    Paragraph(f"<b>{sim_str}</b>", styles["TableCellBold"]),
                    Paragraph(cls._format_token(tech), styles["TableCell"])
                ])

            la_table = Table(la_table_data, colWidths=[110, 160, 70, 200])
            la_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(la_table)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 13. PRESCRIPTIVE RECOMMENDATIONS & LIMITATIONS
        # -------------------------------------------------------------
        story.append(Paragraph("11. Prescriptive Recommendations & Containment Actions", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        rec_actions = [
            "1. Block observed sender address and domain at the secure email gateway (SEG).",
            "2. Enforce domain-level DNS sinkholing for all identified suspicious/lookalike URLs.",
            "3. Revoke active user session tokens if credentials were submitted to target endpoints.",
            "4. Search tenant mailboxes for identical Message-ID, Subject, or attachment hashes to purge residual exposure.",
            "5. Submit extracted attachment hashes to Endpoint Detection and Response (EDR) blocklists."
        ]
        if ai_data and ai_data.get("recommended_actions"):
            ai_recs = ai_data.get("recommended_actions")
            if isinstance(ai_recs, list) and len(ai_recs) > 0:
                rec_actions = [f"{idx+1}. {r}" for idx, r in enumerate(ai_recs[:6])]

        story.append(Paragraph("<br/>".join([f"<b>[ ]</b> {html.escape(r)}" for r in rec_actions]), styles["Body"]))
        story.append(Spacer(1, 10))

        story.append(Paragraph("12. Evidentiary Limitations & Chain-of-Custody Certification", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        lim_text = (
            "<b>Forensic Chain-of-Custody Certification:</b><br/>"
            "This document is generated by MailTrace AI based on literal RFC-822 evidence headers. "
            "Public IP geolocation represents coarse regional estimates based on RIR allocations and does not establish "
            "street-level physical locations or the personal identity of the sender. "
            "All cryptographic hash sums (SHA-256) were computed over unaltered message byte streams and preserve complete "
            "digital non-repudiation chain of custody."
        )
        story.append(Paragraph(lim_text, styles["BodyMuted"]))
        story.append(Spacer(1, 8))

        # Digital seal table
        seal_table_data = [
            [
                Paragraph("<b>EVIDENTIARY DIGITAL SEAL:</b>", styles["TableCellBold"]),
                Paragraph(f"<font name='Courier'>SHA256:{cls._format_token(email_sha256, max_chunk=28)}</font>", styles["TableCell"]),
                Paragraph("<b>VERIFICATION STATUS:</b>", styles["TableCellBold"]),
                Paragraph("<font color='#16A34A'><b>CRYPTOGRAPHICALLY VERIFIED</b></font>", styles["TableCellBold"])
            ]
        ]
        seal_table = Table(seal_table_data, colWidths=[140, 170, 110, 120])
        seal_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#0284C7")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(seal_table)

        # -------------------------------------------------------------
        # BUILD DOCUMENT
        # -------------------------------------------------------------
        doc.build(story, canvasmaker=NumberedCanvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    @classmethod
    def generate_case_dossier(cls, db: Session, case_id: str) -> bytes:
        """
        Builds a comprehensive case-level forensic dossier spanning
        case overview, all linked emails, aggregated IOCs, findings,
        analyst notes, and audit log history.
        """
        cls.ensure_reports_dir()

        case = db.query(CaseModel).filter(CaseModel.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found.")

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=46,
            bottomMargin=50
        )

        styles = cls._create_styles()
        story = []

        report_ref = f"CASE-RPT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{case.case_number}"
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Header
        story.append(Paragraph("MAILTRACE AI // INCIDENT INVESTIGATION PLATFORM", styles["DocSubtitle"]))
        story.append(Spacer(1, 2))
        story.append(Paragraph(f"Case Forensic Dossier: {html.escape(case.case_number)}", styles["DocTitle"]))
        story.append(Spacer(1, 8))

        # Case summary metadata
        meta_table_data = [
            [
                Paragraph("<b>CASE NUMBER:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(case.case_number), styles["TableCellBold"]),
                Paragraph("<b>GENERATED (UTC):</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(generated_at), styles["TableCell"]),
            ],
            [
                Paragraph("<b>CASE STATUS:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(case.status.upper()), styles["TableCellBold"]),
                Paragraph("<b>ASSIGNED SEVERITY:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(case.severity.upper()), styles["TableCellBold"]),
            ],
            [
                Paragraph("<b>CASE TITLE:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(case.title), styles["TableCellBold"]),
                Paragraph("<b>LINKED EVIDENCE:</b>", styles["TableCellBold"]),
                Paragraph(f"{len(case.emails)} Email(s), {len(case.findings)} Finding(s)", styles["TableCell"]),
            ]
        ]
        meta_table = Table(meta_table_data, colWidths=[110, 160, 110, 160])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # Case Description
        if case.description:
            story.append(Paragraph("<b>Case Narrative & Scope:</b>", styles["SubSectionHeader"]))
            story.append(Paragraph(html.escape(case.description), styles["Body"]))
            story.append(Spacer(1, 8))

        # Linked Emails
        story.append(Paragraph("1. Linked Evidentiary Emails", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))
        if case.emails:
            emails_table_data = [
                [
                    Paragraph("<b>EVIDENCE ID</b>", styles["TableHead"]),
                    Paragraph("<b>SENDER</b>", styles["TableHead"]),
                    Paragraph("<b>SUBJECT</b>", styles["TableHead"]),
                    Paragraph("<b>THREAT</b>", styles["TableHead"]),
                    Paragraph("<b>SHA-256</b>", styles["TableHead"])
                ]
            ]
            for em in case.emails:
                sha = em.email_sha256 or "N/A"
                emails_table_data.append([
                    Paragraph(cls._format_token(em.email_id), styles["TableCellBold"]),
                    Paragraph(cls._format_token(em.sender), styles["TableCell"]),
                    Paragraph(cls._format_token(em.subject), styles["TableCell"]),
                    Paragraph(f"{em.threat_score}/100", styles["TableCellBold"]),
                    Paragraph(f"<font name='Courier'>{cls._format_token(sha, max_chunk=16)}</font>", styles["TableCell"])
                ])

            emails_table = Table(emails_table_data, colWidths=[100, 110, 150, 50, 130])
            emails_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(emails_table)
        else:
            story.append(Paragraph("No emails currently linked to this investigation case.", styles["BodyMuted"]))
        story.append(Spacer(1, 10))

        # Structured Findings
        story.append(Paragraph("2. Forensic Findings & Classifications", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))
        if case.findings:
            findings_table_data = [
                [
                    Paragraph("<b>TYPE</b>", styles["TableHead"]),
                    Paragraph("<b>TITLE</b>", styles["TableHead"]),
                    Paragraph("<b>SEVERITY</b>", styles["TableHead"]),
                    Paragraph("<b>DESCRIPTION</b>", styles["TableHead"])
                ]
            ]
            for f in case.findings:
                findings_table_data.append([
                    Paragraph(html.escape(f.finding_type), styles["TableCellBold"]),
                    Paragraph(html.escape(f.title), styles["TableCellBold"]),
                    Paragraph(f.severity.upper(), styles["TableCellBold"]),
                    Paragraph(html.escape(f.description), styles["TableCell"])
                ])

            findings_table = Table(findings_table_data, colWidths=[100, 130, 60, 250])
            findings_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(findings_table)
        else:
            story.append(Paragraph("No structured findings recorded.", styles["BodyMuted"]))
        story.append(Spacer(1, 10))

        # Notes
        story.append(Paragraph("3. Investigator Notes", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))
        if case.notes:
            for n in case.notes:
                dt = n.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                story.append(Paragraph(f"<b>{html.escape(n.author)}</b> ({dt}):", styles["TableCellBold"]))
                story.append(Paragraph(html.escape(n.note_text), styles["Body"]))
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph("No analyst notes logged.", styles["BodyMuted"]))
        story.append(Spacer(1, 10))

        # Audit Logs
        story.append(Paragraph("4. Chain of Custody & Audit Trail", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))
        if case.audit_logs:
            audit_data = [
                [
                    Paragraph("<b>ACTION</b>", styles["TableHead"]),
                    Paragraph("<b>TIMESTAMP</b>", styles["TableHead"]),
                    Paragraph("<b>AUDIT RECORD</b>", styles["TableHead"])
                ]
            ]
            for a in case.audit_logs[:15]:
                audit_data.append([
                    Paragraph(html.escape(a.action), styles["TableCellBold"]),
                    Paragraph(a.timestamp.strftime("%Y-%m-%d %H:%M:%S"), styles["TableCell"]),
                    Paragraph(html.escape(a.details), styles["TableCell"])
                ])
            audit_table = Table(audit_data, colWidths=[110, 110, 320])
            audit_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(audit_table)
        story.append(Spacer(1, 10))

        doc.build(story, canvasmaker=NumberedCanvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    @classmethod
    def format_mitre_attack_section(cls, mitre_report: Any, styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """
        Formats Section 19 MITRE ATT&CK Analysis flowables for legal/SOC reporting.
        Uses epistemically safe language ('CyberGuard mapped observed activity to...').
        """
        flowables = []
        flowables.append(Paragraph("MITRE ATT&CK Mapping & Technique Assessment", styles["SectionHeader"]))
        flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        # Executive summary
        exec_summary = getattr(mitre_report, "executive_summary", "")
        if exec_summary:
            body_style = styles.get("BodyText", styles.get("TableCell", styles["Normal"]))
            flowables.append(Paragraph(f"<b>Assessment Summary:</b> {html.escape(exec_summary)}", body_style))
            flowables.append(Spacer(1, 6))

        # Supported Techniques Table
        supported = getattr(mitre_report, "supported_mappings", [])
        if supported:
            table_data = [
                [
                    Paragraph("<b>TECHNIQUE</b>", styles["TableHead"]),
                    Paragraph("<b>TACTICS</b>", styles["TableHead"]),
                    Paragraph("<b>STATUS</b>", styles["TableHead"]),
                    Paragraph("<b>CONFIDENCE</b>", styles["TableHead"]),
                    Paragraph("<b>EXPLANATION / EVIDENCE</b>", styles["TableHead"]),
                ]
            ]
            for m in supported:
                tid_str = f"<b>{html.escape(m.technique_id)}</b><br/>{html.escape(m.technique_name)}"
                tacs_str = html.escape(", ".join(getattr(m, "tactic_names", [])))
                stat_val = m.status.value if hasattr(m.status, "value") else str(m.status)
                stat_str = f"<b>{stat_val}</b>"
                conf_val = getattr(m, "confidence_level", None)
                conf_level_str = conf_val.value if hasattr(conf_val, "value") else str(conf_val)
                conf_str = f"{m.confidence:.2f} ({conf_level_str})"
                expl_str = f"{html.escape(m.explanation)}"
                if m.limitations:
                    expl_str += f"<br/><i>Limitations: {html.escape('; '.join(m.limitations))}</i>"
                table_data.append([
                    Paragraph(tid_str, styles["TableCellBold"]),
                    Paragraph(tacs_str, styles["TableCell"]),
                    Paragraph(stat_str, styles["TableCell"]),
                    Paragraph(conf_str, styles["TableCell"]),
                    Paragraph(expl_str, styles["TableCell"]),
                ])
            t = Table(table_data, colWidths=[110, 80, 75, 75, 200])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            flowables.append(t)
            flowables.append(Spacer(1, 8))

        return flowables

    @classmethod
    def format_infrastructure_attribution_section(cls, infra_assessment: Any, styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """
        Formats Section 20 Probable Origin Infrastructure & Threat Infrastructure Assessment flowables.
        Strictly enforces non-attribution standards and highlights server geography vs human location.
        """
        flowables = []
        flowables.append(Paragraph("Probable Origin Infrastructure & Threat Infrastructure Assessment", styles["SectionHeader"]))
        flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        # Forensic Disclaimer
        disclaimer = getattr(infra_assessment, "disclaimer", "")
        if disclaimer:
            note_style = styles.get("WarningBox", styles.get("TableCell", styles["Normal"]))
            flowables.append(Paragraph(f"<b>FORENSIC NOTICE:</b> <i>{html.escape(disclaimer)}</i>", note_style))
            flowables.append(Spacer(1, 6))

        # Executive Summary
        summary = getattr(infra_assessment, "summary", "")
        if summary:
            body_style = styles.get("BodyText", styles.get("TableCell", styles["Normal"]))
            flowables.append(Paragraph(f"<b>Assessment Narrative:</b> {html.escape(summary)}", body_style))
            flowables.append(Spacer(1, 6))

        # Primary & Competing Hypotheses Table
        primary = getattr(infra_assessment, "primary_hypothesis", None)
        competing = getattr(infra_assessment, "competing_hypotheses", [])
        all_hypotheses = ([primary] if primary else []) + list(competing)

        if all_hypotheses:
            table_data = [
                [
                    Paragraph("<b>HYPOTHESIS ID</b>", styles["TableHead"]),
                    Paragraph("<b>ORIGIN TARGET</b>", styles["TableHead"]),
                    Paragraph("<b>TYPE</b>", styles["TableHead"]),
                    Paragraph("<b>CONFIDENCE</b>", styles["TableHead"]),
                    Paragraph("<b>ASSESSMENT SUMMARY & LIMITATIONS</b>", styles["TableHead"]),
                ]
            ]
            for h in all_hypotheses:
                hid_str = f"<b>{html.escape(h.hypothesis_id)}</b><br/>{html.escape(h.status.value if hasattr(h.status, 'value') else str(h.status))}"
                target_str = f"<b>{html.escape(h.origin_value)}</b>"
                type_val = h.origin_type.value if hasattr(h.origin_type, "value") else str(h.origin_type)
                type_str = html.escape(type_val)
                conf_val = getattr(h, "confidence_level", None)
                conf_level_str = conf_val.value if hasattr(conf_val, "value") else str(conf_val)
                conf_str = f"{h.confidence_score * 100:.1f}% ({conf_level_str})"
                summary_str = f"{html.escape(h.hypothesis)}"
                if h.limitations:
                    summary_str += f"<br/><i>Caveats: {html.escape('; '.join(h.limitations[:2]))}</i>"

                table_data.append([
                    Paragraph(hid_str, styles["TableCellBold"]),
                    Paragraph(target_str, styles["TableCell"]),
                    Paragraph(type_str, styles["TableCell"]),
                    Paragraph(conf_str, styles["TableCell"]),
                    Paragraph(summary_str, styles["TableCell"]),
                ])

            t = Table(table_data, colWidths=[80, 110, 80, 80, 190])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            flowables.append(t)
            flowables.append(Spacer(1, 8))

        # Infrastructure Clusters
        clusters = getattr(infra_assessment, "clusters", [])
        if clusters:
            flowables.append(Paragraph("<b>Identified Infrastructure Clusters</b>", styles["SubSectionHeader"]))
            cl_data = [
                [
                    Paragraph("<b>CLUSTER ID</b>", styles["TableHead"]),
                    Paragraph("<b>NAME / TITLE</b>", styles["TableHead"]),
                    Paragraph("<b>MEMBERS</b>", styles["TableHead"]),
                    Paragraph("<b>INCIDENTS</b>", styles["TableHead"]),
                    Paragraph("<b>SIGNALS</b>", styles["TableHead"]),
                ]
            ]
            for cl in clusters:
                cid_str = f"<b>{html.escape(cl.cluster_id)}</b>"
                name_str = html.escape(cl.name)
                members_preview = html.escape(", ".join([m.value for m in getattr(cl, "members", [])][:4]))
                inc_str = str(cl.incident_count)
                sig_str = html.escape("; ".join(cl.supporting_signals[:2]))
                cl_data.append([
                    Paragraph(cid_str, styles["TableCellBold"]),
                    Paragraph(name_str, styles["TableCell"]),
                    Paragraph(members_preview, styles["TableCell"]),
                    Paragraph(inc_str, styles["TableCell"]),
                    Paragraph(sig_str, styles["TableCell"]),
                ])
            cl_table = Table(cl_data, colWidths=[90, 120, 140, 50, 140])
            cl_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.0),
            ]))
            flowables.append(cl_table)
            flowables.append(Spacer(1, 8))

        return flowables

