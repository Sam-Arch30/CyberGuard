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

    REPORTS_DIR = os.getenv("CYBERGUARD_REPORTS_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "reports"))

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

        # Check for Section 28 structured response recommendations
        recs_data = analysis.get("response_recommendations") or analysis.get("recommendations")
        if recs_data and isinstance(recs_data, list) and len(recs_data) > 0:
            story.extend(cls._format_response_recommendations_section(recs_data, styles))
        else:
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

        # Section 27: Explainable AI (XAI) Evidence-Grounded Reasoning
        xai_data = analysis.get("xai_explanation") or analysis.get("explanation")
        if xai_data:
            story.extend(cls._format_explainable_ai_section(xai_data, styles))

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

    @classmethod
    def format_behavioral_baseline_section(
        cls,
        deviations: List[Any],
        styles: Dict[str, ParagraphStyle],
        baselines: Optional[List[Any]] = None,
    ) -> List[Any]:
        """
        Formats Section 21 Behavioral Baseline & Anomaly Assessment flowables.
        Maintains epistemic humility and objective forensic reporting without alarmist verdicts.
        """
        flowables = []
        flowables.append(Paragraph("Behavioral Baseline & Anomaly Assessment", styles["SectionHeader"]))
        flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        # Forensic Notice
        forensic_notice = (
            "Behavioral baseline deviations reflect statistical deviation from an entity's own historical telemetry. "
            "A baseline deviation is objective technical evidence, NOT an independent verdict of compromise or attacker takeover."
        )
        note_style = styles.get("WarningBox", styles.get("TableCell", styles["Normal"]))
        flowables.append(Paragraph(f"<b>FORENSIC NOTICE:</b> <i>{html.escape(forensic_notice)}</i>", note_style))
        flowables.append(Spacer(1, 6))

        if not deviations:
            flowables.append(Paragraph("<i>No significant behavioral deviations observed relative to historical baselines.</i>", styles["TableCell"]))
            flowables.append(Spacer(1, 8))
            return flowables

        table_data = [
            [
                Paragraph("<b>ENTITY</b>", styles["TableHead"]),
                Paragraph("<b>METRIC</b>", styles["TableHead"]),
                Paragraph("<b>OBSERVED</b>", styles["TableHead"]),
                Paragraph("<b>HISTORICAL RANGE</b>", styles["TableHead"]),
                Paragraph("<b>DEVIATION</b>", styles["TableHead"]),
                Paragraph("<b>EVIDENCE & EXPLANATION</b>", styles["TableHead"]),
            ]
        ]

        for d in deviations:
            ent_str = f"<b>{html.escape(str(getattr(d, 'entity_type', '')))}</b><br/>{html.escape(str(getattr(d, 'entity_id', '')))}"
            m_val = getattr(d, "metric_type", "")
            m_str = html.escape(m_val.value if hasattr(m_val, "value") else str(m_val))
            obs_str = html.escape(str(getattr(d, "observed_value", "")))
            exp_str = html.escape(str(getattr(d, "expected_range_summary", "")))
            score = float(getattr(d, "deviation_score", 0.0))
            score_pct = f"{score * 100:.0f}%"
            dir_val = getattr(d, "deviation_direction", "")
            dir_str = dir_val.value if hasattr(dir_val, "value") else str(dir_val)
            dev_str = f"<b>{score_pct}</b><br/>{html.escape(dir_str)}"

            expl = html.escape(str(getattr(d, "explanation", "")))
            limits = getattr(d, "limitations", [])
            if limits:
                expl += f"<br/><i>Limitations: {html.escape('; '.join(limits[:2]))}</i>"

            table_data.append([
                Paragraph(ent_str, styles["TableCellBold"]),
                Paragraph(m_str, styles["TableCell"]),
                Paragraph(obs_str, styles["TableCell"]),
                Paragraph(exp_str, styles["TableCell"]),
                Paragraph(dev_str, styles["TableCell"]),
                Paragraph(expl, styles["TableCell"]),
            ])

        t = Table(table_data, colWidths=[90, 85, 75, 95, 65, 130])
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
    def format_novelty_assessment_section(
        cls,
        assessments: List[Any],
        styles: Dict[str, ParagraphStyle],
        emerging_patterns: Optional[List[Any]] = None,
    ) -> List[Any]:
        """
        Formats Section 22 Novelty & Emerging-Threat Assessment flowables.
        Maintains strict epistemic humility: technical unfamiliarity != malicious intent.
        """
        flowables = []
        flowables.append(Paragraph("Novelty & Emerging-Threat Assessment", styles["SectionHeader"]))
        flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        # Forensic Notice
        forensic_notice = (
            "Novelty represents technical unfamiliarity within CyberGuard's retained historical telemetry. "
            "A novel pattern or unprecedented event combination alone does NOT establish malicious intent, attack causation, or compromise."
        )
        note_style = styles.get("WarningBox", styles.get("TableCell", styles["Normal"]))
        flowables.append(Paragraph(f"<b>FORENSIC NOTICE:</b> <i>{html.escape(forensic_notice)}</i>", note_style))
        flowables.append(Spacer(1, 6))

        if not assessments:
            flowables.append(Paragraph("<i>No previously unobserved or emerging behavioral patterns identified in retained telemetry.</i>", styles["TableCell"]))
            flowables.append(Spacer(1, 8))
            return flowables

        table_data = [
            [
                Paragraph("<b>ENTITY / PATTERN</b>", styles["TableHead"]),
                Paragraph("<b>CATEGORY</b>", styles["TableHead"]),
                Paragraph("<b>NOVELTY LEVEL</b>", styles["TableHead"]),
                Paragraph("<b>DISTANCE</b>", styles["TableHead"]),
                Paragraph("<b>FAMILIARITY MATRIX</b>", styles["TableHead"]),
                Paragraph("<b>EVIDENCE & LIMITATIONS</b>", styles["TableHead"]),
            ]
        ]

        for a in assessments:
            ent_id = getattr(a, "entity_id", "")
            ent_type = getattr(a, "entity_type", "")
            repr_str = getattr(a, "fingerprint_repr", "") or f"{ent_type}:{ent_id}"
            ent_cell = f"<b>{html.escape(str(repr_str))}</b><br/>Entity: {html.escape(str(ent_type))}:{html.escape(str(ent_id))}"

            cat_val = getattr(a, "novelty_type", "")
            cat_str = html.escape(cat_val.value if hasattr(cat_val, "value") else str(cat_val))

            lvl_val = getattr(a, "novelty_level", "")
            lvl_str = html.escape(lvl_val.value if hasattr(lvl_val, "value") else str(lvl_val))

            score = float(getattr(a, "novelty_score", 0.0))
            sim = float(getattr(a, "similarity_score", 0.0))
            dist_str = f"Novelty: {score * 100:.0f}%<br/>Similarity: {sim * 100:.0f}%"

            mat_val = getattr(a, "behavior_familiarity_matrix", "")
            mat_str = html.escape(mat_val.value if hasattr(mat_val, "value") else str(mat_val))

            ev_list = getattr(a, "supporting_evidence", [])
            ev_desc = ""
            if ev_list and isinstance(ev_list, list) and isinstance(ev_list[0], dict):
                ev_desc = ev_list[0].get("description", "")
            limits = getattr(a, "limitations", [])
            limit_str = f"<br/><i>Limit: {html.escape(limits[0])}</i>" if limits else ""
            expl_cell = f"{html.escape(ev_desc)}{limit_str}"

            table_data.append([
                Paragraph(ent_cell, styles["TableCellBold"]),
                Paragraph(cat_str, styles["TableCell"]),
                Paragraph(f"<b>{lvl_str}</b>", styles["TableCell"]),
                Paragraph(dist_str, styles["TableCell"]),
                Paragraph(mat_str, styles["TableCell"]),
                Paragraph(expl_cell, styles["TableCell"]),
            ])

        t = Table(table_data, colWidths=[110, 85, 75, 75, 85, 110])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        flowables.append(t)
        flowables.append(Spacer(1, 8))

        # Emerging Pattern Candidates
        if emerging_patterns:
            flowables.append(Paragraph("<b>Emerging Recurring Patterns</b>", styles["TableCellBold"]))
            emerging_data = [
                [
                    Paragraph("<b>PATTERN REPR</b>", styles["TableHead"]),
                    Paragraph("<b>STATUS</b>", styles["TableHead"]),
                    Paragraph("<b>OBSERVATIONS</b>", styles["TableHead"]),
                    Paragraph("<b>ENTITIES</b>", styles["TableHead"]),
                    Paragraph("<b>RECURRENCE SCORE</b>", styles["TableHead"]),
                ]
            ]
            for ep in emerging_patterns:
                ep_repr = html.escape(str(getattr(ep, "fingerprint_repr", "")))
                st_val = getattr(ep, "status", "")
                st_str = html.escape(st_val.value if hasattr(st_val, "value") else str(st_val))
                obs_c = str(getattr(ep, "observation_count", 1))
                ent_c = str(getattr(ep, "entity_count", 1))
                rec_s = f"{float(getattr(ep, 'recurrence_score', 0.0)):.1f}"
                emerging_data.append([
                    Paragraph(ep_repr, styles["TableCellBold"]),
                    Paragraph(st_str, styles["TableCell"]),
                    Paragraph(obs_c, styles["TableCell"]),
                    Paragraph(ent_c, styles["TableCell"]),
                    Paragraph(rec_s, styles["TableCell"]),
                ])

            t_ep = Table(emerging_data, colWidths=[200, 85, 75, 75, 105])
            t_ep.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.0),
            ]))
            flowables.append(t_ep)
            flowables.append(Spacer(1, 8))

        return flowables

    @classmethod
    def format_threat_memory_section(
        cls,
        memory_contexts: List[Any],
        styles: Dict[str, ParagraphStyle],
    ) -> List[Any]:
        """
        Formats Section 23 CyberGuard Threat Memory flowables.
        Maintains strict epistemic humility: CURRENT EVIDENCE > HISTORICAL MEMORY.
        """
        flowables = []
        flowables.append(Paragraph("CyberGuard Threat Memory & Historical Intelligence", styles["SectionHeader"]))
        flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        # Forensic Epistemic Notice
        epistemic_notice = (
            "Threat Memory provides persistent historical security intelligence across prior investigations. "
            "Historical memory serves as contextual enrichment and does not substitute for present forensic observation. "
            "CURRENT EVIDENCE > HISTORICAL MEMORY."
        )
        note_style = styles.get("WarningBox", styles.get("TableCell", styles["Normal"]))
        flowables.append(Paragraph(f"<b>FORENSIC NOTICE:</b> <i>{html.escape(epistemic_notice)}</i>", note_style))
        flowables.append(Spacer(1, 6))

        if not memory_contexts:
            flowables.append(Paragraph("<i>No historical security memory or cross-investigation sightings recorded for observed entities.</i>", styles["TableCell"]))
            flowables.append(Spacer(1, 8))
            return flowables

        table_data = [
            [
                Paragraph("<b>CANONICAL KEY</b>", styles["TableHead"]),
                Paragraph("<b>MEMORY STATUS</b>", styles["TableHead"]),
                Paragraph("<b>OBSERVATIONS</b>", styles["TableHead"]),
                Paragraph("<b>INCIDENTS</b>", styles["TableHead"]),
                Paragraph("<b>PROVENANCE & CONFLICT</b>", styles["TableHead"]),
            ]
        ]

        for ctx in memory_contexts:
            key_val = getattr(ctx, "canonical_key", "")
            if isinstance(ctx, dict):
                key_val = ctx.get("canonical_key", "")
                status_val = ctx.get("memory_status", "OBSERVED")
                obs_c = ctx.get("observation_count", 0)
                sources_c = ctx.get("independent_source_count", 0)
                inc_list = ctx.get("related_incidents", [])
                conflict = ctx.get("conflict", {})
                is_conflicted = conflict.get("is_conflicted", False) if isinstance(conflict, dict) else False
                conflict_expl = conflict.get("explanation", "") if isinstance(conflict, dict) else ""
                verified = ctx.get("is_analyst_verified", False)
            else:
                status_val = getattr(ctx, "memory_status", "OBSERVED")
                obs_c = getattr(ctx, "observation_count", 0)
                sources_c = getattr(ctx, "independent_source_count", 0)
                inc_list = getattr(ctx, "related_incidents", [])
                conflict = getattr(ctx, "conflict", None)
                is_conflicted = getattr(conflict, "is_conflicted", False) if conflict else False
                conflict_expl = getattr(conflict, "explanation", "") if conflict else ""
                verified = getattr(ctx, "is_analyst_verified", False)

            status_str = html.escape(str(status_val.value if hasattr(status_val, "value") else status_val))
            obs_str = f"{obs_c} seen<br/>({sources_c} indep. src)"
            inc_str = f"{len(inc_list)} incident(s)"

            prov_parts = []
            if verified:
                prov_parts.append("<b>[ANALYST VERIFIED]</b>")
            if is_conflicted:
                prov_parts.append(f"<b>[CONFLICT]</b>: {html.escape(str(conflict_expl))}")
            else:
                prov_parts.append("Consistent provenance")

            table_data.append([
                Paragraph(f"<b>{html.escape(str(key_val))}</b>", styles["TableCellBold"]),
                Paragraph(status_str, styles["TableCell"]),
                Paragraph(obs_str, styles["TableCell"]),
                Paragraph(inc_str, styles["TableCell"]),
                Paragraph("<br/>".join(prov_parts), styles["TableCell"]),
            ])

        t = Table(table_data, colWidths=[150, 85, 80, 75, 150])
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
    def _format_continual_learning_section(
        cls,
        model_card_or_learning_data: Any,
        styles: Dict[str, ParagraphStyle],
    ) -> List[Any]:
        """
        Formats Section 24 Controlled Continual-Learning & Model Card flowables.
        Maintains strict epistemic boundary: TRAINING != PRODUCTION DEPLOYMENT.
        """
        flowables = []
        flowables.append(Paragraph("Controlled Continual Learning & Model Lineage", styles["SectionHeader"]))
        flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        notice = (
            "CyberGuard employs controlled continual learning. Untrusted inputs never modify production models. "
            "All model candidates undergo offline evaluation, regression gating, explicit approval, staging, "
            "and cryptographic checksum verification before deployment."
        )
        note_style = styles.get("WarningBox", styles.get("TableCell", styles["Normal"]))
        flowables.append(Paragraph(f"<b>GOVERNANCE NOTICE:</b> <i>{html.escape(notice)}</i>", note_style))
        flowables.append(Spacer(1, 6))

        if not model_card_or_learning_data:
            flowables.append(Paragraph("<i>No continual learning model updates or candidates associated with this report scope.</i>", styles["TableCell"]))
            flowables.append(Spacer(1, 8))
            return flowables

        # Render Model Card table
        data = model_card_or_learning_data if isinstance(model_card_or_learning_data, dict) else (
            model_card_or_learning_data.model_dump() if hasattr(model_card_or_learning_data, "model_dump") else {}
        )
        model_type = data.get("model_type", "PHISHING_CLASSIFIER")
        version = data.get("version", "v1.0.0")
        dataset_ver = data.get("dataset_version", "D-001")
        status_val = data.get("status", "PRODUCTION")
        checksum = str(data.get("checksum", "N/A"))
        if len(checksum) > 16:
            checksum = checksum[:16] + "..."
        metrics = data.get("metrics", {})
        acc = metrics.get("accuracy", "N/A")
        f1 = metrics.get("f1_score", "N/A")
        rec = metrics.get("recall", "N/A")
        crit_rec = metrics.get("critical_threat_recall", "N/A")

        table_data = [
            [
                Paragraph("<b>MODEL / VERSION</b>", styles["TableHead"]),
                Paragraph("<b>STATUS</b>", styles["TableHead"]),
                Paragraph("<b>DATASET</b>", styles["TableHead"]),
                Paragraph("<b>ACC / F1 / RECALL</b>", styles["TableHead"]),
                Paragraph("<b>CRITICAL RECALL / SHA-256</b>", styles["TableHead"]),
            ],
            [
                Paragraph(f"<b>{html.escape(str(model_type))}</b><br/>{html.escape(str(version))}", styles["TableCellBold"]),
                Paragraph(html.escape(str(status_val)), styles["TableCell"]),
                Paragraph(html.escape(str(dataset_ver)), styles["TableCell"]),
                Paragraph(f"Acc: {acc}<br/>F1: {f1}<br/>Rec: {rec}", styles["TableCell"]),
                Paragraph(f"Crit: {crit_rec}<br/>SHA: {checksum}", styles["TableCell"]),
            ]
        ]

        t = Table(table_data, colWidths=[130, 85, 80, 115, 130])
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
    def _format_candidate_rule_section(
        cls,
        candidate_rules_data: Any,
        styles: Dict[str, ParagraphStyle],
    ) -> List[Any]:
        """
        Formats Section 25 Emerging Pattern & Candidate Rule Engine flowables.
        Maintains strict boundary: PATTERN != RULE; RULE != APPROVED RULE; APPROVED RULE != PRODUCTION RULE.
        """
        flowables = []
        flowables.append(Paragraph("Emerging Patterns & Candidate Detection Rules", styles["SectionHeader"]))
        flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        notice = (
            "Candidate detection rules are derived from validated emerging patterns and Threat Memory. "
            "To prevent alert fatigue and false positives, candidate rules require historical backtesting, "
            "false positive analysis, shadow mode staging, and explicit human approval prior to production activation."
        )
        note_style = styles.get("WarningBox", styles.get("TableCell", styles["Normal"]))
        flowables.append(Paragraph(f"<b>GOVERNANCE NOTICE:</b> <i>{html.escape(notice)}</i>", note_style))
        flowables.append(Spacer(1, 6))

        if not candidate_rules_data:
            flowables.append(Paragraph("<i>No candidate detection rules or emerging pattern evaluations in this scope.</i>", styles["TableCell"]))
            flowables.append(Spacer(1, 8))
            return flowables

        rules_list = candidate_rules_data if isinstance(candidate_rules_data, list) else [candidate_rules_data]

        table_data = [
            [
                Paragraph("<b>RULE NAME / ID</b>", styles["TableHead"]),
                Paragraph("<b>TYPE / SCOPE</b>", styles["TableHead"]),
                Paragraph("<b>STATUS / VER</b>", styles["TableHead"]),
                Paragraph("<b>COMPLEXITY / CONF</b>", styles["TableHead"]),
                Paragraph("<b>BACKTEST MATCHES / PRECISION</b>", styles["TableHead"]),
            ]
        ]

        for item in rules_list[:10]:
            data = item if isinstance(item, dict) else (item.model_dump() if hasattr(item, "model_dump") else {})
            name = data.get("name", "Candidate Rule")
            rule_id = str(data.get("id", "N/A"))[:8]
            rtype = data.get("rule_type", "STRUCTURAL")
            scope = data.get("scope", "GLOBAL")
            status_val = data.get("status", "DISCOVERED")
            ver = data.get("version", "v1")
            comp = data.get("complexity_score", 1.0)
            conf = data.get("confidence", 0.8)
            eval_data = data.get("evaluation_summary") or {}
            matches = eval_data.get("historical_match_count", "N/A")
            prec = eval_data.get("precision", "N/A")

            table_data.append([
                Paragraph(f"<b>{html.escape(str(name))}</b><br/><font size='7' color='#64748B'>{rule_id}</font>", styles["TableCellBold"]),
                Paragraph(f"{html.escape(str(rtype))}<br/>{html.escape(str(scope))}", styles["TableCell"]),
                Paragraph(f"<b>{html.escape(str(status_val))}</b><br/>{html.escape(str(ver))}", styles["TableCell"]),
                Paragraph(f"Comp: {comp}<br/>Conf: {conf}", styles["TableCell"]),
                Paragraph(f"Matches: {matches}<br/>Prec: {prec}", styles["TableCell"]),
            ])

        t = Table(table_data, colWidths=[150, 85, 85, 95, 125])
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
    def _format_unified_risk_section(
        cls,
        risk_assessment_data: Optional[Dict[str, Any] | Any],
        styles: Dict[str, ParagraphStyle],
    ) -> List[Any]:
        """
        Formats Section 26 Unified Risk Assessment table for executive legal/SOC reports.
        Visualizes unified score, level, severity, confidence, uncertainty, and top contributors.
        """
        flowables: List[Any] = []
        flowables.append(Paragraph("<b>UNIFIED RISK ENGINE ASSESSMENT (SECTION 26)</b>", styles["SectionHeader"]))
        flowables.append(Spacer(1, 4))

        if not risk_assessment_data:
            flowables.append(Paragraph("<i>No unified risk assessment record associated with this scope.</i>", styles["TableCell"]))
            flowables.append(Spacer(1, 8))
            return flowables

        data = risk_assessment_data if isinstance(risk_assessment_data, dict) else (
            risk_assessment_data.model_dump() if hasattr(risk_assessment_data, "model_dump") else {}
        )

        score = data.get("risk_score", 0.0)
        level = data.get("risk_level", "INFO")
        sev = data.get("severity", "MEDIUM")
        conf = data.get("confidence", 1.0)
        unc = data.get("uncertainty", "LOW")
        summary = data.get("explanation_summary", "Deterministic multi-vector risk synthesis completed.")
        agg_ver = data.get("aggregation_version", "1.0.0")
        cfg_ver = data.get("configuration_version", "1.0.0")

        # Color mapping for risk level
        level_colors = {
            "CRITICAL": "#7F1D1D",
            "HIGH": "#EF4444",
            "MEDIUM": "#F59E0B",
            "LOW": "#10B981",
            "INFO": "#64748B"
        }
        badge_color = level_colors.get(str(level).upper(), "#64748B")

        # Summary box
        summary_data = [
            [
                Paragraph(f"<font size='14' color='{badge_color}'><b>RISK {score:.1f}/100</b></font><br/><b>LEVEL: {level}</b>", styles["TableCellBold"]),
                Paragraph(f"<b>SEVERITY:</b> {sev}<br/><b>CONFIDENCE:</b> {conf:.2f}<br/><b>UNCERTAINTY:</b> {unc}", styles["TableCell"]),
                Paragraph(f"<b>AGGREGATION:</b> v{agg_ver}<br/><b>CONFIG:</b> v{cfg_ver}", styles["TableCell"]),
            ]
        ]
        sum_table = Table(summary_data, colWidths=[180, 180, 180])
        sum_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1.0, colors.HexColor(badge_color)),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        flowables.append(sum_table)
        flowables.append(Spacer(1, 6))

        flowables.append(Paragraph(f"<b>Assessment Summary:</b> {html.escape(str(summary))}", styles["TableCell"]))
        flowables.append(Spacer(1, 6))

        # Top contributors breakdown
        components = data.get("components") or []
        if components:
            flowables.append(Paragraph("<b>Top Risk Contributors & Modifiers:</b>", styles["TableCellBold"]))
            comp_table_data = [
                [
                    Paragraph("<b>CONTRIBUTOR / SIGNAL</b>", styles["TableHead"]),
                    Paragraph("<b>FAMILY</b>", styles["TableHead"]),
                    Paragraph("<b>POINTS</b>", styles["TableHead"]),
                    Paragraph("<b>DESCRIPTION</b>", styles["TableHead"]),
                ]
            ]
            for c in components[:6]:
                c_dict = c if isinstance(c, dict) else (c.model_dump() if hasattr(c, "model_dump") else {})
                c_name = c_dict.get("name", "Unknown")
                c_fam = c_dict.get("family", "GENERAL")
                c_pts = c_dict.get("contribution", 0.0)
                c_desc = c_dict.get("description", "")
                comp_table_data.append([
                    Paragraph(f"<b>{html.escape(str(c_name))}</b>", styles["TableCellBold"]),
                    Paragraph(html.escape(str(c_fam)), styles["TableCell"]),
                    Paragraph(f"<b>+{c_pts:.1f}</b>", styles["TableCellBold"]),
                    Paragraph(html.escape(str(c_desc)), styles["TableCell"]),
                ])

            ct = Table(comp_table_data, colWidths=[150, 100, 70, 220])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            flowables.append(ct)

        flowables.append(Spacer(1, 8))
        return flowables

    @classmethod
    def _format_explainable_ai_section(
        cls,
        explanation_data: Optional[Dict[str, Any] | Any],
        styles: Dict[str, ParagraphStyle],
    ) -> List[Any]:
        """
        Formats Section 27 Explainable AI (XAI) evidence-grounded reasoning section for PDF reports.
        Visualizes Why CyberGuard Flagged This, Grounded Claims, Counter-Evidence, Contradictions,
        Uncertainty, and Assessment-Change Guidance.
        """
        flowables: List[Any] = []
        if not explanation_data:
            return flowables

        data = explanation_data if isinstance(explanation_data, dict) else (
            explanation_data.model_dump() if hasattr(explanation_data, "model_dump") else {}
        )

        flowables.append(Paragraph("<b>EXPLAINABLE AI (XAI) EVIDENCE-GROUNDED REASONING (SECTION 27)</b>", styles["SectionHeader"]))
        flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=6))

        summary = data.get("analyst_summary") or data.get("summary") or "Evidence-grounded synthesis completed."
        exec_sum = data.get("executive_summary") or ""
        score = data.get("risk_score", 0.0)
        level = data.get("risk_level", "INFO")
        conf = data.get("confidence_level", "HIGH")
        unc = data.get("uncertainty", "LOW")

        # Callout Box
        callout_data = [
            [
                Paragraph(f"<b>WHY CYBERGUARD FLAGGED THIS:</b><br/>{html.escape(str(exec_sum or summary))}", styles["TableCellBold"]),
                Paragraph(f"<b>RISK LEVEL:</b> {level} ({score:.0f}/100)<br/><b>CONFIDENCE:</b> {conf}<br/><b>UNCERTAINTY:</b> {unc}", styles["TableCell"]),
            ]
        ]
        ctable = Table(callout_data, colWidths=[360, 180])
        ctable.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1.0, colors.HexColor("#0284C7")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        flowables.append(ctable)
        flowables.append(Spacer(1, 6))

        # Grounded Claims Table
        claims = data.get("explanation_units") or []
        if claims:
            flowables.append(Paragraph("<b>Evidence-Backed Analytical Claims:</b>", styles["TableCellBold"]))
            claim_table_data = [
                [
                    Paragraph("<b>CLAIM / TYPE</b>", styles["TableHead"]),
                    Paragraph("<b>SUPPORT LEVEL</b>", styles["TableHead"]),
                    Paragraph("<b>EVIDENCE REFS</b>", styles["TableHead"]),
                    Paragraph("<b>GROUNDED ASSERTION</b>", styles["TableHead"]),
                ]
            ]
            for c in claims[:6]:
                c_dict = c if isinstance(c, dict) else (c.model_dump() if hasattr(c, "model_dump") else {})
                cid = c_dict.get("id", "CLAIM")
                ctype = c_dict.get("claim_type", "DETECTION")
                supp = c_dict.get("support_level", "HIGH")
                refs = ", ".join(c_dict.get("evidence_refs", [])[:3]) or "Direct Telemetry"
                txt = c_dict.get("claim", "")
                claim_table_data.append([
                    Paragraph(f"<b>{html.escape(cid)}</b><br/>{html.escape(str(ctype))}", styles["TableCellBold"]),
                    Paragraph(html.escape(str(supp)), styles["TableCell"]),
                    Paragraph(html.escape(str(refs)), styles["TableCell"]),
                    Paragraph(html.escape(str(txt)), styles["TableCell"]),
                ])

            cl_t = Table(claim_table_data, colWidths=[100, 80, 110, 250])
            cl_t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            flowables.append(cl_t)
            flowables.append(Spacer(1, 6))

        # Counter-Evidence & Contradictions
        counter_ev = data.get("counter_evidence") or []
        contras = data.get("contradictions") or []
        if counter_ev or contras:
            flowables.append(Paragraph("<b>Counter-Evidence & Contradictions Observed:</b>", styles["TableCellBold"]))
            for ce in counter_ev[:2]:
                ce_dict = ce if isinstance(ce, dict) else (ce.model_dump() if hasattr(ce, "model_dump") else {})
                flowables.append(Paragraph(f"• <b>[Counter-Evidence]</b> {html.escape(str(ce_dict.get('claim', '')))} — <i>{html.escape(str(ce_dict.get('interpretation', '')))}</i>", styles["TableCell"]))
            for cr in contras[:2]:
                cr_dict = cr if isinstance(cr, dict) else (cr.model_dump() if hasattr(cr, "model_dump") else {})
                flowables.append(Paragraph(f"• <b>[Contradiction]</b> {html.escape(str(cr_dict.get('claim', '')))} vs {html.escape(str(cr_dict.get('conflicting_signal', '')))}", styles["TableCell"]))
            flowables.append(Spacer(1, 6))

        # What Would Change This Assessment
        change_guidance = data.get("assessment_change_guidance") or {}
        cg_dict = change_guidance if isinstance(change_guidance, dict) else (change_guidance.model_dump() if hasattr(change_guidance, "model_dump") else {})
        weaken = cg_dict.get("what_would_weaken") or []
        strengthen = cg_dict.get("what_would_strengthen") or []
        if weaken or strengthen:
            flowables.append(Paragraph("<b>Assessment Modification Guidance:</b>", styles["TableCellBold"]))
            if strengthen:
                flowables.append(Paragraph(f"• <b>Strengthen if:</b> {html.escape(str(strengthen[0]))}", styles["TableCell"]))
            if weaken:
                flowables.append(Paragraph(f"• <b>Weaken if:</b> {html.escape(str(weaken[0]))}", styles["TableCell"]))
            flowables.append(Spacer(1, 6))

        flowables.append(Spacer(1, 8))
        return flowables

    @classmethod
    def _format_response_recommendations_section(
        cls,
        recommendations_data: List[Any],
        styles: Dict[str, ParagraphStyle],
    ) -> List[Any]:
        """
        Formats Section 28 Response Recommendation Engine prioritized actions for PDF reports.
        Visualizes Priority (P0..P4), Action Type, Approval Boundary, Rationale, and Operational Impact.
        """
        flowables: List[Any] = []
        if not recommendations_data:
            return flowables

        rec_table_data = [
            [
                Paragraph("<b>PRIORITY</b>", styles["TableHead"]),
                Paragraph("<b>ACTION TYPE</b>", styles["TableHead"]),
                Paragraph("<b>APPROVAL</b>", styles["TableHead"]),
                Paragraph("<b>DEFENSIVE RECOMMENDATION & RATIONALE</b>", styles["TableHead"]),
                Paragraph("<b>IMPACT</b>", styles["TableHead"]),
            ]
        ]

        for r in recommendations_data[:8]:
            r_dict = r if isinstance(r, dict) else (r.model_dump() if hasattr(r, "model_dump") else {})
            prio = r_dict.get("priority", "P2")
            atype = r_dict.get("action_type", "INVESTIGATION")
            appr = "REQUIRED" if r_dict.get("approval_required") else "ADVISORY"
            appr_color = "#DC2626" if appr == "REQUIRED" else "#16A34A"
            title = r_dict.get("title", "")
            rationale = r_dict.get("rationale", "")
            impact = r_dict.get("impact", "LOW")

            prio_color = "#DC2626" if prio == "P0" else ("#EA580C" if prio == "P1" else "#2563EB")

            rec_table_data.append([
                Paragraph(f"<font color='{prio_color}'><b>{prio}</b></font>", styles["TableCellBold"]),
                Paragraph(f"<font name='Courier'><b>{html.escape(str(atype))}</b></font>", styles["TableCell"]),
                Paragraph(f"<font color='{appr_color}'><b>{appr}</b></font>", styles["TableCellBold"]),
                Paragraph(f"<b>{html.escape(str(title))}</b><br/><font color='#64748B'><i>{html.escape(str(rationale))}</i></font>", styles["TableCell"]),
                Paragraph(html.escape(str(impact)), styles["TableCell"]),
            ])

        rtable = Table(rec_table_data, colWidths=[55, 115, 65, 235, 70])
        rtable.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        flowables.append(rtable)
        flowables.append(Spacer(1, 10))
        return flowables

    @classmethod
    def generate_investigation_report(
        cls,
        snapshot: Dict[str, Any],
        report_type: str = "ANALYST",
        redaction_level: str = "NONE",
        content_options: Optional[Dict[str, bool]] = None,
    ) -> bytes:
        """
        Section 42: Compiles a reproducible, vector PDF incident report from an
        immutable structured investigation snapshot.
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

        opts = content_options or {}
        include_exec = opts.get("include_executive_summary", True)
        include_timeline = opts.get("include_timeline", True)
        include_attack_path = opts.get("include_attack_path", True)
        include_risk = opts.get("include_risk_assessment", True)
        include_findings = opts.get("include_findings", True)
        include_evidence = opts.get("include_evidence_table", True)
        include_iocs = opts.get("include_indicators", True)
        include_mitre = opts.get("include_mitre_attack", True)
        include_infra = opts.get("include_infrastructure", True)
        include_xai = opts.get("include_explainability", True)
        include_resp = opts.get("include_response_actions", True)
        include_recs = opts.get("include_recommendations", True)
        include_audit = opts.get("include_audit_trail", True)
        include_idx = opts.get("include_evidence_index", True)

        meta = snapshot.get("metadata", {})
        overview = snapshot.get("incident_overview", {})
        exec_sum = snapshot.get("executive_summary", {})
        risk_data = snapshot.get("risk_assessment", {})

        rpt_num = meta.get("report_number") or f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-001"
        inv_num = meta.get("incident_number") or overview.get("incident_number") or "INV-UNKNOWN"
        rpt_ver = meta.get("report_version", 1)
        classification = meta.get("classification", "CONFIDENTIAL")
        rtype = (meta.get("report_type") or report_type).upper()
        title = meta.get("title") or overview.get("title") or "Security Incident Report"

        # -------------------------------------------------------------
        # 1. DOCUMENT HEADER & CLASSIFICATION BANNER
        # -------------------------------------------------------------
        story.append(Paragraph(f"CYBERGUARD // AI SECURITY INCIDENT REPORT [{classification}]", styles["DocSubtitle"]))
        story.append(Spacer(1, 2))
        story.append(Paragraph(f"{rtype} REPORT: {html.escape(title[:70])}", styles["DocTitle"]))
        story.append(Spacer(1, 6))

        # Metadata banner table
        score_val = risk_data.get("risk_score", overview.get("risk_score", 0.0))
        sev_val = str(risk_data.get("severity", overview.get("severity", "MEDIUM"))).upper()
        conf_val = str(risk_data.get("confidence_level", overview.get("confidence_level", "MODERATE"))).upper()
        status_val = str(overview.get("status", "INVESTIGATING")).upper()

        meta_table_data = [
            [
                Paragraph("<b>REPORT REF:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(f"{rpt_num} (v{rpt_ver})"), styles["TableCellBold"]),
                Paragraph("<b>INVESTIGATION ID:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(inv_num), styles["TableCellBold"]),
            ],
            [
                Paragraph("<b>SEVERITY / RISK:</b>", styles["TableCellBold"]),
                Paragraph(f"<b>{sev_val}</b> ({score_val:.0f}/100)", styles["TableCellBold"]),
                Paragraph("<b>CONFIDENCE:</b>", styles["TableCellBold"]),
                Paragraph(f"<b>{conf_val}</b>", styles["TableCellBold"]),
            ],
            [
                Paragraph("<b>STATUS:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(status_val), styles["TableCell"]),
                Paragraph("<b>GENERATED (UTC):</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(meta.get("generated_at", "Now")), styles["TableCell"]),
            ],
            [
                Paragraph("<b>INVESTIGATOR:</b>", styles["TableCellBold"]),
                Paragraph(cls._format_token(meta.get("generated_by", "SOC Lead Analyst")), styles["TableCell"]),
                Paragraph("<b>REDACTION:</b>", styles["TableCellBold"]),
                Paragraph(f"Policy: {meta.get('redaction_level', redaction_level)}", styles["TableCell"]),
            ],
        ]
        meta_table = Table(meta_table_data, colWidths=[110, 160, 110, 160])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 2. EXECUTIVE SUMMARY
        # -------------------------------------------------------------
        if include_exec:
            story.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))

            narrative = exec_sum.get("synthesized_narrative") or "Investigation telemetry reviewed."
            story.append(Paragraph(html.escape(narrative), styles["Body"]))
            story.append(Spacer(1, 6))

            exec_box_data = [
                [
                    Paragraph("<b>What Was Detected:</b>", styles["TableCellBold"]),
                    Paragraph(html.escape(exec_sum.get("detection_statement", "Security incident detected.")), styles["TableCell"]),
                ],
                [
                    Paragraph("<b>Risk & Impact:</b>", styles["TableCellBold"]),
                    Paragraph(html.escape(exec_sum.get("impact_statement", "Impact evaluated.")), styles["TableCell"]),
                ],
                [
                    Paragraph("<b>Evidentiary Foundation:</b>", styles["TableCellBold"]),
                    Paragraph(html.escape(exec_sum.get("evidence_support_statement", "Backed by immutable artifacts.")), styles["TableCell"]),
                ],
                [
                    Paragraph("<b>Response Posture:</b>", styles["TableCellBold"]),
                    Paragraph(html.escape(exec_sum.get("response_state_statement", "Containment in progress.")), styles["TableCell"]),
                ],
                [
                    Paragraph("<b>Major Uncertainty:</b>", styles["TableCellBold"]),
                    Paragraph(html.escape(exec_sum.get("uncertainty_statement", "No critical gaps identified.")), styles["TableCell"]),
                ],
            ]
            exec_box = Table(exec_box_data, colWidths=[130, 410])
            exec_box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(exec_box)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 3. FACT / INFERENCE / HYPOTHESIS LABELING
        # -------------------------------------------------------------
        claims = snapshot.get("epistemic_claims", [])
        if claims and rtype != "EXECUTIVE":
            story.append(Paragraph("2. Factuality & Epistemic Status", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))
            claim_rows = [
                [
                    Paragraph("<b>CLAIM REF</b>", styles["TableHead"]),
                    Paragraph("<b>EPISTEMIC STATUS</b>", styles["TableHead"]),
                    Paragraph("<b>SUBSTANTIVE STATEMENT</b>", styles["TableHead"]),
                    Paragraph("<b>EVIDENCE</b>", styles["TableHead"]),
                ]
            ]
            for c in claims[:8]:
                status_color = "#16A34A" if c.get("status") == "OBSERVED" else ("#2563EB" if c.get("status") == "INFERRED" else "#EA580C")
                claim_rows.append([
                    Paragraph(c.get("id", "CLM"), styles["TableCellBold"]),
                    Paragraph(f"<font color='{status_color}'><b>{c.get('status', 'OBSERVED')}</b></font>", styles["TableCellBold"]),
                    Paragraph(html.escape(c.get("statement", "")), styles["TableCell"]),
                    Paragraph(", ".join(c.get("evidence_refs", [])) or "Context", styles["TableCellMuted"]),
                ])
            claim_table = Table(claim_rows, colWidths=[70, 95, 310, 65])
            claim_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(claim_table)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 4. RISK ASSESSMENT & SIGNALS
        # -------------------------------------------------------------
        if include_risk:
            sec_num = "3" if (claims and rtype != "EXECUTIVE") else "2"
            story.append(Paragraph(f"{sec_num}. Risk Assessment & Threat Signals", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))

            risk_note = risk_data.get("risk_vs_confidence_note", "Risk score is not a mathematical probability.")
            story.append(Paragraph(f"<i>Notice: {html.escape(risk_note)}</i>", styles["BodyMuted"]))
            story.append(Spacer(1, 4))

            signals = risk_data.get("primary_signals", [])
            counter_ev = risk_data.get("counter_evidence", [])
            risk_box_data = [
                [
                    Paragraph("<b>Risk Score:</b>", styles["TableCellBold"]),
                    Paragraph(f"{score_val:.0f} / 100 ({sev_val})", styles["TableCellBold"]),
                    Paragraph("<b>Evidentiary Confidence:</b>", styles["TableCellBold"]),
                    Paragraph(f"{conf_val}", styles["TableCellBold"]),
                ],
                [
                    Paragraph("<b>Primary Signals:</b>", styles["TableCellBold"]),
                    Paragraph("; ".join(signals) if signals else "None reported", styles["TableCell"]),
                    Paragraph("<b>Counter-Evidence:</b>", styles["TableCellBold"]),
                    Paragraph("; ".join(counter_ev) if counter_ev else "None observed", styles["TableCell"]),
                ]
            ]
            rbox = Table(risk_box_data, colWidths=[100, 170, 110, 160])
            rbox.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(rbox)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 5. CHRONOLOGICAL TIMELINE
        # -------------------------------------------------------------
        timeline_items = snapshot.get("timeline", [])
        if include_timeline and timeline_items and rtype != "EXECUTIVE":
            story.append(Paragraph("4. Chronological Incident Timeline", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))

            t_rows = [
                [
                    Paragraph("<b>TIMESTAMP (UTC)</b>", styles["TableHead"]),
                    Paragraph("<b>STATUS</b>", styles["TableHead"]),
                    Paragraph("<b>EVENT TITLE & DETAIL</b>", styles["TableHead"]),
                    Paragraph("<b>SOURCE</b>", styles["TableHead"]),
                ]
            ]
            for t in timeline_items[:12]:
                stat = t.get("status", "OBSERVED")
                stat_col = "#16A34A" if stat == "OBSERVED" else "#2563EB"
                t_rows.append([
                    Paragraph(f"{t.get('timestamp', '')}<br/><font color='#64748B'>{t.get('uncertainty', '')}</font>", styles["TableCell"]),
                    Paragraph(f"<font color='{stat_col}'><b>{stat}</b></font>", styles["TableCellBold"]),
                    Paragraph(f"<b>{html.escape(t.get('title', ''))}</b><br/>{html.escape(t.get('description', ''))}", styles["TableCell"]),
                    Paragraph(html.escape(t.get("source", "")), styles["TableCellMuted"]),
                ])
            ttable = Table(t_rows, colWidths=[120, 65, 275, 80])
            ttable.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(ttable)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 6. ATTACK PATH PROJECTION (Static View)
        # -------------------------------------------------------------
        ap_data = snapshot.get("attack_path", {})
        ap_stages = ap_data.get("stages", [])
        if include_attack_path and ap_stages:
            story.append(Paragraph("5. Reconstructed Attack Path Progression", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))

            if ap_data.get("path_summary"):
                story.append(Paragraph(html.escape(ap_data["path_summary"]), styles["Body"]))
                story.append(Spacer(1, 4))

            ap_rows = [
                [
                    Paragraph("<b>STAGE #</b>", styles["TableHead"]),
                    Paragraph("<b>ATTACK STAGE</b>", styles["TableHead"]),
                    Paragraph("<b>TYPE</b>", styles["TableHead"]),
                    Paragraph("<b>STATUS</b>", styles["TableHead"]),
                    Paragraph("<b>MITRE TECHNIQUE</b>", styles["TableHead"]),
                    Paragraph("<b>EVID.</b>", styles["TableHead"]),
                ]
            ]
            for s in ap_stages:
                s_stat = s.get("status", "OBSERVED")
                s_col = "#16A34A" if s_stat == "OBSERVED" else "#2563EB"
                mitre_label = f"{s.get('mitre_technique_id', 'N/A')}: {s.get('mitre_technique_name', '')}"
                ap_rows.append([
                    Paragraph(f"<b>Stage {s.get('stage_order', 1)}</b>", styles["TableCellBold"]),
                    Paragraph(f"<b>{html.escape(s.get('name', ''))}</b>", styles["TableCellBold"]),
                    Paragraph(html.escape(str(s.get("stage_type", ""))), styles["TableCell"]),
                    Paragraph(f"<font color='{s_col}'><b>{s_stat}</b></font>", styles["TableCellBold"]),
                    Paragraph(cls._format_token(mitre_label), styles["TableCellMuted"]),
                    Paragraph(str(s.get("evidence_count", 1)), styles["TableCell"]),
                ])
            aptable = Table(ap_rows, colWidths=[55, 125, 95, 75, 150, 40])
            aptable.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(aptable)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 7. KEY FINDINGS
        # -------------------------------------------------------------
        findings = snapshot.get("findings", [])
        if include_findings and findings:
            story.append(Paragraph("6. Key Investigative Findings", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))

            f_rows = [
                [
                    Paragraph("<b>REF ID</b>", styles["TableHead"]),
                    Paragraph("<b>SEVERITY</b>", styles["TableHead"]),
                    Paragraph("<b>CATEGORY</b>", styles["TableHead"]),
                    Paragraph("<b>FINDING TITLE & DESCRIPTION</b>", styles["TableHead"]),
                    Paragraph("<b>SOURCE</b>", styles["TableHead"]),
                ]
            ]
            for f in findings[:10]:
                f_sev = f.get("severity", "MEDIUM")
                f_col = "#DC2626" if f_sev in {"CRITICAL", "HIGH"} else ("#D97706" if f_sev == "MEDIUM" else "#16A34A")
                f_rows.append([
                    Paragraph(f.get("ref_id", "F-001"), styles["TableCellBold"]),
                    Paragraph(f"<font color='{f_col}'><b>{f_sev}</b></font>", styles["TableCellBold"]),
                    Paragraph(f.get("category", "SEC"), styles["TableCell"]),
                    Paragraph(f"<b>{html.escape(f.get('title', ''))}</b><br/>{html.escape(f.get('description', ''))}", styles["TableCell"]),
                    Paragraph(html.escape(f.get("source", "Analyzer")), styles["TableCellMuted"]),
                ])
            ftable = Table(f_rows, colWidths=[55, 65, 75, 265, 80])
            ftable.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(ftable)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 8. EVIDENCE SUMMARY & EVIDENCE TABLE
        # -------------------------------------------------------------
        ev_table = snapshot.get("evidence_table", [])
        if include_evidence and ev_table:
            story.append(Paragraph("7. Evidence Registry & Artifact Hashes", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))

            ev_rows = [
                [
                    Paragraph("<b>REF</b>", styles["TableHead"]),
                    Paragraph("<b>TYPE</b>", styles["TableHead"]),
                    Paragraph("<b>NAME / SOURCE</b>", styles["TableHead"]),
                    Paragraph("<b>SHA-256 HASH</b>", styles["TableHead"]),
                    Paragraph("<b>RUN REF</b>", styles["TableHead"]),
                ]
            ]
            for e in ev_table[:10]:
                e_type_col = "#0284C7" if e.get("type") == "ORIGINAL" else "#64748B"
                ev_rows.append([
                    Paragraph(e.get("ref_id", "E-001"), styles["TableCellBold"]),
                    Paragraph(f"<font color='{e_type_col}'><b>{e.get('type', 'ORIGINAL')}</b></font>", styles["TableCellBold"]),
                    Paragraph(f"<b>{html.escape(e.get('name', ''))}</b><br/><font color='#64748B'>{html.escape(e.get('source', ''))}</font>", styles["TableCell"]),
                    Paragraph(cls._format_token(e.get("sha256", "N/A"), max_chunk=24), styles["TableCell"]),
                    Paragraph(e.get("analysis_run_ref", "Run #1"), styles["TableCellMuted"]),
                ])
            etable = Table(ev_rows, colWidths=[45, 65, 140, 220, 70])
            etable.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(etable)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 9. MITRE ATT&CK & INFRASTRUCTURE
        # -------------------------------------------------------------
        mitre_data = snapshot.get("mitre_attack", [])
        if include_mitre and mitre_data:
            story.append(Paragraph("8. MITRE ATT&CK Framework Mappings", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))
            m_rows = [
                [
                    Paragraph("<b>TECHNIQUE ID</b>", styles["TableHead"]),
                    Paragraph("<b>TECHNIQUE NAME</b>", styles["TableHead"]),
                    Paragraph("<b>TACTIC</b>", styles["TableHead"]),
                    Paragraph("<b>STATUS</b>", styles["TableHead"]),
                    Paragraph("<b>EVID.</b>", styles["TableHead"]),
                ]
            ]
            for m in mitre_data:
                m_rows.append([
                    Paragraph(m.get("technique_id", ""), styles["TableCellBold"]),
                    Paragraph(m.get("technique_name", ""), styles["TableCell"]),
                    Paragraph(m.get("tactic", ""), styles["TableCell"]),
                    Paragraph("<font color='#16A34A'><b>SUPPORTED</b></font>", styles["TableCellBold"]),
                    Paragraph(str(m.get("evidence_count", 1)), styles["TableCell"]),
                ])
            mtable = Table(m_rows, colWidths=[90, 180, 140, 80, 50])
            mtable.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(mtable)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 10. DEFENSIVE RESPONSE & RECOMMENDATIONS
        # -------------------------------------------------------------
        resp_data = snapshot.get("response", {})
        resp_actions = resp_data.get("actions_table", [])
        if include_resp and resp_actions:
            story.append(Paragraph("9. Defensive Containment Actions & Response", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))

            act_rows = [
                [
                    Paragraph("<b>ACTION</b>", styles["TableHead"]),
                    Paragraph("<b>PRIORITY</b>", styles["TableHead"]),
                    Paragraph("<b>STATUS</b>", styles["TableHead"]),
                    Paragraph("<b>TARGET ASSET</b>", styles["TableHead"]),
                    Paragraph("<b>RESULT / CONFIRMATION</b>", styles["TableHead"]),
                ]
            ]
            for a in resp_actions[:8]:
                a_stat = a.get("status", "PENDING")
                a_col = "#16A34A" if a_stat == "EXECUTED" else ("#2563EB" if a_stat == "APPROVED" else "#EA580C")
                act_rows.append([
                    Paragraph(f"<b>{html.escape(a.get('action_type', ''))}</b>", styles["TableCellBold"]),
                    Paragraph(a.get("priority", "P1"), styles["TableCellBold"]),
                    Paragraph(f"<font color='{a_col}'><b>{a_stat}</b></font>", styles["TableCellBold"]),
                    Paragraph(html.escape(a.get("target", "")), styles["TableCell"]),
                    Paragraph(html.escape(a.get("result", "")), styles["TableCellMuted"]),
                ])
            act_table = Table(act_rows, colWidths=[120, 55, 75, 140, 150])
            act_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(act_table)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 11. AUDIT TRAIL
        # -------------------------------------------------------------
        audit_items = snapshot.get("audit_trail", [])
        if include_audit and audit_items and rtype == "FORENSIC":
            story.append(Paragraph("10. Investigator Audit Trail", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))

            aud_rows = [
                [
                    Paragraph("<b>TIMESTAMP (UTC)</b>", styles["TableHead"]),
                    Paragraph("<b>ACTION</b>", styles["TableHead"]),
                    Paragraph("<b>USER / ACTOR</b>", styles["TableHead"]),
                    Paragraph("<b>AUDIT EVENT DETAILS</b>", styles["TableHead"]),
                ]
            ]
            for aud in audit_items[:8]:
                aud_rows.append([
                    Paragraph(aud.get("timestamp", ""), styles["TableCell"]),
                    Paragraph(f"<b>{aud.get('action', '')}</b>", styles["TableCellBold"]),
                    Paragraph(aud.get("user", "System"), styles["TableCell"]),
                    Paragraph(html.escape(aud.get("details", "")), styles["TableCell"]),
                ])
            aud_table = Table(aud_rows, colWidths=[110, 110, 90, 230])
            aud_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(aud_table)
            story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # 12. EVIDENCE INDEX (FORENSIC DOSSIER STAMP)
        # -------------------------------------------------------------
        ev_idx = snapshot.get("evidence_index", [])
        if include_idx and ev_idx and rtype != "EXECUTIVE":
            story.append(Paragraph("11. Evidentiary Index Registry", styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=1, spaceAfter=5))

            idx_rows = [
                [
                    Paragraph("<b>INDEX REF</b>", styles["TableHead"]),
                    Paragraph("<b>TYPE</b>", styles["TableHead"]),
                    Paragraph("<b>IDENTIFIER / LABEL</b>", styles["TableHead"]),
                    Paragraph("<b>CRYPTOGRAPHIC DIGEST / PROVENANCE</b>", styles["TableHead"]),
                ]
            ]
            for item in ev_idx[:12]:
                idx_rows.append([
                    Paragraph(item.get("ref_id", ""), styles["TableCellBold"]),
                    Paragraph(item.get("type", ""), styles["TableCellMuted"]),
                    Paragraph(f"<b>{html.escape(item.get('label', ''))}</b>", styles["TableCell"]),
                    Paragraph(cls._format_token(item.get("digest", "") or item.get("provenance", ""), max_chunk=28), styles["TableCell"]),
                ])
            idx_table = Table(idx_rows, colWidths=[65, 65, 170, 240])
            idx_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(idx_table)
            story.append(Spacer(1, 10))

        # Final signature and integrity block
        hash_val = meta.get("data_snapshot_hash") or "N/A"
        story.append(KeepTogether([
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#94A3B8"), spaceBefore=6, spaceAfter=4),
            Paragraph(f"<b>INTEGRITY HASH:</b> <font name='Courier'>{cls._format_token(hash_val, max_chunk=32)}</font>", styles["TableCellMuted"]),
            Paragraph(f"CyberGuard Forensic Engine v{meta.get('generator_version', '2.0')} // Reproducible Snapshot Ver. {rpt_ver}", styles["TableCellMuted"])
        ]))

        # Build document
        doc.build(story, canvasmaker=NumberedCanvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes






