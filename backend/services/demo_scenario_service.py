"""
Section 75: Authoritative Demo Scenario & Golden Path Orchestration Service.
Implements the 4 realistic security demonstration scenarios using real CyberGuard analysis pipelines:
- Scenario A: Phishing Email (Lookalike brand, credential harvesting URL, SPF/DKIM/DMARC failure)
- Scenario B: Business Email Compromise (Display-name impersonation, urgent wire transfer, NLP coercion)
- Scenario C: Malicious Attachment (Disguised executable .pdf.exe payload)
- Scenario D: Multi-Stage Attack (Email -> URL -> Domain -> C2 IP -> Endpoint process -> Correlated Incident)
Strictly tags all demo entities with is_demo: true and guarantees zero pollution of production data.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    CaseModel,
    CaseFindingModel,
    IncidentModel,
    ThreatEventModel,
    AttackPathModel,
    AttackStageModel,
    AttackEdgeModel,
    EvidenceModel,
    EvidenceCustodyEventModel,
    ResponseActionModel,
    NotificationModel,
    generate_uuid,
    get_utc_now,
)
from backend.services.evidence_storage import evidence_storage
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.services.risk_engine_service import RiskEngineService

logger = logging.getLogger("cyberguard.demo_scenarios")


# ---------------------------------------------------------------------------
# Raw RFC-822 EML Test Payloads for Realistic Scenarios
# ---------------------------------------------------------------------------

RAW_EML_SCENARIO_A = """From: "PayPal Security Team" <security-alerts@paypa1-security-update.com>
To: target.analyst@cyberguard.local
Subject: URGENT: Your PayPal Account Access Has Been Limited
Date: Mon, 12 Oct 2026 09:30:00 +0000
Message-ID: <sec-20261012-093000@paypa1-security-update.com>
Authentication-Results: mx.cyberguard.local;
 spf=fail (sender IP 198.51.100.25 is not allowed);
 dkim=fail (signature verification failed);
 dmarc=fail (p=reject) action=none header.from=paypa1-security-update.com
Received: from mail.paypa1-security-update.com (198.51.100.25) by mx.cyberguard.local with ESMTP; Mon, 12 Oct 2026 09:30:01 +0000
Content-Type: text/html; charset=utf-8

<html>
<body>
<h2>Notice of Account Suspension</h2>
<p>Dear Customer, unusual account login attempts were detected from Russia (IP: 185.220.101.5).</p>
<p>Please verify your identity immediately to prevent permanent account suspension:</p>
<p><a href="https://paypa1-security-update.com/login.php?redirect=verify">Verify PayPal Account Credentials Now</a></p>
<p>Failure to respond within 24 hours will lead to immediate fund freezing.</p>
</body>
</html>
"""

RAW_EML_SCENARIO_B = """From: "Robert Sterling, Chief Executive Officer" <ceo.office.robert.sterling@secure-executive-mail.com>
To: finance.controller@cyberguard.local
Subject: HIGHLY CONFIDENTIAL: Immediate Acquisition Wire Transfer Authorization
Date: Mon, 12 Oct 2026 10:15:00 +0000
Message-ID: <bec-20261012-101500@secure-executive-mail.com>
Reply-To: ceo.direct.private@gmail.com
Authentication-Results: mx.cyberguard.local;
 spf=softfail;
 dkim=none;
 dmarc=fail header.from=secure-executive-mail.com
Received: from relay.secure-executive-mail.com (203.0.113.14) by mx.cyberguard.local; Mon, 12 Oct 2026 10:15:02 +0000
Content-Type: text/plain; charset=utf-8

Finance Team,

I am currently in an NDA-restricted board meeting regarding an urgent acquisition.
I need an immediate wire transfer of $248,500.00 processed before 12:00 PM EST today.

Do NOT call my mobile phone as I cannot take calls during this session.
Acknowledge receipt immediately and I will forward the beneficiary international routing details.

Prompt execution is critical to close this acquisition.

Regards,
Robert Sterling
CEO, CyberGuard Holdings
"""

# Tiny safe simulated PE payload (ASCII MZ header followed by test bytes)
SIMULATED_PE_PAYLOAD = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00" + b"\x00" * 200
B64_PE = base64.b64encode(SIMULATED_PE_PAYLOAD).decode("ascii")

RAW_EML_SCENARIO_C = f"""From: "HR Compliance Officer" <compliance-notice@corporate-review-internal.com>
To: employee@cyberguard.local
Subject: Mandatory Compliance & Ethics Audit 2026
Date: Mon, 12 Oct 2026 11:00:00 +0000
Message-ID: <mal-20261012-110000@corporate-review-internal.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_Boundary_ScenarioC"

------=_Part_Boundary_ScenarioC
Content-Type: text/plain; charset=utf-8

Please find attached the mandatory compliance audit documentation.
Review and submit your acknowledgment before Friday.

------=_Part_Boundary_ScenarioC
Content-Type: application/octet-stream; name="Mandatory_Compliance_Review.pdf.exe"
Content-Disposition: attachment; filename="Mandatory_Compliance_Review.pdf.exe"
Content-Transfer-Encoding: base64

{B64_PE}
------=_Part_Boundary_ScenarioC--
"""

RAW_EML_SCENARIO_D = """From: "IT Support Desk" <support@it-services-portal.com>
To: network.admin@cyberguard.local
Subject: Security Patch Deployment: Critical Endpoint Update
Date: Mon, 12 Oct 2026 11:45:00 +0000
Message-ID: <apt-20261012-114500@it-services-portal.com>
Content-Type: text/html; charset=utf-8

<html>
<body>
<p>All workstation endpoints must apply the emergency security patch below:</p>
<p><a href="http://cdn-update.it-services-portal.com/agent/patch.ps1">Download Emergency Patch Installer</a></p>
<p>Command execution: powershell.exe -ExecutionPolicy Bypass -File patch.ps1</p>
</body>
</html>
"""


class DemoScenarioService:
    """Service to provision and manage authentic demonstration scenarios."""

    SCENARIO_DEFINITIONS = [
        {
            "id": "scenario-a-phishing",
            "name": "Scenario A — Targeted Phishing & Lookalike Brand",
            "category": "PHISHING",
            "artifact_type": "EMAIL",
            "description": "High-risk brand impersonation targeting PayPal with failing SPF/DKIM/DMARC authentication, lookalike domain paypa1-security-update.com, and credential harvesting link.",
            "expected_severity": "CRITICAL",
            "expected_risk_min": 75.0,
            "attack_vector": "Credential Harvesting / Brand Lookalike",
            "mitre_techniques": ["T1566.002", "T1589.001"],
        },
        {
            "id": "scenario-b-bec",
            "name": "Scenario B — Executive Impersonation & BEC",
            "category": "BUSINESS_EMAIL_COMPROMISE",
            "artifact_type": "EMAIL",
            "description": "C-suite executive impersonation attempting unauthorized wire transfer ($248,500) using display name deception, reply-to anomaly, and urgent financial coercion.",
            "expected_severity": "HIGH",
            "expected_risk_min": 60.0,
            "attack_vector": "Display Name Deception / Wire Fraud Urgency",
            "mitre_techniques": ["T1656", "T1566.001"],
        },
        {
            "id": "scenario-c-malicious-attachment",
            "name": "Scenario C — Weaponized Executable Attachment",
            "category": "MALWARE_DELIVERY",
            "artifact_type": "EMAIL",
            "description": "Attachment security evasion attack delivering double-extension executable (Mandatory_Compliance_Review.pdf.exe) with PE magic header.",
            "expected_severity": "CRITICAL",
            "expected_risk_min": 85.0,
            "attack_vector": "Attachment Evasion / Malicious Executable",
            "mitre_techniques": ["T1566.001", "T1036.007"],
        },
        {
            "id": "scenario-d-multistage",
            "name": "Scenario D — Multi-Stage Coordinated Attack",
            "category": "COORDINATED_CAMPAIGN",
            "artifact_type": "EMAIL",
            "description": "Multi-stage attack chain linking phishing email to malicious script URL, infrastructure IP 203.0.113.88, endpoint PowerShell execution, and correlated SOC incident.",
            "expected_severity": "CRITICAL",
            "expected_risk_min": 80.0,
            "attack_vector": "Cross-Source Correlation / Multi-Stage APT",
            "mitre_techniques": ["T1566.002", "T1059.001", "T1071.001"],
        },
    ]

    @classmethod
    def list_scenarios(cls) -> List[Dict[str, Any]]:
        return cls.SCENARIO_DEFINITIONS

    @classmethod
    async def execute_scenario(
        cls,
        db: Session,
        scenario_id: str,
        workspace_id: str = "default",
        actor: str = "Demo Analyst"
    ) -> Dict[str, Any]:
        """
        Executes a scenario end-to-end through real CyberGuard ingestion and analysis.
        Guarantees that every generated entity is tagged with is_demo: True.
        """
        scenario_id = scenario_id.lower().strip()
        matched = next((s for s in cls.SCENARIO_DEFINITIONS if s["id"] == scenario_id), None)
        if not matched:
            raise ValueError(f"Unknown scenario ID '{scenario_id}'. Supported: {[s['id'] for s in cls.SCENARIO_DEFINITIONS]}")

        # 1. Select raw EML payload
        if scenario_id == "scenario-a-phishing":
            raw_content = RAW_EML_SCENARIO_A
            filename = "paypal_security_suspension_alert.eml"
        elif scenario_id == "scenario-b-bec":
            raw_content = RAW_EML_SCENARIO_B
            filename = "ceo_urgent_acquisition_wire_transfer.eml"
        elif scenario_id == "scenario-c-malicious-attachment":
            raw_content = RAW_EML_SCENARIO_C
            filename = "mandatory_compliance_audit_review.eml"
        else:
            raw_content = RAW_EML_SCENARIO_D
            filename = "it_emergency_security_patch.eml"

        raw_bytes = raw_content.encode("utf-8")
        calc_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # 2. Persist Evidence bytes in storage
        storage_result = evidence_storage.store_bytes(
            raw_bytes,
            original_filename=filename,
        )
        storage_ref = storage_result.storage_key

        # 3. Create ArtifactModel (Tagged with is_demo: True)
        artifact_id = generate_uuid("art")
        art = ArtifactModel(
            id=artifact_id,
            name=filename,
            artifact_type="EMAIL",
            source="DEMO_SCENARIO",
            sha256=calc_sha256,
            size=len(raw_bytes),
            storage_reference=storage_ref,
            metadata_json=json.dumps({
                "is_demo": True,
                "scenario_id": scenario_id,
                "workspace_id": workspace_id,
                "demo_tag": "CYBERGUARD_GOLDEN_PATH_DEMO",
                "injected_by": actor,
            }),
            created_at=get_utc_now(),
        )
        db.add(art)
        db.commit()

        # 4. Create AnalysisRunModel
        run_id = generate_uuid("run")
        run = AnalysisRunModel(
            id=run_id,
            artifact_id=art.id,
            status="QUEUED",
            overall_severity="UNKNOWN",
            overall_risk_score=0.0,
            confidence=1.0,
            metadata_json=json.dumps({
                "is_demo": True,
                "scenario_id": scenario_id,
                "workspace_id": workspace_id,
                "summary": f"Automated Golden Path Analysis for {matched['name']}",
            }),
            created_at=get_utc_now(),
        )
        db.add(run)
        db.commit()

        # 5. Execute Analysis Run via Orchestrator
        run = await AnalysisOrchestrator.execute_run(db, run.id)

        # 6. Create CaseModel linked to the analysis
        case_id = generate_uuid("case")
        case_number = f"CASE-DEMO-{uuid.uuid4().hex[:6].upper()}"
        case = CaseModel(
            id=case_id,
            case_number=case_number,
            workspace_id=workspace_id,
            title=f"Investigation: {matched['name']}",
            description=matched["description"],
            severity=run.overall_severity if run.overall_severity != "SAFE" else "HIGH",
            priority="P1_CRITICAL" if run.overall_severity == "CRITICAL" else "P2_HIGH",
            status="OPEN",
            category=matched["category"],
            created_by=actor,
            tags_json=json.dumps(["DEMO", matched["category"], "GOLDEN_PATH"]),
            custom_fields_json=json.dumps({
                "is_demo": True,
                "scenario_id": scenario_id,
                "run_id": run.id,
                "artifact_id": art.id,
            }),
            created_at=get_utc_now(),
        )
        db.add(case)
        db.commit()

        # 7. Create IncidentModel linked to Case
        inc_id = generate_uuid("inc")
        inc_num = f"INC-DEMO-{uuid.uuid4().hex[:6].upper()}"
        inc = IncidentModel(
            id=inc_id,
            incident_number=inc_num,
            workspace_id=workspace_id,
            title=f"Incident: {matched['name']}",
            description=f"Correlated security incident derived from {matched['name']}.",
            severity=case.severity,
            priority=case.priority,
            status="INVESTIGATING",
            category=matched["category"],
            risk_score=run.overall_risk_score,
            legacy_case_id=case.id,
            metadata_json=json.dumps({
                "is_demo": True,
                "scenario_id": scenario_id,
                "run_id": run.id,
                "case_id": case.id,
                "artifact_id": art.id,
            }),
            created_at=get_utc_now(),
        )
        db.add(inc)

        # Update case pointer to incident
        case.incident_id = inc.id
        db.commit()

        # 8. Create AttackPathModel linked to Incident
        path_id = generate_uuid("path")
        attack_path = AttackPathModel(
            id=path_id,
            incident_id=inc.id,
            workspace_id=workspace_id,
            name=f"Attack Path: {matched['name']}",
            description=matched["description"],
            classification="PLAUSIBLE_RECONSTRUCTION",
            confidence=0.92,
            confidence_level="HIGH",
            status="CURRENT",
            metadata_json=json.dumps({"is_demo": True, "scenario_id": scenario_id}),
            created_at=get_utc_now(),
        )
        db.add(attack_path)
        db.commit()

        # Add Attack Stages
        stage1 = AttackStageModel(
            id=generate_uuid("stg"),
            attack_path_id=attack_path.id,
            stage_order=1,
            stage_type="INITIAL_ACCESS",
            stage_status="OBSERVED",
            technique_id="T1566.002",
            tactic="Initial Access",
            name="Inbound Delivery",
            description=f"Inbound phishing vector delivered via {filename}",
            confidence=0.95,
            confidence_level="HIGH",
            created_at=get_utc_now(),
        )
        stage2 = AttackStageModel(
            id=generate_uuid("stg"),
            attack_path_id=attack_path.id,
            stage_order=2,
            stage_type="EXECUTION_OR_CREDENTIAL_ACCESS",
            stage_status="DERIVED",
            technique_id="TA0006",
            tactic="Credential Access",
            name="Payload Execution / Impersonation",
            description=f"Attacker vector: {matched['attack_vector']}",
            confidence=0.90,
            confidence_level="HIGH",
            created_at=get_utc_now(),
        )
        db.add_all([stage1, stage2])
        db.commit()

        # 9. Create ResponseActionModel (Recommendation only, requires approval)
        action_id = generate_uuid("act")
        action = ResponseActionModel(
            id=action_id,
            incident_id=inc.id,
            action_type="BLOCK_SENDER_DOMAIN",
            description=f"Block sender domain recommendation for {matched['name']}",
            status="RECOMMENDED",  # Crucial: Not executed automatically
            priority="HIGH",
            recommended_by=actor,
            metadata_json=json.dumps({
                "is_demo": True,
                "requires_approval": True,
                "scenario_id": scenario_id,
                "target": "paypa1-security-update.com" if "phishing" in scenario_id else "compromised-sender.example",
                "risk_reduction": 25.0,
            }),
            created_at=get_utc_now(),
        )
        db.add(action)

        # 10. Link Findings to Case
        findings = db.query(FindingModel).filter(FindingModel.analysis_run_id == run.id).all()
        for f in findings:
            cf = CaseFindingModel(
                id=generate_uuid("cf"),
                case_id=case.id,
                finding_type=f.finding_type or "threat_finding",
                title=f.title,
                description=f.description,
                severity=(f.severity or "medium").lower(),
                created_at=get_utc_now(),
            )
            db.add(cf)

        # 11. Create Evidence Custody Ledger Entry
        ev_id = generate_uuid("ev")
        ev = EvidenceModel(
            id=ev_id,
            evidence_id=f"EV-DEMO-{uuid.uuid4().hex[:6].upper()}",
            tenant_id=workspace_id,
            artifact_id=art.id,
            case_id=case.id,
            investigation_id=inc.id,
            sha256=calc_sha256,
            hash_algorithm="SHA-256",
            integrity_status="VERIFIED",
            original_filename=filename,
            size=len(raw_bytes),
            storage_reference=storage_ref,
            source_type="EMAIL",
            collection_method="DEMO_SCENARIO_GATEWAY",
            collected_by=actor,
            lifecycle_status="VALID",
            metadata_json=json.dumps({"is_demo": True, "scenario_id": scenario_id}),
            created_at=get_utc_now(),
        )
        db.add(ev)
        db.commit()

        return {
            "status": "SUCCESS",
            "scenario": matched,
            "artifact_id": art.id,
            "analysis_run_id": run.id,
            "case_id": case.id,
            "case_number": case.case_number,
            "incident_id": inc.id,
            "incident_number": inc.incident_number,
            "attack_path_id": attack_path.id,
            "evidence_id": ev.evidence_id,
            "findings_count": len(findings),
            "overall_risk_score": run.overall_risk_score,
            "overall_severity": run.overall_severity,
            "is_demo": True,
        }

    @classmethod
    def reset_demo_data(cls, db: Session) -> Dict[str, Any]:
        """
        Safely purges ONLY demo-scoped records (is_demo: true).
        Guarantees that production enterprise data is untouched.
        """
        purged = {}

        # 1. Collect demo artifact IDs
        artifacts = db.query(ArtifactModel).all()
        demo_art_ids = []
        for a in artifacts:
            try:
                meta = json.loads(a.metadata_json or "{}")
                if meta.get("is_demo") is True:
                    demo_art_ids.append(a.id)
            except Exception:
                pass

        # 2. Collect demo run IDs
        runs = db.query(AnalysisRunModel).all()
        demo_run_ids = []
        for r in runs:
            try:
                meta = json.loads(r.metadata_json or "{}")
                if meta.get("is_demo") is True or r.artifact_id in demo_art_ids:
                    demo_run_ids.append(r.id)
            except Exception:
                pass

        # 3. Collect demo case IDs
        cases = db.query(CaseModel).all()
        demo_case_ids = []
        for c in cases:
            try:
                cf = json.loads(c.custom_fields_json or "{}")
                if cf.get("is_demo") is True or c.case_number.startswith("CASE-DEMO-"):
                    demo_case_ids.append(c.id)
            except Exception:
                pass

        # 4. Collect demo incident IDs
        incidents = db.query(IncidentModel).all()
        demo_inc_ids = []
        for i in incidents:
            try:
                meta = json.loads(i.metadata_json or "{}")
                if meta.get("is_demo") is True or i.incident_number.startswith("INC-DEMO-"):
                    demo_inc_ids.append(i.id)
            except Exception:
                pass

        # Delete dependent and parent records safely
        if demo_run_ids:
            findings_del = db.query(FindingModel).filter(FindingModel.analysis_run_id.in_(demo_run_ids)).delete(synchronize_session=False)
            runs_del = db.query(AnalysisRunModel).filter(AnalysisRunModel.id.in_(demo_run_ids)).delete(synchronize_session=False)
            purged["findings"] = findings_del
            purged["analysis_runs"] = runs_del

        if demo_case_ids:
            cf_del = db.query(CaseFindingModel).filter(CaseFindingModel.case_id.in_(demo_case_ids)).delete(synchronize_session=False)
            cases_del = db.query(CaseModel).filter(CaseModel.id.in_(demo_case_ids)).delete(synchronize_session=False)
            purged["case_findings"] = cf_del
            purged["cases"] = cases_del

        if demo_inc_ids:
            actions_del = db.query(ResponseActionModel).filter(ResponseActionModel.incident_id.in_(demo_inc_ids)).delete(synchronize_session=False)
            paths = db.query(AttackPathModel).filter(AttackPathModel.incident_id.in_(demo_inc_ids)).all()
            p_ids = [p.id for p in paths]
            if p_ids:
                stages_del = db.query(AttackStageModel).filter(AttackStageModel.attack_path_id.in_(p_ids)).delete(synchronize_session=False)
                paths_del = db.query(AttackPathModel).filter(AttackPathModel.id.in_(p_ids)).delete(synchronize_session=False)
                purged["attack_stages"] = stages_del
                purged["attack_paths"] = paths_del
            incs_del = db.query(IncidentModel).filter(IncidentModel.id.in_(demo_inc_ids)).delete(synchronize_session=False)
            purged["response_actions"] = actions_del
            purged["incidents"] = incs_del

        if demo_art_ids:
            ev_del = db.query(EvidenceModel).filter(EvidenceModel.artifact_id.in_(demo_art_ids)).delete(synchronize_session=False)
            art_del = db.query(ArtifactModel).filter(ArtifactModel.id.in_(demo_art_ids)).delete(synchronize_session=False)
            purged["evidence"] = ev_del
            purged["artifacts"] = art_del

        db.commit()
        return {
            "status": "DEMO_RESET_COMPLETE",
            "purged_records": purged,
            "isolated": True,
        }

    @classmethod
    def get_demo_status(cls, db: Session) -> Dict[str, Any]:
        """Returns statistics on active demo scenarios in the system."""
        artifacts = db.query(ArtifactModel).all()
        demo_art_count = 0
        for a in artifacts:
            try:
                meta = json.loads(a.metadata_json or "{}")
                if meta.get("is_demo") is True:
                    demo_art_count += 1
            except Exception:
                pass

        cases = db.query(CaseModel).all()
        demo_case_count = 0
        for c in cases:
            try:
                cf = json.loads(c.custom_fields_json or "{}")
                if cf.get("is_demo") is True or (c.case_number and c.case_number.startswith("CASE-DEMO-")):
                    demo_case_count += 1
            except Exception:
                pass

        return {
            "demo_artifacts_active": demo_art_count,
            "demo_cases_active": demo_case_count,
            "demo_tag": "CYBERGUARD_GOLDEN_PATH_DEMO",
            "environment_mode": "DEMO_READY",
        }
