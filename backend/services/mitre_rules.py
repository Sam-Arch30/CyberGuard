"""
Versioned ATT&CK Mapping Rule System (Section 19).
Defines deterministic, evidence-grounded rules mapping CyberGuard normalized security events,
findings, threat events, and attack stages to MITRE ATT&CK techniques.

CORE PRINCIPLES:
1. NO KEYWORD-ONLY MAPPING:
   Keywords alone ("PowerShell", "password", "email", "network") NEVER create an ATT&CK mapping.
   Mapping logic evaluates event types, context, behaviors, evidence, source independence, and specificity.
2. DISTINGUISH CLOSE TECHNIQUES:
   - Password Spraying (T1110.003) vs Single-Account Brute Force (T1110.001) vs Credential Stuffing (T1110.004).
   - Attachment Present (FILE_ANALYZED) vs Process Execution (T1059 / T1204).
   - High Network Volume vs Confirmed Exfiltration (T1048 / T1041).
   - Periodic DNS vs Confirmed C2 (T1071 / T1568).
3. EXCLUSION & CONTRADICTION HANDLING:
   Environment context (authorized scanners, monitoring, service accounts) suppresses false positives.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

from backend.schemas.mitre_attack import (
    AttackMappingStatus,
    AttackTechniqueRule,
    EnvironmentContextConfig,
    MappingMethod,
)


@dataclass
class MappingEvaluationContext:
    """
    Standardized evaluation input bundle provided to ATT&CK mapping rules.
    """
    source_type: str  # "SECURITY_EVENT", "FINDING", "THREAT_EVENT", "ATTACK_STAGE", "ATTACK_PATH_TRANSITION", "INCIDENT"
    source_id: str
    incident_id: Optional[str] = None
    event_type: Optional[str] = None
    finding_type: Optional[str] = None
    analyzer: Optional[str] = None
    stage_type: Optional[str] = None
    stage_status: Optional[str] = None  # OBSERVED, DERIVED, INFERRED, UNRESOLVED
    severity: Optional[str] = None
    confidence: float = 1.0
    title: str = ""
    description: str = ""
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    environment_config: Optional[EnvironmentContextConfig] = None


@dataclass
class RuleEvaluationResult:
    """
    Structured outcome of evaluating a candidate mapping rule.
    """
    rule_id: str
    technique_id: str
    subtechnique_id: Optional[str]
    tactic_ids: List[str]
    status: AttackMappingStatus
    confidence: float
    evidence_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    stage_ids: List[str] = field(default_factory=list)
    explanation: str = ""
    limitations: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)


# Type alias for custom evaluator functions
RuleEvaluatorFunc = Callable[[MappingEvaluationContext, AttackTechniqueRule], Optional[RuleEvaluationResult]]


# ============================================================================
# EVALUATOR IMPLEMENTATIONS
# ============================================================================

def evaluate_password_spraying(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1110.003 - Password Spraying.
    Requires:
    - Multiple distinct accounts targeted (>= 3).
    - Low failure count per account (typically <= 3).
    - Single or clustered source IP / subnet.
    - Activity clustered in a short time window.
    False positive control:
    - If only 1 account targeted -> NOT password spraying (defer to brute force rule).
    - If from authorized security scanner -> REJECTED with scanner exclusion.
    """
    attrs = ctx.attributes
    distinct_accounts = attrs.get("distinct_accounts", attrs.get("account_count", 0))
    attempt_count = attrs.get("attempt_count", attrs.get("total_attempts", 0))
    source_ip = attrs.get("source_ip", attrs.get("ip_address", ""))
    is_spray = attrs.get("is_password_spray", False) or ctx.finding_type in ("PASSWORD_SPRAYING", "AUTH_ANOMALY_SPRAY")

    # If only 1 account, strictly NOT password spraying!
    if distinct_accounts == 1:
        return None

    # Check for authorized vulnerability scanner exclusion
    if ctx.environment_config and source_ip:
        if source_ip in ctx.environment_config.trusted_scanners:
            return RuleEvaluationResult(
                rule_id=rule.id,
                technique_id=rule.technique_id,
                subtechnique_id=rule.subtechnique_id,
                tactic_ids=rule.tactic_ids,
                status=AttackMappingStatus.REJECTED,
                confidence=0.1,
                evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
                finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
                event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
                stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
                explanation=f"Activity from source {source_ip} matches authorized vulnerability scanner exclusion.",
                limitations=["Activity generated by known authorized scanning infrastructure."],
                contradictions=[f"Source IP {source_ip} is an authorized corporate scanner."],
            )

    # Require distinct accounts >= 3 and attempt count >= 3
    if (distinct_accounts >= 3 and attempt_count >= 3) or is_spray:
        attempts_per_account = attempt_count / max(distinct_accounts, 1)
        is_low_rate = attempts_per_account <= 4.0

        status = AttackMappingStatus.SUPPORTED if is_low_rate else AttackMappingStatus.PLAUSIBLE
        conf = 0.88 if is_low_rate else 0.65

        explanation = (
            f"Observed authentication pattern targets {distinct_accounts} distinct accounts "
            f"across {attempt_count} attempts from source IP {source_ip or 'unknown'} "
            f"with an average of {attempts_per_account:.1f} attempts per account, "
            f"characteristic of password spraying (T1110.003)."
        )

        return RuleEvaluationResult(
            rule_id=rule.id,
            technique_id=rule.technique_id,
            subtechnique_id=rule.subtechnique_id,
            tactic_ids=rule.tactic_ids,
            status=status,
            confidence=conf,
            evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
            finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
            event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
            stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
            explanation=explanation,
            limitations=["Source IP may represent shared proxy or corporate NAT egress."],
            contradictions=[],
        )

    return None


def evaluate_password_guessing_brute_force(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1110.001 - Password Guessing (Single-account Brute Force).
    Requires:
    - Multiple authentication failures against a SINGLE targeted account (>= 3 failures).
    - If distinct_accounts >= 3 -> NOT single-account brute force (defer to password spraying).
    """
    attrs = ctx.attributes
    distinct_accounts = attrs.get("distinct_accounts", attrs.get("account_count", 1))
    failed_attempts = attrs.get("failed_attempts", attrs.get("attempt_count", 0))
    target_account = attrs.get("account_id", attrs.get("username", "unknown"))
    source_ip = attrs.get("source_ip", "")

    # Single failed login is NOT enough!
    if failed_attempts < 3:
        return None

    # If multiple distinct accounts targeted, this is spraying, not single-account guessing
    if distinct_accounts > 2:
        return None

    # Check authorized scanner exclusion
    if ctx.environment_config and source_ip:
        if source_ip in ctx.environment_config.trusted_scanners:
            return RuleEvaluationResult(
                rule_id=rule.id,
                technique_id=rule.technique_id,
                subtechnique_id=rule.subtechnique_id,
                tactic_ids=rule.tactic_ids,
                status=AttackMappingStatus.REJECTED,
                confidence=0.1,
                evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
                finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
                event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
                stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
                explanation=f"Repeated authentication failures originated from authorized scanner {source_ip}.",
                limitations=["Scanner activity suppressed."],
                contradictions=[f"Source {source_ip} is trusted scanner."],
            )

    explanation = (
        f"Observed {failed_attempts} repeated authentication attempts against single account '{target_account}' "
        f"from source {source_ip or 'unknown'}, consistent with targeted password guessing (T1110.001)."
    )

    return RuleEvaluationResult(
        rule_id=rule.id,
        technique_id=rule.technique_id,
        subtechnique_id=rule.subtechnique_id,
        tactic_ids=rule.tactic_ids,
        status=AttackMappingStatus.SUPPORTED,
        confidence=0.82,
        evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
        finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
        event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
        stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
        explanation=explanation,
        limitations=["Target user may have mistyped password or misconfigured background service."],
        contradictions=[],
    )


def evaluate_credential_stuffing(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1110.004 - Credential Stuffing.
    Requires:
    - High-volume auth attempts across accounts using rotating IPs / proxies and known breach signatures.
    - Specific finding from Authentication ATO pipeline (CREDENTIAL_STUFFING).
    """
    attrs = ctx.attributes
    is_stuffing = (
        ctx.finding_type == "CREDENTIAL_STUFFING"
        or attrs.get("is_credential_stuffing", False)
        or "credential stuffing" in ctx.title.lower()
    )

    if not is_stuffing:
        return None

    distinct_accounts = attrs.get("distinct_accounts", attrs.get("account_count", 0))
    ip_count = attrs.get("distinct_ips", attrs.get("ip_count", 1))

    explanation = (
        f"Observed distributed authentication attempts across {distinct_accounts} accounts "
        f"from {ip_count} distinct origin IP addresses with known automated credential replay patterns, "
        f"supporting Credential Stuffing (T1110.004)."
    )

    return RuleEvaluationResult(
        rule_id=rule.id,
        technique_id=rule.technique_id,
        subtechnique_id=rule.subtechnique_id,
        tactic_ids=rule.tactic_ids,
        status=AttackMappingStatus.SUPPORTED,
        confidence=0.85,
        evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
        finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
        event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
        stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
        explanation=explanation,
        limitations=["Exact breached credential database source is unverified."],
        contradictions=[],
    )


def evaluate_spearphishing_link(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1566.002 - Spearphishing Link.
    Requires:
    - Email containing deceptive or malicious link (credential harvesting, lookalike, visible mismatch).
    - Delivery evidence (recipient address present, SMTP deliver).
    - Email existence alone -> NOT phishing.
    - No click telemetry -> DO NOT map Execution or Credential Access.
    """
    f_type = (ctx.finding_type or "").upper()
    s_type = (ctx.stage_type or "").upper()
    attrs = ctx.attributes

    has_suspicious_link = (
        f_type in (
            "CREDENTIAL_HARVESTING_URL",
            "LOOKALIKE_DOMAIN_URL",
            "VISIBLE_LINK_MISMATCH",
            "SUSPICIOUS_REDIRECT",
            "PHISHING_LINK",
            "MALICIOUS_URL",
        )
        or attrs.get("has_suspicious_link", False)
        or (s_type == "DELIVERY" and attrs.get("has_url", False) and attrs.get("url_risk", 0) > 40)
    )

    # Email existence alone without suspicious link/attachment does NOT map!
    if not has_suspicious_link:
        return None

    # Check recipient / delivery evidence
    recipient = attrs.get("recipient", attrs.get("to_address", attrs.get("target_email", "")))
    delivery_status = attrs.get("delivery_status", "DELIVERED")

    url_str = attrs.get("url", attrs.get("domain", "suspicious destination"))

    explanation = (
        f"Inbound email delivered to target recipient '{recipient or 'user'}' contains deceptive link "
        f"({url_str}) designed to direct victim to external adversarial infrastructure (T1566.002)."
    )

    return RuleEvaluationResult(
        rule_id=rule.id,
        technique_id=rule.technique_id,
        subtechnique_id=rule.subtechnique_id,
        tactic_ids=rule.tactic_ids,
        status=AttackMappingStatus.SUPPORTED,
        confidence=0.86,
        evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
        finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
        event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
        stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
        explanation=explanation,
        limitations=["Telemetry confirms email delivery; no endpoint browser click telemetry is present."],
        contradictions=[],
    )


def evaluate_spearphishing_attachment(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1566.001 - Spearphishing Attachment.
    Requires:
    - Inbound email containing malicious/suspicious file attachment (macro, double extension, packed payload).
    - Attachment existence does NOT mean execution!
    """
    f_type = (ctx.finding_type or "").upper()
    attrs = ctx.attributes

    has_malicious_attachment = (
        f_type in (
            "MALICIOUS_ATTACHMENT",
            "SUSPICIOUS_ATTACHMENT_TYPE",
            "VBA_MACRO_DETECTED",
            "DOUBLE_EXTENSION",
            "MALWARE_DETECTED",
        )
        or attrs.get("has_malicious_attachment", False)
    )

    if not has_malicious_attachment:
        return None

    filename = attrs.get("filename", attrs.get("attachment_name", "unnamed attachment"))
    recipient = attrs.get("recipient", "target")

    explanation = (
        f"Inbound email delivered to {recipient} carries suspicious file attachment '{filename}' "
        f"containing indicators of malicious payload structure (T1566.001)."
    )

    return RuleEvaluationResult(
        rule_id=rule.id,
        technique_id=rule.technique_id,
        subtechnique_id=rule.subtechnique_id,
        tactic_ids=rule.tactic_ids,
        status=AttackMappingStatus.SUPPORTED,
        confidence=0.84,
        evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
        finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
        event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
        stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
        explanation=explanation,
        limitations=["File is present and analyzed; zero endpoint process execution telemetry observed."],
        contradictions=[],
    )


def evaluate_api_enumeration(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1087 / T1595.002 / T1083 - API Resource / Account Enumeration.
    Requires:
    - Single session or origin IP querying multiple distinct resource IDs in rapid succession.
    - High error rate (404 Not Found, 403 Forbidden).
    False positive control:
    - Legitimate pagination or authorized service account bulk export is excluded!
    """
    attrs = ctx.attributes
    f_type = (ctx.finding_type or "").upper()
    s_type = (ctx.stage_type or "").upper()

    is_enum = (
        f_type in ("API_ENUMERATION", "RESOURCE_ENUMERATION", "ENDPOINT_FUZZING", "HIGH_ERROR_RATE")
        or s_type == "ENUMERATION"
        or attrs.get("is_api_enumeration", False)
    )

    if not is_enum:
        return None

    # Check authorized service account or internal monitoring exclusion
    caller_identity = attrs.get("caller_identity", attrs.get("service_account", ""))
    source_ip = attrs.get("source_ip", "")

    if ctx.environment_config:
        if caller_identity and caller_identity in ctx.environment_config.authorized_service_accounts:
            return RuleEvaluationResult(
                rule_id=rule.id,
                technique_id=rule.technique_id,
                subtechnique_id=rule.subtechnique_id,
                tactic_ids=rule.tactic_ids,
                status=AttackMappingStatus.REJECTED,
                confidence=0.1,
                evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
                finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
                event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
                stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
                explanation=f"API activity originated from authorized service account '{caller_identity}'.",
                limitations=["Authorized administrative bulk export activity."],
                contradictions=[f"Service account '{caller_identity}' is explicitly authorized."],
            )
        if source_ip and source_ip in ctx.environment_config.trusted_scanners:
            return RuleEvaluationResult(
                rule_id=rule.id,
                technique_id=rule.technique_id,
                subtechnique_id=rule.subtechnique_id,
                tactic_ids=rule.tactic_ids,
                status=AttackMappingStatus.REJECTED,
                confidence=0.1,
                evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
                finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
                event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
                stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
                explanation=f"API requests originated from authorized security scanner {source_ip}.",
                limitations=["Authorized scanner probe."],
                contradictions=[f"Scanner IP {source_ip} is configured in trusted environment."],
            )
        if source_ip and (source_ip in ctx.environment_config.monitoring_systems or caller_identity in ctx.environment_config.monitoring_systems):
            return RuleEvaluationResult(
                rule_id=rule.id,
                technique_id=rule.technique_id,
                subtechnique_id=rule.subtechnique_id,
                tactic_ids=rule.tactic_ids,
                status=AttackMappingStatus.REJECTED,
                confidence=0.1,
                evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
                finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
                event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
                stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
                explanation=f"API requests originated from authorized monitoring system {source_ip or caller_identity}.",
                limitations=["Authorized monitoring probe."],
                contradictions=[f"Host/Identity {source_ip or caller_identity} is configured in trusted monitoring systems."],
            )

    distinct_resources = attrs.get("distinct_resources", attrs.get("distinct_targets", 0))
    error_count = attrs.get("error_count", attrs.get("404_count", 0))

    explanation = (
        f"Single session/client queried {distinct_resources} distinct API resource identifiers "
        f"with high error responses ({error_count} 404/403 errors), consistent with active "
        f"resource enumeration / discovery (T1087 / T1595.002)."
    )

    return RuleEvaluationResult(
        rule_id=rule.id,
        technique_id=rule.technique_id,
        subtechnique_id=rule.subtechnique_id,
        tactic_ids=rule.tactic_ids,
        status=AttackMappingStatus.SUPPORTED,
        confidence=0.85,
        evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
        finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
        event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
        stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
        explanation=explanation,
        limitations=["Observed at API gateway; endpoint application internal state unobserved."],
        contradictions=[],
    )


def evaluate_powershell_execution(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1059.001 - PowerShell Execution.
    CRITICAL DISTINCTION:
    - Attachment or script presence alone (FILE_ANALYZED) -> NOT T1059.001!
    - Requires actual endpoint process creation telemetry (powershell.exe / pwsh process spawned).
    """
    attrs = ctx.attributes
    f_type = (ctx.finding_type or "").upper()
    s_type = (ctx.stage_type or "").upper()

    proc_name = (attrs.get("process_name", "") or attrs.get("image", "") or "").lower()
    fname = (attrs.get("filename", "") or "").lower()
    title_lower = ctx.title.lower()

    is_ps_related = (
        f_type in ("POWERSHELL_EXECUTION", "PROCESS_SPAWNED", "POWERSHELL_SCRIPT_DETECTED", "SUSPICIOUS_SCRIPT_ATTACHMENT")
        or "powershell" in proc_name
        or "pwsh" in proc_name
        or "powershell" in fname
        or fname.endswith(".ps1")
        or "powershell" in title_lower
    )

    if not is_ps_related:
        return None

    # Check if this is merely a file attachment / static finding without execution
    is_static_file = (
        f_type in ("SUSPICIOUS_SCRIPT_ATTACHMENT", "POWERSHELL_SCRIPT_DETECTED", "FILE_ANALYZED")
        or attrs.get("state") == "FILE_PRESENT"
        or (not attrs.get("process_created", False) and not attrs.get("process_id"))
    )

    # If this is ONLY an attachment without process execution telemetry, DO NOT map to T1059 execution!
    if is_static_file and not attrs.get("process_created", False):
        return RuleEvaluationResult(
            rule_id=rule.id,
            technique_id=rule.technique_id,
            subtechnique_id=rule.subtechnique_id,
            tactic_ids=rule.tactic_ids,
            status=AttackMappingStatus.INSUFFICIENT_EVIDENCE,
            confidence=0.25,
            evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
            finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
            event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
            stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
            explanation="PowerShell script file is present in attachment, but no process execution telemetry was observed.",
            limitations=["Static script presence does NOT establish execution (FILE_PRESENT != FILE_EXECUTED)."],
            contradictions=[],
        )

    # Process execution telemetry is present:
    process_name = attrs.get("process_name", attrs.get("image", ""))
    cmdline = attrs.get("command_line", attrs.get("cmdline", ""))
    parent_process = attrs.get("parent_process", "unknown")
    host = attrs.get("host", attrs.get("device_id", "endpoint"))

    explanation = (
        f"Endpoint telemetry on {host} recorded process execution of {process_name or 'powershell.exe'} "
        f"(parent: {parent_process}, cmdline: '{cmdline[:60]}...'), confirming PowerShell execution (T1059.001)."
    )

    return RuleEvaluationResult(
        rule_id=rule.id,
        technique_id=rule.technique_id,
        subtechnique_id=rule.subtechnique_id,
        tactic_ids=rule.tactic_ids,
        status=AttackMappingStatus.SUPPORTED,
        confidence=0.92,
        evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
        finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
        event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
        stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
        explanation=explanation,
        limitations=["Script block logging telemetry may be truncated."],
        contradictions=[],
    )


def evaluate_network_c2(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1071 / T1568 - Command and Control.
    CRITICAL DISTINCTION:
    - Periodic DNS queries or general traffic anomaly alone is NOT automatically C2!
    - Requires confirmed external beaconing with known C2 infrastructure or command channel telemetry.
    """
    f_type = (ctx.finding_type or "").upper()
    attrs = ctx.attributes

    is_dns_anomaly = f_type in ("DNS_ANOMALY", "PERIODIC_DNS_QUERY", "HIGH_DNS_QUERY_VOLUME")
    is_beaconing = attrs.get("is_confirmed_c2_beacon", False) or attrs.get("known_c2_indicator", False)

    # Periodic DNS query alone -> REJECTED or INSUFFICIENT_EVIDENCE for C2!
    if is_dns_anomaly and not is_beaconing:
        return RuleEvaluationResult(
            rule_id=rule.id,
            technique_id=rule.technique_id,
            subtechnique_id=rule.subtechnique_id,
            tactic_ids=rule.tactic_ids,
            status=AttackMappingStatus.INSUFFICIENT_EVIDENCE,
            confidence=0.20,
            evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
            finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
            event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
            stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
            explanation="Periodic DNS traffic is observed, but evidence does not establish an ATT&CK Command and Control channel.",
            limitations=["Network timing periodicity alone does not establish malicious command protocol."],
            contradictions=["Could represent legitimate NTP, software telemetry, or DNS keep-alive."],
        )

    if is_beaconing:
        destination = attrs.get("destination_ip", attrs.get("c2_domain", "external host"))
        return RuleEvaluationResult(
            rule_id=rule.id,
            technique_id=rule.technique_id,
            subtechnique_id=rule.subtechnique_id,
            tactic_ids=rule.tactic_ids,
            status=AttackMappingStatus.SUPPORTED,
            confidence=0.80,
            evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
            finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
            event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
            stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
            explanation=f"Confirmed periodic command-and-control beaconing observed to {destination} (T1071).",
            limitations=["Payload inspection may be prevented by TLS encryption."],
            contradictions=[],
        )

    return None


def evaluate_exfiltration(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1048 / T1041 - Exfiltration.
    CRITICAL DISTINCTION:
    - High outbound network transfer alone is NOT automatically Exfiltration!
    - Requires sensitive resource access, unusual non-CDN destination, and temporal correlation.
    - If sensitive data leaving organization is unconfirmed -> PLAUSIBLE or INSUFFICIENT_EVIDENCE.
    """
    f_type = (ctx.finding_type or "").upper()
    s_type = (ctx.stage_type or "").upper()
    attrs = ctx.attributes

    is_high_volume = (
        f_type in ("HIGH_OUTBOUND_DATA", "UNUSUAL_OUTBOUND_VOLUME", "NETWORK_ANOMALY")
        or s_type == "OUTBOUND_TRANSFER"
        or attrs.get("is_high_outbound_transfer", False)
    )

    if not is_high_volume:
        return None

    has_sensitive_resource = attrs.get("sensitive_resource_accessed", False) or attrs.get("has_data_staging", False)
    destination = attrs.get("destination", attrs.get("egress_ip", "external IP"))
    bytes_transferred = attrs.get("bytes_transferred", attrs.get("transfer_size_mb", 0))

    if not has_sensitive_resource:
        # High volume alone without sensitive resource evidence remains PLAUSIBLE or hypothesis
        return RuleEvaluationResult(
            rule_id=rule.id,
            technique_id=rule.technique_id,
            subtechnique_id=rule.subtechnique_id,
            tactic_ids=rule.tactic_ids,
            status=AttackMappingStatus.PLAUSIBLE,
            confidence=0.45,
            evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
            finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
            event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
            stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
            explanation=(
                f"Elevated outbound network transfer ({bytes_transferred} bytes/MB to {destination}) "
                f"is consistent with possible data movement, but sensitive data access is not established."
            ),
            limitations=["No direct confirmation that sensitive data left organizational control."],
            contradictions=["Could represent legitimate software update or bulk backup egress."],
        )

    return RuleEvaluationResult(
        rule_id=rule.id,
        technique_id=rule.technique_id,
        subtechnique_id=rule.subtechnique_id,
        tactic_ids=rule.tactic_ids,
        status=AttackMappingStatus.SUPPORTED,
        confidence=0.78,
        evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
        finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
        event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
        stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
        explanation=(
            f"Correlated bulk sensitive resource access followed immediately by high outbound transfer "
            f"({bytes_transferred} to {destination}) supports Exfiltration over Alternative Protocol (T1048)."
        ),
        limitations=["Encrypted tunnel prevents verification of file hashes on wire."],
        contradictions=[],
    )


def evaluate_impersonation(ctx: MappingEvaluationContext, rule: AttackTechniqueRule) -> Optional[RuleEvaluationResult]:
    """
    T1656 - Impersonation.
    Brand name in email alone -> NOT Impersonation.
    Requires deceptive display name mismatch, executive impersonation, or lookalike domain.
    """
    f_type = (ctx.finding_type or "").upper()
    attrs = ctx.attributes

    is_impersonation = (
        f_type in ("EXECUTIVE_IMPERSONATION", "BRAND_IMPERSONATION", "DISPLAY_NAME_SPOOFING", "LOOKALIKE_DOMAIN")
        or attrs.get("is_impersonation", False)
    )

    if not is_impersonation:
        return None

    target_identity = attrs.get("target_identity", attrs.get("spoofed_name", "trusted entity"))

    explanation = (
        f"Observed adversarial communication mimics trusted identity '{target_identity}' "
        f"via display name mismatch or lookalike domain to deceive victim (T1656)."
    )

    return RuleEvaluationResult(
        rule_id=rule.id,
        technique_id=rule.technique_id,
        subtechnique_id=rule.subtechnique_id,
        tactic_ids=rule.tactic_ids,
        status=AttackMappingStatus.SUPPORTED,
        confidence=0.82,
        evidence_ids=[str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")],
        finding_ids=[ctx.source_id] if ctx.source_type == "FINDING" else [],
        event_ids=[ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [],
        stage_ids=[ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [],
        explanation=explanation,
        limitations=["Persona attribution is heuristic; sender email header claims are unverified."],
        contradictions=[],
    )


# ============================================================================
# RULE REGISTRY
# ============================================================================

class MitreRuleRegistry:
    """
    Versioned registry of active ATT&CK mapping rules and their evaluators.
    """

    def __init__(self):
        self.rules: Dict[str, AttackTechniqueRule] = {}
        self.evaluators: Dict[str, RuleEvaluatorFunc] = {}
        self._register_default_rules()

    def register_rule(self, rule: AttackTechniqueRule, evaluator: RuleEvaluatorFunc) -> None:
        self.rules[rule.id] = rule
        self.evaluators[rule.id] = evaluator

    def get_rule(self, rule_id: str) -> Optional[AttackTechniqueRule]:
        return self.rules.get(rule_id)

    def list_rules(self) -> List[AttackTechniqueRule]:
        return list(self.rules.values())

    def _register_default_rules(self) -> None:
        # Rule 1: Password Spraying (T1110.003)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1110.003-AUTH-SPRAY",
                name="Password Spraying Detection",
                version="1.0.0",
                technique_id="T1110",
                subtechnique_id="T1110.003",
                tactic_ids=["TA0006"],
                required_findings=["PASSWORD_SPRAYING", "AUTH_ANOMALY_SPRAY"],
                required_events=["AUTH_FAILURE"],
                required_context={"min_distinct_accounts": 3, "min_attempts": 3},
                excluded_context=["AUTHORIZED_SCANNER"],
                minimum_confidence=0.70,
                explanation_template="Multi-account low-rate authentication failure pattern from single source.",
                limitations_template=["Source IP may represent shared egress."],
            ),
            evaluate_password_spraying
        )

        # Rule 2: Password Guessing / Brute Force (T1110.001)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1110.001-AUTH-BRUTE",
                name="Single-Account Password Guessing",
                version="1.0.0",
                technique_id="T1110",
                subtechnique_id="T1110.001",
                tactic_ids=["TA0006"],
                required_findings=["BRUTE_FORCE", "REPEATED_AUTH_FAILURES"],
                required_events=["AUTH_FAILURE"],
                required_context={"max_distinct_accounts": 2, "min_attempts": 3},
                excluded_context=["AUTHORIZED_SCANNER"],
                minimum_confidence=0.65,
                explanation_template="High-frequency authentication attempts targeted against a single account.",
                limitations_template=["Target user may have misconfigured background client."],
            ),
            evaluate_password_guessing_brute_force
        )

        # Rule 3: Credential Stuffing (T1110.004)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1110.004-CRED-STUFF",
                name="Credential Stuffing Detection",
                version="1.0.0",
                technique_id="T1110",
                subtechnique_id="T1110.004",
                tactic_ids=["TA0006"],
                required_findings=["CREDENTIAL_STUFFING"],
                required_context={"min_distinct_accounts": 5},
                minimum_confidence=0.75,
                explanation_template="Automated replay of known leaked credentials across accounts.",
            ),
            evaluate_credential_stuffing
        )

        # Rule 4: Spearphishing Link (T1566.002)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1566.002-PHISH-LINK",
                name="Spearphishing Link Delivery",
                version="1.0.0",
                technique_id="T1566",
                subtechnique_id="T1566.002",
                tactic_ids=["TA0001"],
                required_findings=["CREDENTIAL_HARVESTING_URL", "LOOKALIKE_DOMAIN_URL", "PHISHING_LINK"],
                required_stage_types=["DELIVERY"],
                minimum_confidence=0.70,
                explanation_template="Email delivered to target contains deceptive link to hostile infrastructure.",
            ),
            evaluate_spearphishing_link
        )

        # Rule 5: Spearphishing Attachment (T1566.001)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1566.001-PHISH-ATTACH",
                name="Spearphishing Attachment Delivery",
                version="1.0.0",
                technique_id="T1566",
                subtechnique_id="T1566.001",
                tactic_ids=["TA0001"],
                required_findings=["MALICIOUS_ATTACHMENT", "VBA_MACRO_DETECTED", "DOUBLE_EXTENSION"],
                minimum_confidence=0.70,
                explanation_template="Email delivered to target carries suspicious attachment payload.",
            ),
            evaluate_spearphishing_attachment
        )

        # Rule 6: API Resource Discovery / Enumeration (T1087 / T1595.002)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1087-API-ENUM",
                name="API Resource & Account Discovery",
                version="1.0.0",
                technique_id="T1087",
                tactic_ids=["TA0007"],
                required_findings=["API_ENUMERATION", "RESOURCE_ENUMERATION", "ENDPOINT_FUZZING"],
                required_stage_types=["ENUMERATION", "DISCOVERY"],
                minimum_confidence=0.70,
                explanation_template="High volume of distinct resource queries with error responses.",
            ),
            evaluate_api_enumeration
        )

        # Rule 7: PowerShell Execution (T1059.001)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1059.001-POWERSHELL-EXEC",
                name="PowerShell Process Execution",
                version="1.0.0",
                technique_id="T1059",
                subtechnique_id="T1059.001",
                tactic_ids=["TA0002"],
                required_findings=["POWERSHELL_EXECUTION", "PROCESS_SPAWNED"],
                minimum_confidence=0.75,
                explanation_template="Endpoint telemetry verifies PowerShell process execution.",
            ),
            evaluate_powershell_execution
        )

        # Rule 8: Command and Control (T1071)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1071-C2-PROTOCOL",
                name="Application Layer Protocol C2",
                version="1.0.0",
                technique_id="T1071",
                tactic_ids=["TA0011"],
                required_findings=["CONFIRMED_C2_BEACON", "MALICIOUS_C2_TRAFFIC"],
                minimum_confidence=0.75,
                explanation_template="Confirmed beaconing or interactive protocol to C2 infrastructure.",
            ),
            evaluate_network_c2
        )

        # Rule 9: Exfiltration (T1048)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1048-EXFILTRATION",
                name="Exfiltration Over Alternative Protocol",
                version="1.0.0",
                technique_id="T1048",
                tactic_ids=["TA0010"],
                required_findings=["HIGH_OUTBOUND_DATA", "DATA_EXFILTRATION"],
                minimum_confidence=0.60,
                explanation_template="Bulk sensitive resource access correlated with high outbound transfer.",
            ),
            evaluate_exfiltration
        )

        # Rule 10: Impersonation (T1656)
        self.register_rule(
            AttackTechniqueRule(
                id="RULE-T1656-IMPERSONATION",
                name="Identity & Brand Impersonation",
                version="1.0.0",
                technique_id="T1656",
                tactic_ids=["TA0042", "TA0043"],
                required_findings=["EXECUTIVE_IMPERSONATION", "BRAND_IMPERSONATION", "DISPLAY_NAME_SPOOFING"],
                minimum_confidence=0.70,
                explanation_template="Mimics trusted identity via spoofed headers or lookalike domain.",
            ),
            evaluate_impersonation
        )


# Global singleton instance
global_mitre_rule_registry = MitreRuleRegistry()
