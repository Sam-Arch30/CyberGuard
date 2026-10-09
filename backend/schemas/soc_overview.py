"""
Pydantic schemas for Section 44: SOC Overview Dashboard.
Provides structured contracts for security posture, priority queue,
risk distribution, activity feed, threat intelligence, and system/fleet health.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class SocPostureMetrics(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    active_investigations: int = Field(0, description="Active investigations in OPEN, INVESTIGATING, or CONTAINED status")
    high_risk_open: int = Field(0, description="Distinct open investigations with HIGH or CRITICAL risk/severity")
    pending_response_approvals: int = Field(0, description="Defensive recommendations awaiting human analyst approval")
    failed_analysis_jobs: int = Field(0, description="Analysis runs or ingestion tasks with FAILED status in window")
    new_findings_count: int = Field(0, description="New evidence-backed findings detected within selected window")
    active_endpoint_agents: int = Field(0, description="Currently active and enrolled fleet endpoint agents")
    total_investigations: int = Field(0, description="Total historical investigations in database")


class SocRiskDistribution(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    critical: int = Field(0, description="Critical risk investigations (score >= 80 or CRITICAL)")
    high: int = Field(0, description="High risk investigations (score 60-79 or HIGH)")
    medium: int = Field(0, description="Medium risk investigations (score 40-59 or MEDIUM)")
    low: int = Field(0, description="Low risk investigations (score 20-39 or LOW)")
    safe: int = Field(0, description="Safe or informational investigations (score < 20 or SAFE)")
    total: int = Field(0, description="Sum of evaluated risk records")


class SocPriorityQueueItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique identifier of the priority item")
    investigation_id: Optional[str] = Field(None, description="Linked investigation ID")
    title: str = Field(..., description="Actionable title for analyst display")
    risk_score: float = Field(0.0, description="Authoritative risk score 0.0 - 100.0")
    severity: str = Field("LOW", description="Severity taxonomy: CRITICAL, HIGH, MEDIUM, LOW, SAFE")
    status: str = Field("OPEN", description="Current lifecycle state")
    resource_type: str = Field(..., description="Resource kind: INVESTIGATION, RECOMMENDATION, ANALYSIS_RUN, FINDING")
    reason_for_inclusion: str = Field(..., description="Deterministic reason why item is in the priority queue")
    urgency: str = Field("P2", description="Operational urgency: P0 (Critical), P1 (Urgent), P2 (Normal), P3 (Low)")
    updated_at: str = Field(..., description="ISO8601 UTC timestamp of last meaningful modification")
    navigation_target: str = Field(..., description="Canonical route to open the resource in workspace")


class SocActivityItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique event identifier")
    event_type: str = Field(..., description="Auditable event type, e.g. CASE_CREATED, STATUS_CHANGED")
    timestamp: str = Field(..., description="ISO8601 UTC event time")
    resource_type: str = Field(..., description="Target resource type")
    resource_id: str = Field(..., description="Target resource ID")
    description: str = Field(..., description="Human-readable summary of the operational event")
    user: Optional[str] = Field(None, description="Initiating analyst or automated system user")
    severity: Optional[str] = Field(None, description="Associated severity if applicable")
    source: str = Field("AUDIT_LOG", description="Originating event source/provenance")
    navigation_target: Optional[str] = Field(None, description="Canonical link to open associated workspace")


class SocThreatIntelItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    indicator_value: str = Field(..., description="Observed indicator value (IP, domain, hash, email)")
    indicator_type: str = Field(..., description="Indicator taxonomy: DOMAIN, IP, HASH, URL, EMAIL")
    investigation_count: int = Field(1, description="Number of investigations where this indicator was observed")
    provenance: str = Field("CURRENT_OBSERVATION", description="Provenance: CURRENT_OBSERVATION, HISTORICAL_MEMORY, EXTERNAL_INTELLIGENCE, ANALYST_VERIFIED")
    reputation: Optional[str] = Field(None, description="Reputation classification if evaluated")
    last_seen_at: str = Field(..., description="ISO8601 UTC timestamp of last observation")


class SocCampaignSummaryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Campaign internal ID")
    campaign_id: str = Field(..., description="Campaign public identifier, e.g. CMP-2026-001")
    name: str = Field(..., description="Campaign name")
    status: str = Field("ACTIVE", description="Campaign status")
    incident_count: int = Field(0, description="Correlated incidents/investigations in this campaign")
    dominant_attack_type: Optional[str] = Field(None, description="Dominant classification")
    updated_at: str = Field(..., description="Last updated timestamp")


class SocEndpointFleetSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    enrolled: int = Field(0, description="Total enrolled endpoint agents")
    active: int = Field(0, description="Online agents with active heartbeat")
    degraded: int = Field(0, description="Agents with degraded health or failed collectors")
    revoked: int = Field(0, description="Decommissioned or revoked agent credentials")
    events_received: int = Field(0, description="Total telemetry events ingested from fleet")


class SocSystemHealth(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: str = Field("operational", description="Overall platform operational status: operational, degraded, unavailable")
    api_status: str = Field("healthy", description="API route availability status")
    database_status: str = Field("connected", description="Postgres/SQLite database connection check")
    analysis_engine_status: str = Field("operational", description="Core pipeline analysis engine readiness")
    active_tasks: int = Field(0, description="Currently running or queued asynchronous analysis tasks")
    failed_tasks: int = Field(0, description="Analysis tasks in FAILED status")
    endpoint_fleet: Optional[SocEndpointFleetSummary] = Field(None, description="Fleet agent telemetry status")


class SocOverviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    generated_at: str = Field(..., description="ISO8601 UTC timestamp of dashboard payload generation")
    time_window: str = Field("30d", description="Selected aggregation window: 24h, 7d, 30d, all")
    posture: SocPostureMetrics
    risk_distribution: SocRiskDistribution
    priority_queue: List[SocPriorityQueueItem] = Field(default_factory=list)
    recent_activity: List[SocActivityItem] = Field(default_factory=list)
    threat_intel: List[SocThreatIntelItem] = Field(default_factory=list)
    active_campaigns: List[SocCampaignSummaryItem] = Field(default_factory=list)
    system_health: SocSystemHealth
    partial_failures: List[str] = Field(default_factory=list, description="List of any degraded or unavailable subsystems")
