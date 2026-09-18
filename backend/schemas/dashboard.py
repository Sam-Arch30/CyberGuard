from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


class DashboardMetrics(BaseModel):
    emails_analyzed: int = Field(..., description="Total count of analyzed emails")
    threats_detected: int = Field(..., description="Total threats detected (score >= 50 or severity medium/high/critical)")
    critical_emails: int = Field(..., description="Count of critical severity emails (score >= 80 or critical)")
    open_cases: int = Field(..., description="Count of non-resolved open/investigating cases")


class SeverityDistributionItem(BaseModel):
    severity: str = Field(..., description="Severity category (low, medium, high, critical, etc.)")
    count: int = Field(..., description="Count of emails in this severity category")


class AnalysisTrendPoint(BaseModel):
    date: str = Field(..., description="Date formatted as YYYY-MM-DD")
    total: int = Field(..., description="Total emails analyzed on this date")
    threats: int = Field(..., description="Suspicious or high/critical threats on this date")


class SuspiciousDomainItem(BaseModel):
    domain: str = Field(..., description="Suspicious or observed domain")
    count: int = Field(..., description="Number of times observed")


class InfrastructureCountryItem(BaseModel):
    country: str = Field(..., description="Observed origin or relay infrastructure country name")
    count: int = Field(..., description="Number of times observed")


class AuthFailureBreakdown(BaseModel):
    spf_failures: int = Field(0, description="SPF failure count")
    dkim_failures: int = Field(0, description="DKIM failure count")
    dmarc_failures: int = Field(0, description="DMARC failure count")
    total_evaluated: int = Field(0, description="Total email authentication checks performed")


class DashboardCaseItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_number: str
    title: str
    severity: str
    status: str
    emails_count: int
    updated_at: str


class DashboardEmailItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_id: Optional[str] = None
    sha256: Optional[str] = None
    subject: str
    sender: str
    threat_score: float
    severity: str
    timestamp: str
    has_eml_file: bool = True
    original_filename: Optional[str] = None


class DashboardSummaryResponse(BaseModel):
    metrics: DashboardMetrics
    severity_distribution: List[SeverityDistributionItem]
    analysis_trend: List[AnalysisTrendPoint]
    top_suspicious_domains: List[SuspiciousDomainItem]
    top_countries: List[InfrastructureCountryItem]
    auth_failures: AuthFailureBreakdown
    recent_cases: List[DashboardCaseItem]
    recent_emails: List[DashboardEmailItem]


class DashboardEmailListResponse(BaseModel):
    items: List[DashboardEmailItem]
    total: int
    skip: int
    limit: int
