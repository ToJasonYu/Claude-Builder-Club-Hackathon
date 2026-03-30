from __future__ import annotations

import re
from datetime import date, datetime
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, HttpUrl, field_validator, model_validator


PopulationServed = Literal[
    "refugees",
    "domestic_violence_survivors",
    "children",
    "elderly",
    "general_public",
]

DataSensitivity = Literal[
    "medical",
    "location",
    "financial",
    "general_pii",
    "non_personal",
]

EaseOfRemediation = Literal["high", "medium", "complex"]

Severity = Literal["critical", "high", "medium", "low", "informational"]

VulnerabilityType = Literal[
    "misconfiguration",
    "injection",
    "auth_bypass",
    "disclosure",
    "xss",
    "csrf",
    "other",
]

RemediationType = Literal["config_change", "code_fix", "architecture_change"]


class NGOProfile(BaseModel):
    name: str
    slug: str
    website_url: HttpUrl
    mission_statement: Optional[str] = None
    contact_email: EmailStr
    population_served: PopulationServed

    @field_validator("slug")
    @classmethod
    def slug_format(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9_]+$", v):
            raise ValueError("slug must match ^[a-z0-9_]+$")
        return v


class VulnerabilityFinding(BaseModel):
    id: str
    title: str
    severity: Severity
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    discovered_date: date
    vulnerability_type: VulnerabilityType
    affected_component: str
    data_sensitivity: DataSensitivity
    ease_of_remediation: EaseOfRemediation
    description: str
    evidence_summary: str
    remediation_code: str
    remediation_type: RemediationType
    references: list[HttpUrl] = []

    @field_validator("cvss_score")
    @classmethod
    def cvss_range(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not (0.0 <= v <= 10.0):
            raise ValueError("cvss_score must be between 0.0 and 10.0")
        return v


class FindingFile(BaseModel):
    ngo: NGOProfile
    findings: list[VulnerabilityFinding]

    @model_validator(mode="after")
    def at_least_one_finding(self) -> "FindingFile":
        if not self.findings:
            raise ValueError("findings list must not be empty")
        return self


# --- SIS scoring models ---

class SISBreakdown(BaseModel):
    population_served: PopulationServed
    data_sensitivity: DataSensitivity
    ease_of_remediation: EaseOfRemediation


class SISResult(BaseModel):
    finding_id: str
    population_score: int
    data_sensitivity_score: int
    ease_of_remediation_score: int
    total_sis: int
    breakdown: SISBreakdown


class SISEnrichment(BaseModel):
    mission_alignment_narrative: str
    urgency_note: str


# --- Dashboard output models ---

class FindingDashboardEntry(BaseModel):
    id: str
    title: str
    severity: Severity
    cvss_score: Optional[float]
    vulnerability_type: VulnerabilityType
    affected_component: str
    sis: SISResult


class NGODashboardEntry(BaseModel):
    slug: str
    name: str
    website_url: str
    population_served: PopulationServed
    contact_email: str
    headline_sis: int
    mission_alignment_narrative: str
    urgency_note: str
    mission_source: str
    processed_at: datetime
    disclosure_draft_path: Optional[str] = None
    findings: list[FindingDashboardEntry]


class DashboardSummary(BaseModel):
    total_ngos: int
    total_findings: int
    critical_count: int
    high_count: int
    avg_sis: float
    ngos_with_drafts: int


class FailureRecord(BaseModel):
    file: str
    error: str
    timestamp: datetime


class DashboardOutput(BaseModel):
    generated_at: datetime
    summary: DashboardSummary
    ngos: list[NGODashboardEntry]
    failures: list[FailureRecord]
