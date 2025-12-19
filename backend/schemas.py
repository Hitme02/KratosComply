"""Pydantic schemas for request and response bodies."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, Field


HexStr64 = Annotated[str, Field(pattern=r"^[0-9a-fA-F]{64}$")]
HexSignature = Annotated[str, Field(pattern=r"^[0-9a-fA-F]+$")]


class ProjectInfo(BaseModel):
    name: str
    path: str
    commit: Optional[str]
    scan_time: str


class Metrics(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    risk_score: int


class Finding(BaseModel):
    """Compliance control violation finding with audit-grade metadata."""
    id: str
    type: str
    file: str
    line: Optional[int]
    snippet: str
    severity: Literal["critical", "high", "medium", "low"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_hash: HexStr64
    # Compliance metadata
    compliance_frameworks_affected: list[str] = Field(default_factory=list)
    control_id: str = ""
    control_category: str = ""
    control_pass_fail_status: str = ""
    required_evidence_missing: str = ""
    auditor_explanation: str = ""


class Report(BaseModel):
    report_version: str
    project: ProjectInfo
    standards: list[str]
    findings: list[Finding]
    metrics: Metrics
    merkle_root: HexStr64
    agent_signature: HexSignature
    agent_version: str


class VerifyReportRequest(BaseModel):
    report: Report
    public_key_hex: HexStr64


class VerifyReportResponse(BaseModel):
    valid: bool
    message: str


class AttestRequest(BaseModel):
    merkle_root: HexStr64
    public_key_hex: HexStr64
    metadata: Optional[dict[str, Any]] = None


class AttestResponse(BaseModel):
    attest_id: int
    status: Literal["recorded"]
    timestamp: datetime
    frameworks_covered: list[str] = Field(default_factory=list)
    control_coverage_percent: float | None = None


class AuditorVerifyRequest(BaseModel):
    """Request for external auditor verification (read-only)."""
    merkle_root: HexStr64
    public_key_hex: HexStr64


class AuditorVerifyResponse(BaseModel):
    """Response for auditor verification with compliance metadata."""
    verified: bool
    attest_id: int | None
    frameworks_covered: list[str]
    control_coverage_percent: float | None
    timestamp: datetime | None
    message: str

