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
    """Request to create a cryptographically sealed compliance attestation."""
    merkle_root: HexStr64
    public_key_hex: HexStr64
    metadata: Optional[dict[str, Any]] = None
    # Legal artifact metadata
    evidence_hashes: Optional[list[str]] = Field(default_factory=list)
    """List of SHA256 hashes of all evidence included in this attestation."""
    human_signer_identities: Optional[list[str]] = Field(default_factory=list)
    """List of hashed human signer identities (SHA256 of public_key:role)."""
    control_states: Optional[dict[str, str]] = Field(default_factory=dict)
    """Mapping of control_id to ControlState (VERIFIED_MACHINE, VERIFIED_SYSTEM, etc.)."""


class AttestResponse(BaseModel):
    """Response for attestation creation - a legal-grade compliance statement."""
    attest_id: int
    status: Literal["recorded"]
    timestamp: datetime
    frameworks_covered: list[str] = Field(default_factory=list)
    control_coverage_percent: float | None = None
    evidence_count: int = Field(default=0, description="Number of evidence items included")
    human_signer_count: int = Field(default=0, description="Number of human signers")
    control_count: int = Field(default=0, description="Total number of controls evaluated")


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


# Human Attestation Schemas
class EvidenceUploadRequest(BaseModel):
    """Request to upload evidence file."""
    file_name: str
    file_type: Literal["policy", "sop", "screenshot", "log_export", "declaration"]
    content_base64: str  # Base64-encoded file content
    metadata: Optional[dict[str, Any]] = None


class EvidenceUploadResponse(BaseModel):
    """Response for evidence upload."""
    upload_id: str
    content_hash: str
    file_size: int
    message: str


class HumanAttestationRequest(BaseModel):
    """Request to create a human attestation."""
    control_id: str
    framework: str
    role: Literal["founder", "compliance_officer", "security_lead", "data_protection_officer", "auditor"]
    scope: str
    attestation_text: str
    expiry_days: int = Field(default=365, ge=1, le=3650)
    evidence_upload_ids: list[str] = Field(default_factory=list)
    signer_public_key: HexStr64
    signature: HexSignature


class HumanAttestationResponse(BaseModel):
    """Response for human attestation creation."""
    attestation_id: str
    control_id: str
    framework: str
    role: str
    timestamp: datetime
    expires_at: datetime
    verified: bool
    message: str


class HumanAttestationListResponse(BaseModel):
    """Response for listing human attestations."""
    attestations: list[dict[str, Any]]
    total: int
    limit: int
    offset: int

