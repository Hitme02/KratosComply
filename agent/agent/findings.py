"""Data models for findings and report assembly.

Findings represent compliance control violations and evidence gaps,
not generic security vulnerabilities.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any


@dataclass(slots=True)
class RawFinding:
    """Intermediate finding data before IDs and hashes are assigned.
    
    Represents a compliance control violation or evidence gap.
    """

    type: str
    file: str
    line: int | None
    snippet: str
    severity: str
    confidence: float
    metadata: dict[str, Any] | None = None


@dataclass(slots=True)
class Finding:
    """Final finding written to the compliance evidence report.
    
    Each finding represents a specific compliance control violation
    with cryptographic evidence and audit-grade metadata.
    """

    id: str
    type: str
    file: str
    line: int | None
    snippet: str
    severity: str
    confidence: float
    evidence_hash: str
    # Compliance metadata
    compliance_frameworks_affected: list[str]
    control_id: str
    control_category: str
    control_pass_fail_status: str
    required_evidence_missing: str
    auditor_explanation: str


def _canonical_evidence_payload(raw: RawFinding) -> str:
    """Generate canonical JSON for evidence hashing.
    
    This ensures deterministic evidence hashes for audit verifiability.
    """
    payload: dict[str, Any] = {
        "type": raw.type,
        "file": raw.file,
        "line": raw.line,
        "snippet": raw.snippet,
        "severity": raw.severity,
        "confidence": raw.confidence,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def finalize_findings(
    raw_findings: list[RawFinding],
) -> tuple[list[Finding], dict[str, RawFinding]]:
    """Assign identifiers and evidence hashes deterministically.
    
    Enriches findings with compliance control metadata for audit verifiability.
    """
    from .compliance import (
        get_auditor_explanation,
        get_control_for_finding_type,
        get_control_status,
        get_frameworks_for_finding_type,
        get_required_evidence_missing,
    )

    sorted_raw = sorted(
        raw_findings,
        key=lambda rf: (
            rf.file,
            rf.line if rf.line is not None else -1,
            rf.type,
            rf.snippet,
        ),
    )
    finalized: list[Finding] = []
    raw_lookup: dict[str, RawFinding] = {}
    for idx, rf in enumerate(sorted_raw, start=1):
        fid = f"F{idx:03d}"
        evidence_hash = sha256(_canonical_evidence_payload(rf).encode()).hexdigest()
        
        # Enrich with compliance metadata
        control = get_control_for_finding_type(rf.type)
        frameworks = get_frameworks_for_finding_type(rf.type)
        control_id = control.control_id if control else "UNKNOWN"
        control_category = control.control_category.value if control else "Unknown"
        
        finalized.append(
            Finding(
                id=fid,
                type=rf.type,
                file=rf.file,
                line=rf.line,
                snippet=rf.snippet,
                severity=rf.severity,
                confidence=rf.confidence,
                evidence_hash=evidence_hash,
                compliance_frameworks_affected=frameworks,
                control_id=control_id,
                control_category=control_category,
                control_pass_fail_status=get_control_status(rf.type),
                required_evidence_missing=get_required_evidence_missing(rf.type),
                auditor_explanation=get_auditor_explanation(rf.type),
            )
        )
        raw_lookup[fid] = rf
    return finalized, raw_lookup


