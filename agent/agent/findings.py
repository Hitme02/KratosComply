"""Data models for findings and report assembly."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any


@dataclass(slots=True)
class RawFinding:
    """Intermediate finding data before IDs and hashes are assigned."""

    type: str
    file: str
    line: int | None
    snippet: str
    severity: str
    confidence: float
    metadata: dict[str, Any] | None = None


@dataclass(slots=True)
class Finding:
    """Final finding written to the report."""

    id: str
    type: str
    file: str
    line: int | None
    snippet: str
    severity: str
    confidence: float
    evidence_hash: str


def _canonical_evidence_payload(raw: RawFinding) -> str:
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
    """Assign identifiers and evidence hashes deterministically."""
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
            )
        )
        raw_lookup[fid] = rf
    return finalized, raw_lookup


