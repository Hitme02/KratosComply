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


@dataclass(slots=True)
class Finding(RawFinding):
    """Final finding written to the report."""

    id: str
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


def finalize_findings(raw_findings: list[RawFinding]) -> list[Finding]:
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
    for idx, rf in enumerate(sorted_raw, start=1):
        fid = f"F{idx:03d}"
        evidence_hash = sha256(_canonical_evidence_payload(rf).encode()).hexdigest()
        finalized.append(
            Finding(
                id=fid,
                evidence_hash=evidence_hash,
                type=rf.type,
                file=rf.file,
                line=rf.line,
                snippet=rf.snippet,
                severity=rf.severity,
                confidence=rf.confidence,
            )
        )
    return finalized


