"""Report generation utilities for the Kratos agent."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import logging
from pathlib import Path
import subprocess
from typing import Any

from .config import AGENT_VERSION, SEVERITY_WEIGHTS
from .detectors import scan_workspace
from .findings import Finding, RawFinding, finalize_findings
from .merkle import build_merkle_root

logger = logging.getLogger(__name__)


def generate_report(
    target: Path,
    project_name: str | None,
) -> tuple[list[Finding], dict[str, RawFinding], dict[str, Any]]:
    """Scan ``target`` and return finalized findings and report metadata."""
    raw_findings = scan_workspace(target)
    findings, raw_lookup = finalize_findings(raw_findings)
    merkle_root = build_merkle_root([f.evidence_hash for f in findings])

    report = {
        "report_version": "1.0",
        "project": {
            "name": project_name or target.name,
            "path": str(target),
            "commit": _resolve_git_commit(target),
            "scan_time": datetime.now(timezone.utc).isoformat(),
        },
        "standards": ["SOC2", "ISO27001"],
        "findings": [asdict(finding) for finding in findings],
        "metrics": _build_metrics(findings),
        "merkle_root": merkle_root,
        "agent_signature": "",
        "agent_version": AGENT_VERSION,
    }
    return findings, raw_lookup, report


def _build_metrics(findings: list[Finding]) -> dict[str, int]:
    metrics = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        metrics[finding.severity] += 1
    metrics["risk_score"] = min(
        100,
        sum(SEVERITY_WEIGHTS[finding.severity] for finding in findings),
    )
    return metrics


def _resolve_git_commit(target: Path) -> str | None:
    git_root = _find_git_root(target)
    if git_root is None:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(git_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return result.stdout.strip() or None


def _find_git_root(path: Path) -> Path | None:
    current = path.resolve()
    for ancestor in [current, *current.parents]:
        if (ancestor / ".git").exists():
            return ancestor
    return None


