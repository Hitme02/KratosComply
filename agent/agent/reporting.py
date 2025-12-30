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
from .system_evidence import collect_system_evidence, SystemEvidence

logger = logging.getLogger(__name__)


def generate_report(
    target: Path,
    project_name: str | None,
) -> tuple[list[Finding], dict[str, RawFinding], dict[str, Any]]:
    """Scan ``target`` and return finalized findings and report metadata.
    
    Now includes system-level evidence collection for VERIFIED_SYSTEM controls.
    """
    # Collect code-level findings (machine-verifiable)
    raw_findings = scan_workspace(target)
    
    # Collect system-level evidence (configuration-verifiable)
    system_evidence = collect_system_evidence(target)
    logger.info(f"Collected {len(system_evidence)} system evidence items")
    
    # Finalize findings with system evidence context
    findings, raw_lookup = finalize_findings(raw_findings, system_evidence)
    
    # Build Merkle root from all evidence hashes
    all_evidence_hashes = [f.evidence_hash for f in findings]
    merkle_root = build_merkle_root(all_evidence_hashes)

    # Resolve control states from findings and system evidence
    control_states = _resolve_control_states(findings, system_evidence)
    
    # Collect all evidence hashes for attestation
    evidence_hashes = [f.evidence_hash for f in findings]
    
    # Determine frameworks from findings
    frameworks_from_findings = set()
    for finding in findings:
        frameworks_from_findings.update(finding.compliance_frameworks_affected)
    
    # Always include all supported frameworks, even if no findings
    ALL_SUPPORTED_FRAMEWORKS = ["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"]
    frameworks = set(ALL_SUPPORTED_FRAMEWORKS) | frameworks_from_findings
    
    report = {
        "report_version": "1.0",
        "project": {
            "name": project_name or target.name,
            "path": str(target),
            "commit": _resolve_git_commit(target),
            "scan_time": datetime.now(timezone.utc).isoformat(),
        },
        "standards": sorted(list(frameworks)),
        "findings": [asdict(finding) for finding in findings],
        "system_evidence": [
            {
                "control_id": ev.control_id,
                "framework": ev.framework,
                "evidence_type": ev.evidence_type.value,
                "evidence_present": ev.evidence_present,
                "evidence_source": ev.evidence_source,
                "expiry_detected": ev.expiry_detected,
            }
            for ev in system_evidence
        ],
        "control_states": control_states,  # Map of control_id -> ControlState
        "evidence_hashes": evidence_hashes,
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


def _resolve_control_states(
    findings: list[Finding],
    system_evidence: list[SystemEvidence],
) -> dict[str, str]:
    """Resolve control states from findings and system evidence.
    
    Returns a mapping of control_id -> ControlState value.
    """
    from .control_model import (
        ControlState,
        get_control,
        VerificationMethod,
    )
    from .system_evidence import get_control_state_for_evidence
    
    control_states: dict[str, str] = {}
    
    # Create a lookup for system evidence by control_id
    evidence_by_control: dict[str, SystemEvidence] = {}
    for ev in system_evidence:
        key = f"{ev.control_id}:{ev.framework}"
        if key not in evidence_by_control or ev.evidence_present:
            evidence_by_control[key] = ev
    
    # Process findings (machine-verifiable evidence)
    for finding in findings:
        control_id = finding.control_id
        if control_id == "UNKNOWN":
            continue
        
        # Parse framework and control_id (format: "SOC2-CC6.1" or "CC6.1")
        if "-" in control_id:
            framework, ctrl_id = control_id.split("-", 1)
        else:
            # Try to infer framework from finding's frameworks
            if finding.compliance_frameworks_affected:
                framework = finding.compliance_frameworks_affected[0]
                ctrl_id = control_id
            else:
                continue
        
        # Get control definition
        control = get_control(framework, ctrl_id)
        if not control:
            # If control not found, mark as missing evidence
            control_states[control_id] = ControlState.MISSING_EVIDENCE.value
            continue
        
        # Machine-verifiable findings indicate VERIFIED_MACHINE (evidence found)
        # But if it's a violation finding, it means evidence is MISSING
        # We need to check the finding type to determine state
        if finding.control_pass_fail_status == "FAIL":
            # This is an evidence gap finding - control is MISSING_EVIDENCE
            control_states[control_id] = ControlState.MISSING_EVIDENCE.value
        else:
            # Evidence is present and verified
            if control.verification_method == VerificationMethod.MACHINE:
                control_states[control_id] = ControlState.VERIFIED_MACHINE.value
            elif control.verification_method == VerificationMethod.CONFIGURATION:
                control_states[control_id] = ControlState.VERIFIED_SYSTEM.value
    
    # Process system evidence (configuration-verifiable)
    for ev in system_evidence:
        control_id = ev.control_id
        framework = ev.framework
        control = get_control(framework, control_id)
        if not control:
            continue
        
        # Get state from system evidence
        state = get_control_state_for_evidence(control, ev)
        
        # Only update if we don't have a state yet, or if this evidence is present
        # (system evidence takes precedence for configuration-verifiable controls)
        if control_id not in control_states or ev.evidence_present:
            control_states[control_id] = state.value
    
    return control_states


