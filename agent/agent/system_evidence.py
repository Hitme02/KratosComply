"""System Evidence Collection for KratosComply.

This module collects system-level evidence (configuration flags, settings)
without making claims about behavior. Outputs are "Evidence present" or
"Evidence missing" - never "compliant/non-compliant" directly.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .control_model import (
    ComplianceControl,
    ControlState,
    ControlType,
    EvidenceType,
    VerificationMethod,
    get_control,
    get_controls_by_type,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SystemEvidence:
    """Represents system-level evidence collected from configuration."""

    control_id: str
    framework: str
    evidence_type: EvidenceType
    evidence_present: bool
    evidence_source: str  # File path or config location
    evidence_data: dict[str, Any]  # Structured evidence data
    expiry_detected: bool = False  # Whether evidence has expired


def detect_logging_configuration(workspace: Path) -> list[SystemEvidence]:
    """Detect logging configuration evidence.

    Looks for:
    - Logging enabled flags
    - Log retention settings
    - Access logging configuration
    """
    evidence_list: list[SystemEvidence] = []
    controls = [
        ctrl
        for ctrl in get_controls_by_type(ControlType.SYSTEM)
        if ctrl.control_category.value == "Logging"
    ]

    # Common logging config patterns
    logging_patterns = [
        (r"logging\.(enabled|enable)\s*[:=]\s*(true|True|1|yes)", "logging_enabled"),
        (r"access.*log.*enabled\s*[:=]\s*(true|True|1|yes)", "access_logging_enabled"),
        (r"audit.*log.*enabled\s*[:=]\s*(true|True|1|yes)", "audit_logging_enabled"),
        (r"log.*retention\s*[:=]\s*(\d+)", "log_retention_days"),
    ]

    for file_path in workspace.rglob("*"):
        if not file_path.is_file():
            continue

        # Skip excluded files
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, evidence_key in logging_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                evidence_present = True
                evidence_data = {
                    "pattern": pattern,
                    "match": match.group(0),
                    "line_number": content[: match.start()].count("\n") + 1,
                }

                # Map to controls
                for control in controls:
                    if "log" in control.description.lower() or "log" in control.control_id.lower():
                        evidence_list.append(
                            SystemEvidence(
                                control_id=control.control_id,
                                framework=control.framework,
                                evidence_type=EvidenceType.CONFIG_PROOF,
                                evidence_present=evidence_present,
                                evidence_source=str(file_path.relative_to(workspace)),
                                evidence_data=evidence_data,
                            )
                        )

    return evidence_list


def detect_retention_configuration(workspace: Path) -> list[SystemEvidence]:
    """Detect data retention configuration evidence.

    Looks for:
    - Retention duration settings
    - Data retention policies
    - Retention period configuration
    """
    evidence_list: list[SystemEvidence] = []
    controls = [
        ctrl
        for ctrl in get_controls_by_type(ControlType.SYSTEM)
        if ctrl.control_category.value == "Retention"
    ]

    retention_patterns = [
        (r"retention.*period\s*[:=]\s*(\d+)", "retention_period"),
        (r"data.*retention\s*[:=]\s*(\d+)", "data_retention_days"),
        (r"retention.*days\s*[:=]\s*(\d+)", "retention_days"),
        (r"retention.*policy", "retention_policy_mentioned"),
    ]

    for file_path in workspace.rglob("*"):
        if not file_path.is_file():
            continue

        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, evidence_key in retention_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                evidence_present = True
                evidence_data = {
                    "pattern": pattern,
                    "match": match.group(0),
                    "line_number": content[: match.start()].count("\n") + 1,
                }

                for control in controls:
                    evidence_list.append(
                        SystemEvidence(
                            control_id=control.control_id,
                            framework=control.framework,
                            evidence_type=EvidenceType.CONFIG_PROOF,
                            evidence_present=evidence_present,
                            evidence_source=str(file_path.relative_to(workspace)),
                            evidence_data=evidence_data,
                        )
                    )

    return evidence_list


def detect_encryption_configuration(workspace: Path) -> list[SystemEvidence]:
    """Detect encryption configuration evidence.

    Looks for:
    - Encryption-at-rest settings
    - Encryption-in-transit settings
    - TLS/SSL configuration
    """
    evidence_list: list[SystemEvidence] = []
    controls = [
        ctrl
        for ctrl in get_controls_by_type(ControlType.SYSTEM)
        if ctrl.control_category.value == "Encryption"
    ]

    encryption_patterns = [
        (r"encryption.*at.*rest\s*[:=]\s*(true|True|1|yes|enabled)", "encryption_at_rest"),
        (r"encryption.*in.*transit\s*[:=]\s*(true|True|1|yes|enabled)", "encryption_in_transit"),
        (r"tls.*enabled\s*[:=]\s*(true|True|1|yes)", "tls_enabled"),
        (r"ssl.*enabled\s*[:=]\s*(true|True|1|yes)", "ssl_enabled"),
        (r"https.*enabled\s*[:=]\s*(true|True|1|yes)", "https_enabled"),
    ]

    for file_path in workspace.rglob("*"):
        if not file_path.is_file():
            continue

        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, evidence_key in encryption_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                evidence_present = True
                evidence_data = {
                    "pattern": pattern,
                    "match": match.group(0),
                    "line_number": content[: match.start()].count("\n") + 1,
                }

                for control in controls:
                    evidence_list.append(
                        SystemEvidence(
                            control_id=control.control_id,
                            framework=control.framework,
                            evidence_type=EvidenceType.CONFIG_PROOF,
                            evidence_present=evidence_present,
                            evidence_source=str(file_path.relative_to(workspace)),
                            evidence_data=evidence_data,
                        )
                    )

    return evidence_list


def detect_mfa_configuration(workspace: Path) -> list[SystemEvidence]:
    """Detect MFA (Multi-Factor Authentication) configuration evidence.

    Looks for:
    - MFA enforcement flags
    - 2FA configuration
    - Multi-factor authentication settings
    """
    evidence_list: list[SystemEvidence] = []
    controls = [
        ctrl
        for ctrl in get_controls_by_type(ControlType.SYSTEM)
        if ctrl.control_category.value == "Access Control"
    ]

    mfa_patterns = [
        (r"mfa.*enabled\s*[:=]\s*(true|True|1|yes|enabled|required)", "mfa_enabled"),
        (r"2fa.*enabled\s*[:=]\s*(true|True|1|yes|enabled|required)", "2fa_enabled"),
        (r"multi.*factor.*enabled\s*[:=]\s*(true|True|1|yes|enabled|required)", "mfa_enabled"),
        (r"mfa.*required\s*[:=]\s*(true|True|1|yes)", "mfa_required"),
    ]

    for file_path in workspace.rglob("*"):
        if not file_path.is_file():
            continue

        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, evidence_key in mfa_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                evidence_present = True
                evidence_data = {
                    "pattern": pattern,
                    "match": match.group(0),
                    "line_number": content[: match.start()].count("\n") + 1,
                }

                for control in controls:
                    if "access" in control.description.lower() or "access" in control.control_id.lower():
                        evidence_list.append(
                            SystemEvidence(
                                control_id=control.control_id,
                                framework=control.framework,
                                evidence_type=EvidenceType.CONFIG_PROOF,
                                evidence_present=evidence_present,
                                evidence_source=str(file_path.relative_to(workspace)),
                                evidence_data=evidence_data,
                            )
                        )

    return evidence_list


def detect_backup_configuration(workspace: Path) -> list[SystemEvidence]:
    """Detect backup policy configuration evidence.

    Looks for:
    - Backup enabled flags
    - Backup frequency settings
    - Backup retention policies
    """
    evidence_list: list[SystemEvidence] = []
    # Note: Backup controls would need to be added to control_model.py
    # For now, we'll detect but not map to specific controls

    backup_patterns = [
        (r"backup.*enabled\s*[:=]\s*(true|True|1|yes|enabled)", "backup_enabled"),
        (r"backup.*frequency\s*[:=]\s*(\d+)", "backup_frequency"),
        (r"backup.*retention\s*[:=]\s*(\d+)", "backup_retention"),
    ]

    for file_path in workspace.rglob("*"):
        if not file_path.is_file():
            continue

        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, evidence_key in backup_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Evidence detected but not mapped to controls yet
                logger.debug(f"Backup configuration detected: {match.group(0)} in {file_path}")

    return evidence_list


def collect_system_evidence(workspace: Path) -> list[SystemEvidence]:
    """Collect all system-level evidence from workspace.

    This function aggregates evidence from all system evidence detectors.
    Returns a list of SystemEvidence objects indicating what evidence is
    present or missing.
    """
    all_evidence: list[SystemEvidence] = []

    # Collect evidence from all detectors
    all_evidence.extend(detect_logging_configuration(workspace))
    all_evidence.extend(detect_retention_configuration(workspace))
    all_evidence.extend(detect_encryption_configuration(workspace))
    all_evidence.extend(detect_mfa_configuration(workspace))
    all_evidence.extend(detect_backup_configuration(workspace))

    # Remove duplicates (same control_id + framework + evidence_source)
    seen = set()
    unique_evidence = []
    for evidence in all_evidence:
        key = (evidence.control_id, evidence.framework, evidence.evidence_source)
        if key not in seen:
            seen.add(key)
            unique_evidence.append(evidence)

    return unique_evidence


def get_control_state_for_evidence(control: ComplianceControl, evidence: SystemEvidence | None) -> ControlState:
    """Determine control state based on evidence availability.

    Args:
        control: The compliance control to evaluate
        evidence: System evidence for this control (None if missing)

    Returns:
        ControlState indicating compliance status
    """
    if evidence is None:
        return ControlState.MISSING_EVIDENCE

    if evidence.expiry_detected:
        return ControlState.EXPIRED_EVIDENCE

    if not evidence.evidence_present:
        return ControlState.MISSING_EVIDENCE

    # Determine state based on verification method
    if control.verification_method == VerificationMethod.MACHINE:
        return ControlState.VERIFIED_MACHINE
    elif control.verification_method == VerificationMethod.CONFIGURATION:
        return ControlState.VERIFIED_SYSTEM
    elif control.verification_method == VerificationMethod.HUMAN_ATTESTATION:
        return ControlState.ATTESTED_HUMAN

    return ControlState.MISSING_EVIDENCE


