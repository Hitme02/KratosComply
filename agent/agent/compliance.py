"""Compliance Control Abstraction Layer for KratosComply.

DEPRECATED: This module is maintained for backward compatibility.
New code should use agent.control_model for the unified control model.

Every detection rule must map to a specific compliance control,
legal requirement, or audit verifiability requirement.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

# Import the new unified control model
from .control_model import (
    ComplianceControl as UnifiedComplianceControl,
    ControlCategory,
    ControlState,
    ControlType,
    EvidenceType,
    VerificationMethod,
    get_control,
    get_controls_by_framework,
)


@dataclass(frozen=True, slots=True)
class ComplianceControl:
    """Legacy compliance control representation.

    DEPRECATED: Use agent.control_model.ComplianceControl instead.
    This is maintained for backward compatibility with existing code.
    """

    control_id: str  # e.g., "SOC2-CC6.1", "ISO27001-A.9.2", "DPDP-Section-8"
    control_category: ControlCategory
    evidence_type: EvidenceType
    frameworks: list[str]  # ["SOC2", "ISO27001", "DPDP"]
    description: str
    auditor_explanation: str  # Plain English explanation for auditors


# Compliance Control Registry
COMPLIANCE_CONTROLS: dict[str, ComplianceControl] = {
    # Secrets Management Controls (Security & Compliance)
    "hardcoded_secret": ComplianceControl(
        control_id="SOC2-CC6.2",
        control_category=ControlCategory.SECRETS_MANAGEMENT,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["SOC2", "ISO27001", "DPDP", "GDPR"],
        description="Secrets must not be hardcoded in source code or configuration files",
        auditor_explanation=(
            "Hardcoded secrets violate access control and data protection requirements by exposing "
            "credentials in source code. This creates both a security risk and an evidence gap: "
            "there is no proof that secrets are managed through secure, auditable channels. "
            "Compliance requires secrets to be stored in environment variables or secure vaults "
            "with access logging to meet SOC2, ISO27001, GDPR Article 32 (security of processing), "
            "and DPDP requirements."
        ),
    ),
    # Infrastructure Security Controls (Security & Compliance)
    "insecure_acl": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.INFRASTRUCTURE_SECURITY,
        evidence_type=EvidenceType.CONFIG_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="Infrastructure resources must not have public-read ACLs without justification",
        auditor_explanation=(
            "Public-read ACLs on storage resources violate access control and data protection requirements. "
            "This creates both a security risk and an evidence gap: there is no proof that data access is "
            "restricted to authorized parties. Compliance requires explicit access policies and audit logs "
            "for all data access to meet SOC2, ISO27001, and GDPR Article 32 (security of processing) requirements."
        ),
    ),
    # DPDP-Specific Controls
    "dpdp_missing_retention": ComplianceControl(
        control_id="DPDP-Section-8",
        control_category=ControlCategory.RETENTION,
        evidence_type=EvidenceType.CONFIG_PROOF,
        frameworks=["DPDP", "GDPR", "HIPAA"],
        description="Data retention policies must be explicitly configured",
        auditor_explanation=(
            "The DPDP Act (India) Section 8 requires data fiduciaries to retain "
            "personal data only as long as necessary. Missing retention configuration "
            "creates an evidence gap: there is no proof that data retention complies "
            "with legal requirements. Compliance requires explicit retention policies "
            "in configuration files or policy documents."
        ),
    ),
    "dpdp_missing_consent": ComplianceControl(
        control_id="DPDP-Section-7",
        control_category=ControlCategory.CONSENT,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["DPDP", "GDPR"],
        description="Consent handling mechanisms must be present for personal data processing",
        auditor_explanation=(
            "The DPDP Act (India) Section 7 requires explicit consent for processing "
            "personal data. Missing consent handling creates an evidence gap: there is "
            "no proof that data processing complies with legal requirements. Compliance "
            "requires explicit consent mechanisms in code with audit logging."
        ),
    ),
    "dpdp_missing_access_logging": ComplianceControl(
        control_id="DPDP-Section-9",
        control_category=ControlCategory.LOGGING,
        evidence_type=EvidenceType.LOG_PROOF,
        frameworks=["DPDP", "GDPR"],
        description="Access to personal data must be logged for audit purposes",
        auditor_explanation=(
            "The DPDP Act (India) Section 9 and GDPR Article 30 (records of processing activities) require "
            "data fiduciaries to maintain audit logs for personal data access. Missing access logging "
            "creates an evidence gap: there is no proof that data access is monitored and auditable. "
            "Compliance requires explicit logging for all personal data access operations."
        ),
    ),
    # GDPR-Specific Controls
    "gdpr_missing_encryption": ComplianceControl(
        control_id="GDPR-Article-32",
        control_category=ControlCategory.ENCRYPTION,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["GDPR", "DPDP"],
        description="Personal data must be encrypted in transit and at rest",
        auditor_explanation=(
            "GDPR Article 32 (security of processing) requires appropriate technical and organizational "
            "measures, including encryption of personal data. Missing encryption creates both a security "
            "risk and an evidence gap: there is no proof that data protection measures meet regulatory "
            "requirements. Compliance requires explicit encryption configuration and evidence."
        ),
    ),
    "gdpr_missing_consent": ComplianceControl(
        control_id="GDPR-Article-6",
        control_category=ControlCategory.CONSENT,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["GDPR", "DPDP"],
        description="Consent mechanisms must be present for lawful processing of personal data",
        auditor_explanation=(
            "GDPR Article 6 requires lawful basis for processing personal data, with explicit consent "
            "being one valid basis. Missing consent handling creates an evidence gap: there is no proof "
            "that data processing complies with GDPR requirements. Compliance requires explicit consent "
            "mechanisms in code with audit logging and withdrawal capabilities."
        ),
    ),
    "gdpr_missing_retention": ComplianceControl(
        control_id="GDPR-Article-5",
        control_category=ControlCategory.RETENTION,
        evidence_type=EvidenceType.CONFIG_PROOF,
        frameworks=["GDPR", "DPDP"],
        description="Data retention policies must be explicitly configured and enforced",
        auditor_explanation=(
            "GDPR Article 5(1)(e) requires personal data to be kept in a form which permits identification "
            "of data subjects for no longer than necessary. Missing retention configuration creates an "
            "evidence gap: there is no proof that data retention complies with legal requirements. "
            "Compliance requires explicit retention policies in configuration files or policy documents."
        ),
    ),
    "gdpr_missing_right_to_erasure": ComplianceControl(
        control_id="GDPR-Article-17",
        control_category=ControlCategory.DATA_PROTECTION,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["GDPR", "DPDP"],
        description="Right to erasure (right to be forgotten) mechanisms must be implemented",
        auditor_explanation=(
            "GDPR Article 17 grants data subjects the right to erasure of their personal data under "
            "specific circumstances. Missing erasure mechanisms creates an evidence gap: there is no "
            "proof that data subject rights are implemented. Compliance requires explicit erasure "
            "functionality in code with audit logging."
        ),
    ),
    "gdpr_missing_data_portability": ComplianceControl(
        control_id="GDPR-Article-20",
        control_category=ControlCategory.DATA_PROTECTION,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["GDPR", "DPDP"],
        description="Data portability mechanisms must be implemented for data subjects",
        auditor_explanation=(
            "GDPR Article 20 grants data subjects the right to data portability. Missing portability "
            "mechanisms creates an evidence gap: there is no proof that data subject rights are implemented. "
            "Compliance requires explicit data export functionality in code with audit logging."
        ),
    ),
    # New detection types
    "unencrypted_database": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.INFRASTRUCTURE_SECURITY,
        evidence_type=EvidenceType.CONFIG_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="Databases must be encrypted at rest",
        auditor_explanation="Unencrypted databases violate data protection requirements and create security risks.",
    ),
    "insecure_network_acl": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.INFRASTRUCTURE_SECURITY,
        evidence_type=EvidenceType.CONFIG_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="Network access controls must restrict public access",
        auditor_explanation="Security groups allowing 0.0.0.0/0 violate access control requirements.",
    ),
    "container_runs_as_root": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.ACCESS_CONTROL,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="Containers should not run as root user",
        auditor_explanation="Running containers as root violates principle of least privilege.",
    ),
    "missing_security_context": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.ACCESS_CONTROL,
        evidence_type=EvidenceType.CONFIG_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="Kubernetes resources must have security contexts defined",
        auditor_explanation="Missing security contexts create access control gaps.",
    ),
    "unauthenticated_api_endpoint": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.ACCESS_CONTROL,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="API endpoints must require authentication",
        auditor_explanation="Unauthenticated endpoints violate access control requirements.",
    ),
    "api_key_in_url": ComplianceControl(
        control_id="SOC2-CC6.2",
        control_category=ControlCategory.SECRETS_MANAGEMENT,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="API keys must not be passed in URL parameters",
        auditor_explanation="API keys in URLs are exposed in logs and violate secrets management requirements.",
    ),
    "potential_sql_injection": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.INFRASTRUCTURE_SECURITY,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["SOC2", "ISO27001", "PCI-DSS"],
        description="SQL queries must use parameterized statements",
        auditor_explanation="String concatenation in SQL queries creates injection vulnerabilities.",
    ),
    "unencrypted_database_connection": ComplianceControl(
        control_id="ISO27001-A.10.1.1",
        control_category=ControlCategory.ENCRYPTION,
        evidence_type=EvidenceType.CODE_PROOF,
        frameworks=["ISO27001", "GDPR", "HIPAA"],
        description="Database connections must use SSL/TLS encryption",
        auditor_explanation="Unencrypted database connections violate encryption requirements.",
    ),
    "unsigned_artifacts": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.INFRASTRUCTURE_SECURITY,
        evidence_type=EvidenceType.CONFIG_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="Container images must be cryptographically signed",
        auditor_explanation="Unsigned artifacts create supply chain security risks.",
    ),
    "missing_dependency_lock": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.INFRASTRUCTURE_SECURITY,
        evidence_type=EvidenceType.METADATA_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="Dependencies must be locked to specific versions",
        auditor_explanation="Missing lock files create reproducibility and security risks.",
    ),
    "unpinned_dependency": ComplianceControl(
        control_id="SOC2-CC6.1",
        control_category=ControlCategory.INFRASTRUCTURE_SECURITY,
        evidence_type=EvidenceType.METADATA_PROOF,
        frameworks=["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
        description="Dependencies must be pinned to specific versions",
        auditor_explanation="Unpinned dependencies create reproducibility risks.",
    ),
}


def get_control_for_finding_type(finding_type: str) -> ComplianceControl | None:
    """Get the compliance control for a finding type."""
    return COMPLIANCE_CONTROLS.get(finding_type)


def get_frameworks_for_finding_type(finding_type: str) -> list[str]:
    """Get the compliance frameworks affected by a finding type."""
    control = get_control_for_finding_type(finding_type)
    if control:
        return control.frameworks
    return []


def get_control_status(finding_type: str) -> str:
    """Get the control pass/fail status for a finding type."""
    # If a finding exists, the control has failed
    return "FAIL"


def get_required_evidence_missing(finding_type: str) -> str:
    """Get description of required evidence that is missing."""
    control = get_control_for_finding_type(finding_type)
    if control:
        return f"Missing {control.evidence_type.value} for {control.control_id}"
    return "Unknown evidence requirement"


def get_auditor_explanation(finding_type: str) -> str:
    """Get plain English explanation for auditors."""
    control = get_control_for_finding_type(finding_type)
    if control:
        return control.auditor_explanation
    return "No compliance mapping available for this finding type."

