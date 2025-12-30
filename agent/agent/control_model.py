"""Unified Compliance Control Model for KratosComply.

This is the canonical Control Definition Schema - the single source of truth
for all compliance logic. Every control must be defined here with complete
metadata for audit defensibility and legal clarity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from typing import Any


class ControlCategory(str, Enum):
    """Categories of compliance controls."""

    ACCESS_CONTROL = "Access Control"
    ENCRYPTION = "Encryption"
    LOGGING = "Logging"
    RETENTION = "Retention"
    CONSENT = "Consent"
    SECRETS_MANAGEMENT = "Secrets Management"
    INFRASTRUCTURE_SECURITY = "Infrastructure Security"
    DATA_PROTECTION = "Data Protection"
    INCIDENT_RESPONSE = "Incident Response"
    VENDOR_RISK = "Vendor Risk"
    EMPLOYEE_TRAINING = "Employee Training"
    ACCESS_REVIEWS = "Access Reviews"
    DATA_SUBJECT_RIGHTS = "Data Subject Rights"


class ControlType(str, Enum):
    """Types of controls based on verification method."""

    TECHNICAL = "technical"  # Machine-verifiable (code, config)
    SYSTEM = "system"  # System-config verifiable (logging enabled, retention settings)
    PROCEDURAL = "procedural"  # Human-attested (policies, SOPs, training records)


class EvidenceType(str, Enum):
    """Types of evidence that can be generated or collected."""

    CONFIG_PROOF = "config_proof"  # Configuration file evidence
    CODE_PROOF = "code_proof"  # Source code evidence
    POLICY_PROOF = "policy_proof"  # Policy document evidence
    LOG_PROOF = "log_proof"  # Audit log evidence
    METADATA_PROOF = "metadata_proof"  # Repository metadata evidence
    SCREENSHOT_PROOF = "screenshot_proof"  # Screenshot evidence
    DECLARATION_PROOF = "declaration_proof"  # Structured human declaration
    ATTESTATION_PROOF = "attestation_proof"  # Human attestation record


class VerificationMethod(str, Enum):
    """Methods for verifying control compliance."""

    MACHINE = "machine"  # Fully automated verification (AST, regex, config parsing)
    CONFIGURATION = "configuration"  # Configuration detection (flags, settings)
    HUMAN_ATTESTATION = "human_attestation"  # Requires human declaration/attestation


class ControlState(str, Enum):
    """State machine for control compliance status.

    Every control must resolve to exactly one of these states.
    Never merge these states. Never soften missing evidence.
    """

    VERIFIED_MACHINE = "VERIFIED_MACHINE"  # Machine-verified evidence present
    VERIFIED_SYSTEM = "VERIFIED_SYSTEM"  # System-config evidence present
    ATTESTED_HUMAN = "ATTESTED_HUMAN"  # Human-attested evidence present
    MISSING_EVIDENCE = "MISSING_EVIDENCE"  # No evidence found
    EXPIRED_EVIDENCE = "EXPIRED_EVIDENCE"  # Evidence exists but has expired


@dataclass(frozen=True, slots=True)
class ComplianceControl:
    """Canonical compliance control definition.

    This is the single source of truth for compliance logic.
    Every control must be fully specified for audit defensibility.
    """

    # Control Identification
    control_id: str  # e.g., "SOC2-CC6.1", "ISO27001-A.9.2.1", "DPDP-Section-8", "GDPR-Article-32"
    framework: str  # "SOC2", "ISO27001", "DPDP", "GDPR"
    control_category: ControlCategory

    # Control Classification
    control_type: ControlType  # technical, system, or procedural
    verification_method: VerificationMethod  # machine, configuration, or human_attestation

    # Evidence Requirements
    required_evidence_types: list[EvidenceType] = field(default_factory=list)
    """List of evidence types required to satisfy this control."""

    # Operational Metadata
    review_frequency: timedelta | None = None
    """How often this control must be reviewed/verified."""

    expiry_policy: timedelta | None = None
    """How long evidence remains valid before requiring renewal."""

    # Human-Readable Descriptions
    description: str = ""
    """Brief description of the control requirement."""

    auditor_explanation: str = ""
    """Plain English explanation for auditors explaining why this control matters."""

    # Additional Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    """Additional control-specific metadata."""

    def get_state(self, evidence_present: bool, evidence_expired: bool = False) -> ControlState:
        """Determine control state based on evidence availability.

        Args:
            evidence_present: Whether evidence exists for this control
            evidence_expired: Whether existing evidence has expired

        Returns:
            ControlState indicating the current compliance status
        """
        if not evidence_present:
            return ControlState.MISSING_EVIDENCE

        if evidence_expired:
            return ControlState.EXPIRED_EVIDENCE

        # Determine verification state based on control type
        if self.verification_method == VerificationMethod.MACHINE:
            return ControlState.VERIFIED_MACHINE
        elif self.verification_method == VerificationMethod.CONFIGURATION:
            return ControlState.VERIFIED_SYSTEM
        elif self.verification_method == VerificationMethod.HUMAN_ATTESTATION:
            return ControlState.ATTESTED_HUMAN

        # Fallback (should not happen)
        return ControlState.MISSING_EVIDENCE


# Compliance Control Registry
# This is the canonical registry of all compliance controls.
# Controls are organized by framework and control_id for easy lookup.
COMPLIANCE_CONTROLS: dict[str, ComplianceControl] = {}

# Helper function to register controls
def register_control(control: ComplianceControl) -> None:
    """Register a compliance control in the global registry."""
    key = f"{control.framework}-{control.control_id}"
    COMPLIANCE_CONTROLS[key] = control


# SOC2 Controls
register_control(
    ComplianceControl(
        control_id="CC6.1",
        framework="SOC2",
        control_category=ControlCategory.INFRASTRUCTURE_SECURITY,
        control_type=ControlType.TECHNICAL,
        verification_method=VerificationMethod.MACHINE,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.CODE_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Logical and physical access controls must be implemented and monitored",
        auditor_explanation=(
            "SOC2 CC6.1 requires logical and physical access controls to prevent unauthorized access. "
            "Public-read ACLs on infrastructure resources violate this requirement by allowing "
            "unrestricted access. Evidence must demonstrate that access is restricted and monitored."
        ),
    )
)

register_control(
    ComplianceControl(
        control_id="CC6.2",
        framework="SOC2",
        control_category=ControlCategory.SECRETS_MANAGEMENT,
        control_type=ControlType.TECHNICAL,
        verification_method=VerificationMethod.MACHINE,
        required_evidence_types=[EvidenceType.CODE_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Credentials and secrets must be managed securely",
        auditor_explanation=(
            "SOC2 CC6.2 requires secure management of credentials and secrets. Hardcoded secrets "
            "in source code violate this requirement by exposing credentials in an unsecured manner. "
            "Evidence must demonstrate that secrets are stored in secure vaults with access logging."
        ),
    )
)

register_control(
    ComplianceControl(
        control_id="CC7.2",
        framework="SOC2",
        control_category=ControlCategory.LOGGING,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.LOG_PROOF],
        review_frequency=timedelta(days=30),
        expiry_policy=timedelta(days=90),
        description="System activities must be logged and monitored",
        auditor_explanation=(
            "SOC2 CC7.2 requires system activities to be logged and monitored for security events. "
            "Missing access logging creates an evidence gap: there is no proof that system activities "
            "are monitored. Evidence must demonstrate that logging is enabled and configured."
        ),
    )
)

# ISO 27001 Controls
register_control(
    ComplianceControl(
        control_id="A.9.2.1",
        framework="ISO27001",
        control_category=ControlCategory.ACCESS_CONTROL,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="User access management procedures must be established",
        auditor_explanation=(
            "ISO 27001 A.9.2.1 requires user access management procedures. Evidence must demonstrate "
            "that access controls are configured and enforced, including MFA where applicable."
        ),
    )
)

register_control(
    ComplianceControl(
        control_id="A.10.1.1",
        framework="ISO27001",
        control_category=ControlCategory.ENCRYPTION,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.CODE_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Cryptographic controls must be implemented",
        auditor_explanation=(
            "ISO 27001 A.10.1.1 requires cryptographic controls for data protection. Evidence must "
            "demonstrate that encryption is configured for data in transit and at rest."
        ),
    )
)

# DPDP Act Controls
register_control(
    ComplianceControl(
        control_id="Section-7",
        framework="DPDP",
        control_category=ControlCategory.CONSENT,
        control_type=ControlType.TECHNICAL,
        verification_method=VerificationMethod.MACHINE,
        required_evidence_types=[EvidenceType.CODE_PROOF, EvidenceType.LOG_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Consent must be obtained before processing personal data",
        auditor_explanation=(
            "DPDP Act Section 7 requires explicit consent for processing personal data. Missing consent "
            "handling creates an evidence gap: there is no proof that data processing complies with "
            "legal requirements. Evidence must demonstrate consent mechanisms with audit logging."
        ),
    )
)

register_control(
    ComplianceControl(
        control_id="Section-8",
        framework="DPDP",
        control_category=ControlCategory.RETENTION,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.POLICY_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Data retention policies must be explicitly configured",
        auditor_explanation=(
            "DPDP Act Section 8 requires data fiduciaries to retain personal data only as long as "
            "necessary. Missing retention configuration creates an evidence gap. Evidence must "
            "demonstrate explicit retention policies in configuration or policy documents."
        ),
    )
)

register_control(
    ComplianceControl(
        control_id="Section-9",
        framework="DPDP",
        control_category=ControlCategory.LOGGING,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.LOG_PROOF],
        review_frequency=timedelta(days=30),
        expiry_policy=timedelta(days=90),
        description="Access to personal data must be logged for audit purposes",
        auditor_explanation=(
            "DPDP Act Section 9 requires audit logs for personal data access. Missing access logging "
            "creates an evidence gap: there is no proof that data access is monitored. Evidence must "
            "demonstrate that logging is enabled and configured."
        ),
    )
)

# GDPR Controls
register_control(
    ComplianceControl(
        control_id="Article-5",
        framework="GDPR",
        control_category=ControlCategory.RETENTION,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.POLICY_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Personal data must be retained only as long as necessary",
        auditor_explanation=(
            "GDPR Article 5(1)(e) requires personal data to be kept for no longer than necessary. "
            "Missing retention configuration creates an evidence gap. Evidence must demonstrate "
            "explicit retention policies."
        ),
    )
)

register_control(
    ComplianceControl(
        control_id="Article-6",
        framework="GDPR",
        control_category=ControlCategory.CONSENT,
        control_type=ControlType.TECHNICAL,
        verification_method=VerificationMethod.MACHINE,
        required_evidence_types=[EvidenceType.CODE_PROOF, EvidenceType.LOG_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Lawful basis for processing personal data must be established",
        auditor_explanation=(
            "GDPR Article 6 requires lawful basis for processing. Missing consent handling creates "
            "an evidence gap. Evidence must demonstrate consent mechanisms with audit logging."
        ),
    )
)

register_control(
    ComplianceControl(
        control_id="Article-17",
        framework="GDPR",
        control_category=ControlCategory.DATA_SUBJECT_RIGHTS,
        control_type=ControlType.TECHNICAL,
        verification_method=VerificationMethod.MACHINE,
        required_evidence_types=[EvidenceType.CODE_PROOF, EvidenceType.LOG_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Right to erasure (right to be forgotten) must be implemented",
        auditor_explanation=(
            "GDPR Article 17 grants data subjects the right to erasure. Missing erasure mechanisms "
            "creates an evidence gap. Evidence must demonstrate erasure functionality with audit logging."
        ),
    )
)

register_control(
    ComplianceControl(
        control_id="Article-20",
        framework="GDPR",
        control_category=ControlCategory.DATA_SUBJECT_RIGHTS,
        control_type=ControlType.TECHNICAL,
        verification_method=VerificationMethod.MACHINE,
        required_evidence_types=[EvidenceType.CODE_PROOF, EvidenceType.LOG_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Data portability mechanisms must be implemented",
        auditor_explanation=(
            "GDPR Article 20 grants data subjects the right to data portability. Missing portability "
            "mechanisms creates an evidence gap. Evidence must demonstrate data export functionality."
        ),
    )
)

register_control(
    ComplianceControl(
        control_id="Article-32",
        framework="GDPR",
        control_category=ControlCategory.ENCRYPTION,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.CODE_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Security of processing must include encryption",
        auditor_explanation=(
            "GDPR Article 32 requires appropriate technical measures including encryption. Missing "
            "encryption creates an evidence gap. Evidence must demonstrate encryption configuration."
        ),
    )
)

# Additional SOC2 Controls
register_control(
    ComplianceControl(
        control_id="CC7.3",
        framework="SOC2",
        control_category=ControlCategory.INCIDENT_RESPONSE,
        control_type=ControlType.PROCEDURAL,
        verification_method=VerificationMethod.HUMAN_ATTESTATION,
        required_evidence_types=[EvidenceType.POLICY_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Incident response procedures must be established and tested",
        auditor_explanation="SOC2 CC7.3 requires documented incident response procedures with regular testing.",
    )
)

register_control(
    ComplianceControl(
        control_id="CC8.1",
        framework="SOC2",
        control_category=ControlCategory.VENDOR_RISK,
        control_type=ControlType.PROCEDURAL,
        verification_method=VerificationMethod.HUMAN_ATTESTATION,
        required_evidence_types=[EvidenceType.POLICY_PROOF],
        review_frequency=timedelta(days=180),
        expiry_policy=timedelta(days=365),
        description="Vendor risk management procedures must be established",
        auditor_explanation="SOC2 CC8.1 requires vendor risk assessment and management procedures.",
    )
)

# HIPAA Controls
register_control(
    ComplianceControl(
        control_id="164.308",
        framework="HIPAA",
        control_category=ControlCategory.ACCESS_CONTROL,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.POLICY_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Access controls for ePHI",
        auditor_explanation="HIPAA requires access controls to restrict ePHI access to authorized users only.",
    )
)

register_control(
    ComplianceControl(
        control_id="164.312",
        framework="HIPAA",
        control_category=ControlCategory.ENCRYPTION,
        control_type=ControlType.TECHNICAL,
        verification_method=VerificationMethod.MACHINE,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.CODE_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Encryption of ePHI in transit and at rest",
        auditor_explanation="HIPAA requires encryption of ePHI to protect against unauthorized access.",
    )
)

# PCI-DSS Controls
register_control(
    ComplianceControl(
        control_id="3.4",
        framework="PCI-DSS",
        control_category=ControlCategory.SECRETS_MANAGEMENT,
        control_type=ControlType.TECHNICAL,
        verification_method=VerificationMethod.MACHINE,
        required_evidence_types=[EvidenceType.CODE_PROOF, EvidenceType.CONFIG_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Render PAN unreadable anywhere it is stored",
        auditor_explanation="PCI-DSS requires cardholder data to be encrypted or tokenized.",
    )
)

register_control(
    ComplianceControl(
        control_id="8.2",
        framework="PCI-DSS",
        control_category=ControlCategory.ACCESS_CONTROL,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Strong authentication for all system components",
        auditor_explanation="PCI-DSS requires strong authentication mechanisms including MFA.",
    )
)

# NIST Cybersecurity Framework Controls
register_control(
    ComplianceControl(
        control_id="PR.AC-1",
        framework="NIST-CSF",
        control_category=ControlCategory.ACCESS_CONTROL,
        control_type=ControlType.SYSTEM,
        verification_method=VerificationMethod.CONFIGURATION,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.POLICY_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Identities and credentials are issued, managed, verified, revoked, and audited",
        auditor_explanation="NIST CSF requires identity and access management controls.",
    )
)

register_control(
    ComplianceControl(
        control_id="PR.DS-1",
        framework="NIST-CSF",
        control_category=ControlCategory.DATA_PROTECTION,
        control_type=ControlType.TECHNICAL,
        verification_method=VerificationMethod.MACHINE,
        required_evidence_types=[EvidenceType.CONFIG_PROOF, EvidenceType.CODE_PROOF],
        review_frequency=timedelta(days=90),
        expiry_policy=timedelta(days=365),
        description="Data-at-rest is protected",
        auditor_explanation="NIST CSF requires data-at-rest protection through encryption.",
    )
)


def get_control(framework: str, control_id: str) -> ComplianceControl | None:
    """Get a compliance control by framework and control_id."""
    key = f"{framework}-{control_id}"
    return COMPLIANCE_CONTROLS.get(key)


def get_controls_by_framework(framework: str) -> list[ComplianceControl]:
    """Get all controls for a specific framework."""
    return [ctrl for ctrl in COMPLIANCE_CONTROLS.values() if ctrl.framework == framework]


def get_controls_by_category(category: ControlCategory) -> list[ComplianceControl]:
    """Get all controls in a specific category."""
    return [ctrl for ctrl in COMPLIANCE_CONTROLS.values() if ctrl.control_category == category]


def get_controls_by_type(control_type: ControlType) -> list[ComplianceControl]:
    """Get all controls of a specific type."""
    return [ctrl for ctrl in COMPLIANCE_CONTROLS.values() if ctrl.control_type == control_type]


