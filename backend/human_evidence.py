"""Human-in-the-Loop Evidence System for KratosComply.

This module handles human attestations and procedural evidence that cannot
be machine-verified. All human evidence must be cryptographically signed
and time-scoped.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from nacl import signing
from pydantic import BaseModel, Field


class HumanAttestationRole(str, Enum):
    """Roles that can provide human attestations."""

    FOUNDER = "founder"
    COMPLIANCE_OFFICER = "compliance_officer"
    SECURITY_LEAD = "security_lead"
    DATA_PROTECTION_OFFICER = "data_protection_officer"
    AUDITOR = "auditor"


class EvidenceUploadType(str, Enum):
    """Types of evidence that can be uploaded."""

    POLICY = "policy"  # PDF/MD policy documents
    SOP = "sop"  # Standard Operating Procedures
    SCREENSHOT = "screenshot"  # Screenshot evidence
    LOG_EXPORT = "log_export"  # Log file exports
    DECLARATION = "declaration"  # Structured declarations


class HumanAttestationRequest(BaseModel):
    """Request for human attestation."""

    control_id: str
    framework: str
    role: HumanAttestationRole
    scope: str  # Description of what is being attested
    attestation_text: str  # Human-readable attestation statement
    expiry_days: int = Field(default=365, ge=1, le=3650)  # Evidence validity period
    evidence_uploads: list[str] = Field(default_factory=list)  # File IDs of uploaded evidence


class HumanAttestationRecord(BaseModel):
    """Cryptographically signed human attestation record."""

    attestation_id: str
    control_id: str
    framework: str
    role: HumanAttestationRole
    scope: str
    attestation_text: str
    evidence_hash: str  # SHA256 hash of all evidence
    signer_public_key: str  # Ed25519 public key of signer
    signature: str  # Ed25519 signature
    timestamp: datetime
    expires_at: datetime
    evidence_upload_ids: list[str]


def hash_evidence_content(content: bytes) -> str:
    """Generate SHA256 hash of evidence content."""
    return hashlib.sha256(content).hexdigest()


def create_human_attestation(
    request: HumanAttestationRequest,
    signer_key: signing.SigningKey,
    evidence_contents: list[bytes],
) -> HumanAttestationRecord:
    """Create a cryptographically signed human attestation.

    Args:
        request: Attestation request details
        signer_key: Ed25519 signing key of the attester
        evidence_contents: Raw bytes of uploaded evidence files

    Returns:
        HumanAttestationRecord with cryptographic signature
    """
    # Hash all evidence content
    evidence_hashes = [hash_evidence_content(content) for content in evidence_contents]
    combined_hash = hashlib.sha256("".join(evidence_hashes).encode()).hexdigest()

    # Create attestation payload
    timestamp = datetime.now(timezone.utc)
    expires_at = timestamp.replace(
        day=timestamp.day + request.expiry_days
    )  # Simplified - should use timedelta

    payload = {
        "control_id": request.control_id,
        "framework": request.framework,
        "role": request.role.value,
        "scope": request.scope,
        "attestation_text": request.attestation_text,
        "evidence_hash": combined_hash,
        "timestamp": timestamp.isoformat(),
        "expires_at": expires_at.isoformat(),
        "evidence_upload_ids": request.evidence_uploads,
    }

    # Canonical JSON serialization for deterministic hashing
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_bytes = payload_json.encode("utf-8")

    # Sign the payload
    signature_bytes = signer_key.sign(payload_bytes).signature
    signature_hex = signature_bytes.hex()

    # Get public key
    public_key_hex = signer_key.verify_key.encode().hex()

    # Generate attestation ID from hash
    attestation_id = hashlib.sha256(
        f"{request.control_id}:{request.framework}:{timestamp.isoformat()}:{signature_hex}".encode()
    ).hexdigest()[:16]

    return HumanAttestationRecord(
        attestation_id=attestation_id,
        control_id=request.control_id,
        framework=request.framework,
        role=request.role,
        scope=request.scope,
        attestation_text=request.attestation_text,
        evidence_hash=combined_hash,
        signer_public_key=public_key_hex,
        signature=signature_hex,
        timestamp=timestamp,
        expires_at=expires_at,
        evidence_upload_ids=request.evidence_uploads,
    )


def verify_human_attestation(record: HumanAttestationRecord) -> bool:
    """Verify the cryptographic signature of a human attestation.

    Args:
        record: Human attestation record to verify

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Reconstruct payload
        payload = {
            "control_id": record.control_id,
            "framework": record.framework,
            "role": record.role.value,
            "scope": record.scope,
            "attestation_text": record.attestation_text,
            "evidence_hash": record.evidence_hash,
            "timestamp": record.timestamp.isoformat(),
            "expires_at": record.expires_at.isoformat(),
            "evidence_upload_ids": record.evidence_upload_ids,
        }

        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload_bytes = payload_json.encode("utf-8")

        # Verify signature
        verify_key = signing.VerifyKey(bytes.fromhex(record.signer_public_key))
        verify_key.verify(payload_bytes, bytes.fromhex(record.signature))

        return True
    except Exception:
        return False


def is_attestation_expired(record: HumanAttestationRecord) -> bool:
    """Check if a human attestation has expired.

    Args:
        record: Human attestation record to check

    Returns:
        True if expired, False otherwise
    """
    return datetime.now(timezone.utc) > record.expires_at

