"""SQLAlchemy models for the KratosComply compliance ledger."""
from __future__ import annotations

from datetime import datetime, timezone
import json

from sqlalchemy import Column, DateTime, Float, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship

from database import Base


class Attestation(Base):
    __table_args__ = {'extend_existing': True}
    """Compliance ledger record for legal-grade attestation statements.
    
    Each attestation is a cryptographically sealed compliance statement,
    not just a database record. It represents verified compliance evidence
    suitable for audit, investor, and regulatory review.
    """

    __tablename__ = "attestations"

    id = Column(Integer, primary_key=True, index=True)
    merkle_root = Column(Text, nullable=False, index=True)
    public_key_hex = Column(Text, nullable=False)  # Agent public key
    metadata_json = Column(Text, nullable=True)
    
    # Compliance ledger metadata
    frameworks_covered = Column(Text, nullable=True)  # JSON array of frameworks
    control_coverage_percent = Column(Float, nullable=True)  # Percentage of controls passed
    
    # Legal artifact metadata
    evidence_hashes = Column(Text, nullable=True)  # JSON array of evidence hashes
    human_signer_identities = Column(Text, nullable=True)  # JSON array of hashed signer identities
    control_states = Column(Text, nullable=True)  # JSON object mapping control_id -> state
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    verified_at = Column(DateTime(timezone=True), nullable=True)  # When attestation was verified

    def set_metadata(self, metadata: dict | None) -> None:
        self.metadata_json = json.dumps(metadata or {}, separators=(",", ":"))

    def get_metadata(self) -> dict:
        if not self.metadata_json:
            return {}
        return json.loads(self.metadata_json)
    
    def set_frameworks(self, frameworks: list[str]) -> None:
        """Set compliance frameworks covered by this attestation."""
        self.frameworks_covered = json.dumps(frameworks, separators=(",", ":"))
    
    def get_frameworks(self) -> list[str]:
        """Get compliance frameworks covered by this attestation."""
        if not self.frameworks_covered:
            return []
        return json.loads(self.frameworks_covered)
    
    def set_evidence_hashes(self, hashes: list[str]) -> None:
        """Set evidence hashes for this attestation."""
        self.evidence_hashes = json.dumps(hashes, separators=(",", ":"))
    
    def get_evidence_hashes(self) -> list[str]:
        """Get evidence hashes for this attestation."""
        if not self.evidence_hashes:
            return []
        return json.loads(self.evidence_hashes)
    
    def set_human_signer_identities(self, identities: list[str]) -> None:
        """Set hashed human signer identities for this attestation.
        
        Each identity should be a SHA256 hash of the signer's public key
        and role to preserve privacy while maintaining auditability.
        """
        self.human_signer_identities = json.dumps(identities, separators=(",", ":"))
    
    def get_human_signer_identities(self) -> list[str]:
        """Get hashed human signer identities for this attestation."""
        if not self.human_signer_identities:
            return []
        return json.loads(self.human_signer_identities)
    
    def set_control_states(self, states: dict[str, str]) -> None:
        """Set control states for this attestation.
        
        States map control_id (e.g., "SOC2-CC6.1") to ControlState values:
        VERIFIED_MACHINE, VERIFIED_SYSTEM, ATTESTED_HUMAN, MISSING_EVIDENCE, EXPIRED_EVIDENCE
        """
        self.control_states = json.dumps(states, separators=(",", ":"))
    
    def get_control_states(self) -> dict[str, str]:
        """Get control states for this attestation."""
        if not self.control_states:
            return {}
        return json.loads(self.control_states)


class HumanAttestation(Base):
    """Human-in-the-loop attestation for procedural controls.
    
    These attestations are cryptographically signed by authorized roles
    (Founder, Compliance Officer, etc.) and represent non-technical evidence
    that cannot be machine-verified.
    """
    __tablename__ = "human_attestations"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(Text, nullable=False, index=True)
    framework = Column(Text, nullable=False, index=True)
    role = Column(Text, nullable=False)  # e.g., "founder", "compliance_officer"
    scope = Column(Text, nullable=False)  # Description of what is being attested
    attestation_text = Column(Text, nullable=False)  # Human-readable statement
    
    # Cryptographic integrity
    evidence_hash = Column(Text, nullable=False)  # SHA256 hash of all evidence
    signer_public_key = Column(Text, nullable=False)  # Ed25519 public key
    signature = Column(Text, nullable=False)  # Ed25519 signature
    attestation_id = Column(Text, nullable=False, unique=True, index=True)  # Unique ID
    
    # Time-scoping
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    # Evidence references
    evidence_upload_ids_json = Column(Text, nullable=True)  # JSON array of file IDs
    
    # Metadata
    metadata_json = Column(Text, nullable=True)
    
    def set_evidence_upload_ids(self, ids: list[str]) -> None:
        """Set evidence upload IDs."""
        self.evidence_upload_ids_json = json.dumps(ids, separators=(",", ":"))
    
    def get_evidence_upload_ids(self) -> list[str]:
        """Get evidence upload IDs."""
        if not self.evidence_upload_ids_json:
            return []
        return json.loads(self.evidence_upload_ids_json)
    
    def set_metadata(self, metadata: dict | None) -> None:
        """Set metadata."""
        self.metadata_json = json.dumps(metadata or {}, separators=(",", ":"))
    
    def get_metadata(self) -> dict:
        """Get metadata."""
        if not self.metadata_json:
            return {}
        return json.loads(self.metadata_json)


class EvidenceUpload(Base):
    """Stored evidence files for human attestations.
    
    Evidence can be policies, SOPs, screenshots, log exports, or declarations.
    Files are stored with cryptographic hashes for integrity verification.
    """
    __tablename__ = "evidence_uploads"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    upload_id = Column(Text, nullable=False, unique=True, index=True)  # Unique file ID
    file_name = Column(Text, nullable=False)
    file_type = Column(Text, nullable=False)  # policy, sop, screenshot, log_export, declaration
    content_hash = Column(Text, nullable=False)  # SHA256 hash of file content
    file_size = Column(Integer, nullable=False)  # Size in bytes
    
    # Storage (in production, this would reference blob storage)
    storage_path = Column(Text, nullable=True)  # Path to stored file
    
    # Metadata
    uploaded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    uploaded_by = Column(Text, nullable=True)  # User/role who uploaded
    metadata_json = Column(Text, nullable=True)
    
    def set_metadata(self, metadata: dict | None) -> None:
        """Set metadata."""
        self.metadata_json = json.dumps(metadata or {}, separators=(",", ":"))
    
    def get_metadata(self) -> dict:
        """Get metadata."""
        if not self.metadata_json:
            return {}
        return json.loads(self.metadata_json)

