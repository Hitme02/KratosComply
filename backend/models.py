"""SQLAlchemy models for the KratosComply compliance ledger."""
from __future__ import annotations

from datetime import datetime, timezone
import json

from sqlalchemy import Column, DateTime, Float, Integer, Text

from database import Base


class Attestation(Base):
    """Compliance ledger record for legal-grade attestation statements.
    
    Each attestation represents a verified compliance evidence report
    suitable for audit, investor, and regulatory review.
    """

    __tablename__ = "attestations"

    id = Column(Integer, primary_key=True, index=True)
    merkle_root = Column(Text, nullable=False, index=True)
    public_key_hex = Column(Text, nullable=False)
    metadata_json = Column(Text, nullable=True)
    # Compliance ledger metadata
    frameworks_covered = Column(Text, nullable=True)  # JSON array of frameworks
    control_coverage_percent = Column(Float, nullable=True)  # Percentage of controls passed
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

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

