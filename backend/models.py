"""SQLAlchemy models for the KratosComply backend."""
from __future__ import annotations

from datetime import datetime, timezone
import json

from sqlalchemy import Column, DateTime, Integer, Text

from .database import Base


class Attestation(Base):
    """Persistence model for attestation records."""

    __tablename__ = "attestations"

    id = Column(Integer, primary_key=True, index=True)
    merkle_root = Column(Text, nullable=False, index=True)
    public_key_hex = Column(Text, nullable=False)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def set_metadata(self, metadata: dict | None) -> None:
        self.metadata_json = json.dumps(metadata or {}, separators=(",", ":"))

    def get_metadata(self) -> dict:
        if not self.metadata_json:
            return {}
        return json.loads(self.metadata_json)

