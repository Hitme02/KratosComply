"""Pytest configuration and fixtures for backend tests."""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Set test mode before any imports
os.environ["TESTING"] = "1"

# Add project root to path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Import models to register them with Base metadata
# This must happen before any table creation
from backend.models import Attestation  # noqa: F401

# Now we can safely import Base
from backend.database import Base

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import get_db
from backend.main import app


@pytest.fixture
def isolated_db():
    """Fixture that provides an isolated in-memory database for each test."""
    # Clear any existing overrides FIRST
    if get_db in app.dependency_overrides:
        del app.dependency_overrides[get_db]
    app.dependency_overrides.clear()
    
    # Create temporary file-based database for better isolation
    import tempfile
    import os
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp_file.close()
    db_path = tmp_file.name
    
    test_engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    # Set the override - this MUST happen before creating the test client
    app.dependency_overrides[get_db] = override_get_db
    
    yield test_engine
    
    # Cleanup
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()
    # Remove temp file
    try:
        os.unlink(db_path)
    except Exception:
        pass


@pytest.fixture
def test_client(isolated_db):
    """Fixture that provides a test client with isolated database.
    
    The isolated_db fixture ensures the dependency override is set before
    the client is created.
    """
    # Verify override is set
    assert get_db in app.dependency_overrides, "Dependency override not set!"
    return TestClient(app)

