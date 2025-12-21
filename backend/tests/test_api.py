from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Tuple

from fastapi.testclient import TestClient
from nacl import signing
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# conftest.py handles the setup, so we can import directly
from backend.database import Base, get_db
from backend.models import Attestation
from backend.security import build_merkle_root, canonical_json
from backend.main import app


def _build_signed_report() -> tuple[dict, str, signing.SigningKey]:
    findings = [
        {
            "id": "F001",
            "type": "hardcoded_secret",
            "file": "app.py",
            "line": 1,
            "snippet": 'API_KEY = "demo"',
            "severity": "high",
            "confidence": 0.98,
            "evidence_hash": "9" * 64,
            "compliance_frameworks_affected": [],
            "control_id": "",
            "control_category": "",
            "control_pass_fail_status": "",
            "required_evidence_missing": "",
            "auditor_explanation": "",
        }
    ]
    merkle_root = build_merkle_root([finding["evidence_hash"] for finding in findings])
    # Build unsigned report (without signature)
    unsigned_report = {
        "report_version": "1.0",
        "project": {
            "name": "sample",
            "path": "/workspace/sample",
            "commit": None,
            "scan_time": datetime.now(timezone.utc).isoformat(),
        },
        "standards": ["SOC2", "ISO27001"],
        "findings": findings,
        "metrics": {"critical": 0, "high": 1, "medium": 0, "low": 0, "risk_score": 20},
        "merkle_root": merkle_root,
        "agent_version": "kratos-agent-demo-0.1",
    }
    signing_key = signing.SigningKey.generate()
    # Sign the unsigned report
    signature = signing_key.sign(
        canonical_json(unsigned_report).encode("utf-8")
    )
    # Add signature to report
    report = {**unsigned_report, "agent_signature": signature.signature.hex()}
    public_key_hex = signing_key.verify_key.encode().hex()
    return report, public_key_hex, signing_key


def _setup_client(tmp_path):
    # Create a fresh engine and metadata for testing
    test_engine = create_engine(
        f"sqlite:///{tmp_path}/test.db",
        connect_args={"check_same_thread": False},
    )
    # Drop all tables first to avoid conflicts
    Base.metadata.drop_all(bind=test_engine)
    # Create fresh tables - ensure this happens synchronously
    # Models are already imported via conftest.py
    Base.metadata.create_all(bind=test_engine)
    
    # Verify table was created
    from sqlalchemy import inspect
    inspector = inspect(test_engine)
    tables = inspector.get_table_names()
    if "attestations" not in tables:
        # Force create if not present
        Base.metadata.create_all(bind=test_engine, checkfirst=True)
    
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    return client, TestingSessionLocal, test_engine


def test_verify_report_success(tmp_path) -> None:
    client, _, _ = _setup_client(tmp_path)
    report, public_key_hex, _ = _build_signed_report()
    payload = {"report": report, "public_key_hex": public_key_hex}
    response = client.post("/verify-report", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["message"] == "Compliance evidence report verified"


def test_verify_report_merkle_mismatch(tmp_path) -> None:
    client, _, _ = _setup_client(tmp_path)
    report, public_key_hex, signing_key = _build_signed_report()
    # Create a valid signed report with tampered merkle_root
    # We need to sign it correctly so signature passes, but merkle root will fail
    tampered = deepcopy(report)
    tampered["merkle_root"] = "0" * 64
    # Remove signature, sign the tampered payload, then add signature back
    tampered_unsigned = {k: v for k, v in tampered.items() if k != "agent_signature"}
    tampered["agent_signature"] = signing_key.sign(
        canonical_json(tampered_unsigned).encode("utf-8")
    ).signature.hex()
    response = client.post("/verify-report", json={"report": tampered, "public_key_hex": public_key_hex})
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    # The signature will verify, but Merkle root will mismatch
    assert body["message"] == "Merkle root mismatch"


def test_attest_records_entry(tmp_path) -> None:
    client, SessionLocal, test_engine = _setup_client(tmp_path)
    report, public_key_hex, _ = _build_signed_report()
    attest_payload = {
        "merkle_root": report["merkle_root"],
        "public_key_hex": public_key_hex,
        "metadata": {"env": "dev"},
    }
    response = client.post("/attest", json=attest_payload)
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "recorded"
    attest_id = body["attest_id"]
    assert attest_id > 0  # Just check it's a positive ID

    # Verify via API endpoint - check that our attestation is in the list
    list_response = client.get("/api/attestations")
    assert list_response.status_code == 200
    list_body = list_response.json()
    # Find our attestation by merkle_root
    our_attestation = next(
        (a for a in list_body["attestations"] if a["merkle_root"] == report["merkle_root"].lower()),
        None
    )
    assert our_attestation is not None, "Attestation not found in list"
    assert our_attestation["id"] == attest_id

