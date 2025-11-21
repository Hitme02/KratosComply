from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Tuple

import sys
from pathlib import Path

from fastapi.testclient import TestClient
from nacl import signing
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.database import Base, get_db
from backend.main import app
from backend.models import Attestation
from backend.security import build_merkle_root, canonical_json


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
        }
    ]
    merkle_root = build_merkle_root([finding["evidence_hash"] for finding in findings])
    report = {
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
        "agent_signature": "",
        "agent_version": "kratos-agent-demo-0.1",
    }
    signing_key = signing.SigningKey.generate()
    signature = signing_key.sign(
        canonical_json({k: v for k, v in report.items() if k != "agent_signature"}).encode("utf-8")
    )
    report["agent_signature"] = signature.signature.hex()
    public_key_hex = signing_key.verify_key.encode().hex()
    return report, public_key_hex, signing_key


def _setup_client(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/test.db",
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    return client, TestingSessionLocal


def test_verify_report_success(tmp_path) -> None:
    client, _ = _setup_client(tmp_path)
    report, public_key_hex, _ = _build_signed_report()
    payload = {"report": report, "public_key_hex": public_key_hex}
    response = client.post("/verify-report", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["message"] == "Report verified"


def test_verify_report_merkle_mismatch(tmp_path) -> None:
    client, _ = _setup_client(tmp_path)
    report, public_key_hex, signing_key = _build_signed_report()
    tampered = deepcopy(report)
    tampered["merkle_root"] = "0" * 64
    tampered_payload = {k: v for k, v in tampered.items() if k != "agent_signature"}
    tampered["agent_signature"] = signing_key.sign(
        canonical_json(tampered_payload).encode("utf-8")
    ).signature.hex()
    response = client.post("/verify-report", json={"report": tampered, "public_key_hex": public_key_hex})
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert body["message"] == "Merkle root mismatch"


def test_attest_records_entry(tmp_path) -> None:
    client, SessionLocal = _setup_client(tmp_path)
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
    assert body["attest_id"] == 1

    session = SessionLocal()
    try:
        records = session.query(Attestation).all()
        assert len(records) == 1
        assert records[0].merkle_root == report["merkle_root"]
    finally:
        session.close()

