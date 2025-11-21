# Stage D Summary – Backend Verify + Attest

## What was added
- FastAPI endpoints for `/verify-report` (signature + Merkle validation) and `/attest`
  (SQLite-backed ledger) with reusable security + database utilities.
- SQLAlchemy models, Pydantic schemas, and NaCl-based verification logic aligned with
  the agent's canonical JSON + Merkle algorithms.
- Backend pytest coverage for verification success/failure paths and attestation
  persistence using an isolated SQLite database.

## How to verify Stage D
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pytest -q
uvicorn main:app --reload  # then POST to /verify-report and /attest as needed
```

## Sample verify payload (truncated)
```
{
  "report": {
    "report_version": "1.0",
    "project": { "name": "sample", "path": "/workspace/sample", ... },
    "findings": [ { "id": "F001", "evidence_hash": "9..." } ],
    "merkle_root": "27ad3a34...",
    "agent_signature": "458014...",
    ...
  },
  "public_key_hex": "8f2e6..."
}
```
