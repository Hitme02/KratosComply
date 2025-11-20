# KratosComply Backend (Stage A)

This FastAPI application will verify signed reports and provide a minimal attestation ledger in later stages. Stage A delivers a simple health endpoint and project metadata so the service can run via `uvicorn`.

## Quickstart

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
uvicorn main:app --reload
```
