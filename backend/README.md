# KratosComply Backend

The backend now exposes two primary capabilities:

- `POST /verify-report` – verifies the ed25519 signature and recomputes the Merkle
  root for an `aegis-report.json` produced by the agent.
- `POST /attest` – records a Merkle root/public-key pair (plus optional metadata) in
  the local SQLite ledger for demo purposes.

SQLite is used for local development, and the database file defaults to `kratos.db`
in the backend directory. Override the location with `KRATOS_DB_URL`.

## Quickstart

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
uvicorn main:app --reload

# Run backend unit tests
pytest -q
```
