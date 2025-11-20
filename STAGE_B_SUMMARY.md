# Stage B Summary – Agent Detectors, Merkle, Signing, CLI

## What was added
- Deterministic detectors for Python hardcoded secrets and IaC public ACLs with evidence hashing.
- Merkle tree builder, ed25519 keystore management, canonical JSON signing helpers, and enhanced Typer CLI.
- Unit tests covering detectors, Merkle determinism, and signing round-trips plus repository-level `conftest.py`.
- Updated docs, README, and acceptance checklist to reflect Stage B capabilities.

## How to verify Stage B
```bash
cd agent
poetry install
poetry run python -m agent.cli generate-key --keystore ~/.kratos/keys
poetry run python -m agent.cli scan ../examples/sample-app --output ../examples/sample-app/aegis-report.json
cd ..
pytest -q
```

## Sample `aegis-report.json` (first 10 lines)
```
{
  "report_version": "1.0",
  "project": {
    "name": "sample-app",
    "path": "/Users/user/Desktop/KratosCompliance/examples/sample-app",
    "commit": "ff5c10debc85d24342a77e99b9b49ec11a9b52bc",
    "scan_time": "2025-11-20T09:43:13.918810+00:00"
```

