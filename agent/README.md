# Kratos Agent

The Kratos agent is a privacy-first, deterministic scanner that powers KratosComply.
Stage B introduces working detectors, Merkle tree generation, ed25519 signing, and CLI
commands for key generation and scanning.

## Local setup

```bash
cd agent
poetry install
poetry run python -m agent.cli --help
```

## Quick commands

```bash
# Generate offline key pair (stored under ~/.kratos/keys by default)
poetry run python -m agent.cli generate-key

# Scan a workspace and emit a signed Aegis report
poetry run python -m agent.cli scan ../examples/sample-app \
  --output ../examples/sample-app/aegis-report.json \
  --generate-patches

# Apply a suggested patch (after reviewing the diff)
poetry run python -m agent.cli apply-patch ../examples/sample-app/patches/0001-fix-F001.diff \
  --workspace ../examples/sample-app
```
