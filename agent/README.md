# Kratos Agent (Scaffold)

This directory contains the Python 3.11 agent that will power KratosComply scans.

Stage A provides the Poetry configuration and placeholders for the CLI entry points. Future stages will add detectors, Merkle tree logic, signing, patching, sandboxing, and attestation support.

## Local setup

```bash
cd agent
poetry install
poetry run python -m agent.cli --help  # placeholder for future stages
```
