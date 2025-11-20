# KratosComply

KratosComply is a privacy-first compliance automation engine designed to showcase both an offline-first security agent and a minimal verification backend+frontend stack. This repository will evolve through staged commits to deliver the full MVP described in the project brief.

## Repository Layout

- `agent/` – Python 3.11 agent packaged with Poetry.
- `backend/` – FastAPI service that verifies signed reports and records attestations.
- `frontend/` – Next.js + Tailwind UI for uploading reports and viewing attestations.
- `examples/sample-app/` – Insecure demo app used to produce sample findings.
- `docs/` – Architecture, privacy, and acceptance documentation.
- `.github/workflows/` – CI skeleton for linting, tests, and builds.

## Stage A Status

Stage A focuses on scaffolding the repo and providing the insecure sample application that later stages will scan and patch. Subsequent stages will add fully functional agent capabilities, backend verification, frontend workflows, Docker support, and documentation.

