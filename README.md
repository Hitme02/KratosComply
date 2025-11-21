# KratosComply

KratosComply is a privacy-first compliance automation engine designed to showcase both an offline-first security agent and a minimal verification backend+frontend stack. This repository will evolve through staged commits to deliver the full MVP described in the project brief.

## Repository Layout

- `agent/` – Python 3.11 agent packaged with Poetry.
- `backend/` – FastAPI service that verifies signed reports and records attestations.
- `frontend/` – Next.js + Tailwind UI for uploading reports and viewing attestations.
- `examples/sample-app/` – Insecure demo app used to produce sample findings.
- `docs/` – Architecture, privacy, and acceptance documentation.
- `.github/workflows/` – CI skeleton for linting, tests, and builds.

## Stage Progress

- **Stage A** – Repository scaffold, sample insecure application, base docs, and CI shell.
- **Stage B** – Agent detectors, deterministic Merkle tree + signing pipeline, and CLI
  commands for key generation and scanning that emit reproducible `aegis-report.json`
  artifacts from the sample app.
- **Stage C** – Deterministic patcher that creates sandbox-validated diffs plus CLI
  support for generating and applying fixes, along with sample patch outputs.
- **Stage D** – FastAPI backend with `/verify-report` signature+Merkle checks,
  `/attest` persistence, and pytest coverage for the verification flow.

