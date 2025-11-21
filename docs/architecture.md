# Architecture Overview

The system now includes working components for the agent (Stages A–C) and backend (Stage D):

- A Python agent responsible for scanning local workspaces, building deterministic Merkle trees, and signing reports.
- Deterministic patcher + sandbox harness that emits reviewed diffs for select findings.
- A FastAPI backend that verifies signatures and records attestations in SQLite.
- A React + Vite frontend (Tailwind + shadcn/ui) for uploading reports, visualising metrics, and reviewing attestations.

Future revisions of this file will add a Mermaid system diagram and detailed component responsibilities.
