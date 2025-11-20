# Architecture Overview (Stage A)

Stage A introduces the directory layout but no runtime integration yet. The final architecture will include:

- A Python agent responsible for scanning local workspaces, building deterministic Merkle trees, and signing reports.
- A FastAPI backend that verifies signatures and records attestations in SQLite.
- A Next.js frontend for uploading reports and reviewing attestations.

Future revisions of this file will add a Mermaid system diagram and detailed component responsibilities.
