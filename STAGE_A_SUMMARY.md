# Stage A Summary – Scaffold KratosComply Repo + Sample App

## What was added
- Repository root structure for agent, backend, frontend, docs, CI, and examples
- Poetry + FastAPI + Next.js scaffolds to unblock later feature work
- Vulnerable sample application with pytest coverage and placeholder aegis report

## How to verify Stage A
```bash
ls
python -m venv .venv && source .venv/bin/activate && pip install pytest && pytest examples/sample-app/tests -q
( cd frontend && npm install )
( cd backend && python -m venv .venv && source .venv/bin/activate && pip install -e .[dev] && uvicorn main:app --reload )
```

## Sample `aegis-report.json` (first 10 lines)
```
{
  "report_version": "1.0",
  "project": {
    "name": "sample-app",
    "path": "examples/sample-app",
    "commit": null,
    "scan_time": "2025-01-01T00:00:00Z"
  },
```
