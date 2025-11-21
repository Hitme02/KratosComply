# KratosComply

KratosComply is a privacy-first compliance automation engine designed to showcase both an offline-first security agent and a minimal verification backend+frontend stack. This repository will evolve through staged commits to deliver the full MVP described in the project brief.

## Repository Layout

- `agent/` – Python 3.11 agent packaged with Poetry.
- `backend/` – FastAPI service that verifies signed reports and records attestations.
- `frontend/` – React + Vite + Tailwind + shadcn/ui dashboard for uploads, verification, and attestations.
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
- **Stage E** – React + Vite + Tailwind + shadcn/ui frontend that uploads reports,
  visualises metrics, verifies against the backend, and records attestations with charts.

## Quick Start

### Docker Compose (Recommended)

```bash
# Development mode
docker-compose up --build

# Production mode
docker-compose -f docker-compose.prod.yml up --build -d
```

See [docs/DOCKER_SETUP.md](docs/DOCKER_SETUP.md) for detailed instructions.

### Manual Setup

**Backend:**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
uvicorn main:app --reload  # http://localhost:8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev      # http://localhost:5173
npm run build    # production bundle
```

**Agent:**
```bash
cd agent
poetry install
poetry run python -m agent.cli generate-key --keystore ~/.kratos/keys
poetry run python -m agent.cli scan ../examples/sample-app \
  --output ../examples/sample-app/aegis-report.json
```

## Features

### Frontend (Stage E)
- **Landing page** with step-by-step workflow and mode selection (Docker vs GitHub OAuth)
- **Docker setup page** with copy-paste commands for offline scanning
- **Enhanced upload** with drag & drop, public key input, and visual feedback
- **Verification + attestation** workflows wired to `/verify-report` and `/attest`
- **Charts**: Severity bar + compliance radar, risk cards, and status indicators
- **Attestation history** table with search-ready UI
- **Dark mode** by default, theme toggle, shadcn/ui components, Framer Motion animations

### GitHub OAuth (Partial)
- OAuth authorization flow configured
- Environment variable support
- Token exchange and repository scanning (TODO - see [docs/GITHUB_OAUTH_SETUP.md](docs/GITHUB_OAUTH_SETUP.md))

