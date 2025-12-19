# KratosComply

**Compliance evidence automation for startups.** Generate audit-ready compliance reports with cryptographic verification for SOC2, ISO27001, GDPR, and DPDP Act compliance.

## Overview

KratosComply is a compliance-first, privacy-preserving audit automation platform that generates cryptographically verifiable compliance evidence reports. Every detection maps to specific compliance framework controls, making it suitable for auditors, investors, and regulators.

**Core Philosophy**: Compliance includes security. Every detection maps to a specific compliance control, legal requirement, or audit verifiability requirement.

## Features

- ✅ **Offline-First Agent**: Scans codebases locally, no source code leaves your environment
- ✅ **Cryptographic Verification**: Ed25519 signatures + SHA256 Merkle trees for audit-grade integrity
- ✅ **Compliance Mapping**: Every finding maps to specific framework controls (SOC2, ISO27001, GDPR, DPDP)
- ✅ **Legal-Grade Attestations**: Compliance ledger suitable for audit, investor, and regulatory review
- ✅ **Auto-Fix Support**: Generates safe patches for fixable violations (sandbox-validated)
- ✅ **Modern UI**: React dashboard with animations and comprehensive workflows

## What Gets Detected

### Security Violations
- Hardcoded secrets (API keys, passwords, tokens)
- Insecure ACLs in infrastructure code (public-read, public-write)

### Compliance Framework Gaps
- **DPDP Act (India)**: Missing data retention, consent handling, access logging
- **GDPR (EU)**: Missing encryption, consent, retention, erasure, portability mechanisms

## Quick Start

### Docker Compose (Recommended)

```bash
# Clone repository
git clone <repository-url>
cd KratosCompliance

# Start all services
docker-compose up --build

# Services will be available at:
# - Frontend: http://localhost:5173
# - Backend: http://localhost:8000
# - Backend API docs: http://localhost:8000/docs
```

### Manual Setup

#### 1. Backend Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .[dev]
uvicorn main:app --reload
```

Backend will run at `http://localhost:8000`

#### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend will run at `http://localhost:5173`

#### 3. Agent Setup

```bash
cd agent
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Generate cryptographic keypair
python -m agent.cli generate-key

# Scan a project
python -m agent.cli scan /path/to/project \
    --output report.json \
    --project-name "my-project" \
    --generate-patches
```

## Usage

### 1. Generate Keys

First, generate a cryptographic keypair for signing reports:

```bash
cd agent
source venv/bin/activate
python -m agent.cli generate-key
```

Keys are stored in `~/.kratos/keys/` by default.

### 2. Scan Your Project

```bash
python -m agent.cli scan /path/to/your/project \
    --output report.json \
    --project-name "your-project" \
    --generate-patches
```

### 3. Upload & Verify

1. Open the frontend at `http://localhost:5173`
2. Upload the generated `report.json`
3. Enter your public key (get it with: `python -m agent.cli public-key`)
4. Verify the report signature
5. Create an attestation

### 4. GitHub Integration (Optional)

1. Configure GitHub OAuth app (see GitHub OAuth Setup below)
2. Click "Connect GitHub" on the frontend
3. Select a repository
4. View scan results automatically

## GitHub OAuth Setup

### Step 1: Create GitHub OAuth App

1. Go to [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in:
   - **Application name**: `KratosComply`
   - **Homepage URL**: `http://localhost:5173` (or your production domain)
   - **Authorization callback URL**: `http://localhost:5173/github/callback`
4. Click "Register application"
5. Copy the **Client ID** and generate a **Client Secret**

### Step 2: Configure Environment

Create a `.env` file in the project root:

```bash
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
GITHUB_REDIRECT_URI=http://localhost:5173/github/callback
```

### Step 3: Restart Services

```bash
docker-compose restart backend
```

Or if running manually, restart the backend server.

## Project Structure

```
KratosCompliance/
├── agent/              # Compliance evidence scanner (Python)
│   ├── agent/         # Core agent code
│   ├── tests/         # Agent tests
│   └── requirements.txt
├── backend/            # Verification & attestation API (FastAPI)
│   ├── main.py        # API endpoints
│   ├── models.py      # Database models
│   ├── schemas.py     # Pydantic schemas
│   └── pyproject.toml
├── frontend/           # Audit cockpit UI (React + Vite)
│   ├── src/
│   │   ├── pages/     # Page components
│   │   ├── components/# UI components
│   │   └── services/  # API clients
│   └── package.json
├── docs/               # Documentation
├── examples/           # Sample applications
├── docker-compose.yml  # Development setup
└── README.md
```

## API Endpoints

### Backend API

- `GET /health` - Health check
- `POST /verify-report` - Verify report signature and Merkle root
- `POST /attest` - Create compliance attestation
- `GET /api/attestations` - List all attestations
- `POST /auditor/verify` - External auditor verification
- `GET /api/auth/github` - Initiate GitHub OAuth
- `POST /github/callback` - GitHub OAuth callback

See `http://localhost:8000/docs` for interactive API documentation.

## Agent Commands

```bash
# Generate keypair
python -m agent.cli generate-key

# Scan workspace
python -m agent.cli scan <path> --output <report.json> --project-name <name>

# Generate patches (optional)
python -m agent.cli scan <path> --output <report.json> --generate-patches

# Apply patch
python -m agent.cli apply-patch <patch.diff> --workspace <path>

# Get public key
python -m agent.cli public-key
```

## Environment Variables

### Backend (.env)

```bash
# Database (optional, defaults to SQLite)
KRATOS_DB_URL=postgresql://user:password@host:5432/kratos

# GitHub OAuth (optional)
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
GITHUB_REDIRECT_URI=http://localhost:5173/github/callback
```

### Frontend (.env)

```bash
VITE_API_URL=http://localhost:8000
```

## Production Deployment

### Using Docker Compose

```bash
# Production mode
docker-compose -f docker-compose.prod.yml up --build -d
```

### Requirements

- PostgreSQL database (recommended for production)
- SSL/HTTPS certificates
- Environment variables configured in `.env`
- GitHub OAuth app configured (if using GitHub integration)

### Environment Variables for Production

Create `.env` file:

```bash
# Database
KRATOS_DB_URL=postgresql://user:password@host:5432/kratos

# GitHub OAuth
GITHUB_CLIENT_ID=your_production_client_id
GITHUB_CLIENT_SECRET=your_production_client_secret
GITHUB_REDIRECT_URI=https://yourdomain.com/github/callback

# Frontend API URL
VITE_API_URL=https://api.yourdomain.com
```

## What KratosComply Does NOT Do

KratosComply focuses on compliance evidence generation, not runtime security monitoring:

- ❌ Does NOT scan for CVEs or dependency vulnerabilities
- ❌ Does NOT detect runtime attacks or exploits
- ❌ Does NOT monitor network traffic or runtime behavior
- ❌ Does NOT act as a SIEM, SAST, or DAST tool

KratosComply is compliance infrastructure that includes security controls as part of compliance requirements.

## Architecture

### Components

- **Agent** (`agent/`): Python 3.11+ compliance scanner
  - AST-based detection for Python files
  - Regex-based detection for text files
  - Compliance control mapping (SOC2, ISO27001, GDPR, DPDP)
  - Ed25519 cryptographic signing
  - SHA256 Merkle tree integrity

- **Backend** (`backend/`): FastAPI verification service
  - Report signature verification
  - Compliance attestation ledger
  - GitHub OAuth integration
  - SQLite/PostgreSQL database

- **Frontend** (`frontend/`): React audit cockpit
  - Report upload and verification
  - Attestation creation and history
  - Compliance metrics visualization
  - GitHub repository integration

## Technology Stack

- **Agent**: Python 3.11+, AST parsing, Ed25519 signing, Merkle trees
- **Backend**: FastAPI, SQLAlchemy, SQLite/PostgreSQL, Pydantic
- **Frontend**: React 19, Vite, TailwindCSS, shadcn/ui, Framer Motion, Recharts
- **Infrastructure**: Docker, Docker Compose

## Testing

```bash
# Run E2E tests
./scripts/e2e_test.sh

# Backend tests
cd backend && pytest

# Agent tests
cd agent && pytest
```

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## Support

For issues, questions, or contributions, please open an issue on GitHub.
