# KratosComply

**Complete Compliance Operating System** - Generate audit-ready compliance evidence with cryptographic verification for SOC2, ISO27001, GDPR, and DPDP Act compliance.

## Overview

KratosComply is a compliance-first, privacy-preserving audit automation platform that generates cryptographically verifiable compliance evidence reports. Every detection maps to specific compliance framework controls, making it suitable for auditors, investors, and regulators.

**Core Philosophy**: Compliance includes security. Every detection maps to a specific compliance control, legal requirement, or audit verifiability requirement.

## Features

### ✅ Complete Compliance Coverage
- **Technical Compliance** (Machine-verifiable): Code-level scanning, AST-based detection, cryptographic evidence hashing
- **System Compliance** (Configuration-verifiable): Logging, retention, encryption, MFA, backup configuration detection
- **Procedural Compliance** (Human-attested): Signed attestations for non-technical controls with Ed25519 signatures

### ✅ Cryptographic Integrity
- Ed25519 signatures for all reports and attestations
- SHA256 Merkle trees for evidence binding
- Tamper-proof audit trail

### ✅ Compliance Frameworks
- **SOC2**: CC6.1 (Access Control), CC6.2 (Secrets Management), CC7.2 (Logging)
- **ISO27001**: A.9.2.1 (Access Management), A.10.1.1 (Encryption)
- **DPDP Act (India)**: Section 7 (Consent), Section 8 (Retention), Section 9 (Access Logging)
- **GDPR (EU)**: Article 5 (Retention), Article 6 (Consent), Article 17 (Erasure), Article 20 (Portability), Article 32 (Encryption)

### ✅ Control State Machine
Every control resolves to exactly one state:
- `VERIFIED_MACHINE` - Machine-verified code evidence
- `VERIFIED_SYSTEM` - Configuration-verified system evidence
- `ATTESTED_HUMAN` - Human-signed attestation
- `MISSING_EVIDENCE` - Evidence gap identified
- `EXPIRED_EVIDENCE` - Time-scoped evidence expired

### ✅ Privacy-Preserving
- **Offline-First Agent**: Scans codebases locally, no source code leaves your environment
- **Ephemeral GitHub Workers**: GitHub OAuth scans use temporary workspaces that are destroyed after attestation generation
- **No Code Persistence**: Source code never stored, only compliance attestations

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
pip install -r requirements.txt
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
python -m agent.cli scan /path/to/project --output report.json
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
    --project-name "your-project"
```

The scan will:
- Detect code-level compliance issues (secrets, insecure ACLs)
- Collect system-level evidence (logging, encryption, MFA configs)
- Map findings to compliance controls
- Generate cryptographic evidence hashes
- Create a Merkle root for integrity verification

### 3. Upload & Verify

1. Open the frontend at `http://localhost:5173`
2. Upload the generated `report.json`
3. Enter your public key (get it with: `cat ~/.kratos/keys/pub.key`)
4. Verify the report signature
5. Create an attestation

### 4. Human Attestations (Procedural Controls)

For non-technical controls (incident response, training, vendor risk):

```bash
# Upload evidence file
curl -X POST http://localhost:8000/api/human/upload \
  -H "Content-Type: application/json" \
  -d '{
    "file_name": "policy.pdf",
    "file_type": "policy",
    "content_base64": "...",
    "metadata": {"description": "Security policy"}
  }'

# Create signed attestation
curl -X POST http://localhost:8000/api/human/attest \
  -H "Content-Type: application/json" \
  -d '{
    "control_id": "CC6.1",
    "framework": "SOC2",
    "role": "founder",
    "scope": "Access control procedures",
    "attestation_text": "I attest that access control procedures are in place",
    "expiry_days": 365,
    "signer_public_key": "...",
    "signature": "..."
  }'
```

### 5. GitHub Integration (Optional)

1. Configure GitHub OAuth app (see GitHub OAuth Setup below)
2. Click "Connect GitHub" on the frontend
3. Select a repository
4. View scan results automatically (ephemeral scan, no code stored)

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

## Project Structure

```
KratosCompliance/
├── agent/              # Compliance evidence scanner (Python)
│   ├── agent/         # Core agent code
│   │   ├── control_model.py      # Unified compliance control model
│   │   ├── system_evidence.py    # System-level evidence collection
│   │   ├── detectors.py           # Code-level detection
│   │   ├── reporting.py           # Report generation with control states
│   │   └── ...
│   ├── tests/         # Agent tests
│   └── requirements.txt
├── backend/            # Verification & attestation API (FastAPI)
│   ├── main.py        # API endpoints (including human attestations)
│   ├── models.py      # Database models (Attestation, HumanAttestation, EvidenceUpload)
│   ├── schemas.py     # Pydantic schemas
│   ├── human_evidence.py  # Human attestation logic
│   └── tests/         # Backend tests
├── frontend/           # Audit cockpit UI (React + Vite)
│   ├── src/
│   │   ├── pages/     # Page components (AuditCockpit, ControlsEvidence, etc.)
│   │   ├── components/# UI components
│   │   └── services/  # API clients
│   └── package.json
├── examples/           # Sample applications
├── docker-compose.yml  # Development setup
└── README.md
```

## API Endpoints

### Backend API

**Core Endpoints:**
- `GET /health` - Health check
- `POST /verify-report` - Verify report signature and Merkle root
- `POST /attest` - Create compliance attestation
- `GET /api/attestations` - List all attestations
- `POST /auditor/verify` - External auditor verification

**Human Attestation Endpoints:**
- `POST /api/human/upload` - Upload evidence file
- `POST /api/human/attest` - Create signed human attestation
- `GET /api/human/attestations` - List human attestations

**GitHub Integration:**
- `GET /api/auth/github` - Initiate GitHub OAuth
- `POST /github/callback` - GitHub OAuth callback

See `http://localhost:8000/docs` for interactive API documentation.

## Agent Commands

```bash
# Generate keypair
python -m agent.cli generate-key

# Scan workspace
python -m agent.cli scan <path> --output <report.json> --project-name <name>

# Get public key
python -m agent.cli public-key
```

## Compliance Evidence Types

### Machine-Verifiable (Code Evidence)
- Hardcoded secrets detection
- Insecure ACLs in infrastructure code
- AST-based pattern detection
- Cryptographic evidence hashing

### System-Verifiable (Configuration Evidence)
- Logging configuration detection
- Retention policy detection
- Encryption configuration detection
- MFA configuration detection
- Backup policy detection

### Human-Attested (Procedural Evidence)
- Policy documents (PDF/MD)
- Standard Operating Procedures (SOPs)
- Screenshot evidence
- Log exports
- Structured declarations
- All cryptographically signed with Ed25519

## Report Structure

Each report includes:

```json
{
  "report_version": "1.0",
  "project": {...},
  "standards": ["SOC2", "ISO27001", "DPDP", "GDPR"],
  "findings": [...],           // Machine-verifiable evidence gaps
  "system_evidence": [...],    // Configuration-verifiable evidence
  "control_states": {...},     // control_id -> ControlState mapping
  "evidence_hashes": [...],    // All evidence hashes
  "merkle_root": "...",        // Cryptographic integrity root
  "agent_signature": "...",    // Ed25519 signature
  "agent_version": "..."
}
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

## Testing

### Quick Test

```bash
# Agent scan
cd agent && source venv/bin/activate
python3 -m agent.cli scan . --output report.json

# Backend tests
cd backend && pytest tests/ -v

# Frontend (ensure backend is running)
cd frontend && npm run dev
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

## What KratosComply Does NOT Do

KratosComply focuses on compliance evidence generation, not runtime security monitoring:

- ❌ Does NOT scan for CVEs or dependency vulnerabilities
- ❌ Does NOT detect runtime attacks or exploits
- ❌ Does NOT monitor network traffic or runtime behavior
- ❌ Does NOT act as a SIEM, SAST, or DAST tool

KratosComply is compliance infrastructure that includes security controls as part of compliance requirements.

## Architecture

```mermaid
graph TB
    subgraph "User Environment"
        CODE[Codebase]
        CONFIG[Config Files]
        USER[User]
    end

    subgraph "Agent (Offline-First)"
        SCAN[Code Scanner<br/>AST + Regex]
        SYS[System Evidence<br/>Collection]
        CTRL[Control Model<br/>Mapping]
        MERKLE[Merkle Tree<br/>Builder]
        SIGN[Ed25519<br/>Signing]
        REPORT[Compliance Report<br/>JSON]
    end

    subgraph "Backend API"
        VERIFY[Report Verification<br/>Signature + Merkle]
        ATTEST[Attestation<br/>Ledger]
        HUMAN[Human Attestation<br/>Management]
        EVIDENCE[Evidence Upload<br/>Storage]
        GITHUB[GitHub OAuth<br/>Ephemeral Workers]
        DB[(Database<br/>SQLite/PostgreSQL)]
    end

    subgraph "Frontend (Audit Cockpit)"
        UPLOAD[Report Upload]
        VIEW[Control State<br/>Visualization]
        GAPS[Evidence Gap<br/>Tracking]
        HISTORY[Attestation<br/>History]
        REPO[GitHub Repo<br/>Integration]
    end

    subgraph "Compliance Frameworks"
        SOC2[SOC2<br/>CC6.1, CC6.2, CC7.2]
        ISO[ISO27001<br/>A.9.2.1, A.10.1.1]
        DPDP[DPDP Act<br/>Section 7, 8, 9]
        GDPR[GDPR<br/>Article 5, 6, 17, 20, 32]
    end

    CODE --> SCAN
    CONFIG --> SYS
    SCAN --> CTRL
    SYS --> CTRL
    CTRL --> MERKLE
    MERKLE --> SIGN
    SIGN --> REPORT

    REPORT --> UPLOAD
    UPLOAD --> VERIFY
    VERIFY --> ATTEST
    ATTEST --> DB
    ATTEST --> VIEW

    USER --> HUMAN
    HUMAN --> EVIDENCE
    EVIDENCE --> DB
    HUMAN --> ATTEST

    USER --> GITHUB
    GITHUB --> SCAN
    GITHUB --> REPORT

    CTRL --> SOC2
    CTRL --> ISO
    CTRL --> DPDP
    CTRL --> GDPR

    VIEW --> GAPS
    VIEW --> HISTORY
    VIEW --> REPO

    style CODE fill:#e1f5ff
    style CONFIG fill:#e1f5ff
    style REPORT fill:#fff4e1
    style DB fill:#ffe1f5
    style SOC2 fill:#e8f5e9
    style ISO fill:#e8f5e9
    style DPDP fill:#e8f5e9
    style GDPR fill:#e8f5e9
```

### Components

- **Agent** (`agent/`): Python 3.11+ compliance scanner
  - AST-based detection for Python files
  - Regex-based detection for text files
  - System evidence collection (config files)
  - Compliance control mapping (SOC2, ISO27001, GDPR, DPDP)
  - Ed25519 cryptographic signing
  - SHA256 Merkle tree integrity
  - Control state resolution

- **Backend** (`backend/`): FastAPI verification service
  - Report signature verification
  - Compliance attestation ledger
  - Human attestation management
  - Evidence upload handling
  - GitHub OAuth integration
  - SQLite/PostgreSQL database

- **Frontend** (`frontend/`): React audit cockpit
  - Report upload and verification
  - Attestation creation and history
  - Control state visualization
  - Evidence gap tracking
  - GitHub repository integration

## Technology Stack

- **Agent**: Python 3.11+, AST parsing, Ed25519 signing, Merkle trees
- **Backend**: FastAPI, SQLAlchemy, SQLite/PostgreSQL, Pydantic
- **Frontend**: React 19, Vite, TailwindCSS, shadcn/ui, Framer Motion, Recharts
- **Infrastructure**: Docker, Docker Compose

## Status

✅ **PRODUCTION READY**

- ✅ Full technical, system, and procedural compliance coverage
- ✅ Cryptographic integrity throughout
- ✅ Legal-grade attestation artifacts
- ✅ Complete audit traceability
- ✅ All compliance sectors operational

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
