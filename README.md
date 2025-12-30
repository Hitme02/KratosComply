# KratosComply

**Complete Compliance Operating System** - Generate audit-ready compliance evidence with cryptographic verification for SOC2, ISO27001, GDPR, DPDP Act, HIPAA, PCI-DSS, and NIST CSF compliance.

[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-popslala1%2Fkratos--agent-blue)](https://hub.docker.com/r/popslala1/kratos-agent)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

## Overview

KratosComply is a compliance-first, privacy-preserving audit automation platform that generates cryptographically verifiable compliance evidence reports. Every detection maps to specific compliance framework controls, making it suitable for auditors, investors, and regulators.

**Core Philosophy**: Compliance includes security. Every detection maps to a specific compliance control, legal requirement, or audit verifiability requirement.

## Features

### ✅ Complete Compliance Coverage

- **Technical Compliance** (Machine-verifiable): Code-level scanning, AST-based detection, cloud provider secrets, infrastructure-as-code security, container security, API security, database security, CI/CD security, dependency compliance, cryptographic evidence hashing
- **System Compliance** (Configuration-verifiable): Logging, retention, encryption, MFA, backup configuration detection, AWS/GCP/Azure security settings
- **Procedural Compliance** (Human-attested): Signed attestations for non-technical controls with Ed25519 signatures

### ✅ Cryptographic Integrity

- Ed25519 signatures for all reports and attestations
- SHA256 Merkle trees for evidence binding
- Tamper-proof audit trail
- Canonical JSON serialization for deterministic hashing

### ✅ Compliance Frameworks

- **SOC2**: CC6.1 (Access Control), CC6.2 (Secrets Management), CC7.2 (Logging), CC7.3 (Incident Response), CC8.1 (Vendor Risk)
- **ISO27001**: A.9.2.1 (Access Management), A.10.1.1 (Encryption)
- **DPDP Act (India)**: Section 7 (Consent), Section 8 (Retention), Section 9 (Access Logging)
- **GDPR (EU)**: Article 5 (Retention), Article 6 (Consent), Article 17 (Erasure), Article 20 (Portability), Article 32 (Encryption)
- **HIPAA**: 164.308 (Access Control), 164.312 (Encryption)
- **PCI-DSS**: 3.4 (PAN Protection), 8.2 (Strong Authentication)
- **NIST CSF**: PR.AC-1 (Identity Management), PR.DS-1 (Data Protection)

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

## Architecture

### System Architecture

```mermaid
graph TB
    subgraph "User Environment"
        A[Developer/Compliance Officer] --> B[KratosComply Frontend]
        A --> C[Docker Agent]
    end
    
    subgraph "Frontend Layer"
        B --> D[React + TypeScript]
        D --> E[Vite Dev Server]
        D --> F[shadcn/ui Components]
    end
    
    subgraph "Backend Layer"
        E --> G[FastAPI Backend]
        G --> H[SQLite/PostgreSQL]
        G --> I[GitHub OAuth]
        G --> J[Ephemeral Workers]
    end
    
    subgraph "Agent Layer"
        C --> K[Compliance Scanner]
        K --> L[AST Parser]
        K --> M[Regex Detectors]
        K --> N[System Evidence Collector]
        K --> O[Report Generator]
        O --> P[Ed25519 Signer]
        O --> Q[Merkle Tree Builder]
    end
    
    subgraph "Compliance Frameworks"
        K --> R[SOC2]
        K --> S[ISO27001]
        K --> T[GDPR]
        K --> U[DPDP]
        K --> V[HIPAA]
        K --> W[PCI-DSS]
        K --> X[NIST-CSF]
    end
    
    subgraph "Evidence Types"
        N --> Y[Machine-Verified]
        N --> Z[System-Verified]
        N --> AA[Human-Attested]
    end
    
    style A fill:#e1f5ff
    style B fill:#fff4e6
    style G fill:#f3e5f5
    style K fill:#e8f5e9
    style R fill:#ffebee
    style S fill:#ffebee
    style T fill:#ffebee
    style U fill:#ffebee
    style V fill:#ffebee
    style W fill:#ffebee
    style X fill:#ffebee
```

### Data Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant Backend
    participant Agent
    participant Database
    
    User->>Agent: Scan Workspace
    Agent->>Agent: Detect Violations
    Agent->>Agent: Collect System Evidence
    Agent->>Agent: Map to Compliance Controls
    Agent->>Agent: Generate Merkle Root
    Agent->>Agent: Sign Report (Ed25519)
    Agent->>User: Return Signed Report
    
    User->>Frontend: Upload Report + Public Key
    Frontend->>Backend: POST /api/verify
    Backend->>Backend: Verify Signature
    Backend->>Backend: Verify Merkle Root
    Backend->>Backend: Check Evidence Integrity
    Backend->>Database: Store Attestation
    Backend->>Frontend: Verification Result
    Frontend->>User: Display Compliance Status
    
    User->>Frontend: Create Human Attestation
    Frontend->>Backend: POST /api/human/attest
    Backend->>Backend: Sign Attestation
    Backend->>Database: Store Attestation
    Backend->>Frontend: Return Attestation ID
```

### Compliance Control Flow

```mermaid
stateDiagram-v2
    [*] --> ScanWorkspace
    ScanWorkspace --> DetectFindings: Code Analysis
    ScanWorkspace --> CollectSystemEvidence: Config Detection
    
    DetectFindings --> MapToControls: Compliance Mapping
    CollectSystemEvidence --> MapToControls
    
    MapToControls --> ResolveState: State Resolution
    
    ResolveState --> VERIFIED_MACHINE: Code Evidence Found
    ResolveState --> VERIFIED_SYSTEM: Config Evidence Found
    ResolveState --> MISSING_EVIDENCE: No Evidence
    ResolveState --> EXPIRED_EVIDENCE: Evidence Expired
    
    MISSING_EVIDENCE --> HumanAttestation: Optional
    HumanAttestation --> ATTESTED_HUMAN: Signed
    
    VERIFIED_MACHINE --> GenerateReport
    VERIFIED_SYSTEM --> GenerateReport
    ATTESTED_HUMAN --> GenerateReport
    MISSING_EVIDENCE --> GenerateReport
    EXPIRED_EVIDENCE --> GenerateReport
    
    GenerateReport --> BuildMerkleTree
    BuildMerkleTree --> SignReport
    SignReport --> [*]
```

### Component Architecture

```mermaid
graph LR
    subgraph "Agent Components"
        A1[CLI] --> A2[Detectors]
        A2 --> A3[Compliance Mapper]
        A3 --> A4[Control Model]
        A2 --> A5[System Evidence]
        A4 --> A6[Report Generator]
        A5 --> A6
        A6 --> A7[Signature Module]
        A6 --> A8[Merkle Builder]
    end
    
    subgraph "Backend Components"
        B1[FastAPI Routes] --> B2[Security Module]
        B1 --> B3[Models]
        B1 --> B4[Schemas]
        B2 --> B5[Signature Verifier]
        B2 --> B6[Merkle Verifier]
        B3 --> B7[Database]
        B1 --> B8[GitHub Service]
        B8 --> B9[Ephemeral Worker]
    end
    
    subgraph "Frontend Components"
        C1[React App] --> C2[Pages]
        C1 --> C3[Components]
        C1 --> C4[Services]
        C2 --> C5[Dashboard]
        C2 --> C6[Compliance Coverage]
        C2 --> C7[Controls Evidence]
        C3 --> C8[Charts]
        C3 --> C9[Verification Panel]
        C4 --> C10[API Client]
    end
    
    style A1 fill:#e8f5e9
    style B1 fill:#f3e5f5
    style C1 fill:#fff4e6
```

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

### Using Docker Hub Agent

```bash
# Pull the official image
docker pull popslala1/kratos-agent:latest

# Generate keys (mount a local directory for key storage)
docker run --rm -v $(pwd)/keys:/root/.kratos/keys popslala1/kratos-agent:latest generate-key

# Scan a project
docker run --rm \
  -v $(pwd)/keys:/root/.kratos/keys \
  -v $(pwd)/project:/workspace \
  -v $(pwd)/output:/output \
  popslala1/kratos-agent:latest scan /workspace --output /output/report.json
```

### Manual Setup

#### 1. Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
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
# Using Docker
docker run --rm -v $(pwd)/keys:/root/.kratos/keys popslala1/kratos-agent:latest generate-key

# Or locally
cd agent
source venv/bin/activate
python -m agent.cli generate-key
```

Keys are stored in `~/.kratos/keys/` by default.

### 2. Scan Your Project

```bash
# Using Docker
docker run --rm \
  -v $(pwd)/keys:/root/.kratos/keys \
  -v $(pwd)/project:/workspace \
  -v $(pwd)/output:/output \
  popslala1/kratos-agent:latest scan /workspace --output /output/report.json

# Or locally
python -m agent.cli scan /path/to/your/project \
    --output report.json \
    --project-name "your-project"
```

The scan will:
- **Detect code-level compliance issues**: Hardcoded secrets (including cloud provider credentials), insecure ACLs, SQL injection risks, unencrypted database connections, API authentication gaps
- **Infrastructure-as-Code security**: Terraform/CloudFormation misconfigurations (public S3 buckets, unencrypted RDS, open security groups)
- **Container security**: Docker and Kubernetes security issues (root user, missing security contexts, secrets in manifests)
- **CI/CD pipeline security**: Secrets in workflows, unsigned artifacts
- **Dependency compliance**: Missing lock files, unpinned dependencies
- **Collect system-level evidence**: Logging, encryption, MFA configs, AWS CloudTrail, S3 encryption, IAM MFA
- **Map findings to compliance controls**: All findings mapped to specific framework controls
- **Generate cryptographic evidence hashes**: SHA256 hashes for all evidence
- **Create a Merkle root**: Cryptographic proof of report integrity

### 3. Upload & Verify

1. Open the frontend at `http://localhost:5173`
2. Upload the generated `report.json`
3. Enter your public key (get it with: `cat ~/.kratos/keys/pub.key` or `docker run --rm -v $(pwd)/keys:/root/.kratos/keys popslala1/kratos-agent:latest public-key`)
4. Verify the report signature
5. Create an attestation

### 4. Human Attestations (Procedural Controls)

For controls that require human attestation (policies, training records, incident response procedures):

```bash
# Upload evidence file
curl -X POST http://localhost:8000/api/human/upload \
  -F "file=@policy.pdf" \
  -F "control_id=CC7.3" \
  -F "framework=SOC2"

# Create signed attestation
curl -X POST http://localhost:8000/api/human/attest \
  -H "Content-Type: application/json" \
  -d '{
    "control_id": "CC7.3",
    "framework": "SOC2",
    "attester_name": "John Doe",
    "attester_email": "john@example.com",
    "evidence_hash": "...",
    "declaration": "Incident response procedures are documented and tested quarterly."
  }'
```

## Project Structure

```
KratosCompliance/
├── agent/              # Compliance evidence scanner (Python)
│   ├── agent/         # Core agent code
│   │   ├── cli.py     # CLI interface
│   │   ├── detectors.py  # Compliance violation detectors
│   │   ├── compliance.py  # Compliance control mappings
│   │   ├── control_model.py  # Control definitions
│   │   ├── reporting.py  # Report generation
│   │   ├── signature.py  # Ed25519 signing
│   │   ├── merkle.py  # Merkle tree builder
│   │   └── system_evidence.py  # System evidence collection
│   ├── Dockerfile     # Docker image definition
│   ├── build-docker.sh  # Build script
│   └── requirements.txt
│
├── backend/            # FastAPI backend (Python)
│   ├── main.py        # FastAPI application
│   ├── models.py      # SQLAlchemy models
│   ├── schemas.py     # Pydantic schemas
│   ├── security.py    # Cryptographic verification
│   ├── database.py    # Database utilities
│   ├── github_service.py  # GitHub OAuth integration
│   └── tests/         # Backend tests
│
├── frontend/           # React frontend (TypeScript)
│   ├── src/
│   │   ├── pages/     # Page components
│   │   ├── components/  # Reusable components
│   │   ├── services/  # API client
│   │   └── types/     # TypeScript types
│   └── package.json
│
├── docker-compose.yml  # Development setup
└── docker-compose.prod.yml  # Production setup
```

## API Documentation

### Backend API Endpoints

#### Report Verification

```http
POST /api/verify
Content-Type: application/json

{
  "report": { ... },
  "public_key": "hex_string"
}
```

#### Attestation Creation

```http
POST /api/attest
Content-Type: application/json

{
  "report_id": "uuid",
  "attester_name": "John Doe",
  "attester_email": "john@example.com"
}
```

#### Human Attestations

```http
POST /api/human/upload
Content-Type: multipart/form-data

file: <file>
control_id: "CC7.3"
framework: "SOC2"

POST /api/human/attest
Content-Type: application/json

{
  "control_id": "CC7.3",
  "framework": "SOC2",
  "attester_name": "John Doe",
  "evidence_hash": "...",
  "declaration": "..."
}
```

Full API documentation available at `http://localhost:8000/docs` when the backend is running.

## Compliance Frameworks

### SOC2 (Service Organization Control 2)

- **CC6.1**: Logical and physical access controls
- **CC6.2**: Prior to issuing system credentials and granting system access
- **CC7.2**: The entity monitors system components and the operation of those components
- **CC7.3**: The entity evaluates security events
- **CC8.1**: The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures

### ISO27001

- **A.9.2.1**: User registration and de-registration
- **A.10.1.1**: Cryptographic controls

### GDPR (General Data Protection Regulation)

- **Article 5**: Principles relating to processing of personal data
- **Article 6**: Lawfulness of processing
- **Article 17**: Right to erasure ('right to be forgotten')
- **Article 20**: Right to data portability
- **Article 32**: Security of processing

### DPDP Act (India)

- **Section 7**: Consent
- **Section 8**: Retention
- **Section 9**: Access Logging

### HIPAA (Health Insurance Portability and Accountability Act)

- **164.308**: Administrative safeguards (Access Control)
- **164.312**: Technical safeguards (Encryption)

### PCI-DSS (Payment Card Industry Data Security Standard)

- **3.4**: Render PAN unreadable anywhere it is stored
- **8.2**: In addition to assigning a unique ID, employ at least one of the following methods to authenticate all users

### NIST Cybersecurity Framework

- **PR.AC-1**: Identities and credentials are issued, managed, verified, revoked, and audited
- **PR.DS-1**: Data-at-rest is protected

## Verification Methods

### Machine-Verified
Fully automated verification through AST parsing and regex patterns. Examples: hardcoded secrets, insecure ACLs, consent handling code.

### System-Verified
Configuration detection (flags, settings). Examples: logging enabled, retention duration, encryption settings, MFA configuration.

### Human-Attested
Requires human declaration with cryptographic signature. Examples: incident response procedures, access review policies, training records.

**Important**: KratosComply does NOT claim "full automation" for compliance. Many controls require human attestation. The system clearly distinguishes between machine-verified, system-verified, and human-attested evidence.

## Report Structure

```json
{
  "report_version": "1.0",
  "project": {
    "name": "my-project",
    "path": "/path/to/project",
    "commit": "abc123",
    "scan_time": "2025-12-30T09:00:00Z"
  },
  "standards": ["SOC2", "ISO27001", "GDPR", "DPDP", "HIPAA", "PCI-DSS", "NIST-CSF"],
  "findings": [
    {
      "id": "F001",
      "type": "hardcoded_secret",
      "file": "config.py",
      "line": 42,
      "severity": "high",
      "compliance_frameworks_affected": ["SOC2", "ISO27001"],
      "control_id": "SOC2-CC6.2",
      "control_state": "MISSING_EVIDENCE",
      "evidence_hash": "..."
    }
  ],
  "system_evidence": [
    {
      "control_id": "SOC2-CC7.2",
      "framework": "SOC2",
      "evidence_type": "config_proof",
      "evidence_present": true,
      "evidence_source": "logging.yaml"
    }
  ],
  "control_states": {
    "SOC2-CC6.2": "MISSING_EVIDENCE",
    "SOC2-CC7.2": "VERIFIED_SYSTEM"
  },
  "merkle_root": "sha256_hash",
  "agent_signature": "ed25519_signature",
  "agent_version": "1.0.0"
}
```

## Development

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Agent tests
cd agent
pytest
```

### Building Docker Images

```bash
# Agent image
cd agent
./build-docker.sh

# Backend image
cd backend
docker build -t kratos-backend .

# Frontend image
cd frontend
docker build -t kratos-frontend .
```

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. Code follows existing style conventions
3. New compliance controls are properly documented
4. Cryptographic operations are tested

## License

MIT License - see LICENSE file for details

## Support

For issues, questions, or contributions, please open an issue on the repository.

---

**KratosComply** - Making compliance verifiable, one control at a time.

