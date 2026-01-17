# KratosComply Architecture Diagram

```mermaid
graph TB
    subgraph "Startup/Developer Workspace"
        Codebase["Codebase & IaC<br/>• Source Code<br/>• Terraform/K8s<br/>• Dockerfile<br/>• Config Files<br/>• Logs"]
        Keystore["User Keystore<br/>(Local ed25519 keys)"]
    end

    subgraph "Local Docker Agent (Offline Mode)"
        InputCollector["Input Collector<br/>Reads files locally"]
        Preprocessor["Preprocessor & Parsers<br/>• AST (Python/JS/Java)<br/>• YAML/JSON<br/>• Dependency Analysis"]
        
        subgraph "Detectors & AI Analyzers"
            StaticAnalyzers["Static Analyzers<br/>• AST Rules<br/>• Regex Patterns<br/>• 500+ Detection Rules"]
            MLClassifiers["AI Validator<br/>• Sentence Transformers<br/>• 500+ Pattern DB<br/>• Top-K Ensemble<br/>• False Positive Reduction"]
            VulnerabilityDetectors["Vulnerability Detectors<br/>• XSS, SQL Injection<br/>• Command Injection<br/>• XXE, SSRF<br/>• Path Traversal<br/>• Crypto Misuse"]
        end
        
        ComplianceEngine["Compliance Engine<br/>• SOC2 Mapping<br/>• GDPR Mapping<br/>• ISO27001 Mapping<br/>• HIPAA/PCI-DSS<br/>• Control State Machine"]
        
        PatchGenerator["Patch Generator<br/>(Diff / PR draft)"]
        SandboxTester["Sandbox Tester<br/>• Unit Tests<br/>• Terraform Plan<br/>• Validation"]
        
        SigningMerkle["Signing & Merkle<br/>• Build Evidence<br/>• SHA256 Merkle Tree<br/>• Ed25519 Signature"]
        
        ReportOutput["Signed Report JSON<br/>+ Merkle Root<br/>(local)"]
    end

    subgraph "GitHub Connected Mode (Online Worker)"
        GitHubToken["GitHub Token<br/>(OAuth)"]
        GitHubRepo["GitHub Private Repo"]
        EphemeralWorker["Ephemeral Worker<br/>• Clone Repo<br/>• Run Agent Pipeline<br/>• Destroy Workspace<br/>(Code Never Persisted)"]
    end

    subgraph "KratosComply Backend (Optional)"
        Upload["Upload Report"]
        VerifySig["Verify Signature & Merkle<br/>• Ed25519 Verification<br/>• Merkle Root Validation<br/>• Report Integrity Check"]
        AttestationService["Attestation Service<br/>• SQLite/PostgreSQL<br/>• Immutable Ledger<br/>• Timestamped Records"]
        Dashboard["Dashboard & Insights<br/>• Findings View<br/>• Risk Assessment<br/>• Compliance Status<br/>• Attestation History"]
    end

    subgraph "Frontend (React/TypeScript)"
        LandingPage["Landing Page<br/>• Introduction<br/>• Mode Selection"]
        DockerSetup["Docker Setup<br/>• Instructions<br/>• Commands"]
        GitHubRepos["GitHub Repos<br/>• Repository Selection<br/>• OAuth Flow"]
        MainDashboard["Main Dashboard<br/>• Report Upload<br/>• Verification Panel<br/>• Compliance Summary<br/>• Charts & Visualizations"]
        Attestations["Attestations Page<br/>• History View<br/>• Download/Share"]
    end

    %% Workflow connections
    Codebase -->|mounts| InputCollector
    Keystore -.->|signing key| SigningMerkle
    
    InputCollector --> Preprocessor
    Preprocessor --> StaticAnalyzers
    Preprocessor --> MLClassifiers
    Preprocessor --> VulnerabilityDetectors
    
    StaticAnalyzers --> ComplianceEngine
    MLClassifiers -->|validates| ComplianceEngine
    VulnerabilityDetectors --> ComplianceEngine
    
    ComplianceEngine -->|fails| PatchGenerator
    ComplianceEngine -->|passes| SandboxTester
    
    PatchGenerator --> SigningMerkle
    SandboxTester --> SigningMerkle
    MLClassifiers -.->|review| SigningMerkle
    
    SigningMerkle --> ReportOutput
    
    %% GitHub OAuth Flow
    GitHubToken --> GitHubRepo
    GitHubRepo --> EphemeralWorker
    EphemeralWorker -->|same pipeline| Preprocessor
    EphemeralWorker -->|generates| ReportOutput
    
    %% Backend Flow
    ReportOutput -->|upload| Upload
    Upload --> VerifySig
    VerifySig --> AttestationService
    AttestationService --> Dashboard
    
    %% Frontend Flow
    LandingPage -->|Offline Mode| DockerSetup
    LandingPage -->|GitHub Mode| GitHubRepos
    DockerSetup -.->|user follows| Codebase
    GitHubRepos -->|triggers| EphemeralWorker
    ReportOutput -->|upload| MainDashboard
    MainDashboard -->|verify| VerifySig
    MainDashboard -->|create attestation| AttestationService
    AttestationService --> Attestations
    
    %% Styling
    classDef workspace fill:#3b82f6,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef agent fill:#fbbf24,stroke:#d97706,stroke-width:2px,color:#000
    classDef github fill:#10b981,stroke:#059669,stroke-width:2px,color:#fff
    classDef backend fill:#a855f7,stroke:#7c3aed,stroke-width:2px,color:#fff
    classDef frontend fill:#ec4899,stroke:#be185d,stroke-width:2px,color:#fff
    classDef critical fill:#ef4444,stroke:#dc2626,stroke-width:3px,color:#fff
    
    class Codebase,Keystore workspace
    class InputCollector,Preprocessor,StaticAnalyzers,MLClassifiers,VulnerabilityDetectors,ComplianceEngine,PatchGenerator,SandboxTester,SigningMerkle,ReportOutput agent
    class GitHubToken,GitHubRepo,EphemeralWorker github
    class Upload,VerifySig,AttestationService,Dashboard backend
    class LandingPage,DockerSetup,GitHubRepos,MainDashboard,Attestations frontend
    class SigningMerkle,VerifySig,AttestationService critical
```

## Architecture Components

### 1. Startup/Developer Workspace (Blue)
- **Codebase & IaC**: Source code, infrastructure definitions, Dockerfiles, configuration files
- **User Keystore**: Local Ed25519 keypair for cryptographic signing

### 2. Local Docker Agent (Yellow) - Offline Mode
- **Input Collector**: Reads files from mounted workspace
- **Preprocessor & Parsers**: AST parsing, YAML/JSON parsing, dependency analysis
- **Detectors & AI Analyzers**:
  - **Static Analyzers**: AST rules, regex patterns, 500+ detection rules
  - **AI Validator**: Sentence transformers, 500+ pattern database, top-k ensemble matching
  - **Vulnerability Detectors**: XSS, SQL injection, command injection, XXE, SSRF, path traversal, crypto misuse
- **Compliance Engine**: Maps findings to SOC2, GDPR, ISO27001, HIPAA, PCI-DSS controls
- **Patch Generator**: Generates fix patches (diffs/PR drafts)
- **Sandbox Tester**: Validates patches with unit tests, terraform plan
- **Signing & Merkle**: Builds evidence, creates SHA256 Merkle tree, signs with Ed25519

### 3. GitHub Connected Mode (Green) - Online Worker
- **Ephemeral Worker**: Clones repo, runs same agent pipeline, destroys workspace immediately
- **No Code Persistence**: Source code never stored, only signed attestation returned

### 4. KratosComply Backend (Purple) - Optional
- **Verify Signature & Merkle**: Validates Ed25519 signature and Merkle root integrity
- **Attestation Service**: Immutable ledger (SQLite/PostgreSQL) with timestamped records
- **Dashboard & Insights**: Findings view, risk assessment, compliance status, attestation history

### 5. Frontend (Pink) - React/TypeScript
- **Landing Page**: Introduction and mode selection
- **Docker Setup**: Instructions for offline mode
- **GitHub Repos**: Repository selection and OAuth flow
- **Main Dashboard**: Report upload, verification, compliance summary, charts
- **Attestations**: History view, download/share functionality

## Key Features

### Privacy-First Design
- **Offline Mode**: 100% local processing, zero data exfiltration
- **Ephemeral Workers**: Code destroyed immediately after scanning
- **No Code Storage**: Only signed attestations stored, never source code

### Cryptographic Integrity
- **Ed25519 Signatures**: Tamper-proof report signing
- **SHA256 Merkle Trees**: Evidence integrity verification
- **Immutable Ledger**: Timestamped attestation records

### AI-Powered Validation
- **500+ Pattern Database**: Real-world false positives and vulnerabilities
- **Top-K Ensemble**: Weighted matching for better generalization
- **Context-Aware**: Repository-type specific patterns

### Compliance Coverage
- **SOC2**: CC6.1, CC6.2, CC7.2, CC8.1
- **GDPR**: Article 5, 6, 17, 20, 32
- **ISO27001**: A.9.2.1, A.10.1.1
- **HIPAA**: 164.308, 164.312
- **PCI-DSS**: 3.4, 8.2
- **DPDP Act**: Section 7, 8, 9
