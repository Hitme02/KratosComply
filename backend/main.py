"""KratosComply Backend: Compliance Evidence Verification & Attestation Ledger.

This backend verifies cryptographically signed compliance evidence reports
and maintains a legal-grade attestation ledger for audit verifiability.
"""
from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
from typing import Any, Iterable

from dotenv import load_dotenv
import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

load_dotenv()

from database import Base, engine, get_db
from github_service import exchange_code_for_token, fetch_user_info, fetch_user_repositories
from models import Attestation, HumanAttestation, EvidenceUpload
from schemas import (
    AttestRequest,
    AttestResponse,
    AuditorVerifyRequest,
    AuditorVerifyResponse,
    EvidenceUploadRequest,
    EvidenceUploadResponse,
    Finding,
    HumanAttestationRequest,
    HumanAttestationResponse,
    HumanAttestationListResponse,
    Metrics,
    ProjectInfo,
    Report,
    VerifyReportRequest,
    VerifyReportResponse,
)
from security import build_merkle_root, verify_signature

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# Only create tables if not in testing mode
if not os.getenv("TESTING"):
    Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="KratosComply Compliance Evidence Backend",
    description="Verifies compliance evidence reports and maintains attestation ledger",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root() -> dict[str, str]:
    """Simple health endpoint."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/health")
def health_check() -> dict[str, Any]:
    """Health check endpoint for monitoring and load balancers."""
    try:
        # Check database connection
        db = next(get_db())
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        logger.warning(f"Database health check failed: {e}")
        db_status = "unhealthy"
    
    return {
        "status": "ok" if db_status == "healthy" else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_status,
        "version": "1.0.0",
    }


@app.post("/verify-report", response_model=VerifyReportResponse)
def verify_report(payload: VerifyReportRequest) -> VerifyReportResponse:
    """Verify compliance evidence report signature and Merkle root integrity.
    
    Validates that the report is cryptographically authentic and suitable
    for audit, investor, and regulatory verification.
    """
    report_dict = payload.report.model_dump()
    signature_hex = report_dict.get("agent_signature")
    if not signature_hex:
        return VerifyReportResponse(valid=False, message="agent_signature missing")
    unsigned_payload = {k: v for k, v in report_dict.items() if k != "agent_signature"}
    if not verify_signature(unsigned_payload, signature_hex, payload.public_key_hex):
        logger.warning("Signature verification failed for project %s", payload.report.project.name)
        return VerifyReportResponse(valid=False, message="Signature verification failed")

    try:
        expected_root = build_merkle_root(_ordered_hashes(payload.report.findings))
    except ValueError as exc:
        return VerifyReportResponse(valid=False, message=str(exc))
    if expected_root != payload.report.merkle_root.lower():
        return VerifyReportResponse(valid=False, message="Merkle root mismatch")

    return VerifyReportResponse(valid=True, message="Compliance evidence report verified")


@app.post("/attest", response_model=AttestResponse, status_code=201)
def record_attestation(
    request: AttestRequest,
    db: Session = Depends(get_db),
) -> AttestResponse:
    """Record a compliance attestation as a legal-grade compliance statement.
    
    Creates a cryptographically sealed attestation record with:
    - Framework coverage
    - Control coverage metrics
    - Evidence hashes (cryptographic binding)
    - Human signer identities (hashed for privacy)
    - Control states (VERIFIED_MACHINE, VERIFIED_SYSTEM, ATTESTED_HUMAN, etc.)
    
    This attestation is suitable for audit, investor, and regulatory verification.
    """
    attestation = Attestation(
        merkle_root=request.merkle_root.lower(),
        public_key_hex=request.public_key_hex.lower(),
        verified_at=datetime.now(timezone.utc),
    )
    attestation.set_metadata(request.metadata)
    
    # Extract compliance metadata from request
    if request.metadata:
        frameworks = request.metadata.get("frameworks", [])
        if frameworks:
            attestation.set_frameworks(frameworks)
        control_coverage = request.metadata.get("control_coverage_percent")
        if control_coverage is not None:
            attestation.control_coverage_percent = float(control_coverage)
    
    # Set legal artifact metadata
    if request.evidence_hashes:
        attestation.set_evidence_hashes(request.evidence_hashes)
    
    if request.human_signer_identities:
        attestation.set_human_signer_identities(request.human_signer_identities)
    
    if request.control_states:
        attestation.set_control_states(request.control_states)
    
    db.add(attestation)
    db.commit()
    db.refresh(attestation)
    
    return AttestResponse(
        attest_id=attestation.id,
        status="recorded",
        timestamp=attestation.created_at or datetime.now(timezone.utc),
        frameworks_covered=attestation.get_frameworks(),
        control_coverage_percent=attestation.control_coverage_percent,
        evidence_count=len(attestation.get_evidence_hashes()),
        human_signer_count=len(attestation.get_human_signer_identities()),
        control_count=len(attestation.get_control_states()),
    )


@app.get("/api/attestations")
def list_attestations(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List all attestations in the compliance ledger."""
    attestations = (
        db.query(Attestation)
        .order_by(Attestation.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    
    total = db.query(Attestation).count()
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "attestations": [
            {
                "id": att.id,
                "merkle_root": att.merkle_root,
                "public_key_hex": att.public_key_hex,
                "created_at": att.created_at.isoformat() if att.created_at else None,
                "frameworks_covered": att.get_frameworks(),
                "control_coverage_percent": att.control_coverage_percent,
            }
            for att in attestations
        ],
    }


@app.post("/auditor/verify", response_model=AuditorVerifyResponse)
def auditor_verify(
    request: AuditorVerifyRequest,
    db: Session = Depends(get_db),
) -> AuditorVerifyResponse:
    """External auditor verification endpoint (read-only).
    
    Allows auditors, investors, and regulators to verify attestation records
    without exposing sensitive findings or source code.
    """
    attestation = (
        db.query(Attestation)
        .filter(
            Attestation.merkle_root == request.merkle_root.lower(),
            Attestation.public_key_hex == request.public_key_hex.lower(),
        )
        .first()
    )
    
    if not attestation:
        return AuditorVerifyResponse(
            verified=False,
            attest_id=None,
            frameworks_covered=[],
            control_coverage_percent=None,
            timestamp=None,
            message="Attestation not found in compliance ledger",
        )
    
    return AuditorVerifyResponse(
        verified=True,
        attest_id=attestation.id,
        frameworks_covered=attestation.get_frameworks(),
        control_coverage_percent=attestation.control_coverage_percent,
        timestamp=attestation.created_at,
        message="Attestation verified in compliance ledger",
    )


def _ordered_hashes(findings: Iterable[Finding]) -> list[str]:
    return [
        finding.evidence_hash.lower()
        for finding in sorted(
            findings,
            key=lambda f: (
                f.file,
                f.line if f.line is not None else -1,
                f.type,
                f.id,
            ),
        )
    ]


# GitHub OAuth endpoints (stub implementation)
# In production, these would integrate with GitHub OAuth and trigger agent scans


class GitHubCallbackRequest(BaseModel):
    code: str
    state: str


class GitHubReposResponse(BaseModel):
    """Response containing user's repositories for selection."""
    username: str
    repositories: list[dict[str, Any]]


@app.get("/api/auth/github")
def github_auth() -> RedirectResponse:
    """Initiate GitHub OAuth flow."""
    github_client_id = os.getenv("GITHUB_CLIENT_ID")
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:5173/github/callback")
    
    if not github_client_id:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.",
        )
    
    # Generate state for CSRF protection (in production, store in session/redis)
    import secrets
    state = secrets.token_urlsafe(32)
    
    github_oauth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={github_client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=repo"
        f"&state={state}"
    )
    return RedirectResponse(url=github_oauth_url)


@app.post("/github/callback", response_model=GitHubReposResponse)
async def github_callback(request: GitHubCallbackRequest) -> GitHubReposResponse:
    """Handle GitHub OAuth callback and return user's repositories for selection."""
    github_client_id = os.getenv("GITHUB_CLIENT_ID")
    github_client_secret = os.getenv("GITHUB_CLIENT_SECRET")
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:5173/github/callback")
    
    if not github_client_id or not github_client_secret:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.",
        )
    
    logger.info("GitHub OAuth callback received (code=%s, state=%s)", request.code[:10], request.state)
    
    try:
        # Exchange code for access token
        access_token = await exchange_code_for_token(
            request.code, github_client_id, github_client_secret, redirect_uri
        )
        logger.info("GitHub access token obtained")
        
        # Fetch user information
        user_info = await fetch_user_info(access_token)
        username = user_info.get("login", "unknown")
        logger.info("GitHub user authenticated: %s", username)
        
        # Fetch user's repositories
        repos = await fetch_user_repositories(access_token, limit=20)
        if not repos:
            raise HTTPException(
                status_code=404,
                detail="No repositories found. Please ensure your GitHub account has at least one repository.",
            )
        
        # Format repositories for frontend selection
        formatted_repos = [
            {
                "id": repo["id"],
                "name": repo["name"],
                "full_name": repo["full_name"],
                "owner": repo["owner"]["login"],
                "description": repo.get("description", ""),
                "private": repo.get("private", False),
                "updated_at": repo.get("updated_at", ""),
                "default_branch": repo.get("default_branch", "main"),
            }
            for repo in repos
        ]
        
        logger.info("Returning %d repositories for user selection", len(formatted_repos))
        
        # NOTE: Access token should be stored securely for later use
        # For now, we'll need to re-authenticate or use a session
        # TODO: Store access token in secure session/database
        
        return GitHubReposResponse(username=username, repositories=formatted_repos)
        
    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error: %s", e.response.text)
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"GitHub API error: {e.response.text}",
        )
    except ValueError as e:
        logger.error("GitHub OAuth error: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error in GitHub callback")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


# Human Attestation Endpoints
@app.post("/api/human/upload", response_model=EvidenceUploadResponse, status_code=201)
def upload_evidence(
    request: EvidenceUploadRequest,
    db: Session = Depends(get_db),
) -> EvidenceUploadResponse:
    """Upload evidence file for human attestation.
    
    Evidence files are stored with cryptographic hashes for integrity verification.
    """
    import base64
    import hashlib
    import uuid
    from backend.models import EvidenceUpload
    
    try:
        # Decode base64 content
        content_bytes = base64.b64decode(request.content_base64)
        content_hash = hashlib.sha256(content_bytes).hexdigest()
        
        # Generate unique upload ID
        upload_id = str(uuid.uuid4())
        
        # Create evidence upload record
        evidence_upload = EvidenceUpload(
            upload_id=upload_id,
            file_name=request.file_name,
            file_type=request.file_type,
            content_hash=content_hash,
            file_size=len(content_bytes),
            storage_path=None,  # In production, store file in blob storage
            uploaded_by=None,  # In production, get from auth context
        )
        evidence_upload.set_metadata(request.metadata)
        
        db.add(evidence_upload)
        db.commit()
        db.refresh(evidence_upload)
        
        return EvidenceUploadResponse(
            upload_id=upload_id,
            content_hash=content_hash,
            file_size=len(content_bytes),
            message="Evidence uploaded successfully",
        )
    except Exception as e:
        logger.exception("Error uploading evidence")
        raise HTTPException(status_code=500, detail=f"Failed to upload evidence: {str(e)}")


@app.post("/api/human/attest", response_model=HumanAttestationResponse, status_code=201)
def create_human_attestation(
    request: HumanAttestationRequest,
    db: Session = Depends(get_db),
) -> HumanAttestationResponse:
    """Create a cryptographically signed human attestation.
    
    This endpoint creates a human-in-the-loop attestation for procedural controls
    that cannot be machine-verified. The attestation must be cryptographically signed.
    """
    from datetime import timedelta
    from nacl import signing
    import hashlib
    from backend.models import HumanAttestation, EvidenceUpload
    from backend.human_evidence import verify_human_attestation, HumanAttestationRecord, HumanAttestationRole
    
    try:
        # Verify signature
        verify_key = signing.VerifyKey(bytes.fromhex(request.signer_public_key))
        payload = {
            "control_id": request.control_id,
            "framework": request.framework,
            "role": request.role,
            "scope": request.scope,
            "attestation_text": request.attestation_text,
            "expiry_days": request.expiry_days,
            "evidence_upload_ids": request.evidence_upload_ids,
        }
        import json
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload_bytes = payload_json.encode("utf-8")
        
        try:
            verify_key.verify(payload_bytes, bytes.fromhex(request.signature))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid signature")
        
        # Verify evidence uploads exist
        evidence_hashes = []
        for upload_id in request.evidence_upload_ids:
            upload = db.query(EvidenceUpload).filter(EvidenceUpload.upload_id == upload_id).first()
            if not upload:
                raise HTTPException(status_code=404, detail=f"Evidence upload {upload_id} not found")
            evidence_hashes.append(upload.content_hash)
        
        # Calculate combined evidence hash
        combined_hash = hashlib.sha256("".join(evidence_hashes).encode()).hexdigest()
        
        # Generate attestation ID
        timestamp = datetime.now(timezone.utc)
        attestation_id = hashlib.sha256(
            f"{request.control_id}:{request.framework}:{timestamp.isoformat()}:{request.signature}".encode()
        ).hexdigest()[:16]
        
        # Calculate expiry
        expires_at = timestamp + timedelta(days=request.expiry_days)
        
        # Create human attestation record
        human_attestation = HumanAttestation(
            attestation_id=attestation_id,
            control_id=request.control_id,
            framework=request.framework,
            role=request.role,
            scope=request.scope,
            attestation_text=request.attestation_text,
            evidence_hash=combined_hash,
            signer_public_key=request.signer_public_key,
            signature=request.signature,
            expires_at=expires_at,
        )
        human_attestation.set_evidence_upload_ids(request.evidence_upload_ids)
        
        db.add(human_attestation)
        db.commit()
        db.refresh(human_attestation)
        
        return HumanAttestationResponse(
            attestation_id=attestation_id,
            control_id=request.control_id,
            framework=request.framework,
            role=request.role,
            timestamp=timestamp,
            expires_at=expires_at,
            verified=True,
            message="Human attestation created successfully",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error creating human attestation")
        raise HTTPException(status_code=500, detail=f"Failed to create attestation: {str(e)}")


@app.get("/api/human/attestations", response_model=HumanAttestationListResponse)
def list_human_attestations(
    control_id: str | None = None,
    framework: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> HumanAttestationListResponse:
    """List human attestations with optional filtering."""
    from backend.models import HumanAttestation
    
    query = db.query(HumanAttestation)
    
    if control_id:
        query = query.filter(HumanAttestation.control_id == control_id)
    if framework:
        query = query.filter(HumanAttestation.framework == framework)
    
    total = query.count()
    attestations = query.order_by(HumanAttestation.timestamp.desc()).limit(limit).offset(offset).all()
    
    return HumanAttestationListResponse(
        attestations=[
            {
                "attestation_id": a.attestation_id,
                "control_id": a.control_id,
                "framework": a.framework,
                "role": a.role,
                "scope": a.scope,
                "timestamp": a.timestamp.isoformat(),
                "expires_at": a.expires_at.isoformat(),
                "evidence_hash": a.evidence_hash,
            }
            for a in attestations
        ],
        total=total,
        limit=limit,
        offset=offset,
    )
