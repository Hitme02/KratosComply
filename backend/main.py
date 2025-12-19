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
from models import Attestation
from schemas import (
    AttestRequest,
    AttestResponse,
    AuditorVerifyRequest,
    AuditorVerifyResponse,
    Finding,
    Metrics,
    ProjectInfo,
    Report,
    VerifyReportRequest,
    VerifyReportResponse,
)
from security import build_merkle_root, verify_signature

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

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
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


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
    """Record a compliance attestation in the legal-grade ledger.
    
    Creates an attestation record with framework coverage and control metrics
    suitable for audit, investor, and regulatory verification.
    """
    attestation = Attestation(
        merkle_root=request.merkle_root.lower(),
        public_key_hex=request.public_key_hex.lower(),
    )
    attestation.set_metadata(request.metadata)
    
    # Extract compliance metadata from request metadata if available
    if request.metadata:
        frameworks = request.metadata.get("frameworks", [])
        if frameworks:
            attestation.set_frameworks(frameworks)
        control_coverage = request.metadata.get("control_coverage_percent")
        if control_coverage is not None:
            attestation.control_coverage_percent = float(control_coverage)
    
    db.add(attestation)
    db.commit()
    db.refresh(attestation)
    return AttestResponse(
        attest_id=attestation.id,
        status="recorded",
        timestamp=attestation.created_at or datetime.now(timezone.utc),
        frameworks_covered=attestation.get_frameworks(),
        control_coverage_percent=attestation.control_coverage_percent,
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
