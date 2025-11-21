"""FastAPI application for verifying reports and recording attestations."""
from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
from typing import Iterable

from dotenv import load_dotenv
import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

load_dotenv()

from .database import Base, engine, get_db
from .github_service import exchange_code_for_token, fetch_user_info, fetch_user_repositories
from .models import Attestation
from .schemas import (
    AttestRequest,
    AttestResponse,
    Finding,
    Metrics,
    ProjectInfo,
    Report,
    VerifyReportRequest,
    VerifyReportResponse,
)
from .security import build_merkle_root, verify_signature

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

Base.metadata.create_all(bind=engine)

app = FastAPI(title="KratosComply Backend", version="0.2.0")


@app.get("/")
def read_root() -> dict[str, str]:
    """Simple health endpoint."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.post("/verify-report", response_model=VerifyReportResponse)
def verify_report(payload: VerifyReportRequest) -> VerifyReportResponse:
    """Verify that a report's signature and Merkle root match."""
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

    return VerifyReportResponse(valid=True, message="Report verified")


@app.post("/attest", response_model=AttestResponse, status_code=201)
def record_attestation(
    request: AttestRequest,
    db: Session = Depends(get_db),
) -> AttestResponse:
    """Record an attestation for an already verified Merkle root."""
    attestation = Attestation(
        merkle_root=request.merkle_root.lower(),
        public_key_hex=request.public_key_hex.lower(),
    )
    attestation.set_metadata(request.metadata)
    db.add(attestation)
    db.commit()
    db.refresh(attestation)
    return AttestResponse(
        attest_id=attestation.id,
        status="recorded",
        timestamp=attestation.created_at or datetime.now(timezone.utc),
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


@app.post("/github/callback", response_model=Report)
async def github_callback(request: GitHubCallbackRequest) -> Report:
    """Handle GitHub OAuth callback and return scanned report."""
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
        repos = await fetch_user_repositories(access_token, limit=5)
        if not repos:
            raise HTTPException(
                status_code=404,
                detail="No repositories found. Please ensure your GitHub account has at least one repository.",
            )
        
        # For now, use the first repository as the scan target
        # TODO: Allow user to select repository via frontend
        selected_repo = repos[0]
        repo_name = selected_repo["name"]
        repo_owner = selected_repo["owner"]["login"]
        repo_full_name = f"{repo_owner}/{repo_name}"
        
        logger.info("Selected repository for scanning: %s", repo_full_name)
        
        # TODO: Trigger actual agent scan via worker queue
        # For now, return a placeholder report indicating connection success
        # In production, this would trigger an async scan and return a job ID
        
        # Create a placeholder report structure
        placeholder_report = Report(
            report_version="1.0",
            project=ProjectInfo(
                name=repo_name,
                path=repo_full_name,
                commit=selected_repo.get("default_branch"),
                scan_time=datetime.now(timezone.utc).isoformat(),
            ),
            standards=["SOC2", "ISO27001"],
            findings=[],  # Empty until actual scan is implemented
            metrics=Metrics(critical=0, high=0, medium=0, low=0, risk_score=0),
            merkle_root="0" * 64,  # Placeholder
            agent_signature="0" * 128,  # Placeholder
            agent_version="kratos-agent-demo-0.1",
        )
        
        # Store access token and repo info for future scanning
        # TODO: Store in database with user session/ID for later use
        logger.info("GitHub OAuth flow completed. Repository ready for scanning: %s", repo_full_name)
        
        return placeholder_report
        
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
