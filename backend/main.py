"""FastAPI application for verifying reports and recording attestations."""
from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Iterable

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

from .database import Base, engine, get_db
from .models import Attestation
from .schemas import (
    AttestRequest,
    AttestResponse,
    Finding,
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
    # In production: redirect to GitHub OAuth with client_id and state
    # For demo: redirect to callback with mock code
    github_client_id = "demo_client_id"  # Replace with actual client ID
    redirect_uri = "http://localhost:5173/github/callback"
    state = "demo_state"
    github_oauth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={github_client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=repo"
        f"&state={state}"
    )
    return RedirectResponse(url=github_oauth_url)


@app.post("/github/callback", response_model=Report)
def github_callback(request: GitHubCallbackRequest) -> Report:
    """Handle GitHub OAuth callback and return scanned report."""
    # In production:
    # 1. Exchange code for access token
    # 2. Fetch repository info
    # 3. Trigger agent scan (via queue/worker)
    # 4. Return report when ready
    # For demo: return a mock report structure
    logger.info("GitHub OAuth callback received (code=%s, state=%s)", request.code[:10], request.state)
    # TODO: Implement actual GitHub integration
    # For now, return a placeholder that indicates GitHub mode is not yet implemented
    raise HTTPException(
        status_code=501,
        detail="GitHub OAuth integration is not yet implemented. Please use Docker agent mode for now.",
    )
