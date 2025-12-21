"""GitHub Repository Scanning Endpoint.

This endpoint triggers ephemeral agent scans of GitHub repositories.
No source code is persisted - only signed compliance attestations are returned.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ephemeral_worker import scan_github_repository_ephemeral
from github_service import exchange_code_for_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/github", tags=["github"])


class ScanRepositoryRequest(BaseModel):
    """Request to scan a GitHub repository."""
    repo_url: str
    access_token: str
    project_name: str | None = None


class ScanRepositoryResponse(BaseModel):
    """Response containing signed compliance attestation (identical to offline mode)."""
    report: dict[str, Any]
    message: str = "Scan completed. Workspace destroyed. No code persisted."


@router.post("/scan", response_model=ScanRepositoryResponse)
async def scan_repository(request: ScanRepositoryRequest) -> ScanRepositoryResponse:
    """Scan a GitHub repository using ephemeral worker.
    
    This endpoint:
    1. Creates ephemeral workspace
    2. Clones repository (with authentication)
    3. Runs agent scan
    4. Generates signed compliance attestation
    5. Destroys workspace immediately
    6. Returns only the signed attestation (no source code)
    
    Output is identical to offline mode: signed compliance attestation only.
    """
    try:
        report = await scan_github_repository_ephemeral(
            repo_url=request.repo_url,
            access_token=request.access_token,
            project_name=request.project_name,
        )
        
        return ScanRepositoryResponse(
            report=report,
            message="Scan completed. Ephemeral workspace destroyed. No code persisted.",
        )
    except Exception as e:
        logger.exception("Ephemeral scan failed")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to scan repository: {str(e)}",
        )


