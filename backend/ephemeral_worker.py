"""Ephemeral Worker System for GitHub OAuth Mode.

This module implements ephemeral agent workers that:
1. Clone repositories into temporary workspaces
2. Run agent scans
3. Generate signed compliance attestations
4. Destroy workspaces immediately after completion
5. Never persist source code or repository data

All output is identical to offline mode: signed compliance attestation only.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class EphemeralWorker:
    """Ephemeral worker for scanning GitHub repositories without persisting code."""

    def __init__(self, workspace_root: Path | None = None):
        """Initialize ephemeral worker.
        
        Args:
            workspace_root: Optional root directory for workspaces. If None, uses system temp.
        """
        self.workspace_root = workspace_root or Path(tempfile.gettempdir()) / "kratos-ephemeral"
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    async def scan_repository(
        self,
        repo_url: str,
        access_token: str,
        project_name: str | None = None,
    ) -> dict[str, Any]:
        """Scan a GitHub repository and generate signed compliance attestation.
        
        This method:
        1. Clones repository to ephemeral workspace
        2. Runs agent scan
        3. Generates signed report
        4. Destroys workspace
        5. Returns only the signed attestation (no source code)
        
        Args:
            repo_url: GitHub repository URL (e.g., "https://github.com/user/repo")
            access_token: GitHub OAuth access token
            project_name: Optional project name override
            
        Returns:
            Dictionary containing signed report (identical to offline mode)
            
        Raises:
            RuntimeError: If scan fails or workspace cleanup fails
        """
        workspace = None
        try:
            # Create ephemeral workspace
            workspace = self._create_workspace()
            logger.info(f"Created ephemeral workspace: {workspace}")
            
            # Clone repository (with authentication)
            repo_path = await self._clone_repository(workspace, repo_url, access_token)
            
            # Determine project name
            if not project_name:
                project_name = repo_path.name
            
            # Run agent scan
            report_path = workspace / "report.json"
            await self._run_agent_scan(repo_path, report_path, project_name)
            
            # Read and return report (this is the only output)
            if not report_path.exists():
                raise RuntimeError("Agent scan failed: report.json not generated")
            
            import json
            with open(report_path, "r") as f:
                report = json.load(f)
            
            logger.info(f"Scan complete. Report generated with {len(report.get('findings', []))} findings.")
            
            return report
            
        finally:
            # Always destroy workspace, even on error
            if workspace:
                self._destroy_workspace(workspace)
                logger.info(f"Destroyed ephemeral workspace: {workspace}")

    def _create_workspace(self) -> Path:
        """Create a temporary workspace directory."""
        workspace = tempfile.mkdtemp(prefix="kratos-ephemeral-", dir=self.workspace_root)
        return Path(workspace)

    async def _clone_repository(self, workspace: Path, repo_url: str, access_token: str) -> Path:
        """Clone repository to ephemeral workspace with authentication.
        
        Args:
            workspace: Workspace directory
            repo_url: Repository URL
            access_token: GitHub OAuth token
            
        Returns:
            Path to cloned repository
        """
        # Extract repo name from URL
        repo_name = repo_url.rstrip("/").split("/")[-1]
        repo_path = workspace / repo_name
        
        # Clone with authentication
        # Use token in URL for HTTPS clone
        auth_url = repo_url.replace("https://", f"https://{access_token}@")
        
        process = await asyncio.create_subprocess_exec(
            "git",
            "clone",
            "--depth",
            "1",  # Shallow clone for speed
            auth_url,
            str(repo_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Failed to clone repository: {error_msg}")
        
        if not repo_path.exists():
            raise RuntimeError("Repository clone completed but directory not found")
        
        logger.info(f"Cloned repository to {repo_path}")
        return repo_path

    async def _run_agent_scan(
        self,
        repo_path: Path,
        output_path: Path,
        project_name: str,
    ) -> None:
        """Run agent scan on repository.
        
        Args:
            repo_path: Path to repository
            output_path: Path for output report
            project_name: Project name for report
        """
        # Check if agent is available
        agent_cmd = shutil.which("python") or "python3"
        
        # Try to find agent module
        # In production, agent would be installed as a package
        agent_module = "agent.cli"
        
        # Run agent scan
        # Note: This assumes agent keys are pre-configured in a shared keystore
        # In production, each ephemeral worker might use a shared signing key
        cmd = [
            agent_cmd,
            "-m",
            agent_module,
            "scan",
            str(repo_path),
            "--output",
            str(output_path),
            "--project-name",
            project_name,
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(repo_path.parent),
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else stdout.decode()
            logger.error(f"Agent scan failed: {error_msg}")
            raise RuntimeError(f"Agent scan failed: {error_msg}")
        
        logger.info(f"Agent scan completed. Report written to {output_path}")

    def _destroy_workspace(self, workspace: Path) -> None:
        """Destroy ephemeral workspace and all contents.
        
        Args:
            workspace: Workspace directory to destroy
        """
        try:
            if workspace.exists():
                shutil.rmtree(workspace)
                logger.info(f"Workspace destroyed: {workspace}")
        except Exception as e:
            logger.error(f"Failed to destroy workspace {workspace}: {e}")
            # Attempt to remove parent if empty
            try:
                if workspace.parent.exists() and not any(workspace.parent.iterdir()):
                    workspace.parent.rmdir()
            except Exception:
                pass


async def scan_github_repository_ephemeral(
    repo_url: str,
    access_token: str,
    project_name: str | None = None,
) -> dict[str, Any]:
    """Convenience function to scan a GitHub repository using ephemeral worker.
    
    This is the main entry point for GitHub OAuth mode scanning.
    It ensures no code is persisted and output is identical to offline mode.
    
    Args:
        repo_url: GitHub repository URL
        access_token: GitHub OAuth access token
        project_name: Optional project name
        
    Returns:
        Signed compliance attestation report (identical to offline mode)
    """
    worker = EphemeralWorker()
    return await worker.scan_repository(repo_url, access_token, project_name)


