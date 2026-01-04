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
import stat
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class EphemeralWorker:
    """Ephemeral worker for scanning GitHub repositories without persisting code."""

    def __init__(self, workspace_root: Path | None = None):
        """Initialize ephemeral worker.
        
        Args:
            workspace_root: Optional root directory for workspaces. If None, uses system temp.
                           On macOS, uses /tmp which is accessible to Docker Desktop.
        """
        if workspace_root:
            self.workspace_root = Path(workspace_root).resolve()
        else:
            # Use /tmp directly on macOS/Linux for Docker Desktop compatibility
            # Docker Desktop on macOS can access /tmp by default
            import platform
            if platform.system() == "Darwin":  # macOS
                self.workspace_root = Path("/tmp") / "kratos-ephemeral"
            else:
                self.workspace_root = Path(tempfile.gettempdir()) / "kratos-ephemeral"
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        logger.info(f"Ephemeral worker initialized with workspace root: {self.workspace_root}")

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
            logger.info(f"Creating ephemeral workspace in {self.workspace_root}")
            workspace = self._create_workspace()
            logger.info(f"Created ephemeral workspace: {workspace} (exists: {workspace.exists()})")
            
            # Clone repository (with authentication)
            logger.info(f"Cloning repository: {repo_url}")
            repo_path = await self._clone_repository(workspace, repo_url, access_token)
            logger.info(f"Repository cloned to: {repo_path} (exists: {repo_path.exists()})")
            
            # Determine project name
            if not project_name:
                project_name = repo_path.name
            logger.info(f"Project name: {project_name}")
            
            # Run agent scan
            report_path = workspace / "report.json"
            # Ensure output directory exists
            report_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info(f"Report will be written to: {report_path} (parent exists: {report_path.parent.exists()})")
            
            # _run_agent_scan may return a different path if file was found elsewhere
            actual_report_path = await self._run_agent_scan(repo_path, report_path, project_name)
            
            # Use the actual path returned (may be different if file was found elsewhere)
            if actual_report_path and actual_report_path.exists():
                report_path = actual_report_path
            elif not report_path.exists():
                raise RuntimeError(f"Agent scan failed: report.json not generated at {report_path}")
            
            import json
            # Read report before workspace is destroyed
            logger.info(f"Reading report from: {report_path} (exists: {report_path.exists()})")
            if report_path.exists():
                file_size = report_path.stat().st_size
                logger.info(f"Report file size: {file_size} bytes")
            with open(report_path, "r") as f:
                report = json.load(f)
            
            # Log report details for debugging
            report_project = report.get("project", {}).get("name", "unknown")
            report_findings_count = len(report.get('findings', []))
            logger.info(f"Scan complete. Report for project '{report_project}' generated with {report_findings_count} findings.")
            logger.info(f"Report standards: {report.get('standards', [])}")
            logger.info(f"Report timestamp: {report.get('timestamp', 'unknown')}")
            
            return report
            
        except Exception as e:
            logger.exception(f"Error during repository scan: {e}")
            raise
        finally:
            # Always destroy workspace, even on error
            if workspace:
                try:
                    self._destroy_workspace(workspace)
                    logger.info(f"Destroyed ephemeral workspace: {workspace}")
                except Exception as e:
                    logger.error(f"Failed to destroy workspace {workspace}: {e}")

    def _create_workspace(self) -> Path:
        """Create a temporary workspace directory."""
        # Ensure workspace root exists
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        workspace = tempfile.mkdtemp(prefix="kratos-ephemeral-", dir=str(self.workspace_root))
        workspace_path = Path(workspace)
        if not workspace_path.exists():
            workspace_path.mkdir(parents=True, exist_ok=True)
        return workspace_path

    async def _clone_repository(self, workspace: Path, repo_url: str, access_token: str) -> Path:
        """Clone repository to ephemeral workspace with authentication.
        
        Args:
            workspace: Workspace directory
            repo_url: Repository URL (e.g., "https://github.com/user/repo")
            access_token: GitHub OAuth token
            
        Returns:
            Path to cloned repository
        """
        # Extract repo name from URL
        # Handle both full URLs and just owner/repo format
        if "/" in repo_url:
            parts = repo_url.rstrip("/").split("/")
            repo_name = parts[-1]
        else:
            repo_name = repo_url
        
        repo_path = workspace / repo_name
        
        # Clone with authentication
        # Use token in URL for HTTPS clone
        # Format: https://TOKEN@github.com/owner/repo.git
        if repo_url.startswith("https://github.com/"):
            auth_url = repo_url.replace("https://github.com/", f"https://{access_token}@github.com/")
        elif repo_url.startswith("http://github.com/"):
            auth_url = repo_url.replace("http://github.com/", f"https://{access_token}@github.com/")
        else:
            # Assume it's owner/repo format
            auth_url = f"https://{access_token}@github.com/{repo_url}.git"
        
        # Ensure .git suffix
        if not auth_url.endswith(".git"):
            auth_url += ".git"
        
        # Check if git is available
        git_cmd = shutil.which("git")
        if not git_cmd:
            raise RuntimeError("Git is required for cloning repositories. Please install Git.")
        
        logger.info(f"Cloning repository from {repo_url} to {repo_path}")
        logger.info(f"Using git command: {git_cmd}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                git_cmd,
                "clone",
                "--depth",
                "1",  # Shallow clone for speed
                auth_url,
                str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await process.communicate()
            
            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""
            
            if process.returncode != 0:
                error_msg = stderr_text or stdout_text or "Unknown error"
                logger.error(f"Git clone failed (exit code {process.returncode})")
                logger.error(f"STDOUT: {stdout_text}")
                logger.error(f"STDERR: {stderr_text}")
                raise RuntimeError(f"Failed to clone repository: {error_msg}")
            
            if not repo_path.exists():
                logger.error(f"Repository path does not exist after clone: {repo_path}")
                logger.error(f"Workspace contents: {list(workspace.iterdir()) if workspace.exists() else 'Workspace does not exist'}")
                raise RuntimeError("Repository clone completed but directory not found")
            
            logger.info(f"Cloned repository to {repo_path} (exists: {repo_path.exists()})")
            return repo_path
        except FileNotFoundError as e:
            logger.error(f"Git command not found: {e}")
            raise RuntimeError(f"Git command not found. Please install Git: {str(e)}")
        except Exception as e:
            logger.exception(f"Unexpected error during git clone: {e}")
            raise

    async def _run_agent_scan(
        self,
        repo_path: Path,
        output_path: Path,
        project_name: str,
    ) -> Path | None:
        """Run agent scan on repository using Docker.
        
        Args:
            repo_path: Path to repository
            output_path: Path for output report
            project_name: Project name for report
        """
        # Use Docker agent for scanning (preferred) or fallback to Python agent
        docker_cmd = shutil.which("docker")
        use_docker = docker_cmd is not None
        
        if use_docker:
            logger.info(f"Docker found at: {docker_cmd}")
        else:
            logger.warning("Docker not found, will try Python agent fallback")
        
        # Use a temporary keystore in the workspace for ephemeral scans
        # This ensures the path is accessible to Docker and gets cleaned up
        keystore_path = output_path.parent / ".kratos-keys"
        keystore_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using ephemeral keystore at: {keystore_path}")
        
        # Keys will be generated INSIDE the Docker container to avoid macOS mount sync issues
        # We'll generate them as part of the Docker scan command
        
        # Ensure all paths exist and are absolute
        repo_path_abs = repo_path.resolve()
        keystore_path_abs = keystore_path.resolve()
        output_dir_abs = output_path.parent.resolve()
        
        # Verify paths exist
        if not repo_path_abs.exists():
            raise RuntimeError(f"Repository path does not exist: {repo_path_abs}")
        if not keystore_path_abs.exists():
            raise RuntimeError(f"Keystore path does not exist: {keystore_path_abs}")
        output_dir_abs.mkdir(parents=True, exist_ok=True)
        
        # Keys will be generated inside Docker container, so no need to verify on host
        if use_docker and docker_cmd:
            # Verify Docker is actually working
            try:
                test_process = await asyncio.create_subprocess_exec(
                    docker_cmd,
                    "version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await test_process.communicate()
                if test_process.returncode != 0:
                    logger.warning("Docker version check failed, falling back to Python agent")
                    use_docker = False
            except FileNotFoundError:
                logger.warning("Docker command not executable, falling back to Python agent")
                use_docker = False
            
            if use_docker:
                # Run agent scan using Docker
                # Convert Path objects to strings for Docker mount compatibility
                # Docker Desktop on macOS requires paths to be explicitly shared
                repo_host_path = str(repo_path_abs)
                keystore_host_path = str(keystore_path_abs)
                output_host_path = str(output_dir_abs)
                
                logger.info(f"Mounting Docker volumes:")
                logger.info(f"  Repository: {repo_host_path} -> /workspace:ro")
                logger.info(f"  Keystore: {keystore_host_path} -> /root/.kratos/keys (writable for key generation)")
                logger.info(f"  Output: {output_host_path} -> /output")
                
                # Generate keys INSIDE the container first (avoids macOS mount sync issues)
                logger.info("Generating keys inside Docker container...")
                gen_cmd = [
                    docker_cmd,
                    "run",
                    "--rm",
                    "-v",
                    f"{keystore_host_path}:/root/.kratos/keys",
                    "popslala1/kratos-agent:latest",
                    "generate-key",
                    "--keystore",
                    "/root/.kratos/keys",
                ]
                gen_process = await asyncio.create_subprocess_exec(
                    *gen_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                gen_stdout, gen_stderr = await gen_process.communicate()
                gen_stdout_text = gen_stdout.decode() if gen_stdout else ""
                gen_stderr_text = gen_stderr.decode() if gen_stderr else ""
                
                if gen_process.returncode != 0:
                    logger.error(f"Key generation in container failed (exit code {gen_process.returncode})")
                    logger.error(f"STDOUT: {gen_stdout_text}")
                    logger.error(f"STDERR: {gen_stderr_text}")
                    raise RuntimeError(f"Failed to generate keys in Docker container: {gen_stderr_text or gen_stdout_text}")
                
                logger.info(f"Keys generated in container: {gen_stdout_text.strip()}")
                
                cmd = [
                    docker_cmd,
                    "run",
                    "--rm",
                    "-v",
                    f"{repo_host_path}:/workspace:ro",  # Read-only mount for security
                    "-v",
                    f"{keystore_host_path}:/root/.kratos/keys",  # Writable mount (keys already generated in container)
                    "-v",
                    f"{output_host_path}:/output",
                    "popslala1/kratos-agent:latest",
                    "scan",
                    "/workspace",
                    "--output",
                    f"/output/{output_path.name}",
                    "--keystore",
                    "/root/.kratos/keys",
                    "--project-name",
                    project_name,
                ]
                logger.info(f"Running Docker scan command:")
                logger.info(f"  Full command: {' '.join(cmd)}")
                logger.info(f"  Scanning repository: {repo_host_path} -> /workspace:ro")
                logger.info(f"  Project name: {project_name}")
                logger.info(f"  Output path in container: /output/{output_path.name}")
                logger.info(f"  Expected host path: {output_path}")
                logger.info(f"  Keystore in container: /root/.kratos/keys (keys generated in container above)")
                logger.info(f"  Output mount: {output_host_path} -> /output")
                
                # Execute the Docker scan command
                command_path = shutil.which(cmd[0])
        if not command_path:
            raise RuntimeError(f"Command not found in PATH: {cmd[0]}. Please ensure {cmd[0]} is installed and in your PATH.")
        
        logger.info(f"Command found at: {command_path}")
        logger.info(f"Executing: {cmd[0]} {' '.join(cmd[1:8])}...")
        logger.info(f"Repository path: {repo_path_abs} (exists: {repo_path_abs.exists()})")
        logger.info(f"Keystore path: {keystore_path_abs} (exists: {keystore_path_abs.exists()})")
        logger.info(f"Output directory: {output_dir_abs} (exists: {output_dir_abs.exists()})")
        
        try:
            # Use absolute path for command
            cmd_with_path = [command_path] + cmd[1:]
            
            process = await asyncio.create_subprocess_exec(
                *cmd_with_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await process.communicate()
            
            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""
            
            if process.returncode != 0:
                error_msg = stderr_text or stdout_text or "Unknown error"
                logger.error(f"Agent scan failed (exit code {process.returncode})")
                logger.error(f"STDOUT:\n{stdout_text}")
                logger.error(f"STDERR:\n{stderr_text}")
                logger.error(f"Full command: {' '.join(cmd_with_path)}")
                
                # If it's a key error, provide more diagnostic info
                if "key" in stderr_text.lower() or "keystore" in stderr_text.lower():
                    logger.error("Key-related error detected. Checking keystore...")
                    if keystore_path_abs.exists():
                        keystore_contents = list(keystore_path_abs.iterdir())
                        logger.error(f"Keystore path: {keystore_path_abs}")
                        logger.error(f"Keystore contents: {[str(c.name) for c in keystore_contents]}")
                        priv_key_check = keystore_path_abs / "priv.key"
                        logger.error(f"Private key exists: {priv_key_check.exists()}")
                    else:
                        logger.error(f"Keystore directory does not exist: {keystore_path_abs}")
                
                raise RuntimeError(f"Agent scan failed: {error_msg}")
            
            # Log full output for debugging (always log, not just on error)
            logger.info(f"Agent scan completed (exit code: {process.returncode})")
            logger.info(f"STDOUT length: {len(stdout_text)}, STDERR length: {len(stderr_text)}")
            if stdout_text:
                logger.info(f"STDOUT:\n{stdout_text}")
            if stderr_text:
                logger.info(f"STDERR:\n{stderr_text}")
            
            # Verify file exists INSIDE the container (before checking host)
            logger.info("Verifying report file exists inside container...")
            verify_cmd = [
                docker_cmd,
                "run",
                "--rm",
                "--entrypoint",
                "python",
                "-v",
                f"{output_host_path}:/output:ro",
                "popslala1/kratos-agent:latest",
                "-c",
                f"import os; path='/output/{output_path.name}'; exists=os.path.exists(path); size=os.path.getsize(path) if exists else 0; print(f'File exists: {{exists}}, Size: {{size}} bytes')",
            ]
            verify_process = await asyncio.create_subprocess_exec(
                *verify_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            verify_stdout, verify_stderr = await verify_process.communicate()
            verify_stdout_text = verify_stdout.decode() if verify_stdout else ""
            verify_stderr_text = verify_stderr.decode() if verify_stderr else ""
            logger.info(f"Container file check: {verify_stdout_text.strip()}")
            if verify_stderr_text:
                logger.info(f"Container file check STDERR: {verify_stderr_text}")
            
            # If file exists in container, copy it out using docker cp (macOS Docker Desktop sync is unreliable)
            # We need to get the container ID from the scan command to copy from it
            # Actually, the scan container is --rm so it's gone. Let's use a different approach:
            # Run a new container with the same mount and copy the file
            if "File exists: True" in verify_stdout_text:
                logger.info("File exists in container but not on host (macOS sync issue). Using docker cp workaround...")
                # Use docker run with --rm to create a container, copy the file, then it auto-removes
                # We'll use a helper container that just has the mount
                import secrets
                temp_id = secrets.token_hex(4)
                helper_cmd = [
                    docker_cmd,
                    "run",
                    "--rm",
                    "--name",
                    f"kratos-copy-{temp_id}",
                    "--entrypoint",
                    "python",
                    "-v",
                    f"{output_host_path}:/output:ro",
                    "popslala1/kratos-agent:latest",
                    "-c",
                    f"import sys; content = open('/output/{output_path.name}', 'rb').read(); sys.stdout.buffer.write(content)",
                ]
                logger.info(f"Extracting file from container using cat...")
                helper_process = await asyncio.create_subprocess_exec(
                    *helper_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                file_content, helper_stderr = await helper_process.communicate()
                helper_stderr_text = helper_stderr.decode() if helper_stderr else ""
                
                if helper_process.returncode == 0 and file_content:
                    # Write the file content to the host
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_bytes(file_content)
                    logger.info(f"Successfully extracted report file to host: {output_path} (size: {len(file_content)} bytes)")
                    
                    # Verify the extracted file contains valid JSON and log project name
                    try:
                        import json
                        extracted_report = json.loads(file_content.decode('utf-8'))
                        extracted_project = extracted_report.get("project", {}).get("name", "unknown")
                        extracted_findings_count = len(extracted_report.get('findings', []))
                        logger.info(f"Extracted report for project '{extracted_project}' with {extracted_findings_count} findings")
                    except Exception as e:
                        logger.warning(f"Could not parse extracted report JSON: {e}")
                    
                    return output_path
                else:
                    logger.error(f"Failed to extract file from container: {helper_stderr_text}")
                    logger.error(f"File content length: {len(file_content) if file_content else 0}")
            
            # Fallback: Wait and retry for filesystem sync (macOS Docker Desktop can have delays)
            import time
            max_sync_retries = 10
            file_found = False
            
            for sync_attempt in range(max_sync_retries):
                delay = 0.3 * (sync_attempt + 1)
                if sync_attempt > 0:
                    time.sleep(delay)
                    logger.info(f"Retry {sync_attempt + 1}/{max_sync_retries}: Checking for report file after {delay}s delay...")
                
                # Check output directory
                logger.info(f"Checking output directory: {output_dir_abs} (attempt {sync_attempt + 1})")
                if output_dir_abs.exists():
                    contents = list(output_dir_abs.iterdir())
                    logger.info(f"Output directory contents: {[str(c.name) for c in contents]}")
                    # Also check for any files recursively
                    all_files = list(output_dir_abs.rglob("*"))
                    logger.info(f"All files in output directory (recursive): {[str(f.relative_to(output_dir_abs)) for f in all_files]}")
                    
                    # Check if the expected file exists
                    if output_path.exists():
                        logger.info(f"Report file found! Size: {output_path.stat().st_size} bytes")
                        file_found = True
                        break
                else:
                    logger.error(f"Output directory does not exist: {output_dir_abs}")
            
            if not file_found:
                logger.error(f"Report file not found after {max_sync_retries} sync attempts")
                # Also check the workspace directory (in case report was written there)
                workspace_dir = repo_path_abs.parent if repo_path_abs.parent else repo_path_abs
                logger.info(f"Also checking workspace directory: {workspace_dir}")
                if workspace_dir.exists():
                    workspace_files = list(workspace_dir.glob("*.json"))
                    logger.info(f"JSON files in workspace: {[str(f) for f in workspace_files]}")
            
            # Verify report was created (final check)
            if not output_path.exists():
                # Try to find any JSON files in the output directory
                if output_dir_abs.exists():
                    json_files = list(output_dir_abs.glob("*.json"))
                    logger.error(f"Report file not found at {output_path}")
                    logger.error(f"Found JSON files in output directory: {[str(f) for f in json_files]}")
                    if json_files:
                        # Use the first JSON file found
                        logger.warning(f"Using found JSON file: {json_files[0]}")
                        return json_files[0]
                    else:
                        raise RuntimeError(f"Report file not found at {output_path} and no JSON files in {output_dir_abs}")
                else:
                    raise RuntimeError(f"Report file not found at {output_path} and output directory {output_dir_abs} does not exist")
            
            # Report file exists, return it
            return output_path
        except FileNotFoundError as e:
            logger.error(f"File not found error: {e}")
            logger.error(f"Command: {' '.join(cmd_with_path) if 'cmd_with_path' in locals() else ' '.join(cmd)}")
            logger.error(f"Command path: {command_path}")
            logger.error(f"Paths - repo: {repo_path_abs}, keystore: {keystore_path_abs}, output: {output_dir_abs}")
            raise RuntimeError(f"Command execution failed - file not found: {str(e)}. Command: {cmd[0]}")
        except Exception as e:
            logger.exception(f"Unexpected error during scan: {e}")
            raise

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


