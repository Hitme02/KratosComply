"""Sandbox harness for validating auto-fix patches."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .patch_ops import apply_patch_text


class SandboxRunner:
    """Execute patches in an isolated copy of the workspace."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def evaluate_patch(self, patch_text: str) -> tuple[bool, str]:
        """Apply ``patch_text`` inside a sandbox, run tests, and return (safe, log)."""
        with tempfile.TemporaryDirectory(prefix="kratos-sbx-") as tmp_dir:
            sandbox_root = Path(tmp_dir) / "workspace"
            self._copy_workspace(sandbox_root)
            applied, apply_log = apply_patch_text(patch_text, sandbox_root)
            if not applied:
                return False, f"Patch failed to apply:\n{apply_log}"

            cmd, env = self._select_test_command(sandbox_root)
            process = subprocess.run(
                cmd,
                cwd=sandbox_root,
                capture_output=True,
                text=True,
                env=env,
            )
            log = apply_log + process.stdout + process.stderr
            return process.returncode == 0, log

    def _copy_workspace(self, destination: Path) -> None:
        ignore = shutil.ignore_patterns(
            ".git",
            ".venv",
            "node_modules",
            "__pycache__",
            ".pytest_cache",
        )
        shutil.copytree(self.workspace, destination, ignore=ignore)

    def _select_test_command(self, sandbox_root: Path) -> tuple[list[str], dict[str, str]]:
        env = os.environ.copy()
        sample_tests = sandbox_root / "examples" / "sample-app" / "tests"
        if sample_tests.exists():
            env["PYTHONPATH"] = str(sandbox_root / "examples" / "sample-app")
            return ["pytest", "-q", str(sample_tests)], env
        direct_tests = sandbox_root / "tests"
        if direct_tests.exists():
            env["PYTHONPATH"] = str(sandbox_root)
            return ["pytest", "-q"], env
        env["PYTHONPATH"] = str(sandbox_root)
        return ["python", "-m", "compileall", "."], env

