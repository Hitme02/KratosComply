"""Low-level helpers for applying unified diff patches."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Tuple


class PatchApplicationError(RuntimeError):
    """Raised when a patch cannot be applied."""


def apply_patch_text(patch_text: str, workspace: Path) -> tuple[bool, str]:
    """Apply ``patch_text`` inside ``workspace`` using the system `patch` tool."""
    if not patch_text.strip():
        raise PatchApplicationError("Empty patch payload provided")
    process = subprocess.run(
        [
            "patch",
            "-p1",
            "--forward",
            "--batch",
        ],
        input=patch_text.encode("utf-8"),
        capture_output=True,
        cwd=str(workspace),
    )
    output = process.stdout.decode("utf-8") + process.stderr.decode("utf-8")
    return process.returncode == 0, output


def apply_patch_file(patch_file: Path, workspace: Path) -> tuple[bool, str]:
    """Apply the diff stored in ``patch_file`` against ``workspace``."""
    if not patch_file.exists():
        raise PatchApplicationError(f"Patch file {patch_file} does not exist")
    patch_text = patch_file.read_text(encoding="utf-8")
    return apply_patch_text(patch_text, workspace)

