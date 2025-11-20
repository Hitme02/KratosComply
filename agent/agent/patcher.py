"""Deterministic patch generation for Kratos findings."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import difflib

from .findings import Finding, RawFinding
from .sandbox import SandboxRunner


@dataclass(slots=True)
class PatchResult:
    finding_id: str
    patch_path: Path
    safe: bool
    sandbox_log: str


class PatchManager:
    """Generate auto-fix patches and validate them in a sandbox."""

    def __init__(self, workspace: Path, patches_dir: Path | None = None) -> None:
        self.workspace = workspace
        self.patches_dir = patches_dir or workspace / "patches"
        self.sandbox = SandboxRunner(workspace)

    def generate(
        self,
        findings: Iterable[Finding],
        raw_lookup: dict[str, RawFinding],
    ) -> list[PatchResult]:
        self.patches_dir.mkdir(parents=True, exist_ok=True)
        patch_files = sorted(self.patches_dir.glob("*.diff"))
        for existing in patch_files:
            existing.unlink()
            meta = self._metadata_path(existing)
            if meta.exists():
                meta.unlink()

        results: list[PatchResult] = []
        patch_index = 1
        for finding in findings:
            raw = raw_lookup.get(finding.id)
            if raw is None:
                continue
            patch_text = self._build_patch_for_finding(finding, raw)
            if not patch_text:
                continue
            filename = f"{patch_index:04d}-fix-{finding.id}.diff"
            patch_path = self.patches_dir / filename
            patch_path.write_text(patch_text, encoding="utf-8")
            safe, log = self.sandbox.evaluate_patch(patch_text)
            self._write_metadata(patch_path, finding.id, safe, log)
            results.append(
                PatchResult(
                    finding_id=finding.id,
                    patch_path=patch_path,
                    safe=safe,
                    sandbox_log=log,
                )
            )
            patch_index += 1
        return results

    def _write_metadata(self, patch_path: Path, finding_id: str, safe: bool, log: str) -> None:
        metadata_path = self._metadata_path(patch_path)
        payload = {
            "finding_id": finding_id,
            "safe": safe,
            "log": log.strip()[-4000:],
        }
        metadata_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _metadata_path(self, patch_path: Path) -> Path:
        return patch_path.with_name(patch_path.name + ".meta.json")

    def _build_patch_for_finding(
        self,
        finding: Finding,
        raw: RawFinding,
    ) -> str | None:
        if finding.type == "hardcoded_secret" and finding.file.endswith(".py"):
            return _build_python_secret_patch(self.workspace, finding, raw)
        if finding.type == "insecure_acl" and finding.file.endswith(".tf"):
            return _build_terraform_acl_patch(self.workspace, finding)
        return None


def _build_python_secret_patch(
    workspace: Path,
    finding: Finding,
    raw: RawFinding,
) -> str | None:
    metadata = raw.metadata or {}
    var_name = metadata.get("var_name")
    literal = metadata.get("literal")
    if not var_name or literal is None:
        return None

    file_path = workspace / finding.file
    if not file_path.exists():
        return None

    original_lines = file_path.read_text(encoding="utf-8").splitlines()
    replacement_lines = list(original_lines)
    line_index = (finding.line or 1) - 1
    if line_index >= len(original_lines):
        return None

    indent = re.match(r"\s*", original_lines[line_index]).group(0)
    env_var = _derive_env_var(var_name, finding.file)
    literal_json = json.dumps(literal)
    replacement_lines[line_index] = (
        f"{indent}{var_name} = os.getenv('{env_var}', {literal_json})"
    )

    if not _has_import_os(original_lines):
        insert_idx = _import_insertion_index(original_lines)
        replacement_lines.insert(insert_idx, "import os")
        if insert_idx == 0 or replacement_lines[insert_idx + 1].strip():
            replacement_lines.insert(insert_idx + 1, "")

    diffs = [
        _build_diff(original_lines, replacement_lines, finding.file),
    ]

    env_diff = _build_env_template_diff(workspace, env_var, literal)
    if env_diff:
        diffs.append(env_diff)

    return "\n".join(diff for diff in diffs if diff).strip() + "\n"


def _build_terraform_acl_patch(workspace: Path, finding: Finding) -> str | None:
    file_path = workspace / finding.file
    if not file_path.exists():
        return None
    original_lines = file_path.read_text(encoding="utf-8").splitlines()
    replacement_lines = list(original_lines)
    change_made = False
    for idx, line in enumerate(original_lines):
        if "public-read" in line:
            replacement_lines[idx] = line.replace("public-read", "private")
            insertion_idx = idx + 1
            snippet = [
                "  # Enforce server-side encryption",
                "  # server_side_encryption_configuration {",
                "  #   rule {",
                "  #     apply_server_side_encryption_by_default {",
                '  #       sse_algorithm = "AES256"',
                "  #     }",
                "  #   }",
                "  # }",
            ]
            replacement_lines[insertion_idx:insertion_idx] = snippet
            change_made = True
            break
    if not change_made:
        return None
    return _build_diff(original_lines, replacement_lines, finding.file) + "\n"


def _build_diff(original: list[str], updated: list[str], relative_path: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            original,
            updated,
            fromfile=f"a/{relative_path}",
            tofile=f"b/{relative_path}",
            lineterm="",
        )
    )


def _build_env_template_diff(workspace: Path, env_var: str, value: str) -> str | None:
    template_path = workspace / ".env.template"
    if template_path.exists():
        original_lines = template_path.read_text(encoding="utf-8").splitlines()
    else:
        original_lines = []
    updated_lines = list(original_lines)
    entry = f"{env_var}={value}"
    if entry in updated_lines:
        return None
    updated_lines.append(entry)
    return _build_diff(original_lines, updated_lines, ".env.template")


def _derive_env_var(var_name: str, relative_path: str) -> str:
    sanitized = re.sub(r"[^A-Z0-9_]", "_", var_name.upper())
    return sanitized or "KRATOS_SECRET"


def _has_import_os(lines: list[str]) -> bool:
    return any(line.strip() == "import os" for line in lines)


def _import_insertion_index(lines: list[str]) -> int:
    if not lines:
        return 0
    idx = 0
    if lines[0].startswith("#!"):
        idx = 1
    if idx < len(lines) and lines[idx].startswith(("'''", '"""')):
        quote = lines[idx][:3]
        idx += 1
        while idx < len(lines) and quote not in lines[idx]:
            idx += 1
        if idx < len(lines):
            idx += 1
    return idx

