"""Detectors for insecure patterns in source files."""
from __future__ import annotations

from pathlib import Path
import ast
import logging
import re
from typing import Iterable

from .config import (
    EXCLUDED_DIRS,
    EXCLUDED_FILENAMES,
    IAC_EXTENSIONS,
    PUBLIC_ACL_MARKER,
    SECRET_KEYWORDS,
    SECRET_TEXT_EXTENSIONS,
)
from .findings import RawFinding

logger = logging.getLogger(__name__)

SECRET_REGEX = re.compile(
    r"(?P<var>[A-Za-z0-9_]*?(?:password|api[_-]?key|token|secret)[A-Za-z0-9_]*)"
    r"\s*(?:=|:)\s*(?P<value>['\"]?[^\s'\"#]+)",
    flags=re.IGNORECASE,
)


def _should_skip(path: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return True
    if path.name in EXCLUDED_FILENAMES:
        return True
    return False


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def scan_workspace(root: Path) -> list[RawFinding]:
    """Iterate through files under `root` and collect findings."""
    findings: list[RawFinding] = []
    for file_path in _iter_files(root):
        if file_path.suffix == ".py":
            findings.extend(_scan_python_file(file_path, root))
        else:
            findings.extend(_scan_text_file(file_path, root))
    return findings


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and not _should_skip(path):
            yield path


def _scan_python_file(path: Path, root: Path) -> list[RawFinding]:
    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        logger.debug("Unable to parse %s", path)
        return []

    findings: list[RawFinding] = []
    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = []
            if isinstance(node, ast.Assign):
                targets = [t for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = [node.target]
            if not targets:
                continue

            literal_value = None
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                literal_value = node.value.value

            literal_matches = _contains_secret_keyword(literal_value or "")
            for target in targets:
                name_matches = _contains_secret_keyword(target.id)
                if name_matches or literal_matches:
                    line_no = getattr(node, "lineno", None)
                    snippet = _extract_snippet(lines, line_no)
                    findings.append(
                        RawFinding(
                            type="hardcoded_secret",
                            file=_relative_path(path, root),
                            line=line_no,
                            snippet=snippet,
                            severity="high",
                            confidence=0.98,
                            metadata={
                                "var_name": target.id,
                                "literal": literal_value,
                            },
                        )
                    )
    return findings


def _extract_snippet(lines: list[str], line_no: int | None) -> str:
    if line_no is None or line_no - 1 >= len(lines):
        return ""
    return lines[line_no - 1].strip()


def _contains_secret_keyword(value: str) -> bool:
    upper_value = value.upper()
    return any(keyword in upper_value for keyword in SECRET_KEYWORDS)


def _scan_text_file(path: Path, root: Path) -> list[RawFinding]:
    suffix = path.suffix.lower()
    is_iac_file = suffix in IAC_EXTENSIONS
    is_secret_file = suffix in SECRET_TEXT_EXTENSIONS or path.name.startswith(".env")
    if not (is_iac_file or is_secret_file):
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        lines = []

    findings: list[RawFinding] = []
    for line_no, line in enumerate(lines, start=1):
        if is_iac_file and PUBLIC_ACL_MARKER in line:
            findings.append(
                RawFinding(
                    type="insecure_acl",
                    file=_relative_path(path, root),
                    line=line_no,
                    snippet=line.strip(),
                    severity="high",
                    confidence=0.9,
                )
            )
            continue

        if is_secret_file:
            match = SECRET_REGEX.search(line)
        else:
            match = None
        if match:
            findings.append(
                RawFinding(
                    type="hardcoded_secret",
                    file=_relative_path(path, root),
                    line=line_no,
                    snippet=line.strip(),
                    severity="high",
                    confidence=0.8,
                )
            )
    return findings


