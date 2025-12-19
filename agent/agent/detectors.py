"""Compliance evidence detectors for control violations and evidence gaps.

This module detects compliance control violations, not generic security vulnerabilities.
Every detection maps to a specific compliance framework requirement.
"""
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
    """Check if a file path should be skipped during scanning."""
    # Check for excluded directory names in path parts
    path_str = str(path)
    path_parts = path.parts
    path_name_lower = path.name.lower()
    
    # Skip if any excluded directory is in the path
    for part in path_parts:
        if part in EXCLUDED_DIRS:
            return True
        # Also check for patterns like "venv", "site-packages", etc.
        if "venv" in part.lower() or "site-packages" in part.lower():
            return True
        # Skip build artifacts
        if "artifacts" in part.lower() or "build-info" in part.lower():
            return True
    
    # Skip excluded filenames
    if path.name in EXCLUDED_FILENAMES:
        return True
    
    # Skip report files
    if "report.json" in path_name_lower or "aegis-report.json" in path_name_lower:
        return True
    
    # Skip compiled Python files
    if path.suffix in {".pyc", ".pyo"}:
        return True
    
    # Skip if in a virtual environment
    if "venv" in path_str or "site-packages" in path_str:
        return True
    
    # Skip build artifact JSON files (not config files)
    if path.suffix == ".json" and any(artifact_dir in path_str.lower() for artifact_dir in ("artifacts", "build-info", "build/", "dist/")):
        return True
    
    return False


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def scan_workspace(root: Path) -> list[RawFinding]:
    """Scan workspace for compliance control violations and evidence gaps.
    
    Returns findings that represent specific compliance framework violations,
    not generic security issues. Each finding maps to a verifiable control requirement.
    """
    findings: list[RawFinding] = []
    for file_path in _iter_files(root):
        if file_path.suffix == ".py":
            findings.extend(_scan_python_file(file_path, root))
        else:
            findings.extend(_scan_text_file(file_path, root))
    
    # DPDP and GDPR compliance checks
    findings.extend(_scan_dpdp_compliance(root))
    findings.extend(_scan_gdpr_compliance(root))
    
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

            for target in targets:
                var_name = target.id
                
                # Skip if variable name matches false positive patterns
                if not _contains_secret_keyword(var_name):
                    continue
                
                # Skip filename/path constants
                if any(suffix in var_name.upper() for suffix in ("_FILENAME", "_PATH", "_DIR", "_EXTENSION", "_EXTENSIONS")):
                    continue
                
                # Skip boolean flags (is_*, has_*, should_*)
                if var_name.startswith(("is_", "has_", "should_", "can_", "will_")):
                    continue
                
                # Only flag if there's an actual string literal that looks like a secret
                is_real_secret = False
                confidence = 0.7
                
                if literal_value:
                    # Check if the literal value looks like a real secret
                    if _looks_like_real_secret(literal_value):
                        is_real_secret = True
                        confidence = 0.95
                    # Or if it's a reasonably long string (likely not a config constant)
                    elif len(literal_value) >= 8 and not any(
                        fp in var_name.upper() 
                        for fp in ("SECRET_KEYWORDS", "SECRETS_MANAGEMENT", "SECRET_REGEX", "SECRET_TEXT", "SECRET_", "_FILENAME", "_PATH")
                    ):
                        # Variable name suggests secret AND has a substantial value
                        is_real_secret = True
                        confidence = 0.85
                else:
                    # No literal value - could be assignment from another variable
                    # Check if it's a UI component (Streamlit, etc.) - these are false positives
                    snippet_line = _extract_snippet(lines, getattr(node, "lineno", None))
                    if any(ui_pattern in snippet_line for ui_pattern in (
                        "st.text_input", "st.password_input", "st.secret", 
                        "text_input", "password_input", "input(", "Input(",
                        "type=\"password\"", "type='password'"
                    )):
                        # This is a UI component, not a hardcoded secret
                        continue
                    
                    # Only flag if variable name is very explicit (not just "token")
                    explicit_secret_names = ("PASSWORD", "API_KEY", "SECRET", "PRIVATE_KEY", "ACCESS_KEY")
                    if any(name in var_name.upper() for name in explicit_secret_names):
                        # But skip if it's clearly a false positive pattern
                        if not any(fp in var_name.upper() for fp in ("SECRET_KEYWORDS", "SECRETS_MANAGEMENT", "SECRET_REGEX", "_FILENAME", "_PATH")):
                            # This might be a secret, but lower confidence
                            is_real_secret = True
                            confidence = 0.6
                
                if is_real_secret:
                    line_no = getattr(node, "lineno", None)
                    snippet = _extract_snippet(lines, line_no)
                    findings.append(
                        RawFinding(
                            type="hardcoded_secret",
                            file=_relative_path(path, root),
                            line=line_no,
                            snippet=snippet,
                            severity="high",
                            confidence=confidence,
                            metadata={
                                "var_name": var_name,
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
    """Check if a value contains secret-related keywords, excluding false positives."""
    if not value:
        return False
    
    upper_value = value.upper()
    
    # Check for false positive patterns first
    from .config import FALSE_POSITIVE_PATTERNS
    if any(fp_pattern in upper_value for fp_pattern in FALSE_POSITIVE_PATTERNS):
        return False
    
    # Check for secret keywords
    return any(keyword in upper_value for keyword in SECRET_KEYWORDS)


def _looks_like_real_secret(value: str) -> bool:
    """Check if a string value looks like an actual secret (not just a variable name)."""
    if not value or len(value) < 8:
        return False
    
    # Check for common secret prefixes
    secret_prefixes = ("sk_", "pk_", "AKIA", "AIza", "ghp_", "gho_", "xoxb-", "xoxa-", "xoxp-")
    if any(value.startswith(prefix) for prefix in secret_prefixes):
        return True
    
    # Check for long base64-like strings (32+ chars, alphanumeric + / =)
    if len(value) >= 32 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in value):
        return True
    
    # Check for long hex strings (32+ chars, hex only)
    if len(value) >= 32 and all(c in "0123456789abcdefABCDEF" for c in value):
        return True
    
    # Check for JWT tokens (starts with eyJ)
    if value.startswith("eyJ"):
        return True
    
    return False


def _scan_text_file(path: Path, root: Path) -> list[RawFinding]:
    suffix = path.suffix.lower()
    is_iac_file = suffix in IAC_EXTENSIONS
    is_secret_file = suffix in SECRET_TEXT_EXTENSIONS or path.name.startswith(".env")
    
    # Skip .env.example and .env.sample files (these are templates, not actual secrets)
    if path.name.endswith(('.env.example', '.env.sample', '.env.template')):
        return []
    
    if not (is_iac_file or is_secret_file):
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        lines = []

    findings: list[RawFinding] = []
    for line_no, line in enumerate(lines, start=1):
        # Skip comment lines
        if line.strip().startswith('#'):
            continue
        
        # Skip lines that are just comments or placeholders
        stripped = line.strip()
        if any(placeholder in stripped.upper() for placeholder in ('PLACEHOLDER', 'YOUR_', 'CHANGE-ME', 'REPLACE_ME', 'EXAMPLE')):
            # But only if it's clearly a placeholder, not an actual value
            if any(ph in stripped for ph in ('change-me', 'replace_me', 'yourtokenhere', 'placeholder')):
                continue
        
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
            if match:
                var_name = match.group("var")
                value = match.group("value")
                
                # Skip environment variable references (${VAR} or $VAR) - these are correct
                if value and ('${' in value or value.startswith('$')):
                    continue
                
                # Skip false positives
                if _contains_secret_keyword(var_name) and not any(
                    fp in var_name.upper() 
                    for fp in ("SECRET_KEYWORDS", "SECRETS_MANAGEMENT", "SECRET_REGEX", "SECRET_TEXT")
                ):
                    # Check if value looks like a real secret
                    if value and _looks_like_real_secret(value.strip("'\"")):
                        findings.append(
                            RawFinding(
                                type="hardcoded_secret",
                                file=_relative_path(path, root),
                                line=line_no,
                                snippet=line.strip(),
                                severity="high",
                                confidence=0.9,
                            )
                        )
                    elif value and len(value.strip("'\" ")) >= 8:
                        # Long value, likely a secret (but check for placeholders)
                        value_clean = value.strip("'\" ").upper()
                        if not any(ph in value_clean for ph in ('CHANGE-ME', 'REPLACE_ME', 'YOURTOKENHERE', 'PLACEHOLDER', 'EXAMPLE')):
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


def _scan_dpdp_compliance(root: Path) -> list[RawFinding]:
    """Scan for DPDP Act (India) compliance control violations.
    
    Detects:
    - Missing data retention configuration
    - Missing consent handling indicators
    - Missing access logging for personal data paths
    """
    findings: list[RawFinding] = []
    
    # Check for retention configuration
    retention_found = False
    consent_found = False
    access_logging_found = False
    
    for file_path in _iter_files(root):
        if _should_skip(file_path):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
            file_rel = _relative_path(file_path, root)
            
            # DPDP Section 8: Data retention
            if not retention_found:
                if any(
                    keyword in content
                    for keyword in [
                        "retention",
                        "data_retention",
                        "retention_policy",
                        "retention_period",
                    ]
                ):
                    retention_found = True
            
            # DPDP Section 7: Consent handling
            if not consent_found:
                if any(
                    keyword in content
                    for keyword in [
                        "consent",
                        "user_consent",
                        "consent_handler",
                        "consent_management",
                        "gdpr_consent",
                        "dpdp_consent",
                    ]
                ):
                    consent_found = True
            
            # DPDP Section 9: Access logging
            if not access_logging_found:
                if any(
                    keyword in content
                    for keyword in [
                        "access_log",
                        "audit_log",
                        "log_access",
                        "access_audit",
                        "personal_data_log",
                    ]
                ):
                    access_logging_found = True
                    
        except (OSError, UnicodeDecodeError):
            continue
    
    # Generate findings for missing evidence
    if not retention_found:
        findings.append(
            RawFinding(
                type="dpdp_missing_retention",
                file=".",
                line=None,
                snippet="No data retention configuration found",
                severity="medium",
                confidence=0.7,
                metadata={"evidence_type": "config_proof"},
            )
        )
    
    if not consent_found:
        findings.append(
            RawFinding(
                type="dpdp_missing_consent",
                file=".",
                line=None,
                snippet="No consent handling mechanisms found",
                severity="high",
                confidence=0.7,
                metadata={"evidence_type": "code_proof"},
            )
        )
    
    if not access_logging_found:
        findings.append(
            RawFinding(
                type="dpdp_missing_access_logging",
                file=".",
                line=None,
                snippet="No access logging for personal data found",
                severity="high",
                    confidence=0.7,
                    metadata={"evidence_type": "log_proof"},
                )
            )
    
    return findings


def _scan_gdpr_compliance(root: Path) -> list[RawFinding]:
    """Scan for GDPR (EU) compliance control violations.
    
    Detects:
    - Missing encryption configuration
    - Missing consent handling indicators
    - Missing data retention policies
    - Missing right to erasure mechanisms
    - Missing data portability mechanisms
    """
    findings: list[RawFinding] = []
    
    # Check for GDPR compliance indicators
    encryption_found = False
    consent_found = False
    retention_found = False
    erasure_found = False
    portability_found = False
    
    for file_path in _iter_files(root):
        if _should_skip(file_path):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
            
            # GDPR Article 32: Encryption
            if not encryption_found:
                if any(
                    keyword in content
                    for keyword in [
                        "encrypt",
                        "encryption",
                        "tls",
                        "ssl",
                        "aes",
                        "cipher",
                        "crypto",
                    ]
                ):
                    encryption_found = True
            
            # GDPR Article 6: Consent (shared with DPDP)
            if not consent_found:
                if any(
                    keyword in content
                    for keyword in [
                        "consent",
                        "user_consent",
                        "consent_handler",
                        "consent_management",
                        "gdpr_consent",
                        "data_subject_consent",
                    ]
                ):
                    consent_found = True
            
            # GDPR Article 5: Retention (shared with DPDP)
            if not retention_found:
                if any(
                    keyword in content
                    for keyword in [
                        "retention",
                        "data_retention",
                        "retention_policy",
                        "retention_period",
                        "data_retention_policy",
                    ]
                ):
                    retention_found = True
            
            # GDPR Article 17: Right to erasure
            if not erasure_found:
                if any(
                    keyword in content
                    for keyword in [
                        "erase",
                        "erasure",
                        "delete_user_data",
                        "right_to_be_forgotten",
                        "gdpr_delete",
                        "remove_personal_data",
                    ]
                ):
                    erasure_found = True
            
            # GDPR Article 20: Data portability
            if not portability_found:
                if any(
                    keyword in content
                    for keyword in [
                        "data_portability",
                        "export_data",
                        "export_user_data",
                        "gdpr_export",
                        "download_my_data",
                    ]
                ):
                    portability_found = True
                    
        except (OSError, UnicodeDecodeError):
            continue
    
    # Generate findings for missing evidence (only for GDPR-specific controls)
    if not encryption_found:
        findings.append(
            RawFinding(
                type="gdpr_missing_encryption",
                file=".",
                line=None,
                snippet="No encryption configuration found",
                severity="high",
                confidence=0.7,
                metadata={"evidence_type": "code_proof"},
            )
        )
    
    if not erasure_found:
        findings.append(
            RawFinding(
                type="gdpr_missing_right_to_erasure",
                file=".",
                line=None,
                snippet="No right to erasure mechanisms found",
                severity="medium",
                confidence=0.7,
                metadata={"evidence_type": "code_proof"},
            )
        )
    
    if not portability_found:
        findings.append(
            RawFinding(
                type="gdpr_missing_data_portability",
                file=".",
                line=None,
                snippet="No data portability mechanisms found",
                severity="medium",
                confidence=0.7,
                metadata={"evidence_type": "code_proof"},
            )
        )
    
    # Note: Consent and retention are already checked in DPDP scan
    # to avoid duplicate findings, but they apply to both frameworks
    
    return findings


