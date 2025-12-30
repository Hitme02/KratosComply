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
    CLOUD_SECRET_PATTERNS,
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
    
    # Enhanced detection capabilities
    findings.extend(_scan_cloud_secrets(root))
    findings.extend(_scan_terraform_security(root))
    findings.extend(_scan_container_security(root))
    findings.extend(_scan_api_security(root))
    findings.extend(_scan_database_security(root))
    findings.extend(_scan_cicd_security(root))
    findings.extend(_scan_dependencies(root))
    
    # Enhanced detection capabilities
    findings.extend(_scan_cloud_secrets(root))
    findings.extend(_scan_terraform_security(root))
    findings.extend(_scan_container_security(root))
    findings.extend(_scan_api_security(root))
    findings.extend(_scan_database_security(root))
    findings.extend(_scan_cicd_security(root))
    findings.extend(_scan_dependencies(root))
    
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
    
    # Track context for better detection
    is_test_file = "test" in path.name.lower() or "spec" in path.name.lower()
    is_example_file = "example" in path.name.lower() or "sample" in path.name.lower()
    
    for node in ast.walk(tree):
        # Detect secrets in environment variable loading (getenv with defaults)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("getenv", "environ.get"):
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    default_value = node.args[1].value
                    if isinstance(default_value, str) and _looks_like_real_secret(default_value):
                        line_no = getattr(node, "lineno", None)
                        findings.append(RawFinding(
                            type="hardcoded_secret",
                            file=_relative_path(path, root),
                            line=line_no,
                            snippet=_extract_snippet(lines, line_no),
                            severity="high",
                            confidence=0.95,
                            metadata={"context": "environment_default", "var_name": node.args[0].value if isinstance(node.args[0], ast.Constant) else "unknown"}
                        ))
        
        # Detect secrets in class attributes (Pydantic, dataclasses)
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.AnnAssign):
                    if isinstance(item.value, ast.Constant) and isinstance(item.value.value, str):
                        var_name = item.target.id if isinstance(item.target, ast.Name) else "unknown"
                        if _contains_secret_keyword(var_name) and _looks_like_real_secret(item.value.value):
                            line_no = getattr(item, "lineno", None)
                            findings.append(RawFinding(
                                type="hardcoded_secret",
                                file=_relative_path(path, root),
                                line=line_no,
                                snippet=_extract_snippet(lines, line_no),
                                severity="high",
                                confidence=0.9,
                                metadata={"context": "class_attribute", "class_name": node.name, "var_name": var_name}
                            ))
        
        # Standard assignment detection
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
                
                # Adjust confidence based on context
                if is_test_file:
                    confidence -= 0.2
                if is_example_file:
                    confidence -= 0.3
                
                if literal_value:
                    # Check if the literal value looks like a real secret
                    if _looks_like_real_secret(literal_value):
                        is_real_secret = True
                        confidence = min(0.95, confidence + 0.25)
                    # Or if it's a reasonably long string (likely not a config constant)
                    elif len(literal_value) >= 8 and not any(
                        fp in var_name.upper() 
                        for fp in ("SECRET_KEYWORDS", "SECRETS_MANAGEMENT", "SECRET_REGEX", "SECRET_TEXT", "SECRET_", "_FILENAME", "_PATH")
                    ):
                        # Variable name suggests secret AND has a substantial value
                        is_real_secret = True
                        confidence = min(0.85, confidence + 0.15)
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
                            confidence = max(0.5, confidence - 0.1)
                
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
                            confidence=max(0.0, min(1.0, confidence)),
                            metadata={
                                "var_name": var_name,
                                "literal": literal_value,
                                "is_test_file": is_test_file,
                                "is_example_file": is_example_file,
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


def _scan_cloud_secrets(root: Path) -> list[RawFinding]:
    """Detect cloud provider-specific secrets."""
    findings: list[RawFinding] = []
    
    for file_path in _iter_files(root):
        if _should_skip(file_path):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        for provider, patterns in CLOUD_SECRET_PATTERNS.items():
            for pattern, secret_type in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_no = content[:match.start()].count("\n") + 1
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=match.group(0)[:100],
                        severity="critical" if provider in ("aws", "azure") else "high",
                        confidence=0.98,
                        metadata={
                            "provider": provider,
                            "secret_type": secret_type,
                            "context": "cloud_credential"
                        },
                    ))
    
    return findings


def _scan_terraform_security(root: Path) -> list[RawFinding]:
    """Enhanced Terraform/Infrastructure-as-Code security scanning."""
    findings: list[RawFinding] = []
    
    terraform_files = [f for f in _iter_files(root) if f.suffix in (".tf", ".tf.json")]
    
    for tf_file in terraform_files:
        if _should_skip(tf_file):
            continue
        
        try:
            content = tf_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Detect public S3 buckets
        s3_public_pattern = r'resource\s+"aws_s3_bucket"[^}]+(?:public_access_block|acl\s*=\s*["\']public)'
        if re.search(s3_public_pattern, content, re.IGNORECASE | re.DOTALL):
            findings.append(RawFinding(
                type="insecure_acl",
                file=_relative_path(tf_file, root),
                line=None,
                snippet="Public S3 bucket detected",
                severity="high",
                confidence=0.9,
                metadata={"resource_type": "s3_bucket", "control_id": "SOC2-CC6.1"}
            ))
        
        # Detect unencrypted RDS instances
        rds_pattern = r'resource\s+"aws_db_instance"[^}]+storage_encrypted\s*=\s*false'
        if re.search(rds_pattern, content, re.IGNORECASE | re.DOTALL):
            findings.append(RawFinding(
                type="unencrypted_database",
                file=_relative_path(tf_file, root),
                line=None,
                snippet="RDS instance without encryption",
                severity="high",
                confidence=0.85,
                metadata={"resource_type": "rds_instance", "control_id": "SOC2-CC6.1"}
            ))
        
        # Detect security groups allowing 0.0.0.0/0
        sg_public = r'cidr_blocks\s*=\s*\[["\']0\.0\.0\.0/0["\']'
        if re.search(sg_public, content, re.IGNORECASE):
            findings.append(RawFinding(
                type="insecure_network_acl",
                file=_relative_path(tf_file, root),
                line=None,
                snippet="Security group allows public access (0.0.0.0/0)",
                severity="critical",
                confidence=0.95,
                metadata={"resource_type": "security_group", "control_id": "SOC2-CC6.1"}
            ))
    
    return findings


def _scan_container_security(root: Path) -> list[RawFinding]:
    """Detect container security compliance issues."""
    findings: list[RawFinding] = []
    
    # Scan Dockerfiles
    for dockerfile in root.rglob("Dockerfile*"):
        if _should_skip(dockerfile):
            continue
        
        try:
            content = dockerfile.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Detect running as root
        if re.search(r'USER\s+root', content, re.IGNORECASE) or not re.search(r'USER\s+', content, re.IGNORECASE):
            findings.append(RawFinding(
                type="container_runs_as_root",
                file=_relative_path(dockerfile, root),
                line=None,
                snippet="Container runs as root user",
                severity="medium",
                confidence=0.9,
                metadata={"control_id": "SOC2-CC6.1", "container_type": "docker"}
            ))
        
        # Detect secrets in Dockerfile
        secret_pattern = r'(?:ENV|ARG)\s+(?:PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*["\']([^"\']+)["\']'
        matches = re.finditer(secret_pattern, content, re.IGNORECASE)
        for match in matches:
            line_no = content[:match.start()].count("\n") + 1
            findings.append(RawFinding(
                type="hardcoded_secret",
                file=_relative_path(dockerfile, root),
                line=line_no,
                snippet=match.group(0),
                severity="high",
                confidence=0.95,
                metadata={"context": "dockerfile", "control_id": "SOC2-CC6.2"}
            ))
    
    # Scan Kubernetes manifests
    for k8s_file in list(root.rglob("*.yaml")) + list(root.rglob("*.yml")):
        if _should_skip(k8s_file):
            continue
        
        if "k8s" not in str(k8s_file) and "kubernetes" not in str(k8s_file):
            continue
        
        try:
            content = k8s_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Detect secrets in plain text
        if re.search(r'password:\s*["\']([^"\']+)["\']', content, re.IGNORECASE):
            findings.append(RawFinding(
                type="hardcoded_secret",
                file=_relative_path(k8s_file, root),
                line=None,
                snippet="Secret in plain text in Kubernetes manifest",
                severity="high",
                confidence=0.9,
                metadata={"context": "kubernetes", "control_id": "SOC2-CC6.2"}
            ))
        
        # Detect missing security contexts
        if "kind: Deployment" in content or "kind: Pod" in content:
            if "securityContext" not in content:
                findings.append(RawFinding(
                    type="missing_security_context",
                    file=_relative_path(k8s_file, root),
                    line=None,
                    snippet="Missing securityContext in Kubernetes manifest",
                    severity="medium",
                    confidence=0.8,
                    metadata={"control_id": "SOC2-CC6.1"}
                ))
    
    return findings


def _scan_api_security(root: Path) -> list[RawFinding]:
    """Detect API security compliance issues."""
    findings: list[RawFinding] = []
    
    api_files = list(root.rglob("*.py")) + list(root.rglob("*.js")) + list(root.rglob("*.ts"))
    
    for file_path in api_files:
        if _should_skip(file_path):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Detect Flask/FastAPI routes without authentication
        if "flask" in content.lower() or "fastapi" in content.lower():
            route_pattern = r'@(?:app|router)\.(?:route|get|post|put|delete)\(["\']([^"\']+)["\']'
            auth_pattern = r'@(?:require_auth|authenticated|login_required|auth_required)'
            
            routes = re.finditer(route_pattern, content)
            for route in routes:
                route_line = content[:route.start()].count("\n") + 1
                before_route = content[:route.start()]
                if not re.search(auth_pattern, before_route[-500:]):
                    findings.append(RawFinding(
                        type="unauthenticated_api_endpoint",
                        file=_relative_path(file_path, root),
                        line=route_line,
                        snippet=route.group(0),
                        severity="high",
                        confidence=0.7,
                        metadata={"endpoint": route.group(1), "control_id": "SOC2-CC6.1"}
                    ))
        
        # Detect API keys in URL parameters
        api_key_in_url = r'(?:api_key|apikey|token|access_token)\s*=\s*["\']([^"\']+)["\']'
        if re.search(api_key_in_url, content, re.IGNORECASE):
            findings.append(RawFinding(
                type="api_key_in_url",
                file=_relative_path(file_path, root),
                line=None,
                snippet="API key detected in URL parameter",
                severity="high",
                confidence=0.8,
                metadata={"control_id": "SOC2-CC6.2"}
            ))
    
    return findings


def _scan_database_security(root: Path) -> list[RawFinding]:
    """Detect database security compliance issues."""
    findings: list[RawFinding] = []
    
    sql_files = list(root.rglob("*.sql")) + list(root.rglob("*.py"))
    
    for file_path in sql_files:
        if _should_skip(file_path):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Detect string concatenation in SQL queries (potential SQL injection)
        sql_concat_patterns = [
            r'["\'].*SELECT.*["\']\s*\+\s*[a-zA-Z_]+',
            r'f["\'].*SELECT.*{.*}.*["\']',
            r'["\'].*SELECT.*["\']\.format\(',
        ]
        
        for pattern in sql_concat_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_no = content[:match.start()].count("\n") + 1
                findings.append(RawFinding(
                    type="potential_sql_injection",
                    file=_relative_path(file_path, root),
                    line=line_no,
                    snippet=match.group(0)[:100],
                    severity="high",
                    confidence=0.75,
                    metadata={"control_id": "SOC2-CC6.1", "vulnerability_type": "sql_injection"}
                ))
        
        # Detect database connections without SSL/TLS
        db_conn_patterns = [
            r'postgresql://[^:]+:[^@]+@[^/]+/[^\s"\']+',
            r'mysql://[^:]+:[^@]+@[^/]+/[^\s"\']+',
        ]
        
        for pattern in db_conn_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                conn_string = match.group(0)
                if "ssl" not in conn_string.lower() and "tls" not in conn_string.lower():
                    line_no = content[:match.start()].count("\n") + 1
                    findings.append(RawFinding(
                        type="unencrypted_database_connection",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=conn_string,
                        severity="high",
                        confidence=0.9,
                        metadata={"control_id": "ISO27001-A.10.1.1", "connection_type": "database"}
                    ))
    
    return findings


def _scan_cicd_security(root: Path) -> list[RawFinding]:
    """Detect CI/CD pipeline security issues."""
    findings: list[RawFinding] = []
    
    ci_files = list(root.rglob(".github/workflows/*.yml")) + \
               list(root.rglob(".gitlab-ci.yml")) + \
               list(root.rglob(".circleci/config.yml")) + \
               list(root.rglob("Jenkinsfile"))
    
    for ci_file in ci_files:
        if _should_skip(ci_file):
            continue
        
        try:
            content = ci_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Detect secrets in CI/CD files
        secret_patterns = [
            r'password:\s*["\']([^"\']+)["\']',
            r'api_key:\s*["\']([^"\']+)["\']',
            r'secret:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_no = content[:match.start()].count("\n") + 1
                findings.append(RawFinding(
                    type="hardcoded_secret",
                    file=_relative_path(ci_file, root),
                    line=line_no,
                    snippet=match.group(0),
                    severity="critical",
                    confidence=0.95,
                    metadata={"context": "cicd", "control_id": "SOC2-CC6.2"}
                ))
        
        # Detect missing artifact signing
        if "docker build" in content.lower() or "docker push" in content.lower():
            if "cosign" not in content.lower() and "notary" not in content.lower():
                findings.append(RawFinding(
                    type="unsigned_artifacts",
                    file=_relative_path(ci_file, root),
                    line=None,
                    snippet="Docker images not signed in CI/CD pipeline",
                    severity="medium",
                    confidence=0.7,
                    metadata={"control_id": "SOC2-CC6.1"}
                ))
    
    return findings


def _scan_dependencies(root: Path) -> list[RawFinding]:
    """Scan dependencies for compliance issues."""
    findings: list[RawFinding] = []
    
    import json
    
    # Check for dependency lock files
    lock_files = {
        "package-lock.json": "npm",
        "yarn.lock": "yarn",
        "requirements.txt": "pip",
        "Pipfile.lock": "pipenv",
        "poetry.lock": "poetry",
        "Gemfile.lock": "ruby",
        "go.sum": "go",
    }
    
    for lock_file_name, package_manager in lock_files.items():
        lock_file = root / lock_file_name
        if not lock_file.exists():
            findings.append(RawFinding(
                type="missing_dependency_lock",
                file=lock_file_name,
                line=None,
                snippet=f"Missing {lock_file_name} - dependencies not locked",
                severity="medium",
                confidence=0.9,
                metadata={
                    "package_manager": package_manager,
                    "control_id": "SOC2-CC6.1",
                }
            ))
    
    # Check for outdated dependencies (compliance risk)
    package_json = root / "package.json"
    if package_json.exists():
        try:
            package_data = json.loads(package_json.read_text())
            dependencies = package_data.get("dependencies", {})
            
            for dep, version in dependencies.items():
                if version.startswith("^") or version.startswith("~") or version == "latest":
                    findings.append(RawFinding(
                        type="unpinned_dependency",
                        file="package.json",
                        line=None,
                        snippet=f"{dep}: {version}",
                        severity="low",
                        confidence=0.8,
                        metadata={
                            "dependency": dep,
                            "control_id": "SOC2-CC6.1",
                        }
                    ))
        except Exception:
            pass
    
    return findings


