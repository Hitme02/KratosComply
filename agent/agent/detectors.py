"""Compliance evidence detectors for control violations and evidence gaps.

This module detects compliance control violations, not generic security vulnerabilities.
Every detection maps to a specific compliance framework requirement.
"""
from __future__ import annotations

from pathlib import Path
import ast
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
try:
    from .local_ai_detector import validate_finding_with_ai, get_ai_detector
    AI_VALIDATION_AVAILABLE = True
    # Initialize AI detector early to load model
    _ = get_ai_detector()
except ImportError:
    AI_VALIDATION_AVAILABLE = False
    def validate_finding_with_ai(*args, **kwargs):
        return True, 0.5, "AI validation not available"
try:
    from .vulnerability_detectors import (
        _scan_xxe_vulnerabilities,
        _scan_ssrf_vulnerabilities,
        _scan_insecure_deserialization,
        _scan_path_traversal,
        _scan_race_conditions,
        _scan_crypto_misuse,
    )
except ImportError:
    # Fallback if module doesn't exist yet
    def _scan_xxe_vulnerabilities(*args, **kwargs): return []
    def _scan_ssrf_vulnerabilities(*args, **kwargs): return []
    def _scan_insecure_deserialization(*args, **kwargs): return []
    def _scan_path_traversal(*args, **kwargs): return []
    def _scan_race_conditions(*args, **kwargs): return []
    def _scan_crypto_misuse(*args, **kwargs): return []
from .advanced_detectors import (
    detect_consent_via_dependencies,
    detect_consent_via_api_routes,
    detect_consent_via_ast,
    detect_consent_via_database_schema,
    detect_data_portability_via_api_routes,
    detect_data_portability_via_ast,
    detect_access_logging_via_ast,
    detect_access_logging_via_config,
    detect_retention_via_config,
    detect_right_to_erasure_via_api_routes,
    detect_right_to_erasure_via_ast,
    detect_encryption_via_dependencies,
    detect_encryption_via_config,
)

logger = logging.getLogger(__name__)

# Enhanced secret regex patterns to catch more formats (passwd, pwd, auth_token, etc.)
SECRET_REGEX = re.compile(
    r"(?P<var>[A-Za-z0-9_]*?(?:password|passwd|pwd|api[_-]?key|token|secret|auth[_-]?token|credential)[A-Za-z0-9_]*)"
    r"\s*(?:=|:)\s*(?P<value>['\"]?[^\s'\"#]+)",
    flags=re.IGNORECASE,
)


def _load_ignore_file(root: Path, ignore_file: Path | None = None) -> set[str]:
    """Load .kratosignore file patterns for exclusion."""
    ignore_patterns = set()
    
    # Check for .kratosignore in root or specified path
    if ignore_file:
        ignore_path = Path(ignore_file).expanduser()
    else:
        ignore_path = root / ".kratosignore"
    
    if ignore_path.exists():
        try:
            ignore_content = ignore_path.read_text(encoding="utf-8", errors="ignore")
            for line in ignore_content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    ignore_patterns.add(line)
        except Exception:
            logger.debug(f"Could not read ignore file: {ignore_path}")
    
    return ignore_patterns


def _should_skip(path: Path, ignore_patterns: set[str] | None = None) -> bool:
    """Skip excluded directories and files."""
    parts = path.parts
    for excluded in EXCLUDED_DIRS:
        if excluded in parts:
            return True
    if path.name in EXCLUDED_FILENAMES:
        return True
    for pattern in EXCLUDED_FILENAMES:
        if pattern.endswith("*") and path.name.startswith(pattern[:-1]):
            return True
    
    # Check .kratosignore patterns
    if ignore_patterns:
        path_str = str(path)
        for pattern in ignore_patterns:
            # Simple glob-like matching
            if pattern.startswith('**/'):
                pattern = pattern[3:]
            if pattern.startswith('/'):
                pattern = pattern[1:]
            
            # Match directory or file
            if pattern in path_str or path.name == pattern:
                return True
            
            # Simple wildcard matching
            if '*' in pattern:
                import fnmatch
                if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                    return True
    
    return False


def _is_detector_code(path: Path, content: str = None) -> bool:
    """Check if file contains detector/scanner code patterns (to avoid false positives).
    
    Returns True if the file appears to be detector/scanner code that defines patterns
    for detecting vulnerabilities, rather than code that contains vulnerabilities.
    """
    # Check file path for detector/scanner indicators
    path_str = str(path).lower()
    detector_indicators = [
        "detector", "scanner", "scanner", "scan_", "_scan_", "pattern", 
        "compliance.py", "config.py", "detectors.py", "advanced_detectors.py",
        "vulnerability_detectors.py", "local_ai_detector.py"
    ]
    
    if any(indicator in path_str for indicator in detector_indicators):
        return True
    
    # Check content for detector code patterns
    if content is None:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False
    
    content_lower = content.lower()
    
    # Patterns that indicate this is detector code defining patterns, not using them
    detector_patterns = [
        "def _scan_",  # Scanner function definitions
        "xss_patterns = [",  # Pattern definitions
        "secret_patterns = [",
        "injection_patterns = [",
        "weak_cipher_patterns = [",
        "sql_injection_patterns = [",  # SQL injection pattern definitions
        "nosql_injection_patterns = [",  # NoSQL injection pattern definitions
        "weak_ciphers = {",  # Weak cipher dictionary definitions
        "weak_auth_patterns = [",  # Weak auth pattern definitions
        "re.compile(",  # Regex pattern compilation
        "CLOUD_SECRET_PATTERNS",  # Config constants
        "SECRET_REGEX =",  # Pattern definitions
        "pattern.*=.*r\"",  # Pattern assignments
        "patterns = [",  # Pattern lists
        "detection.*pattern",  # Comments about patterns
        "= [",  # List assignments (often pattern lists)
        "= {",  # Dictionary assignments (often pattern dicts)
    ]
    
    # If file contains multiple detector patterns, it's likely detector code
    pattern_count = sum(1 for pattern in detector_patterns if pattern in content_lower)
    if pattern_count >= 2:
        return True
    
    # Check if file contains pattern definitions followed by usage in loops
    if "for pattern" in content_lower and "re.search(pattern" in content_lower:
        return True
    
    return False


def _is_pattern_definition(line: str, context: str = None) -> bool:
    """Check if a line is defining a detection pattern rather than using it.
    
    Returns True if the line appears to be defining a regex pattern or list
    of patterns for detection purposes.
    """
    line_lower = line.lower().strip()
    
    # Pattern definition indicators
    pattern_def_indicators = [
        "pattern", "patterns", "regex", "re.compile", "r\"", "r'",
        "= [", "= {", "= (",  # Assignment to list/dict/tuple
        "CLOUD_SECRET_PATTERNS", "SECRET_REGEX", "FALSE_POSITIVE_PATTERNS",
        "xss_patterns", "injection_patterns", "weak_cipher_patterns",
        "secret_patterns", "acl_patterns"
    ]
    
    # Check if line is a pattern definition
    if any(indicator in line_lower for indicator in pattern_def_indicators):
        # Additional check: is it in a dictionary/list definition?
        if ":" in line or "[" in line or "(" in line:
            # Check context - if it's in a function that scans, it's a pattern definition
            if context:
                context_lower = context.lower()
                if any(func in context_lower for func in ["def _scan_", "def scan_", "patterns =", "pattern =", "= [", "= {"]):
                    return True
            # Check if line looks like a pattern tuple: (r'...', "...")
            if re.search(r'\(r["\']', line) or (re.search(r'\(["\'].*["\']\s*,', line) and '"' in line):
                return True
            return True
    
    # Check for regex pattern strings in pattern definitions
    if re.search(r'r["\'].*["\']', line):
        # If it's in a tuple/list context with pattern indicators, it's a definition
        if context:
            context_lower = context.lower()
            if any(marker in context_lower for marker in ["patterns =", "pattern =", "= [", "= {", "sql_injection_patterns", "xss_patterns"]):
                return True
        if "pattern" in line_lower or "regex" in line_lower:
            return True
    
    # Check for dictionary/list pattern definitions: "TripleDES": [r"...", ...]
    if re.search(r'["\'][^"\']+["\']\s*:\s*\[', line) and ("pattern" in line_lower or "cipher" in line_lower or "secret" in line_lower):
        return True
    
    return False


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def scan_workspace(root: Path, max_workers: int = 4, show_progress: bool = False, ignore_file: Path | None = None) -> list[RawFinding]:
    """Scan workspace for compliance control violations and evidence gaps.
    
    Returns findings that represent specific compliance framework violations,
    not generic security issues. Each finding maps to a verifiable control requirement.
    
    Args:
        root: Root directory to scan
        max_workers: Number of parallel workers for file scanning (default: 4)
        show_progress: Whether to show progress indicators (default: False)
    """
    start_time = time.time()
    
    # Initialize AI detector if available (loads model on first scan)
    if AI_VALIDATION_AVAILABLE:
        try:
            from .local_ai_detector import get_ai_detector
            detector = get_ai_detector()
            if detector.enabled:
                logger.info("AI-powered validation enabled for compliance findings")
        except Exception as e:
            logger.debug(f"AI detector initialization skipped: {e}")
    
    findings: list[RawFinding] = []
    file_count = 0
    error_count = 0
    
    # Load .kratosignore patterns if available
    ignore_patterns = _load_ignore_file(root, ignore_file)
    
    # Collect all files first for progress tracking
    all_files = list(_iter_files(root, ignore_patterns))
    total_files = len(all_files)
    
    if show_progress:
        logger.info(f"Scanning {total_files} files with {max_workers} workers...")
    
    # Parallel file scanning for better performance
    def scan_single_file(file_path: Path) -> tuple[list[RawFinding], bool]:
        """Scan a single file and return findings and success status."""
        file_findings = []
        try:
            if file_path.suffix == ".py":
                file_findings.extend(_scan_python_file(file_path, root))
            else:
                # Scan ALL file types for secrets, not just specific extensions
                file_findings.extend(_scan_text_file(file_path, root))
                # Also scan code files (PHP, Java, C#, etc.) for secrets
                if file_path.suffix in (".php", ".java", ".cs", ".js", ".ts", ".rb", ".go", ".cpp", ".c", ".h", ".swift", ".kt", ".scala"):
                    file_findings.extend(_scan_code_file_for_secrets(file_path, root))
            
            # Scan for SSH private keys in any file
            if file_path.suffix in (".key", ".pem", ".p12", ".pfx") or "key" in file_path.name.lower() or "private" in file_path.name.lower():
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    if "-----BEGIN" in content and ("PRIVATE KEY" in content or "RSA PRIVATE KEY" in content or "DSA PRIVATE KEY" in content):
                        file_findings.append(RawFinding(
                            type="hardcoded_secret",
                            file=_relative_path(file_path, root),
                            line=None,
                            snippet="SSH private key file detected",
                            severity="critical",
                            confidence=0.99,
                            metadata={"secret_type": "SSH_PRIVATE_KEY", "file_type": file_path.suffix}
                        ))
                except Exception:
                    pass
            
            return file_findings, True
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
            return [], False
    
    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all file scanning tasks
        future_to_file = {executor.submit(scan_single_file, file_path): file_path for file_path in all_files}
        
        # Collect results as they complete
        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                file_findings, success = future.result()
                findings.extend(file_findings)
                file_count += 1
                if not success:
                    error_count += 1
                
                if show_progress and file_count % 100 == 0:
                    logger.info(f"Processed {file_count}/{total_files} files ({len(findings)} findings so far)...")
            except Exception as e:
                logger.debug(f"Error processing {file_path}: {e}")
                error_count += 1
                file_count += 1
    
    if show_progress:
        scan_time = time.time() - start_time
        logger.info(f"File scanning complete: {file_count} files, {len(findings)} findings, {error_count} errors in {scan_time:.2f}s")
    
    # Enhanced detection capabilities (these scan the entire workspace, not individual files)
    logger.debug("Running enhanced detection scans...")
    enhanced_start = time.time()
    
    # Enhanced detection capabilities
    findings.extend(_scan_cloud_secrets(root))
    findings.extend(_scan_terraform_security(root))
    findings.extend(_scan_container_security(root))
    findings.extend(_scan_api_security(root))
    findings.extend(_scan_database_security(root))
    findings.extend(_scan_cicd_security(root))
    findings.extend(_scan_dependencies(root))
    findings.extend(_scan_frontend_security(root))  # Frontend security (sessionStorage, localStorage)
    findings.extend(_scan_configuration_security(root))  # Config files (CORS, database encryption)
    
    # Security vulnerability detection (not just compliance)
    findings.extend(_scan_weak_encryption(root))
    findings.extend(_scan_injection_vulnerabilities(root))
    findings.extend(_scan_weak_authentication(root))
    findings.extend(_scan_missing_logging(root))
    findings.extend(_scan_command_injection(root))
    findings.extend(_scan_xss_vulnerabilities(root))
    findings.extend(_scan_xxe_vulnerabilities(root))
    findings.extend(_scan_ssrf_vulnerabilities(root))
    findings.extend(_scan_insecure_deserialization(root))
    findings.extend(_scan_path_traversal(root))
    findings.extend(_scan_race_conditions(root))
    findings.extend(_scan_crypto_misuse(root))
    findings.extend(_scan_debug_mode(root))
    findings.extend(_scan_insecure_cookies(root))
    
    # Industry-grade security detections
    findings.extend(_scan_advanced_secrets(root))
    findings.extend(_scan_authentication_security(root))
    findings.extend(_scan_access_control_issues(root))
    findings.extend(_scan_logging_security(root))
    findings.extend(_scan_encryption_security(root))
    findings.extend(_scan_insecure_configurations(root))
    findings.extend(_scan_supply_chain_security(root))
    
    # Compliance framework-specific scans (using improved detection techniques)
    # Only scan once (removed duplicate scans)
    findings.extend(_scan_dpdp_compliance(root))
    findings.extend(_scan_gdpr_compliance(root))
    
    total_time = time.time() - start_time
    enhanced_time = time.time() - enhanced_start
    
    if show_progress:
        logger.info(f"Scan complete: {len(findings)} total findings in {total_time:.2f}s (enhanced scans: {enhanced_time:.2f}s)")
    
    # Store scan statistics in logger context
    logger.debug(f"Scan statistics: {file_count} files, {len(findings)} findings, {error_count} errors, {total_time:.2f}s")
    
    return findings


def _iter_files(root: Path, ignore_patterns: set[str] | None = None) -> Iterable[Path]:
    """Iterate over all files in the workspace, excluding skipped paths."""
    for path in root.rglob("*"):
        if path.is_file() and not _should_skip(path, ignore_patterns):
            yield path


def _scan_python_file(path: Path, root: Path) -> list[RawFinding]:
    """Scan Python files for compliance control violations."""
    findings: list[RawFinding] = []
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    
    # Check for hardcoded secrets
    findings.extend(_scan_python_secrets(path, root, content))
    
    return findings


def _scan_python_secrets(path: Path, root: Path, content: str) -> list[RawFinding]:
    """Scan Python code for hardcoded secrets."""
    findings: list[RawFinding] = []
    
    # Skip detector code to avoid false positives
    if _is_detector_code(path, content):
        return []
    
    lines = content.splitlines()
    is_test_file = "test" in path.name.lower() or "spec" in path.name.lower()
    is_example_file = "example" in path.name.lower() or "sample" in path.name.lower()
    
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        
        # Skip comment-only lines
        if stripped.startswith('#'):
            continue
        
        # Skip pattern definitions
        if _is_pattern_definition(line, content):
            continue
        
        # Check for hardcoded secrets using regex
        match = SECRET_REGEX.search(line)
        if match:
            var_name = match.group("var")
            value = match.group("value")
            
            # Skip environment variable references
            if value and ('${' in value or value.startswith('$')):
                continue
            
            # Skip false positives
            if _contains_secret_keyword(var_name) and not any(
                fp in var_name.upper() 
                for fp in ("SECRET_KEYWORDS", "SECRETS_MANAGEMENT", "SECRET_REGEX", "SECRET_TEXT")
            ):
                # Check if value looks like a real secret
                if value and _looks_like_real_secret(value.strip("'\"")):
                    confidence = 0.9
                    if is_test_file:
                        confidence *= 0.7
                    if is_example_file:
                        confidence *= 0.6
                    
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=confidence,
                        metadata={
                            "is_test_file": is_test_file,
                            "is_example_file": is_example_file,
                        }
                    ))
    
    return findings


def _contains_secret_keyword(var_name: str) -> bool:
    """Check if variable name contains a secret-related keyword."""
    return any(keyword in var_name.upper() for keyword in SECRET_KEYWORDS)


def _looks_like_real_secret(value: str) -> bool:
    """Determine if a value looks like a real secret (not a placeholder)."""
    if not value:
        return False
    
    upper_value = value.upper()
    
    # Check against false positive patterns
    from .config import FALSE_POSITIVE_PATTERNS
    if any(fp_pattern in upper_value for fp_pattern in FALSE_POSITIVE_PATTERNS):
        return False
    
    # Check for known secret patterns
    secret_indicators = [
        "sk_live_", "pk_live_", "sk_test_", "pk_test_",  # Stripe
        "xoxb-", "xoxa-",  # Slack
        "ghp_", "github_pat_",  # GitHub
        "AKIA",  # AWS
        "AIza",  # GCP
    ]
    
    if any(indicator in value for indicator in secret_indicators):
        return True
    
    # Check for SSH key markers
    if "-----BEGIN" in value and ("PRIVATE KEY" in value or "RSA PRIVATE KEY" in value):
        return True
    
    # Check for database connection strings with embedded passwords
    if "password=" in value.lower() and len(value) > 20:
        return True
    
    # Check for UUID-like patterns (often used as tokens)
    import re
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    if re.match(uuid_pattern, value, re.IGNORECASE):
        return True
    
    # Check for long alphanumeric strings (likely tokens)
    if len(value) >= 20 and value.isalnum():
        return True
    
    # Check for base64-like strings
    if len(value) >= 16 and all(c.isalnum() or c in ('+', '/', '=') for c in value):
        return True
    
    return False


def _scan_code_file_for_secrets(path: Path, root: Path) -> list[RawFinding]:
    """Scan code files (PHP, Java, C#, etc.) for hardcoded secrets with industry-grade patterns."""
    findings: list[RawFinding] = []
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    
    # Skip detector code to avoid false positives
    if _is_detector_code(path, content):
        return []
    
    lines = content.splitlines()
    file_lower = path.name.lower()
    
    # Skip test files with lower confidence (but still scan them)
    is_test_file = "test" in file_lower or "spec" in file_lower
    is_example_file = "example" in file_lower or "sample" in file_lower
    
    # Enhanced regex patterns for different languages and formats
    patterns = [
        # Pattern 1: password = "value" or password: "value" (general, more flexible)
        re.compile(
            r"(?:password|passwd|pwd|secret|api[_-]?key|token|auth[_-]?token|credential|pass)\s*[:=]\s*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE
        ),
        # Pattern 2: $password = "value" (PHP) - more flexible spacing
        re.compile(
            r"\$(?:password|passwd|pwd|secret|api[_-]?key|token|auth[_-]?token)\s*=\s*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE
        ),
        # Pattern 3: String password = "value" (Java/C#) - more flexible
        re.compile(
            r"(?:String|string|const|var|let|final|private|public|protected|static)\s+(?:password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE
        ),
        # Pattern 4: password => "value" (PHP arrays, JavaScript objects)
        re.compile(
            r"['\"]?(?:password|passwd|pwd|secret|api[_-]?key|token|auth[_-]?token)['\"]?\s*[:=]>\s*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE
        ),
        # Pattern 5: password: "value" (YAML, JSON-like, config files)
        re.compile(
            r"(?:password|passwd|pwd|secret|api[_-]?key|token):\s*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE
        ),
        # Pattern 6: Array of passwords (PHP, JavaScript) - improved to catch multi-line arrays
        re.compile(
            r"(?:password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*\[[^\]]*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE | re.MULTILINE | re.DOTALL
        ),
        # Pattern 7: PHP array with passwords (array('password' => 'value'))
        re.compile(
            r"['\"]?(?:password|passwd|pwd|secret|api[_-]?key|token)['\"]?\s*=>\s*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE
        ),
        # Pattern 8: PHP array syntax: array("password" => "value") or ["password" => "value"]
        re.compile(
            r"(?:array\s*\(|\[)\s*['\"]?(?:password|passwd|pwd|secret|api[_-]?key|token)['\"]?\s*=>\s*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE
        ),
        # Pattern 9: Database connection strings (more flexible)
        re.compile(
            r"(?:db[_-]?(?:password|pass)|database[_-]?(?:password|pass)|connection[_-]?string|pwd)\s*[:=]\s*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE
        ),
        # Pattern 10: Java/C# field assignment: password = "value" (without type)
        re.compile(
            r"(?:password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*['\"]([^'\"]{3,})['\"]",
            re.IGNORECASE
        ),
        # Pattern 11: Config file format: password=value (no quotes)
        re.compile(
            r"(?:password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*([^\s#]{3,})",
            re.IGNORECASE
        ),
        # Pattern 12: Empty password detection (security issue)
        re.compile(
            r"(?:password|passwd|pwd)\s*[:=]\s*['\"]\s*['\"]",
            re.IGNORECASE
        ),
    ]
    
    # Check for SSH private keys
    if "-----BEGIN" in content and ("PRIVATE KEY" in content or "RSA PRIVATE KEY" in content or "DSA PRIVATE KEY" in content):
        findings.append(RawFinding(
            type="hardcoded_secret",
            file=_relative_path(path, root),
            line=None,
            snippet="SSH private key detected in file",
            severity="critical",
            confidence=0.99,
            metadata={"language": path.suffix, "pattern": "ssh_private_key", "secret_type": "SSH_PRIVATE_KEY"}
        ))
    
    # Special handling for PHP arrays - scan multi-line arrays
    if path.suffix == ".php":
        # Look for PHP array patterns that span multiple lines
        # Pattern: $passwords = array('admin' => 'admin12345', 'user' => 'password')
        php_array_pattern = re.compile(
            r'\$[a-zA-Z_]*pass[a-zA-Z_]*\s*=\s*array\s*\([^)]*(?:=>\s*["\']([^"\']{3,})["\']|["\']([^"\']{3,})["\'])',
            re.IGNORECASE | re.MULTILINE | re.DOTALL
        )
        for match in php_array_pattern.finditer(content):
            value = match.group(1) or match.group(2)
            if value and len(value.strip()) >= 3:
                value_clean = value.strip("'\" ")
                # Skip placeholders
                if value_clean.upper() not in ('CHANGE-ME', 'REPLACE_ME', 'PLACEHOLDER', 'EXAMPLE', 'TODO', 'FIXME'):
                    # Find line number
                    line_no = content[:match.start()].count('\n') + 1
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(path, root),
                        line=line_no,
                        snippet=match.group(0)[:200],
                        severity="critical",
                        confidence=0.9,
                        metadata={"language": "php", "pattern": "php_array_password", "secret_type": "HARDCODED_PASSWORD"}
                    ))
    
    # Special handling for Java - detect simple password assignments
    if path.suffix == ".java":
        # Pattern: password = "pass1" or password = "pass2" (simple assignments)
        java_simple_pattern = re.compile(
            r'(?:password|passwd|pwd)\s*=\s*["\']([^"\']{3,})["\']',
            re.IGNORECASE
        )
        for line_no, line in enumerate(lines, start=1):
            if java_simple_pattern.search(line):
                match = java_simple_pattern.search(line)
                value = match.group(1)
                if value and len(value.strip()) >= 3:
                    value_clean = value.strip("'\" ")
                    # Skip placeholders
                    if value_clean.upper() not in ('CHANGE-ME', 'REPLACE_ME', 'PLACEHOLDER', 'EXAMPLE'):
                        findings.append(RawFinding(
                            type="hardcoded_secret",
                            file=_relative_path(path, root),
                            line=line_no,
                            snippet=line.strip()[:200],
                            severity="critical",
                            confidence=0.9,
                            metadata={"language": "java", "pattern": "java_simple_password", "secret_type": "HARDCODED_PASSWORD"}
                        ))
    
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        
        # Skip comment lines (but check for secrets in comments too with lower confidence)
        is_comment = stripped.startswith(('//', '/*', '*', '#', '--', '<!--'))
        
        # Skip obvious placeholder patterns
        if any(ph in stripped.upper() for ph in ('PLACEHOLDER', 'YOUR_', 'CHANGE-ME', 'REPLACE_ME', 'EXAMPLE', 'TODO', 'FIXME')):
            # But still check if it contains a real secret pattern
            if not any(secret_word in stripped.upper() for secret_word in ('PASSWORD', 'SECRET', 'TOKEN', 'KEY')):
                continue
        
        # Check for empty password (security issue)
        if re.search(r'(?:password|passwd|pwd)\s*[:=]\s*["\']\s*["\']', line, re.IGNORECASE):
            findings.append(RawFinding(
                type="hardcoded_secret",
                file=_relative_path(path, root),
                line=line_no,
                snippet=line.strip()[:200],
                severity="high",
                confidence=0.95,
                metadata={"language": path.suffix, "pattern": "empty_password", "issue": "Empty password detected"}
            ))
            continue
        
        # Check all patterns
        for pattern in patterns:
            for match in pattern.finditer(line):
                value = match.group(1) if match.lastindex else match.group(0)
                if not value:
                    continue
                
                value_clean = value.strip("'\" ")
                
                # Skip if it's clearly a placeholder (but be less aggressive)
                value_upper = value_clean.upper()
                placeholder_indicators = ('CHANGE-ME', 'REPLACE_ME', 'YOURTOKENHERE', 'PLACEHOLDER', 'TODO', 'XXX', 'FIXME', 'YOUR_', 'SET_', 'CONFIG')
                # Only skip if it's EXACTLY a placeholder, not if it contains one
                if value_upper in placeholder_indicators or value_upper == 'EXAMPLE':
                    continue
                
                # Skip very short values (likely not secrets) - but allow 3+ chars
                if len(value_clean) < 3:
                    continue
                
                # Skip common false positives (but be more strict)
                false_positives = ('null', 'none', 'true', 'false', 'undefined', 'nil')
                if value_clean.lower() in false_positives:
                    continue
                
                # Check if it looks like a real secret
                confidence = 0.85
                if is_test_file:
                    confidence *= 0.7  # Lower confidence for test files
                if is_example_file:
                    confidence *= 0.6  # Lower confidence for example files
                if is_comment:
                    confidence *= 0.8  # Lower confidence for comments
                
                # High confidence for known secret patterns
                if _looks_like_real_secret(value_clean):
                    confidence = min(0.99, confidence + 0.1)
                elif len(value_clean) >= 8:
                    # Medium confidence for long values
                    confidence = min(0.9, confidence)
                elif len(value_clean) >= 4:
                    # Lower confidence for short values (but still check)
                    confidence = max(0.5, confidence - 0.2)
                
                # Only report if confidence is reasonable (lowered threshold to catch more)
                if confidence >= 0.4:
                    # AI validation (optional, graceful degradation if not available)
                    if AI_VALIDATION_AVAILABLE:
                        try:
                            context_lines = lines[max(0, line_no-3):min(len(lines), line_no+3)]
                            context = '\n'.join(context_lines)
                            is_valid, ai_confidence, ai_explanation = validate_finding_with_ai(
                                finding_type="hardcoded_secret",
                                snippet=line.strip()[:200],
                                context=context,
                                file_path=str(path),
                                line_no=line_no
                            )
                            
                            # If AI says it's a false positive, skip it
                            if not is_valid:
                                logger.debug(f"AI filtered false positive: {ai_explanation}")
                                continue
                            
                            # Adjust confidence based on AI validation
                            confidence = (confidence + ai_confidence) / 2
                        except Exception as e:
                            # AI validation failed, continue with original confidence
                            logger.debug(f"AI validation error (continuing): {e}")
                    
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high" if confidence >= 0.8 else "medium",
                        confidence=confidence,
                        metadata={
                            "language": path.suffix,
                            "pattern": "code_file_scan",
                            "is_test_file": is_test_file,
                            "is_example_file": is_example_file,
                            "is_comment": is_comment
                        }
                    ))
                    break  # Only report once per line
    
    return findings


def _scan_text_file(path: Path, root: Path) -> list[RawFinding]:
    suffix = path.suffix.lower()
    is_iac_file = suffix in IAC_EXTENSIONS
    is_secret_file = suffix in SECRET_TEXT_EXTENSIONS or path.name.startswith(".env")
    
    # Skip .env.example and .env.sample files (these are templates, not actual secrets)
    if path.name.endswith(('.env.example', '.env.sample', '.env.template')):
        return []
    
    # Also scan config files for secrets (like .conf files)
    is_config_file = suffix in (".conf", ".ini", ".properties", ".cfg")
    
    if not (is_iac_file or is_secret_file or is_config_file):
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

        if is_secret_file or is_config_file:
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
                                snippet=line.strip()[:200],
                                severity="high",
                                confidence=0.9,
                                metadata={"file_type": suffix}
                            )
                        )

    return findings


def _scan_cloud_secrets(root: Path) -> list[RawFinding]:
    """Scan for cloud provider secrets (AWS, GCP, Azure, etc.)."""
    findings: list[RawFinding] = []
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        for provider, patterns in CLOUD_SECRET_PATTERNS.items():
            for pattern, description in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(file_path, root),
                        line=None,
                        snippet=match.group(0)[:200],
                        severity="critical",
                        confidence=0.95,
                        metadata={"provider": provider, "secret_type": description}
                    ))
    
    return findings


def _scan_terraform_security(root: Path) -> list[RawFinding]:
    """Scan Terraform files for security misconfigurations."""
    findings: list[RawFinding] = []
    
    for file_path in _iter_files(root):
        if file_path.suffix not in (".tf", ".tf.json"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for public ACLs
        for line_no, line in enumerate(lines, start=1):
            if PUBLIC_ACL_MARKER in line:
                findings.append(RawFinding(
                    type="insecure_acl",
                    file=_relative_path(file_path, root),
                    line=line_no,
                    snippet=line.strip()[:200],
                    severity="high",
                    confidence=0.9,
                ))
        
        # Check for IAM policies with wildcard permissions
        if re.search(r'["\']\*["\']', content):
            findings.append(RawFinding(
                type="insecure_acl",
                file=_relative_path(file_path, root),
                line=None,
                snippet="IAM policy with wildcard permissions",
                severity="high",
                confidence=0.9,
                metadata={"issue": "Wildcard permissions in IAM policy"}
            ))
        
        # Check for public API endpoints
        if re.search(r'authorization\s*=\s*["\']?NONE["\']?', content, re.IGNORECASE):
            findings.append(RawFinding(
                type="unauthenticated_api_endpoint",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Public API endpoint without authorization",
                severity="high",
                confidence=0.9,
            ))
        
        # Check for public network access
        if re.search(r'public[_-]?access\s*=\s*true', content, re.IGNORECASE):
            findings.append(RawFinding(
                type="insecure_acl",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Public network access enabled",
                severity="high",
                confidence=0.9,
            ))
    
    return findings


def _scan_container_security(root: Path) -> list[RawFinding]:
    """Scan container configuration files for security issues."""
    findings: list[RawFinding] = []
    
    # Also scan docker-compose files by name
    docker_compose_names = ["docker-compose.yml", "docker-compose.yaml", "docker-compose.json", "compose.yml", "compose.yaml"]
    
    for file_path in _iter_files(root):
        # Scan YAML/JSON files and docker-compose files
        if file_path.suffix not in (".yaml", ".yml", ".json") and file_path.name not in docker_compose_names:
            continue
        
        if "docker" not in file_path.name.lower() and "kubernetes" not in file_path.name.lower() and "k8s" not in file_path.name.lower():
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Check for containers running as root
        if re.search(r'runAsUser\s*:\s*0', content) or re.search(r'USER\s+0', content):
            findings.append(RawFinding(
                type="container_runs_as_root",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Container runs as root user",
                severity="high",
                confidence=0.9,
            ))
        
        # Check for privilege escalation
        if re.search(r'allowPrivilegeEscalation\s*:\s*true', content):
            findings.append(RawFinding(
                type="insecure_acl",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Privilege escalation enabled",
                severity="high",
                confidence=0.9,
            ))
        
        # Check for Docker socket exposure (improved patterns for docker-compose)
        docker_socket_patterns = [
            r'/var/run/docker\.sock',
            r'docker\.sock:/var/run/docker\.sock',
            r'- /var/run/docker\.sock:/var/run/docker\.sock',
            r'volumes:\s*-\s*["\']?/var/run/docker\.sock',
            r'hostPath:\s*path:\s*["\']?/var/run/docker\.sock',
        ]
        for pattern in docker_socket_patterns:
            if re.search(pattern, content):
                findings.append(RawFinding(
                    type="insecure_acl",
                    file=_relative_path(file_path, root),
                    line=None,
                    snippet="Docker socket exposed to container",
                    severity="high",
                    confidence=0.9,
                    metadata={"control_id": "SOC2-CC6.1", "compliance_frameworks": ["SOC2", "ISO27001"]}
                ))
                break
        
        # Check for missing security context
        if "securityContext" not in content and "SecurityContext" not in content:
            findings.append(RawFinding(
                type="missing_security_context",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Missing security context in container configuration",
                severity="medium",
                confidence=0.8,
            ))
    
    return findings


def _scan_api_security(root: Path) -> list[RawFinding]:
    """Scan API code for security issues."""
    findings: list[RawFinding] = []
    
    for file_path in _iter_files(root):
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for unauthenticated API routes
        route_patterns = [
            r'@app\.(get|post|put|delete|patch)\(',
            r'@router\.(get|post|put|delete|patch)\(',
            r'\.(get|post|put|delete|patch)\(',
        ]
        
        has_auth_middleware = False
        has_logging = False
        
        for line in lines:
            # Check for authentication middleware/decorators
            if re.search(r'@(require_auth|authenticated|login_required|auth)', line, re.IGNORECASE):
                has_auth_middleware = True
            if re.search(r'\.(log|logger|logging)', line, re.IGNORECASE):
                has_logging = True
        
        # If auth middleware exists but no logging, flag it
        if has_auth_middleware and not has_logging:
            findings.append(RawFinding(
                type="dpdp_missing_access_logging",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Authentication middleware found but no access logging",
                severity="medium",
                confidence=0.75,
            ))
    
    return findings


def _scan_database_security(root: Path) -> list[RawFinding]:
    """Scan database configuration and code for security issues."""
    findings: list[RawFinding] = []
    
    for file_path in _iter_files(root):
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go", ".sql"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Check for empty passwords in connection strings
        if re.search(r'password\s*=\s*["\']\s*["\']', content, re.IGNORECASE):
            findings.append(RawFinding(
                type="hardcoded_secret",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Empty password in database connection",
                severity="high",
                confidence=0.95,
            ))
        
        # Check for plaintext passwords in connection strings
        if re.search(r'password\s*=\s*["\'][^"\']{3,}["\']', content, re.IGNORECASE):
            findings.append(RawFinding(
                type="hardcoded_secret",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Plaintext password in database connection string",
                severity="high",
                confidence=0.9,
            ))
        
        # Check for unencrypted database connections
        if re.search(r'jdbc:mysql://', content, re.IGNORECASE) and 'useSSL=true' not in content:
            findings.append(RawFinding(
                type="unencrypted_database_connection",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Unencrypted database connection detected",
                severity="high",
                confidence=0.85,
            ))
        
        # Check for SQLite without encryption (SQLite databases are unencrypted by default)
        sqlite_patterns = [
            r'sqlite:///',
            r'sqlite://',
            r'SQLALCHEMY_DATABASE_URI.*sqlite',
            r'DATABASE_URL.*sqlite',
            r'DATABASE.*sqlite',
            r'driver.*=.*sqlite',
        ]
        for pattern in sqlite_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # Check if encryption is mentioned (WAL mode doesn't count as encryption)
                if 'encrypt' not in content.lower() and 'sqlcipher' not in content.lower():
                    findings.append(RawFinding(
                        type="unencrypted_database",
                        file=_relative_path(file_path, root),
                        line=None,
                        snippet="SQLite database without encryption (GDPR Article 32, SOC2-CC6.1)",
                        severity="high",
                        confidence=0.9,
                        metadata={"control_id": "SOC2-CC6.1", "compliance_frameworks": ["GDPR", "SOC2", "HIPAA"]}
                    ))
                    break
    
    return findings


def _scan_cicd_security(root: Path) -> list[RawFinding]:
    """Scan CI/CD configuration files for security issues - Industry-grade comprehensive checks."""
    findings: list[RawFinding] = []
    
    # CI/CD file patterns
    cicd_files = [
        ".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".travis.yml", 
        "circle.yml", ".circleci", "azure-pipelines.yml", ".drone.yml",
        "bitbucket-pipelines.yml", "buildkite.yml", ".gitlab", "Jenkinsfile.groovy"
    ]
    
    for file_path in _iter_files(root):
        # Check if it's a CI/CD file
        is_cicd_file = False
        for cicd_pattern in cicd_files:
            if cicd_pattern in str(file_path) or file_path.name in cicd_files:
                is_cicd_file = True
                break
        
        if not is_cicd_file:
            # Also check common CI/CD file extensions in CI directories
            if file_path.suffix in (".yml", ".yaml", ".json") and (
                ".github" in str(file_path) or ".gitlab" in str(file_path) or 
                ".circleci" in str(file_path) or "jenkins" in file_path.name.lower()
            ):
                is_cicd_file = True
        
        if not is_cicd_file:
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for hardcoded secrets in CI/CD files
        secret_patterns = [
            (r'GITHUB_TOKEN\s*[:=]\s*["\']([^"\']{10,})["\']', "GitHub token in CI/CD"),
            (r'CI.*SECRET\s*[:=]\s*["\']([^"\']{10,})["\']', "CI secret in pipeline"),
            (r'pipeline.*secret\s*[:=]\s*["\']([^"\']{10,})["\']', "Pipeline secret"),
            (r'AWS.*KEY\s*[:=]\s*["\']([^"\']{10,})["\']', "AWS key in CI/CD"),
            (r'password\s*[:=]\s*["\']([^"\']{8,})["\']', "Password in CI/CD"),
        ]
        
        for pattern, description in secret_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="critical",
                        confidence=0.95,
                        metadata={"secret_type": "CI_CD_SECRET", "issue": description, "control_id": "SOC2-CC6.2"}
                    ))
                    break
        
        # Check for unsigned artifacts
        if "sign" not in content.lower() and "gpg" not in content.lower() and "cosign" not in content.lower():
            findings.append(RawFinding(
                type="unsigned_artifacts",
                file=_relative_path(file_path, root),
                line=None,
                snippet="CI/CD pipeline does not sign artifacts",
                severity="medium",
                confidence=0.7,
                metadata={"control_id": "SOC2-CC8.1"}
            ))
        
        # Check for insecure docker image pulls
        if re.search(r'docker\s+pull\s+[^:]+:latest', content, re.IGNORECASE):
            findings.append(RawFinding(
                type="unpinned_dependency",
                file=_relative_path(file_path, root),
                line=None,
                snippet="Docker image pulled with :latest tag (unpinned)",
                severity="medium",
                confidence=0.8,
                metadata={"control_id": "SOC2-CC8.1"}
            ))
        
        # Check for missing dependency scanning
        if not re.search(r'snyk|dependabot|safety|bandit|trivy|grype', content, re.IGNORECASE):
            findings.append(RawFinding(
                type="missing_dependency_lock",
                file=_relative_path(file_path, root),
                line=None,
                snippet="CI/CD pipeline missing dependency vulnerability scanning",
                severity="medium",
                confidence=0.75,
                metadata={"control_id": "SOC2-CC8.1"}
            ))
        
        # Check for missing security scanning
        if not re.search(r'security.*scan|vulnerability.*scan|sast|dast', content, re.IGNORECASE):
            findings.append(RawFinding(
                type="missing_logging",
                file=_relative_path(file_path, root),
                line=None,
                snippet="CI/CD pipeline missing security scanning",
                severity="medium",
                confidence=0.7,
                metadata={"control_id": "SOC2-CC7.2"}
            ))
    
    return findings


def _scan_dependencies(root: Path) -> list[RawFinding]:
    """Scan dependency files for missing lock files."""
    findings: list[RawFinding] = []
    
    dependency_files = {
        "requirements.txt": "requirements.lock",
        "Gemfile": "Gemfile.lock",
        "package.json": "package-lock.json",
        "composer.json": "composer.lock",
        "go.mod": "go.sum",
    }
    
    for dep_file, lock_file in dependency_files.items():
        dep_path = root / dep_file
        lock_path = root / lock_file
        
        if dep_path.exists() and not lock_path.exists():
            findings.append(RawFinding(
                type="missing_dependency_lock",
                file=_relative_path(dep_path, root),
                line=None,
                snippet=f"Missing {lock_file} for {dep_file}",
                severity="low",
                confidence=0.8,
                metadata={
                    "dependency_file": dep_file,
                    "lock_file": lock_file,
                    "control_id": "SOC2-CC8.1",
                }
            ))
    
    return findings


def _scan_weak_encryption(root: Path) -> list[RawFinding]:
    """Detect weak encryption algorithms and SSL/TLS misconfigurations."""
    findings: list[RawFinding] = []
    
    # Weak cipher patterns (improved to catch actual usage)
    weak_ciphers = {
        "TripleDES": [
            r"3DES",
            r"TripleDES",
            r"DES3",
            r"DESede",
            r"algorithms\.TripleDES",
            r"cipher\.TripleDES",
            r"TripleDES\(\)",
        ],
        "Blowfish": [
            r"Blowfish",
            r"blowfish",
            r"algorithms\.Blowfish",
            r"cipher\.Blowfish",
            r"Blowfish\(\)",
        ],
        "ARC4": [
            r"ARC4",
            r"RC4",
            r"arc4",
            r"rc4",
            r"algorithms\.ARC4",
            r"cipher\.ARC4",
            r"ARC4\(\)",
        ],
        "MD5": [r"MD5", r"md5", r"hashlib\.md5", r"MessageDigest\.getInstance\(['\"]MD5"],
        "SHA1": [r"SHA1", r"sha1", r"hashlib\.sha1", r"MessageDigest\.getInstance\(['\"]SHA-1"],
    }
    
    # SSL/TLS misconfiguration patterns (improved to catch more cases)
    ssl_patterns = [
        (r"check_hostname\s*=\s*False", "SSL hostname verification disabled"),
        (r"verify\s*=\s*False", "SSL certificate verification disabled"),
        (r"ssl\.create_default_context\(\)", "SSL context without hostname verification"),
        (r"SSLContext\(\)", "SSL context without proper configuration"),
        (r"ssl\._create_unverified_context\(\)", "Unverified SSL context"),
        (r"ssl\.create_default_context\(\)\s*$", "SSL context without hostname verification (default)"),
        (r"context\.check_hostname\s*=\s*False", "SSL hostname verification disabled"),
        (r"context\.verify_mode\s*=\s*ssl\.CERT_NONE", "SSL certificate verification disabled"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        # Focus on code files
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Skip detector code to avoid false positives
        if _is_detector_code(file_path, content):
            continue
        
        lines = content.splitlines()
        
        # Check for weak ciphers
        for cipher_name, patterns in weak_ciphers.items():
            for pattern in patterns:
                for line_no, line in enumerate(lines, start=1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Skip if it's in a comment or test file
                        stripped = line.strip()
                        if stripped.startswith(('//', '/*', '*', '#', '--')):
                            continue
                        if "test" in file_path.name.lower():
                            continue
                        
                        findings.append(RawFinding(
                            type="weak_encryption",
                            file=_relative_path(file_path, root),
                            line=line_no,
                            snippet=line.strip()[:200],
                            severity="high",
                            confidence=0.9,
                            metadata={"weak_cipher": cipher_name, "control_id": "GDPR-Article-32"}
                        ))
                        break  # Only report once per file per cipher
        
        # Check for SSL/TLS misconfigurations
        for pattern, description in ssl_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's in a comment
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="weak_encryption",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.85,
                        metadata={"issue": description, "control_id": "GDPR-Article-32"}
                    ))
                    break  # Only report once per file per pattern
    
    return findings


def _scan_injection_vulnerabilities(root: Path) -> list[RawFinding]:
    """Detect SQL injection and NoSQL injection vulnerabilities."""
    findings: list[RawFinding] = []
    
    # SQL injection patterns
    sql_injection_patterns = [
        (r'["\'].*SELECT.*["\']\s*\+\s*[a-zA-Z_]+', "String concatenation in SQL query"),
        (r'f["\'].*SELECT.*{.*}.*["\']', "f-string with SQL query"),
        (r'["\'].*SELECT.*["\']\.format\(', "String format in SQL query"),
        (r'execute\s*\(\s*["\'].*%(?:s|d).*["\']', "String formatting in SQL execute"),
        # Java Spring SQL injection patterns
        (r'createStatement\(\)\.executeQuery\s*\(\s*["\'].*\+', "Java Spring: String concatenation in createStatement().executeQuery()"),
        (r'connection\.createStatement\(\)\.executeQuery\s*\(\s*["\'].*\+', "Java Spring: String concatenation in connection.createStatement().executeQuery()"),
        (r'String\s+query\s*=\s*["\'].*SELECT.*["\']\s*\+', "Java: String concatenation in SQL query variable"),
        (r'query\s*=\s*["\'].*SELECT.*["\']\s*\+', "Java: String concatenation in SQL query assignment"),
        (r'executeQuery\s*\(\s*["\'].*SELECT.*["\']\s*\+', "Java: String concatenation in executeQuery()"),
        (r'\.executeQuery\s*\(\s*["\'].*SELECT.*["\']\s*\+', "Java: String concatenation in .executeQuery()"),
        (r'PreparedStatement.*executeQuery.*\+', "Java: String concatenation in PreparedStatement (should use parameters)"),
    ]
    
    # NoSQL injection patterns (improved for Java, Python, JavaScript)
    nosql_injection_patterns = [
        # MongoDB $where with string concatenation
        (r'\$where\s*[:=]\s*["\'].*\+.*["\']', "String concatenation in MongoDB $where"),
        (r'find\s*\(\s*\{[^}]*\$where[^}]*\+', "String concatenation in MongoDB find with $where"),
        # Java: query.put("field", userInput) or query.put("field", userInput + "...")
        (r'\.put\s*\(\s*["\'][^"\']+["\']\s*,\s*[a-zA-Z_]+[^)]*\+', "String concatenation in MongoDB query.put (NoSQL injection)"),
        # Java: BasicDBObject with string concatenation
        (r'BasicDBObject\s*\([^)]*\+', "String concatenation in BasicDBObject (NoSQL injection)"),
        # Java: Query with string concatenation
        (r'Query\s*\([^)]*\+', "String concatenation in Query (NoSQL injection)"),
        # General: eval with string concatenation
        (r'eval\s*\(\s*["\'].*\+', "String concatenation in eval (NoSQL injection risk)"),
        # MongoDB find with string concatenation in query
        (r'\.find\s*\(\s*["\'].*\+.*["\']', "String concatenation in MongoDB find query"),
        # User input directly in query object
        (r'\.find\s*\(\s*\{[^}]*[a-zA-Z_]+[^}]*\+', "String concatenation in MongoDB find query object"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        # Focus on code files
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for SQL injection
        for pattern, description in sql_injection_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE | re.DOTALL):
                    # Skip if it's in a comment
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="potential_sql_injection",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.75,
                        metadata={"issue": description, "control_id": "SOC2-CC6.1", "vulnerability_type": "sql_injection"}
                    ))
                    break  # Only report once per file per pattern
        
        # Check for NoSQL injection
        for pattern, description in nosql_injection_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's in a comment
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="potential_sql_injection",  # Use same type for now
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.75,
                        metadata={"issue": description, "control_id": "SOC2-CC6.1", "vulnerability_type": "nosql_injection"}
                    ))
                    break  # Only report once per file per pattern
    
    return findings


def _scan_weak_authentication(root: Path) -> list[RawFinding]:
    """Detect weak authentication mechanisms (plaintext passwords, no hashing)."""
    findings: list[RawFinding] = []
    
    # Weak authentication patterns
    weak_auth_patterns = [
        (r'password\s*==\s*', "Plaintext password comparison"),
        (r'password\s*=\s*==', "Plaintext password comparison"),
        (r'\.password\s*==\s*', "Plaintext password comparison"),
        (r'NoOpPasswordEncoder', "NoOpPasswordEncoder - passwords not hashed"),
        (r'NoOpPasswordEncoder\.getInstance\(\)', "NoOpPasswordEncoder.getInstance() - passwords not hashed"),
        (r'passwordEncoder\s*=\s*NoOpPasswordEncoder', "NoOpPasswordEncoder - passwords not hashed"),
        (r'\.passwordEncoder\(NoOpPasswordEncoder', "NoOpPasswordEncoder configured - passwords not hashed"),
        (r'String\s+password', "Password stored as String (plaintext)"),
        (r'password\s*:\s*String', "Password stored as String (plaintext)"),
        # Database model plaintext passwords
        (r'password\s*=\s*Column\(String', "Password column as String (plaintext) in database model"),
        (r'password\s*=\s*db\.String', "Password field as String (plaintext) in database model"),
        (r'password\s*=\s*models\.CharField', "Password field as CharField (plaintext) in database model"),
        # Flask SECRET_KEY detection
        (r'SECRET_KEY\s*=\s*["\']([^"\']{10,})["\']', "Flask SECRET_KEY hardcoded"),
        (r'app\.config\[["\']SECRET_KEY["\']\]\s*=\s*["\']([^"\']{10,})["\']', "Flask SECRET_KEY hardcoded in config"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        # Focus on code files
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for weak authentication patterns
        for pattern, description in weak_auth_patterns:
            for line_no, line in enumerate(lines, start=1):
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Skip if it's in a comment or test file
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    if "test" in file_path.name.lower():
                        continue
                    
                    # For Flask SECRET_KEY, check if it's a placeholder
                    if "SECRET_KEY" in description:
                        secret_value = match.group(1) if match.lastindex else ""
                        if secret_value:
                            secret_upper = secret_value.upper()
                            if secret_upper in ('CHANGE-ME', 'REPLACE_ME', 'PLACEHOLDER', 'EXAMPLE', 'YOUR_SECRET_KEY') or 'KEEP IT SECRET' in secret_upper:
                                continue
                    
                    # Check if hashing is used nearby (context check) - but not for SECRET_KEY
                    if "SECRET_KEY" not in description:
                        context_lines = lines[max(0, line_no-5):min(len(lines), line_no+5)]
                        context = '\n'.join(context_lines).lower()
                        hashing_functions = ["hash", "bcrypt", "scrypt", "argon2", "pbkdf2", "sha256", "sha512"]
                        if any(hf in context for hf in hashing_functions):
                            continue  # Skip if hashing is used nearby
                    
                    # AI validation for authentication issues
                    finding_type = "weak_authentication" if "SECRET_KEY" not in description else "hardcoded_secret"
                    final_confidence = 0.9 if "SECRET_KEY" in description else 0.8
                    
                    if AI_VALIDATION_AVAILABLE:
                        try:
                            context_lines = lines[max(0, line_no-3):min(len(lines), line_no+3)]
                            context = '\n'.join(context_lines)
                            is_valid, ai_confidence, ai_explanation = validate_finding_with_ai(
                                finding_type=finding_type,
                                snippet=line.strip()[:200],
                                context=context,
                                file_path=str(file_path),
                                line_no=line_no
                            )
                            
                            if not is_valid:
                                logger.debug(f"AI filtered false positive: {ai_explanation}")
                                continue
                            
                            final_confidence = (final_confidence + ai_confidence) / 2
                        except Exception as e:
                            logger.debug(f"AI validation error (continuing): {e}")
                    
                    findings.append(RawFinding(
                        type=finding_type,
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=final_confidence,
                        metadata={"issue": description, "control_id": "SOC2-CC6.1" if "SECRET_KEY" not in description else "SOC2-CC6.2"}
                    ))
                    break  # Only report once per file per pattern
    
    return findings


def _scan_missing_logging(root: Path) -> list[RawFinding]:
    """Detect missing authentication and security event logging."""
    findings: list[RawFinding] = []
    
    # Patterns that indicate authentication/login code
    auth_patterns = [
        r'password\s*==\s*',
        r'password\s*=\s*==',
        r'\.password\s*==\s*',
        r'login\s*\(',
        r'authenticate\s*\(',
        r'checkPassword\s*\(',
        r'verifyPassword\s*\(',
        r'system\s*\(',
        r'exec\s*\(',
        r'eval\s*\(',
    ]
    
    # Patterns that indicate logging
    logging_patterns = [
        r'\.log\s*\(',
        r'logger\s*\.',
        r'logging\s*\.',
        r'console\s*\.(log|error|warn)',
        r'print\s*\(',
        r'Log\.',
        r'Logger\.',
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        # Focus on code files
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for authentication code without logging
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith(('//', '/*', '*', '#', '--')):
                continue
            
            # Check if line contains authentication pattern
            has_auth = any(re.search(pattern, line, re.IGNORECASE) for pattern in auth_patterns)
            
            if has_auth:
                # Check if there's logging in the surrounding context (10 lines before/after)
                context_start = max(0, line_no - 10)
                context_end = min(len(lines), line_no + 10)
                context = '\n'.join(lines[context_start:context_end])
                
                # Check if logging exists in context
                has_logging = any(re.search(pattern, context, re.IGNORECASE) for pattern in logging_patterns)
                
                if not has_logging:
                    # Determine the type of auth code
                    auth_type = "authentication"
                    if 'system(' in line or 'exec(' in line or 'eval(' in line:
                        auth_type = "command execution"
                    
                    findings.append(RawFinding(
                        type="missing_logging",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="medium",
                        confidence=0.75,
                        metadata={
                            "issue": f"Missing security event logging for {auth_type}",
                            "control_id": "SOC2-CC7.2",
                            "auth_type": auth_type
                        }
                    ))
                    break  # Only report once per file
    
    return findings


def _scan_dpdp_compliance(root: Path) -> list[RawFinding]:
    """Scan for DPDP-specific compliance requirements."""
    findings: list[RawFinding] = []
    
    # Skip educational/vulnerable code repositories
    if _is_educational_code(root):
        return findings
    
    # Only scan web applications
    if not _is_web_application(root):
        return findings
    
    # Check for consent handling
    consent_found = (
        detect_consent_via_dependencies(root) or
        detect_consent_via_api_routes(root) or
        detect_consent_via_ast(root) or
        detect_consent_via_database_schema(root)
    )
    
    if not consent_found:
        findings.append(RawFinding(
            type="dpdp_missing_consent",
            file=".",
            line=None,
            snippet="No consent handling mechanisms found",
            severity="high",
            confidence=0.7,
        ))
    
    # Check for access logging
    access_logging_found = (
        detect_access_logging_via_ast(root) or
        detect_access_logging_via_config(root)
    )
    
    if not access_logging_found:
        findings.append(RawFinding(
            type="dpdp_missing_access_logging",
            file=".",
            line=None,
            snippet="No access logging for personal data found",
            severity="medium",
            confidence=0.7,
        ))
    
    # Check for data retention
    retention_found = detect_retention_via_config(root)
    if not retention_found:
        findings.append(RawFinding(
            type="dpdp_missing_retention",
            file=".",
            line=None,
            snippet="No data retention policies found",
            severity="medium",
            confidence=0.7,
        ))
    
    # Check for right to erasure
    erasure_found = (
        detect_right_to_erasure_via_api_routes(root) or
        detect_right_to_erasure_via_ast(root)
    )
    if not erasure_found:
        findings.append(RawFinding(
            type="dpdp_missing_right_to_erasure",
            file=".",
            line=None,
            snippet="No right to erasure mechanisms found",
            severity="medium",
            confidence=0.7,
        ))
    
    # Check for data portability
    portability_found = (
        detect_data_portability_via_api_routes(root) or
        detect_data_portability_via_ast(root)
    )
    if not portability_found:
        findings.append(RawFinding(
            type="dpdp_missing_data_portability",
            file=".",
            line=None,
            snippet="No data portability mechanisms found",
            severity="medium",
            confidence=0.7,
        ))
    
    return findings


def _scan_gdpr_compliance(root: Path) -> list[RawFinding]:
    """Scan for GDPR-specific compliance requirements."""
    findings: list[RawFinding] = []
    
    # Skip educational/vulnerable code repositories
    if _is_educational_code(root):
        return findings
    
    # Only scan web applications
    if not _is_web_application(root):
        return findings
    
    # Check for encryption
    encryption_found = (
        detect_encryption_via_dependencies(root) or
        detect_encryption_via_config(root)
    )
    if not encryption_found:
        findings.append(RawFinding(
            type="gdpr_missing_encryption",
            file=".",
            line=None,
            snippet="No encryption mechanisms found",
            severity="high",
            confidence=0.7,
        ))
    
    return findings


def _is_web_application(root: Path) -> bool:
    """Determine if a project is a web application."""
    # Check for web framework indicators
    framework_indicators = [
        "flask", "django", "fastapi", "express", "react", "vue", "angular",
        "spring", "rails", "sinatra", "laravel", "symfony", "asp.net"
    ]
    
    # Check package.json, requirements.txt, etc.
    dependency_files = ["package.json", "requirements.txt", "pom.xml", "build.gradle", "Gemfile", "composer.json"]
    
    for dep_file in dependency_files:
        dep_path = root / dep_file
        if dep_path.exists():
            try:
                content = dep_path.read_text(encoding="utf-8", errors="ignore").lower()
                if any(indicator in content for indicator in framework_indicators):
                    return True
            except Exception:
                pass
    
    # Check for common web application files
    web_files = ["app.py", "main.py", "server.js", "index.js", "app.js", "routes.py", "views.py"]
    for web_file in web_files:
        if (root / web_file).exists():
            return True
    
    # Check for user data handling patterns
    for file_path in _iter_files(root):
        if file_path.suffix in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb"):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
                if any(pattern in content for pattern in ["user", "customer", "email", "password", "login", "register"]):
                    return True
            except Exception:
                pass
    
    return False


def _scan_missing_logging(root: Path) -> list[RawFinding]:
    """Detect missing authentication and security event logging."""
    findings: list[RawFinding] = []
    
    # Patterns that indicate authentication/login code
    auth_patterns = [
        r'password\s*==\s*',
        r'password\s*=\s*==',
        r'\.password\s*==\s*',
        r'login\s*\(',
        r'authenticate\s*\(',
        r'checkPassword\s*\(',
        r'verifyPassword\s*\(',
        r'system\s*\(',
        r'exec\s*\(',
        r'eval\s*\(',
    ]
    
    # Patterns that indicate logging
    logging_patterns = [
        r'\.log\s*\(',
        r'logger\s*\.',
        r'logging\s*\.',
        r'console\s*\.(log|error|warn)',
        r'print\s*\(',
        r'Log\.',
        r'Logger\.',
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        # Focus on code files
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for authentication code without logging
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith(('//', '/*', '*', '#', '--')):
                continue
            
            # Check if line contains authentication pattern
            has_auth = any(re.search(pattern, line, re.IGNORECASE) for pattern in auth_patterns)
            
            if has_auth:
                # Check if there's logging in the surrounding context (10 lines before/after)
                context_start = max(0, line_no - 10)
                context_end = min(len(lines), line_no + 10)
                context = '\n'.join(lines[context_start:context_end])
                
                # Check if logging exists in context
                has_logging = any(re.search(pattern, context, re.IGNORECASE) for pattern in logging_patterns)
                
                if not has_logging:
                    # Determine the type of auth code
                    auth_type = "authentication"
                    if 'system(' in line or 'exec(' in line or 'eval(' in line:
                        auth_type = "command execution"
                    
                    findings.append(RawFinding(
                        type="missing_logging",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="medium",
                        confidence=0.75,
                        metadata={
                            "issue": f"Missing security event logging for {auth_type}",
                            "control_id": "SOC2-CC7.2",
                            "auth_type": auth_type
                        }
                    ))
                    break  # Only report once per file
    
    return findings


def _scan_command_injection(root: Path) -> list[RawFinding]:
    """Detect command injection vulnerabilities (system(), exec(), eval() with user input)."""
    findings: list[RawFinding] = []
    
    # Command injection patterns
    command_injection_patterns = [
        # PHP: system($_GET['cmd']), system($_POST['cmd']), system($_REQUEST['cmd'])
        # More flexible patterns to catch variations
        (r'system\s*\(\s*\$_?(?:GET|POST|REQUEST|COOKIE)\[', "Command injection via system() with user input (PHP)"),
        (r'system\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', "Command injection via system() with superglobal (PHP)"),
        (r'exec\s*\(\s*\$_?(?:GET|POST|REQUEST|COOKIE)\[', "Command injection via exec() with user input (PHP)"),
        (r'exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', "Command injection via exec() with superglobal (PHP)"),
        (r'shell_exec\s*\(\s*\$_?(?:GET|POST|REQUEST|COOKIE)\[', "Command injection via shell_exec() with user input (PHP)"),
        (r'passthru\s*\(\s*\$_?(?:GET|POST|REQUEST|COOKIE)\[', "Command injection via passthru() with user input (PHP)"),
        (r'eval\s*\(\s*\$_?(?:GET|POST|REQUEST|COOKIE)\[', "Code injection via eval() with user input (PHP)"),
        (r'eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', "Code injection via eval() with superglobal (PHP)"),
        # Python: os.system(user_input), subprocess.call(user_input)
        (r'os\.system\s*\(\s*[a-zA-Z_]+[^)]*\)', "Command injection via os.system() (Python)"),
        (r'subprocess\.(call|run|Popen)\s*\(\s*[a-zA-Z_]+[^)]*shell\s*=\s*True', "Command injection via subprocess with shell=True (Python)"),
        # Node.js: child_process.exec(user_input)
        (r'child_process\.(exec|spawn)\s*\(\s*[a-zA-Z_]+[^)]*\)', "Command injection via child_process (Node.js)"),
        # General: eval() with user input
        (r'eval\s*\(\s*[a-zA-Z_]+[^)]*\)', "Code injection via eval() with variable"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".php", ".rb"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for command injection
        for pattern, description in command_injection_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    # Skip comments
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    # Check if it's in a test file (lower confidence)
                    is_test = "test" in file_path.name.lower()
                    
                    # AI validation for command injection
                    final_confidence = 0.9 if not is_test else 0.6
                    if AI_VALIDATION_AVAILABLE:
                        try:
                            context_lines = lines[max(0, line_no-3):min(len(lines), line_no+3)]
                            context = '\n'.join(context_lines)
                            is_valid, ai_confidence, ai_explanation = validate_finding_with_ai(
                                finding_type="command_injection",
                                snippet=line.strip()[:200],
                                context=context,
                                file_path=str(file_path),
                                line_no=line_no
                            )
                            
                            if not is_valid:
                                logger.debug(f"AI filtered false positive: {ai_explanation}")
                                continue
                            
                            final_confidence = (final_confidence + ai_confidence) / 2
                        except Exception as e:
                            logger.debug(f"AI validation error (continuing): {e}")
                    
                    findings.append(RawFinding(
                        type="potential_sql_injection",  # Use same type for injection vulnerabilities
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="critical",
                        confidence=final_confidence,
                        metadata={"issue": description, "vulnerability": "command_injection", "control_id": "SOC2-CC6.1"}
                    ))
                    break  # Only report once per file per pattern
    
    return findings


def _scan_xss_vulnerabilities(root: Path) -> list[RawFinding]:
    """Detect Cross-Site Scripting (XSS) vulnerabilities (unsanitized user input in output)."""
    findings: list[RawFinding] = []
    
    # XSS patterns - unsanitized user input in output
    xss_patterns = [
        # PHP: echo $_GET['input'], echo $_POST['input'], print $_REQUEST['input']
        (r'echo\s+\$_?(?:GET|POST|REQUEST|COOKIE)\[', "XSS: Direct echo of user input without sanitization (PHP)"),
        (r'echo\s+\$_(?:GET|POST|REQUEST|COOKIE)', "XSS: Direct echo of superglobal without sanitization (PHP)"),
        (r'print\s+\$_?(?:GET|POST|REQUEST|COOKIE)\[', "XSS: Direct print of user input without sanitization (PHP)"),
        (r'print\s+\$_(?:GET|POST|REQUEST|COOKIE)', "XSS: Direct print of superglobal without sanitization (PHP)"),
        (r'<\?=\s*\$_?(?:GET|POST|REQUEST|COOKIE)\[', "XSS: Direct output of user input in PHP short tag"),
        (r'<\?=\s*\$_(?:GET|POST|REQUEST|COOKIE)', "XSS: Direct output of superglobal in PHP short tag"),
        # Flask/Jinja2: {{ variable | safe }} - CRITICAL: unsafe filter
        (r'\{\{\s*[^}]+\s*\|\s*safe\s*\}\}', "XSS: Template variable with |safe filter (Flask/Jinja2) - CRITICAL"),
        (r'\{\{\s*[^}]+\s*\|\s*safe\s*\}\}', "XSS: Template variable with |safe filter (Django) - CRITICAL"),
        # Django: {% autoescape off %} or |safe filter
        (r'\{%\s*autoescape\s+off\s*%\}', "XSS: Autoescape disabled in Django template"),
        # Thymeleaf (Java Spring): th:utext - unescaped text (CRITICAL)
        (r'th:utext\s*=\s*["\']?\$\{[^}]+\}', "XSS: Thymeleaf th:utext with unescaped expression (Java Spring) - CRITICAL"),
        (r'th:utext\s*=\s*["\']\{[^}]+\}', "XSS: Thymeleaf th:utext with unescaped expression (Java Spring) - CRITICAL"),
        (r'<[^>]*th:utext\s*=\s*["\']?\$\{[^}]+\}[^>]*>', "XSS: Thymeleaf th:utext attribute with unescaped expression (Java Spring) - CRITICAL"),
        (r'<[^>]*th:utext\s*=\s*["\']\{[^}]+\}[^>]*>', "XSS: Thymeleaf th:utext attribute with unescaped expression (Java Spring) - CRITICAL"),
        # Jinja2: {{ variable }} without escaping (when in unsafe context)
        (r'\{\{\s*[a-zA-Z_]+\s*\}\}(?!.*\|escape)(?!.*\|e)(?!.*\|safe)', "XSS: Jinja2 template variable without explicit escaping"),
        # Thymeleaf: [[${variable}]] - unescaped inline text
        (r'\[\[\$\{[^}]+\}\]\]', "XSS: Thymeleaf unescaped inline expression [[${...}]] (Java Spring)"),
        # Python: print(user_input), {{ user_input }} (templates without safe)
        (r'print\s*\(\s*[a-zA-Z_]+[^)]*\)', "XSS: Direct print of variable (Python)"),
        (r'\{\{\s*[a-zA-Z_]+\s*\}\}(?!.*\|safe)', "XSS: Template variable without escaping (Jinja2/Django)"),
        # JavaScript: document.write(user_input), innerHTML = user_input
        (r'document\.write\s*\(\s*[a-zA-Z_]+', "XSS: Direct document.write() with variable (JavaScript)"),
        (r'\.innerHTML\s*=\s*[a-zA-Z_]+', "XSS: Direct innerHTML assignment with variable (JavaScript)"),
        (r'\.outerHTML\s*=\s*[a-zA-Z_]+', "XSS: Direct outerHTML assignment with variable (JavaScript)"),
        # React: dangerouslySetInnerHTML
        (r'dangerouslySetInnerHTML\s*=\s*\{[^}]*__html', "XSS: dangerouslySetInnerHTML usage (React)"),
        # Flask: Markup() or escape=False
        (r'Markup\s*\([^)]*request\.', "XSS: Markup() with request data (Flask)"),
        (r'escape\s*=\s*False', "XSS: escape=False in template rendering"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".php", ".rb", ".html", ".htm", ".jsp", ".erb", ".java", ".xml"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Skip detector code to avoid false positives
        if _is_detector_code(file_path, content):
            continue
        
        lines = content.splitlines()
        
        # Check for XSS vulnerabilities
        for pattern, description in xss_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    # Skip comments
                    if stripped.startswith(('//', '/*', '*', '#', '--', '<!--')):
                        continue
                    
                    # Skip if this is a pattern definition (not actual usage)
                    if _is_pattern_definition(line, content):
                        continue
                    
                    # Check if sanitization exists nearby (except for |safe which is the vulnerability)
                    if '|safe' not in line.lower():
                        context_start = max(0, line_no - 3)
                        context_end = min(len(lines), line_no + 3)
                        context = '\n'.join(lines[context_start:context_end]).lower()
                        # Skip if sanitization functions are used
                        sanitization_functions = ['htmlspecialchars', 'htmlentities', 'escape', 'sanitize', 'xss', 'filter', 'strip_tags', '|escape', '|e']
                        if any(sf in context for sf in sanitization_functions):
                            continue
                    
                    is_test = "test" in file_path.name.lower()
                    
                    # AI validation for XSS (less aggressive for security issues)
                    final_confidence = 0.85 if not is_test else 0.6
                    if AI_VALIDATION_AVAILABLE:
                        try:
                            context_lines = lines[max(0, line_no-3):min(len(lines), line_no+3)]
                            context = '\n'.join(context_lines)
                            is_valid, ai_confidence, ai_explanation = validate_finding_with_ai(
                                finding_type="xss",
                                snippet=line.strip()[:200],
                                context=context,
                                file_path=str(file_path),
                                line_no=line_no
                            )
                            
                            # For critical security issues like XSS, be less aggressive with filtering
                            # Only filter if AI is very confident it's a false positive
                            if not is_valid and ai_confidence < 0.3:
                                logger.debug(f"AI filtered false positive: {ai_explanation}")
                                continue
                            
                            # Boost confidence if AI confirms it's real
                            if is_valid and ai_confidence > 0.7:
                                final_confidence = min(0.95, (final_confidence + ai_confidence) / 2)
                        except Exception as e:
                            logger.debug(f"AI validation error (continuing): {e}")
                    
                    findings.append(RawFinding(
                        type="potential_sql_injection",  # Use same type for injection vulnerabilities
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=final_confidence,
                        metadata={"issue": description, "vulnerability": "xss", "control_id": "SOC2-CC6.1"}
                    ))
                    break  # Only report once per file per pattern
    
    return findings


def _scan_debug_mode(root: Path) -> list[RawFinding]:
    """Detect DEBUG mode enabled in production code (Flask, Django, etc.)."""
    findings: list[RawFinding] = []
    
    debug_patterns = [
        # Flask - more specific patterns
        (r'app\.config\[["\']DEBUG["\']\]\s*=\s*True', "DEBUG mode enabled in Flask (production risk)"),
        (r'app\.config\[["\']debug["\']\]\s*=\s*True', "DEBUG mode enabled in Flask (lowercase key)"),
        (r'DEBUG\s*=\s*True', "DEBUG mode enabled (Flask/Django)"),
        (r'debug\s*=\s*True', "DEBUG mode enabled (lowercase)"),
        (r'FLASK_ENV\s*=\s*["\']development["\']', "Flask environment set to development"),
        (r'FLASK_DEBUG\s*=\s*1', "Flask DEBUG enabled"),
        (r'FLASK_DEBUG\s*=\s*True', "Flask DEBUG enabled (True)"),
        # Django
        (r'DEBUG\s*=\s*True', "DEBUG mode enabled in Django settings"),
        (r'ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']', "Django ALLOWED_HOSTS set to * (insecure)"),
        # Node.js/Express
        (r'process\.env\.NODE_ENV\s*!=\s*["\']production["\']', "Node.js not in production mode"),
        (r'debug\s*:\s*true', "Debug mode enabled (Express/Node.js)"),
        (r'NODE_ENV\s*=\s*["\']development["\']', "Node.js environment set to development"),
        # General
        (r'environment\s*=\s*["\']dev["\']', "Environment set to development"),
        (r'environment\s*=\s*["\']development["\']', "Environment set to development"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        # Skip detector code
        if _is_detector_code(file_path):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".env", ".config", ".conf"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        for pattern, description in debug_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    # Skip comments
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    # Skip pattern definitions
                    if _is_pattern_definition(line, content):
                        continue
                    # Skip test files
                    if "test" in file_path.name.lower() or "test" in file_path.parts:
                        continue
                    
                    findings.append(RawFinding(
                        type="insecure_configuration",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="medium",
                        confidence=0.9,
                        metadata={"issue": description, "control_id": "SOC2-CC7.2"}
                    ))
                    break
    
    return findings


def _scan_insecure_cookies(root: Path) -> list[RawFinding]:
    """Detect insecure cookie handling (user-controlled values, missing flags)."""
    findings: list[RawFinding] = []
    
    insecure_cookie_patterns = [
        # Flask: set_cookie with user input (improved patterns)
        (r'response\.set_cookie\s*\(\s*["\'][^"\']+["\']\s*,\s*[a-zA-Z_]+', "Insecure cookie: user-controlled value (Flask)"),
        (r'set_cookie\s*\(\s*["\'][^"\']+["\']\s*,\s*request\.', "Insecure cookie: request data in cookie value (Flask)"),
        (r'\.set_cookie\s*\(\s*["\'][^"\']+["\']\s*,\s*[a-zA-Z_]+', "Insecure cookie: user-controlled value (Flask/Django)"),
        # More specific: response.set_cookie('name', name) where name is a variable
        (r'response\.set_cookie\s*\(\s*["\']([^"\']+)["\']\s*,\s*\1\s*\)', "Insecure cookie: cookie name and value are the same variable (Flask)"),
        (r'response\.set_cookie\s*\(\s*["\']([^"\']+)["\']\s*,\s*([a-zA-Z_]+)\s*\)', "Insecure cookie: user-controlled value in cookie (Flask)"),
        # Django: set_cookie with user input
        (r'response\.set_cookie\s*\(\s*["\'][^"\']+["\']\s*,\s*[a-zA-Z_]+', "Insecure cookie: user-controlled value (Django)"),
        # Missing secure flag
        (r'set_cookie\s*\([^)]*\)(?!.*secure\s*=\s*True)', "Cookie set without secure flag (Flask/Django)"),
        (r'set_cookie\s*\([^)]*\)(?!.*httponly\s*=\s*True)', "Cookie set without HttpOnly flag (Flask/Django)"),
        # JavaScript: document.cookie with user input
        (r'document\.cookie\s*=\s*[a-zA-Z_]+', "Insecure cookie: direct assignment to document.cookie (JavaScript)"),
        (r'document\.cookie\s*\+=\s*[a-zA-Z_]+', "Insecure cookie: concatenation to document.cookie (JavaScript)"),
        # Express: res.cookie without secure
        (r'res\.cookie\s*\([^)]*\)(?!.*secure\s*:\s*true)', "Cookie set without secure flag (Express)"),
        (r'res\.cookie\s*\([^)]*\)(?!.*httpOnly\s*:\s*true)', "Cookie set without httpOnly flag (Express)"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        # Skip detector code
        if _is_detector_code(file_path):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".php", ".rb"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        for pattern, description in insecure_cookie_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    # Skip comments
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    # Skip pattern definitions
                    if _is_pattern_definition(line, content):
                        continue
                    # Check context for user input
                    context_start = max(0, line_no - 5)
                    context_end = min(len(lines), line_no + 5)
                    context = '\n'.join(lines[context_start:context_end]).lower()
                    
                    # Only flag if it involves user input (request, GET, POST, etc.)
                    user_input_indicators = ['request.', '$_get', '$_post', 'req.', 'req.query', 'req.body', 'req.params']
                    if not any(indicator in context for indicator in user_input_indicators):
                        # For missing flags, still report but with lower confidence
                        if 'secure' in description.lower() or 'httponly' in description.lower():
                            pass  # Report missing flags
                        else:
                            continue  # Skip if no user input involved
                    
                    findings.append(RawFinding(
                        type="insecure_configuration",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.85,
                        metadata={"issue": description, "control_id": "SOC2-CC6.1"}
                    ))
                    break
    
    return findings


def _is_educational_code(root: Path) -> bool:
    """Determine if repository is educational/vulnerable code (not production)."""
    # Check for common educational repository indicators
    educational_indicators = [
        "vulnerable", "vuln", "demo", "example", "sample", "test", "tutorial",
        "educational", "learning", "practice", "dvwa", "mutillidae", "webgoat",
        "broken", "snippet", "snippets"
    ]
    
    repo_name = root.name.lower()
    if any(indicator in repo_name for indicator in educational_indicators):
        return True
    
    # Check for README indicating educational purpose
    readme_files = ["README.md", "README.txt", "README", "readme.md"]
    for readme_file in readme_files:
        readme_path = root / readme_file
        if readme_path.exists():
            try:
                readme_content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
                educational_keywords = [
                    "educational", "learning", "tutorial", "example", "demo",
                    "vulnerable", "intentionally", "for educational purposes",
                    "practice", "test", "not for production"
                ]
                if any(keyword in readme_content for keyword in educational_keywords):
                    return True
            except Exception:
                pass
    
    return False


# ============================================================================
# INDUSTRY-GRADE SECURITY DETECTIONS
# ============================================================================

def _scan_advanced_secrets(root: Path) -> list[RawFinding]:
    """Detect advanced secrets management issues (JWT secrets, OAuth, session secrets, encryption keys)."""
    findings: list[RawFinding] = []
    
    # JWT secret patterns
    jwt_patterns = [
        (r'JWT_SECRET\s*[:=]\s*["\']([^"\']{10,})["\']', "JWT secret in code"),
        (r'jwt\.encode\([^)]*secret[^)]*["\']([^"\']{10,})["\']', "JWT secret in encode call"),
        (r'jwtSecret\s*[:=]\s*["\']([^"\']{10,})["\']', "JWT secret variable"),
        (r'secret_key\s*[:=]\s*["\']([^"\']{10,})["\']', "JWT/Flask secret key"),
    ]
    
    # OAuth client secrets
    oauth_patterns = [
        (r'client_secret\s*[:=]\s*["\']([^"\']{10,})["\']', "OAuth client secret"),
        (r'CLIENT_SECRET\s*[:=]\s*["\']([^"\']{10,})["\']', "OAuth client secret (env var)"),
        (r'oauth.*secret\s*[:=]\s*["\']([^"\']{10,})["\']', "OAuth secret"),
    ]
    
    # Session secrets
    session_patterns = [
        (r'SESSION_SECRET\s*[:=]\s*["\']([^"\']{10,})["\']', "Session secret"),
        (r'session.*secret\s*[:=]\s*["\']([^"\']{10,})["\']', "Session secret variable"),
        (r'cookie.*secret\s*[:=]\s*["\']([^"\']{10,})["\']', "Cookie secret"),
    ]
    
    # Encryption keys
    encryption_key_patterns = [
        (r'ENCRYPTION_KEY\s*[:=]\s*["\']([^"\']{16,})["\']', "Encryption key"),
        (r'encryption_key\s*[:=]\s*["\']([^"\']{16,})["\']', "Encryption key variable"),
        (r'AES.*key\s*[:=]\s*["\']([^"\']{16,})["\']', "AES encryption key"),
    ]
    
    # API keys in URLs/headers
    api_key_in_url_patterns = [
        (r'api[_-]?key\s*=\s*[^&\s]+', "API key in URL parameter"),
        (r'\?.*api[_-]?key\s*=', "API key in query string"),
        (r'api[_-]?key["\']?\s*:\s*["\']?[^"\']+["\']?', "API key in object/header"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go", ".yaml", ".yml", ".json", ".env"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check JWT secrets
        for pattern, description in jwt_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    if 'example' in line.lower() or 'placeholder' in line.lower():
                        continue
                    
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="critical",
                        confidence=0.9,
                        metadata={"secret_type": "JWT_SECRET", "issue": description}
                    ))
                    break
        
        # Check OAuth secrets
        for pattern, description in oauth_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="critical",
                        confidence=0.9,
                        metadata={"secret_type": "OAUTH_SECRET", "issue": description}
                    ))
                    break
        
        # Check session secrets
        for pattern, description in session_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.85,
                        metadata={"secret_type": "SESSION_SECRET", "issue": description}
                    ))
                    break
        
        # Check encryption keys
        for pattern, description in encryption_key_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="critical",
                        confidence=0.95,
                        metadata={"secret_type": "ENCRYPTION_KEY", "issue": description}
                    ))
                    break
        
        # Check API keys in URLs
        for pattern, description in api_key_in_url_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="api_key_in_url",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.8,
                        metadata={"issue": description}
                    ))
                    break
    
    return findings


def _scan_authentication_security(root: Path) -> list[RawFinding]:
    """Detect authentication and authorization security issues."""
    findings: list[RawFinding] = []
    
    # Missing MFA patterns
    mfa_patterns = [
        (r'@require_auth|@login_required|@authenticated', "Authentication required but no MFA check"),
    ]
    
    # Weak session management
    session_patterns = [
        (r'session\.timeout\s*=\s*0', "Session timeout disabled"),
        (r'session\.cookie\.secure\s*=\s*False', "Session cookie not secure"),
        (r'session\.cookie\.httponly\s*=\s*False', "Session cookie not HttpOnly"),
        (r'session\.cookie\.samesite\s*=\s*["\']?None["\']?', "Session cookie SameSite=None (insecure)"),
    ]
    
    # JWT without expiration
    jwt_patterns = [
        (r'jwt\.encode\([^)]*exp\s*=\s*None', "JWT without expiration"),
        (r'jwt\.encode\([^)]*\)(?!.*exp)', "JWT encode without exp parameter"),
    ]
    
    # Missing CSRF protection
    csrf_patterns = [
        (r'@app\.(post|put|delete|patch)\([^)]*\)(?!.*csrf)', "API endpoint without CSRF protection"),
        (r'csrf_protect\s*=\s*False', "CSRF protection disabled"),
    ]
    
    # Missing rate limiting
    rate_limit_patterns = [
        (r'@app\.(post|put)\([^)]*["\']/login["\']', "Login endpoint without rate limiting"),
        (r'@app\.(post|put)\([^)]*["\']/auth["\']', "Auth endpoint without rate limiting"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for weak session management
        for pattern, description in session_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="weak_authentication",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.85,
                        metadata={"issue": description, "control_id": "SOC2-CC6.1"}
                    ))
                    break
        
        # Check for JWT without expiration
        for pattern, description in jwt_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL):
                findings.append(RawFinding(
                    type="weak_authentication",
                    file=_relative_path(file_path, root),
                    line=None,
                    snippet="JWT token without expiration",
                    severity="high",
                    confidence=0.8,
                    metadata={"issue": description, "control_id": "SOC2-CC6.1"}
                ))
                break
        
        # Check for missing CSRF protection
        for pattern, description in csrf_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(RawFinding(
                    type="weak_authentication",
                    file=_relative_path(file_path, root),
                    line=None,
                    snippet="Missing CSRF protection",
                    severity="medium",
                    confidence=0.75,
                    metadata={"issue": description, "control_id": "SOC2-CC6.1"}
                ))
                break
    
    return findings


def _scan_access_control_issues(root: Path) -> list[RawFinding]:
    """Detect access control and authorization issues."""
    findings: list[RawFinding] = []
    
    # Path traversal patterns - only flag if user input is involved
    path_traversal_patterns = [
        (r'open\([^)]*\.\./', "Path traversal in file open"),
        (r'readFile\([^)]*\.\./', "Path traversal in readFile"),
        (r'File\.ReadAllText\([^)]*\.\./', "Path traversal in ReadAllText"),
        (r'\.\./.*\.\./', "Multiple path traversal sequences"),
    ]
    
    # Normal file operation patterns (should NOT be flagged as ACL issues)
    normal_file_ops = [
        r'with open\([^)]*["\']',  # String literal file paths
        r'read_text\([^)]*["\']',  # String literal paths
        r'Path\([^)]*["\']',  # Path objects with literals
        r'file_path\.read',  # Reading from known file_path variable
        r'package_json.*read',  # Reading package.json
        r'requirements.*read',  # Reading requirements files
    ]
    
    # Missing input validation
    input_validation_patterns = [
        (r'request\.(get|post|args)\[[^]]+\]', "Direct user input without validation"),
        (r'request\.(query|params|body)\[', "Direct request parameter access"),
        (r'\$_GET\[|\$_POST\[|\$_REQUEST\[', "Direct superglobal access (PHP)"),
    ]
    
    # IDOR (Insecure Direct Object Reference)
    idor_patterns = [
        (r'/users/\{user_id\}|/users/\{id\}', "User ID in URL without authorization check"),
        (r'/api/users/\d+', "Direct user ID access in API"),
    ]
    
    # Missing authorization checks
    authz_patterns = [
        (r'if\s*\(.*user.*\)\s*\{[^}]*delete|update|modify', "Operation without role check"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Skip detector code to avoid false positives
        if _is_detector_code(file_path, content):
            continue
        
        # Check for path traversal (only if user input is involved)
        for pattern, description in path_traversal_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    # Skip if it's a normal file operation (not user input)
                    if any(re.search(normal_op, line, re.IGNORECASE) for normal_op in normal_file_ops):
                        continue
                    
                    # Check if path is sanitized
                    if 'os.path.join' in line or 'path.join' in line or 'realpath' in line or 'abspath' in line:
                        continue
                    
                    # Only flag if user input is involved (request, input, argv, etc.)
                    context_start = max(0, line_no - 5)
                    context_end = min(len(lines), line_no + 5)
                    context = '\n'.join(lines[context_start:context_end]).lower()
                    user_input_indicators = ['request.', 'input(', 'argv', 'getenv', '$_get', '$_post', 'req.', 'query', 'params']
                    if not any(indicator in context for indicator in user_input_indicators):
                        # If no user input, it's likely a normal file operation - skip
                        continue
                    
                    findings.append(RawFinding(
                        type="insecure_acl",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.8,
                        metadata={"issue": description, "vulnerability": "path_traversal"}
                    ))
                    break
        
        # Check for missing input validation
        for pattern, description in input_validation_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    # Check if validation exists nearby
                    context = '\n'.join(lines[max(0, line_no-3):min(len(lines), line_no+3)])
                    if any(v in context.lower() for v in ['validate', 'sanitize', 'escape', 'filter']):
                        continue
                    
                    findings.append(RawFinding(
                        type="insecure_acl",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="medium",
                        confidence=0.7,
                        metadata={"issue": description, "vulnerability": "missing_input_validation"}
                    ))
                    break
    
    return findings


def _scan_logging_security(root: Path) -> list[RawFinding]:
    """Detect logging and audit trail security issues."""
    findings: list[RawFinding] = []
    
    # Log injection patterns
    log_injection_patterns = [
        (r'log\.(info|error|warn|debug)\([^)]*\+.*user', "String concatenation in log (log injection risk)"),
        (r'logger\.(info|error|warn)\([^)]*\+', "String concatenation in logger"),
        (r'console\.log\([^)]*\+.*request', "String concatenation in console.log"),
    ]
    
    # Sensitive data in logs
    sensitive_log_patterns = [
        (r'log\.(info|error|warn)\([^)]*password', "Password in log statement"),
        (r'logger\.(info|error|warn)\([^)]*password', "Password in logger statement"),
        (r'console\.log\([^)]*password', "Password in console.log"),
        (r'log\.(info|error|warn)\([^)]*token', "Token in log statement"),
        (r'log\.(info|error|warn)\([^)]*secret', "Secret in log statement"),
        (r'log\.(info|error|warn)\([^)]*credit.*card|cc[_-]?number', "Credit card in log statement"),
        (r'log\.(info|error|warn)\([^)]*ssn|social.*security', "SSN in log statement"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for log injection
        for pattern, description in log_injection_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="missing_logging",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="medium",
                        confidence=0.75,
                        metadata={"issue": description, "vulnerability": "log_injection", "control_id": "SOC2-CC7.2"}
                    ))
                    break
        
        # Check for sensitive data in logs
        for pattern, description in sensitive_log_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="missing_logging",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.85,
                        metadata={"issue": description, "vulnerability": "sensitive_data_in_logs", "control_id": "SOC2-CC7.2"}
                    ))
                    break
    
    return findings


def _scan_encryption_security(root: Path) -> list[RawFinding]:
    """Detect encryption and data handling security issues."""
    findings: list[RawFinding] = []
    
    # Missing encryption at rest
    encryption_at_rest_patterns = [
        (r'storage.*encryption\s*=\s*False', "Storage encryption disabled"),
        (r'encrypt.*at.*rest\s*=\s*False', "Encryption at rest disabled"),
    ]
    
    # Insecure key management
    key_management_patterns = [
        (r'key.*rotation\s*=\s*False', "Key rotation disabled"),
        (r'key.*rotation\s*=\s*None', "Key rotation not configured"),
    ]
    
    # PII in error messages
    pii_patterns = [
        (r'raise.*Exception\([^)]*email', "Email in exception message"),
        (r'throw.*Error\([^)]*email', "Email in error message"),
        (r'error\([^)]*password', "Password in error message"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go", ".yaml", ".yml"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for missing encryption at rest
        for pattern, description in encryption_at_rest_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="weak_encryption",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.85,
                        metadata={"issue": description, "control_id": "GDPR-Article-32"}
                    ))
                    break
        
        # Check for PII in error messages
        for pattern, description in pii_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="weak_encryption",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="medium",
                        confidence=0.75,
                        metadata={"issue": description, "vulnerability": "pii_in_errors", "control_id": "GDPR-Article-32"}
                    ))
                    break
    
    return findings


def _scan_insecure_configurations(root: Path) -> list[RawFinding]:
    """Detect insecure configuration issues."""
    findings: list[RawFinding] = []
    
    # Debug mode in production
    debug_patterns = [
        (r'DEBUG\s*=\s*True', "Debug mode enabled"),
        (r'debug\s*=\s*true', "Debug mode enabled (lowercase)"),
        (r'environment\s*=\s*["\']production["\'].*debug\s*=\s*True', "Debug mode in production"),
    ]
    
    # Missing security headers
    security_header_patterns = [
        (r'X-Frame-Options', "Missing X-Frame-Options header"),
        (r'X-Content-Type-Options', "Missing X-Content-Type-Options header"),
        (r'Strict-Transport-Security', "Missing HSTS header"),
        (r'Content-Security-Policy', "Missing CSP header"),
    ]
    
    # Insecure CORS
    cors_patterns = [
        (r'cors.*origin\s*=\s*["\']\*["\']', "CORS allows all origins"),
        (r'Access-Control-Allow-Origin\s*:\s*\*', "CORS header allows all origins"),
    ]
    
    # Insecure cookies
    cookie_patterns = [
        (r'cookie.*secure\s*=\s*False', "Cookie not marked as secure"),
        (r'cookie.*httponly\s*=\s*False', "Cookie not marked as HttpOnly"),
        (r'session.*cookie.*secure\s*=\s*False', "Session cookie not secure"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        if file_path.suffix not in (".py", ".js", ".ts", ".java", ".cs", ".php", ".rb", ".go", ".yaml", ".yml", ".json", ".conf", ".ini"):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for debug mode
        for pattern, description in debug_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    if 'test' in file_path.name.lower():
                        continue
                    
                    findings.append(RawFinding(
                        type="insecure_acl",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.9,
                        metadata={"issue": description, "vulnerability": "debug_mode_enabled"}
                    ))
                    break
        
        # Check for insecure CORS
        for pattern, description in cors_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="insecure_acl",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="medium",
                        confidence=0.8,
                        metadata={"issue": description, "vulnerability": "insecure_cors"}
                    ))
                    break
        
        # Check for insecure cookies
        for pattern, description in cookie_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="weak_authentication",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.85,
                        metadata={"issue": description, "vulnerability": "insecure_cookies"}
                    ))
                    break
    
    return findings


def _scan_supply_chain_security(root: Path) -> list[RawFinding]:
    """Detect CI/CD and supply chain security issues."""
    findings: list[RawFinding] = []
    
    # CI/CD secrets in code
    cicd_secret_patterns = [
        (r'GITHUB_TOKEN\s*[:=]\s*["\']([^"\']{10,})["\']', "GitHub token in code"),
        (r'CI.*SECRET\s*[:=]\s*["\']([^"\']{10,})["\']', "CI secret in code"),
        (r'pipeline.*secret\s*[:=]\s*["\']([^"\']{10,})["\']', "Pipeline secret in code"),
    ]
    
    # Missing dependency scanning
    dependency_scan_patterns = [
        (r'snyk|dependabot|safety|bandit', "Dependency scanning tool found"),
    ]
    
    # Insecure package registries
    registry_patterns = [
        (r'registry\s*=\s*["\']http://', "Insecure package registry (HTTP)"),
        (r'npm.*registry.*http://', "Insecure npm registry"),
    ]
    
            for file_path in _iter_files(root, ignore_patterns):
        if _should_skip(file_path, ignore_patterns):
            continue
        
        # Check CI/CD files
        if file_path.name not in (".github", ".gitlab-ci.yml", "Jenkinsfile", ".travis.yml", "circle.yml", "azure-pipelines.yml", ".circleci"):
            if file_path.suffix not in (".yaml", ".yml", ".json", ".py", ".js", ".ts"):
                continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Check for CI/CD secrets
        for pattern, description in cicd_secret_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="hardcoded_secret",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="critical",
                        confidence=0.95,
                        metadata={"secret_type": "CI_CD_SECRET", "issue": description}
                    ))
                    break
        
        # Check for insecure package registries
        for pattern, description in registry_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*', '#', '--')):
                        continue
                    
                    findings.append(RawFinding(
                        type="insecure_acl",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="medium",
                        confidence=0.8,
                        metadata={"issue": description, "vulnerability": "insecure_registry"}
                    ))
                    break
    
    return findings


def _scan_frontend_security(root: Path) -> list[RawFinding]:
    """Scan frontend code for security issues (sessionStorage, localStorage, insecure token storage)."""
    findings: list[RawFinding] = []
    
    for file_path in _iter_files(root):
        if _should_skip(file_path):
            continue
        
        # Focus on frontend code files
        if file_path.suffix not in (".js", ".ts", ".jsx", ".tsx", ".vue"):
            continue
        
        # Skip detector code
        if _is_detector_code(file_path):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # Frontend security patterns
        frontend_security_patterns = [
            # Insecure token storage in sessionStorage
            (r'sessionStorage\.setItem\s*\([^)]*token[^)]*\)', "Insecure token storage: tokens in sessionStorage (XSS risk)"),
            (r'sessionStorage\.setItem\s*\([^)]*access[^)]*token[^)]*\)', "Insecure token storage: access tokens in sessionStorage (XSS risk)"),
            (r'sessionStorage\.[^=]+=\s*[a-zA-Z_]*token', "Insecure token storage: tokens assigned to sessionStorage (XSS risk)"),
            # Insecure token storage in localStorage
            (r'localStorage\.setItem\s*\([^)]*token[^)]*\)', "Insecure token storage: tokens in localStorage (XSS risk)"),
            (r'localStorage\.setItem\s*\([^)]*secret[^)]*\)', "Insecure secret storage: secrets in localStorage (XSS risk)"),
            # GitHub token in sessionStorage (specific case from evaluation report)
            (r'sessionStorage\.setItem\s*\([^)]*github[^)]*token[^)]*\)', "Insecure GitHub token storage: tokens in sessionStorage (SOC2-CC6.2, GDPR Article 32)"),
            (r'sessionStorage\.setItem\s*\([^)]*github[^)]*access[^)]*\)', "Insecure GitHub access token storage: tokens in sessionStorage"),
            # Insecure API key storage
            (r'(sessionStorage|localStorage)\.setItem\s*\([^)]*api[^)]*key[^)]*\)', "Insecure API key storage: API keys in browser storage"),
        ]
        
        for pattern, description in frontend_security_patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    stripped = line.strip()
                    if stripped.startswith(('//', '/*', '*')):
                        continue
                    
                    findings.append(RawFinding(
                        type="insecure_secret_storage",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="high",
                        confidence=0.9,
                        metadata={
                            "issue": description,
                            "control_id": "SOC2-CC6.2",
                            "compliance_frameworks": ["SOC2", "GDPR", "PCI-DSS"],
                            "vulnerability_type": "frontend_secret_storage"
                        }
                    ))
                    break  # Only report once per file per pattern
    
    return findings


def _scan_configuration_security(root: Path) -> list[RawFinding]:
    """Scan configuration files for security issues (CORS, database encryption, etc.)."""
    findings: list[RawFinding] = []
    
    config_file_patterns = [
        "docker-compose.yml", "docker-compose.yaml", "compose.yml",
        "settings.py", "config.py", "database.py", ".env", ".env.example"
    ]
    
    for file_path in _iter_files(root):
        if _should_skip(file_path, None):
            continue
        
        # Check config files by name or extension
        is_config_file = file_path.name in config_file_patterns or file_path.suffix in (".env", ".conf", ".config", ".ini")
        
        # Also check Python config files
        if file_path.suffix == ".py" and ("config" in file_path.name.lower() or "settings" in file_path.name.lower() or "database" in file_path.name.lower()):
            is_config_file = True
        
        if not is_config_file:
            continue
        
        # Skip detector code
        if _is_detector_code(file_path):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        lines = content.splitlines()
        
        # CORS configuration issues
        for line_no, line in enumerate(lines, start=1):
            # CORS allowing all origins (wildcard)
            if re.search(r'CORS\([^)]*allow_origins\s*=\s*\[?\s*["\']\*["\']', line, re.IGNORECASE):
                findings.append(RawFinding(
                    type="insecure_configuration",
                    file=_relative_path(file_path, root),
                    line=line_no,
                    snippet=line.strip()[:200],
                    severity="medium",
                    confidence=0.85,
                    metadata={
                        "issue": "CORS allows all origins (wildcard)",
                        "control_id": "SOC2-CC6.1",
                        "compliance_frameworks": ["SOC2"],
                        "vulnerability_type": "cors_misconfiguration"
                    }
                ))
                break
            
            # CORS with hardcoded localhost (development pattern)
            if re.search(r'allow_origins\s*=\s*\[?\s*["\']http://localhost', line, re.IGNORECASE):
                if 'production' not in content.lower() and 'os.getenv' not in content and 'os.environ' not in content:
                    findings.append(RawFinding(
                        type="insecure_configuration",
                        file=_relative_path(file_path, root),
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity="low",
                        confidence=0.7,
                        metadata={
                            "issue": "CORS hardcoded to localhost (should be configurable for production)",
                            "control_id": "SOC2-CC6.1",
                            "compliance_frameworks": ["SOC2"],
                            "vulnerability_type": "cors_misconfiguration",
                            "note": "Acceptable for development but should be configurable"
                        }
                    ))
                    break
        
        # Database encryption check (SQLite without encryption)
        if re.search(r'sqlite:///', content, re.IGNORECASE):
            if 'encrypt' not in content.lower() and 'sqlcipher' not in content.lower():
                findings.append(RawFinding(
                    type="unencrypted_database",
                    file=_relative_path(file_path, root),
                    line=None,
                    snippet="SQLite database configuration without encryption",
                    severity="high",
                    confidence=0.9,
                    metadata={
                        "control_id": "SOC2-CC6.1",
                        "compliance_frameworks": ["GDPR", "SOC2", "HIPAA"],
                        "vulnerability_type": "database_encryption"
                    }
                ))
    
    return findings
