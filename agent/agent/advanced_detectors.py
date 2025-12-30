"""Advanced compliance detection techniques using AST, dependency analysis, and more.

This module implements improved detection techniques that are more accurate
than simple keyword searches.
"""
from __future__ import annotations

import ast
import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def detect_consent_via_dependencies(root: Path) -> bool:
    """Detect consent handling via installed packages/libraries.
    
    Checks for known compliance libraries that provide consent features:
    - supabase (has built-in GDPR/consent features)
    - auth0 (has consent management)
    - privacy-policy libraries
    """
    # Check package.json
    package_json = root / "package.json"
    if package_json.exists():
        try:
            with open(package_json, "r") as f:
                data = json.load(f)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                
                # Known compliance libraries
                compliance_libs = [
                    "supabase", "auth0", "@supabase/supabase-js",
                    "privacy-policy", "consent-manager", "cookie-consent",
                    "@segment/consent-manager", "react-cookie-consent"
                ]
                
                for lib in compliance_libs:
                    if lib.lower() in [k.lower() for k in deps.keys()]:
                        logger.debug(f"Found compliance library: {lib}")
                        return True
        except Exception:
            pass
    
    # Check requirements.txt
    requirements_files = [
        root / "requirements.txt",
        root / "requirements-dev.txt",
        root / "pyproject.toml",
        root / "Pipfile",
    ]
    
    for req_file in requirements_files:
        if req_file.exists():
            try:
                content = req_file.read_text(encoding="utf-8", errors="ignore").lower()
                compliance_packages = [
                    "supabase", "auth0", "privacy", "consent", "gdpr"
                ]
                for pkg in compliance_packages:
                    if pkg in content:
                        logger.debug(f"Found compliance package in {req_file.name}: {pkg}")
                        return True
            except Exception:
                continue
    
    return False


def detect_consent_via_api_routes(root: Path) -> bool:
    """Detect consent handling via API routes/endpoints.
    
    Looks for:
    - /api/consent, /consent, /user/consent
    - POST /consent, GET /consent
    """
    route_patterns = [
        r'@(?:app|router|api)\.(?:route|get|post|put|delete|patch)\(["\']([^"\']*consent[^"\']*)["\']',
        r'@(?:app|router|api)\.(?:route|get|post|put|delete|patch)\(["\']([^"\']*\/consent[^"\']*)["\']',
        r'router\.(?:get|post|put|delete|patch)\(["\']([^"\']*consent[^"\']*)["\']',
        r'express\.(?:get|post|put|delete)\(["\']([^"\']*consent[^"\']*)["\']',
    ]
    
    for file_path in root.rglob("*.py"):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for pattern in route_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    logger.debug(f"Found consent route in {file_path}")
                    return True
        except Exception:
            continue
    
    # Check JavaScript/TypeScript files
    for file_path in list(root.rglob("*.js")) + list(root.rglob("*.ts")) + list(root.rglob("*.jsx")) + list(root.rglob("*.tsx")):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for pattern in route_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    logger.debug(f"Found consent route in {file_path}")
                    return True
        except Exception:
            continue
    
    return False


def detect_consent_via_ast(root: Path) -> bool:
    """Detect consent handling via AST analysis of function calls.
    
    Looks for:
    - Function calls: consent_handler(), check_consent(), validate_consent()
    - Decorators: @require_consent, @consent_required
    - Imports: from consent_lib import, import consent_manager
    """
    for file_path in root.rglob("*.py"):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue
        
        for node in ast.walk(tree):
            # Check function calls
            if isinstance(node, ast.Call):
                func_name = _get_function_name(node)
                if func_name and any(pattern in func_name.lower() for pattern in 
                                     ["consent", "check_consent", "validate_consent", "require_consent"]):
                    logger.debug(f"Found consent function call in {file_path}: {func_name}")
                    return True
            
            # Check decorators
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    decorator_name = _get_decorator_name(decorator)
                    if decorator_name and "consent" in decorator_name.lower():
                        logger.debug(f"Found consent decorator in {file_path}: {decorator_name}")
                        return True
            
            # Check imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "consent" in alias.name.lower():
                        logger.debug(f"Found consent import in {file_path}: {alias.name}")
                        return True
            
            if isinstance(node, ast.ImportFrom):
                if node.module and "consent" in node.module.lower():
                    logger.debug(f"Found consent import from {file_path}: {node.module}")
                    return True
    
    return False


def detect_consent_via_database_schema(root: Path) -> bool:
    """Detect consent handling via database schema.
    
    Looks for:
    - consent table/column
    - user_consent table
    - migration files with consent
    """
    # Check SQL files
    for file_path in root.rglob("*.sql"):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules"]):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
            if any(pattern in content for pattern in [
                "create table consent",
                "create table user_consent",
                "alter table.*consent",
                "consent boolean",
                "consent timestamp"
            ]):
                logger.debug(f"Found consent in database schema: {file_path}")
                return True
        except Exception:
            continue
    
    # Check migration files
    for file_path in root.rglob("*migration*.py"):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules"]):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
            if "consent" in content and any(keyword in content for keyword in ["table", "column", "model"]):
                logger.debug(f"Found consent in migration: {file_path}")
                return True
        except Exception:
            continue
    
    return False


def detect_data_portability_via_api_routes(root: Path) -> bool:
    """Detect data portability via API routes.
    
    Looks for:
    - /api/export, /export-data, /api/user/data/export
    - GET /export, POST /export
    """
    route_patterns = [
        r'@(?:app|router|api)\.(?:route|get|post)\(["\']([^"\']*(?:export|download.*data|data.*export)[^"\']*)["\']',
        r'router\.(?:get|post)\(["\']([^"\']*(?:export|download.*data)[^"\']*)["\']',
        r'express\.(?:get|post)\(["\']([^"\']*(?:export|download.*data)[^"\']*)["\']',
    ]
    
    for file_path in list(root.rglob("*.py")) + list(root.rglob("*.js")) + list(root.rglob("*.ts")):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for pattern in route_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    route = match.group(1) if match.lastindex else ""
                    if any(keyword in route.lower() for keyword in ["export", "download", "portability"]):
                        logger.debug(f"Found data export route in {file_path}: {route}")
                        return True
        except Exception:
            continue
    
    return False


def detect_data_portability_via_ast(root: Path) -> bool:
    """Detect data portability via AST analysis.
    
    Looks for:
    - Function calls: export_user_data(), download_data(), get_user_data()
    """
    for file_path in root.rglob("*.py"):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = _get_function_name(node)
                if func_name and any(pattern in func_name.lower() for pattern in 
                                     ["export", "download_data", "get_user_data", "data_portability"]):
                    logger.debug(f"Found data export function in {file_path}: {func_name}")
                    return True
    
    return False


def detect_access_logging_via_ast(root: Path) -> bool:
    """Detect access logging via AST analysis.
    
    Looks for:
    - Logging calls: logger.info(), log_access(), audit_log()
    - Decorators: @log_access, @audit_trail
    - Middleware: AuditMiddleware, LoggingMiddleware
    """
    for file_path in root.rglob("*.py"):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue
        
        for node in ast.walk(tree):
            # Check logging function calls
            if isinstance(node, ast.Call):
                func_name = _get_function_name(node)
                if func_name and any(pattern in func_name.lower() for pattern in 
                                     ["log", "audit", "log_access", "audit_log"]):
                    # Check if it's in a context that suggests access logging
                    if any(keyword in source[max(0, node.lineno-5):node.lineno].lower() 
                           for keyword in ["access", "user", "request", "api"]):
                        logger.debug(f"Found access logging call in {file_path}: {func_name}")
                        return True
            
            # Check decorators
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    decorator_name = _get_decorator_name(decorator)
                    if decorator_name and any(pattern in decorator_name.lower() 
                                            for pattern in ["log", "audit", "track"]):
                        logger.debug(f"Found logging decorator in {file_path}: {decorator_name}")
                        return True
            
            # Check middleware classes
            if isinstance(node, ast.ClassDef):
                if any(pattern in node.name.lower() for pattern in ["middleware", "logger", "audit"]):
                    logger.debug(f"Found logging middleware in {file_path}: {node.name}")
                    return True
    
    return False


def detect_access_logging_via_config(root: Path) -> bool:
    """Detect access logging via configuration files.
    
    Looks for:
    - logging.enabled = true
    - access_log = true
    - audit_logging = enabled
    """
    config_patterns = [
        r'logging\.(?:enabled|enable)\s*[:=]\s*(?:true|True|1|yes|enabled)',
        r'access.*log.*(?:enabled|enable)\s*[:=]\s*(?:true|True|1|yes|enabled)',
        r'audit.*log.*(?:enabled|enable)\s*[:=]\s*(?:true|True|1|yes|enabled)',
        r'ENABLE.*LOG.*=.*true',
        r'ACCESS_LOG.*=.*true',
    ]
    
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        # Check config files
        if file_path.suffix in [".yaml", ".yml", ".json", ".toml", ".env", ".conf", ".config"]:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for pattern in config_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        logger.debug(f"Found logging config in {file_path}")
                        return True
            except Exception:
                continue
    
    return False


def detect_retention_via_config(root: Path) -> bool:
    """Detect data retention via configuration files.
    
    Looks for:
    - retention.days = 90
    - data_retention = 365
    - retention_policy = {...}
    """
    retention_patterns = [
        r'retention.*(?:days|period)\s*[:=]\s*(\d+)',
        r'data.*retention.*(?:days|period)\s*[:=]\s*(\d+)',
        r'retention.*policy',
        r'DATA_RETENTION.*=.*\d+',
    ]
    
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        if file_path.suffix in [".yaml", ".yml", ".json", ".toml", ".env", ".conf", ".config", ".py"]:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for pattern in retention_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        logger.debug(f"Found retention config in {file_path}")
                        return True
            except Exception:
                continue
    
    return False


def detect_right_to_erasure_via_api_routes(root: Path) -> bool:
    """Detect right to erasure via API routes.
    
    Looks for:
    - /api/delete, /api/user/delete, /api/erase
    - DELETE /user, DELETE /account
    """
    route_patterns = [
        r'@(?:app|router|api)\.(?:route|delete|post)\(["\']([^"\']*(?:delete|erase|remove.*user|forget)[^"\']*)["\']',
        r'router\.(?:delete|post)\(["\']([^"\']*(?:delete|erase|remove)[^"\']*)["\']',
        r'express\.(?:delete|post)\(["\']([^"\']*(?:delete|erase)[^"\']*)["\']',
    ]
    
    for file_path in list(root.rglob("*.py")) + list(root.rglob("*.js")) + list(root.rglob("*.ts")):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for pattern in route_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    route = match.group(1) if match.lastindex else ""
                    if any(keyword in route.lower() for keyword in ["delete", "erase", "remove", "forget"]):
                        # Check if it's user-related
                        if any(keyword in route.lower() for keyword in ["user", "account", "data", "profile"]):
                            logger.debug(f"Found erasure route in {file_path}: {route}")
                            return True
        except Exception:
            continue
    
    return False


def detect_right_to_erasure_via_ast(root: Path) -> bool:
    """Detect right to erasure via AST analysis.
    
    Looks for:
    - Function calls: delete_user_data(), erase_user(), remove_personal_data()
    """
    for file_path in root.rglob("*.py"):
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = _get_function_name(node)
                if func_name and any(pattern in func_name.lower() for pattern in 
                                     ["delete", "erase", "remove", "forget"]):
                    # Check if it's user/data related
                    if any(keyword in func_name.lower() for keyword in ["user", "data", "personal"]):
                        logger.debug(f"Found erasure function in {file_path}: {func_name}")
                        return True
    
    return False


def detect_encryption_via_dependencies(root: Path) -> bool:
    """Detect encryption via installed packages.
    
    Checks for encryption libraries:
    - cryptography, pycryptodome, bcrypt
    - crypto libraries in package.json
    """
    # Check Python requirements
    requirements_files = [
        root / "requirements.txt",
        root / "pyproject.toml",
        root / "Pipfile",
    ]
    
    for req_file in requirements_files:
        if req_file.exists():
            try:
                content = req_file.read_text(encoding="utf-8", errors="ignore").lower()
                encryption_packages = [
                    "cryptography", "pycryptodome", "bcrypt", "crypto", "encrypt"
                ]
                for pkg in encryption_packages:
                    if pkg in content:
                        logger.debug(f"Found encryption package in {req_file.name}: {pkg}")
                        return True
            except Exception:
                continue
    
    # Check package.json
    package_json = root / "package.json"
    if package_json.exists():
        try:
            with open(package_json, "r") as f:
                data = json.load(f)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                
                encryption_libs = [
                    "crypto", "crypto-js", "bcrypt", "bcryptjs", "encrypt", "tls"
                ]
                
                for lib in encryption_libs:
                    if lib.lower() in [k.lower() for k in deps.keys()]:
                        logger.debug(f"Found encryption library: {lib}")
                        return True
        except Exception:
            pass
    
    return False


def detect_encryption_via_config(root: Path) -> bool:
    """Detect encryption via configuration files.
    
    Looks for:
    - encryption.enabled = true
    - ssl = true, tls = true
    - https = true
    """
    encryption_patterns = [
        r'encryption.*(?:enabled|enable)\s*[:=]\s*(?:true|True|1|yes|enabled)',
        r'(?:ssl|tls|https).*(?:enabled|enable)\s*[:=]\s*(?:true|True|1|yes|enabled)',
        r'ENCRYPTION.*=.*true',
        r'SSL.*=.*true',
        r'TLS.*=.*true',
    ]
    
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        
        if any(excluded in str(file_path) for excluded in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        
        if file_path.suffix in [".yaml", ".yml", ".json", ".toml", ".env", ".conf", ".config"]:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for pattern in encryption_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        logger.debug(f"Found encryption config in {file_path}")
                        return True
            except Exception:
                continue
    
    return False


# Helper functions
def _get_function_name(node: ast.Call) -> str | None:
    """Extract function name from AST Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _get_decorator_name(node: ast.expr) -> str | None:
    """Extract decorator name from AST expression."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return node.attr
    elif isinstance(node, ast.Call):
        return _get_function_name(node)
    return None

