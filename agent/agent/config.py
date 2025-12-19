"""Shared configuration constants for the Kratos agent."""
from __future__ import annotations

from pathlib import Path

DEFAULT_KEYSTORE = Path("~/.kratos/keys").expanduser()
PRIVATE_KEY_FILENAME = "priv.key"
PUBLIC_KEY_FILENAME = "pub.key"

SECRET_KEYWORDS = ("PASSWORD", "API_KEY", "TOKEN", "SECRET", "AUTH", "CREDENTIAL", "PRIVATE_KEY", "ACCESS_KEY")

# Patterns that indicate false positives (config constants, not actual secrets)
FALSE_POSITIVE_PATTERNS = (
    "SECRET_KEYWORDS",
    "SECRETS_MANAGEMENT", 
    "SECRET_REGEX",
    "SECRET_TEXT",
    "SECRET_",
    "TOKEN_",
    "PASSWORD_",
    "API_KEY_",
    "token_normalize",
    "tokenizer",
    "tokenize",
    "tokenized",
    "tokens[",
    "tokens.",
    "nextToken",
    "tmpToken",
    "token = tokens",
    "token = state",
    "Token(",
    "Token(",
)

# Note: REAL_SECRET_PATTERNS removed - using _looks_like_real_secret() function instead
PUBLIC_ACL_MARKER = "public-read"

EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "env", ".env", "node_modules", "__pycache__", 
    ".pytest_cache", "dist", "build", ".tox", ".mypy_cache", ".ruff_cache",
    "site-packages", ".eggs", "*.egg-info", "artifacts", "build-info"
}
EXCLUDED_FILENAMES = {"aegis-report.json", "report.json", "*.pyc", "*.pyo"}
IAC_EXTENSIONS = {".tf", ".tf.json", ".json", ".yaml", ".yml"}
SECRET_TEXT_EXTENSIONS = {".env", ".ini", ".cfg", ".txt", ".json", ".yaml", ".yml"}

AGENT_VERSION = "kratos-comply-agent-1.0.0"

SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}


