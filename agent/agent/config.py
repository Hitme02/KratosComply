"""Shared configuration constants for the Kratos agent."""
from __future__ import annotations

from pathlib import Path

DEFAULT_KEYSTORE = Path("~/.kratos/keys").expanduser()
PRIVATE_KEY_FILENAME = "priv.key"
PUBLIC_KEY_FILENAME = "pub.key"

SECRET_KEYWORDS = ("PASSWORD", "API_KEY", "TOKEN", "SECRET", "AUTH", "CREDENTIAL", "PRIVATE_KEY", "ACCESS_KEY", "SESSION_KEY", "ENCRYPTION_KEY")

# Cloud provider secret patterns
CLOUD_SECRET_PATTERNS = {
    "aws": [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"aws_secret_access_key\s*[:=]\s*['\"]([^'\"]{40})['\"]", "AWS Secret Access Key"),
        (r"aws_session_token\s*[:=]\s*['\"]([^'\"]+)['\"]", "AWS Session Token"),
    ],
    "gcp": [
        (r"AIza[0-9A-Za-z_-]{35}", "GCP API Key"),
        (r'"type"\s*:\s*"service_account"', "GCP Service Account JSON"),
    ],
    "azure": [
        (r"DefaultEndpointsProtocol=https;AccountName=([^;]+);AccountKey=([^;]+)", "Azure Storage Account Key"),
    ],
    "github": [
        (r"ghp_[0-9A-Za-z]{36}", "GitHub Personal Access Token"),
        (r"github_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59}", "GitHub Fine-grained PAT"),
    ],
    "stripe": [
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key"),
        (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key"),
    ],
    "slack": [
        (r"xoxb-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}", "Slack Bot Token"),
        (r"xoxa-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}", "Slack App Token"),
    ],
}

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


