"""Shared configuration constants for the Kratos agent."""
from __future__ import annotations

from pathlib import Path

DEFAULT_KEYSTORE = Path("~/.kratos/keys").expanduser()
PRIVATE_KEY_FILENAME = "priv.key"
PUBLIC_KEY_FILENAME = "pub.key"

SECRET_KEYWORDS = ("PASSWORD", "API_KEY", "TOKEN", "SECRET", "AUTH", "CREDENTIAL", "PRIVATE_KEY", "ACCESS_KEY", "SESSION_KEY", "ENCRYPTION_KEY")

# Cloud provider secret patterns - Industry-grade comprehensive coverage
CLOUD_SECRET_PATTERNS = {
    "aws": [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"aws_secret_access_key\s*[:=]\s*['\"]([^'\"]{40})['\"]", "AWS Secret Access Key"),
        (r"aws_session_token\s*[:=]\s*['\"]([^'\"]+)['\"]", "AWS Session Token"),
        (r"AWS_ACCESS_KEY_ID\s*[:=]\s*['\"]([^'\"]+)['\"]", "AWS Access Key ID (env var)"),
        (r"AWS_SECRET_ACCESS_KEY\s*[:=]\s*['\"]([^'\"]{40})['\"]", "AWS Secret Access Key (env var)"),
        (r"AKIAIOSFODNN7EXAMPLE", "AWS Example Access Key (should be replaced)"),
        (r"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS Example Secret Key (should be replaced)"),
    ],
    "gcp": [
        (r"AIza[0-9A-Za-z_-]{35}", "GCP API Key"),
        (r'"type"\s*:\s*"service_account"', "GCP Service Account JSON"),
        (r'"private_key"\s*:\s*"-----BEGIN', "GCP Service Account Private Key"),
        (r'"client_email"\s*:\s*"([^"]+@[^"]+\.iam\.gserviceaccount\.com)"', "GCP Service Account Email"),
        (r"GOOGLE_APPLICATION_CREDENTIALS\s*[:=]\s*['\"]([^'\"]+)['\"]", "GCP Credentials Path"),
    ],
    "azure": [
        (r"DefaultEndpointsProtocol=https;AccountName=([^;]+);AccountKey=([^;]+)", "Azure Storage Account Key"),
        (r"AZURE_STORAGE_KEY\s*[:=]\s*['\"]([^'\"]+)['\"]", "Azure Storage Key (env var)"),
        (r"AccountKey=([^;]+)", "Azure Account Key"),
        (r"AZURE_CLIENT_SECRET\s*[:=]\s*['\"]([^'\"]+)['\"]", "Azure Client Secret"),
    ],
    "github": [
        (r"ghp_[0-9A-Za-z]{36}", "GitHub Personal Access Token"),
        (r"github_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59}", "GitHub Fine-grained PAT"),
        (r"gho_[0-9A-Za-z]{36}", "GitHub OAuth Token"),
        (r"ghu_[0-9A-Za-z]{36}", "GitHub User-to-Server Token"),
        (r"ghs_[0-9A-Za-z]{36}", "GitHub Server-to-Server Token"),
        (r"ghr_[0-9A-Za-z]{36}", "GitHub Refresh Token"),
        (r"GITHUB_TOKEN\s*[:=]\s*['\"]([^'\"]+)['\"]", "GitHub Token (env var)"),
    ],
    "stripe": [
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key"),
        (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key"),
        (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key"),
        (r"pk_test_[0-9a-zA-Z]{24,}", "Stripe Test Publishable Key"),
        (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key"),
    ],
    "slack": [
        (r"xoxb-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}", "Slack Bot Token"),
        (r"xoxa-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}", "Slack App Token"),
        (r"xoxp-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}", "Slack User Token"),
        (r"xoxs-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}", "Slack Workspace Token"),
    ],
    "datadog": [
        (r"dd_api_key\s*[:=]\s*['\"]([^'\"]{32})['\"]", "Datadog API Key"),
        (r"DD_API_KEY\s*[:=]\s*['\"]([^'\"]{32})['\"]", "Datadog API Key (env var)"),
    ],
    "sendgrid": [
        (r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}", "SendGrid API Key"),
        (r"SENDGRID_API_KEY\s*[:=]\s*['\"]([^'\"]+)['\"]", "SendGrid API Key (env var)"),
    ],
    "twilio": [
        (r"SK[0-9a-f]{32}", "Twilio API Key"),
        (r"AC[0-9a-f]{32}", "Twilio Account SID"),
        (r"TWILIO_AUTH_TOKEN\s*[:=]\s*['\"]([^'\"]+)['\"]", "Twilio Auth Token"),
    ],
    "mailgun": [
        (r"key-[0-9a-f]{32}", "Mailgun API Key"),
        (r"MAILGUN_API_KEY\s*[:=]\s*['\"]([^'\"]+)['\"]", "Mailgun API Key (env var)"),
    ],
    "paypal": [
        (r"access_token\$production\$[0-9a-z]{32}\$[0-9a-f]{32}", "PayPal Access Token"),
    ],
    "square": [
        (r"sq0atp-[0-9A-Za-z_-]{22}", "Square Access Token"),
        (r"sq0csp-[0-9A-Za-z_-]{43}", "Square Application Secret"),
    ],
    "heroku": [
        (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "Heroku API Key"),
    ],
    "digitalocean": [
        (r"dop_v1_[0-9a-f]{64}", "DigitalOcean Personal Access Token"),
    ],
    "mongodb": [
        (r"mongodb\+srv://[^:]+:([^@]+)@", "MongoDB Connection String with Password"),
    ],
    "redis": [
        (r"redis://:[^@]+@", "Redis Connection String with Password"),
    ],
    "postgres": [
        (r"postgres://[^:]+:([^@]+)@", "PostgreSQL Connection String with Password"),
        (r"postgresql://[^:]+:([^@]+)@", "PostgreSQL Connection String with Password"),
    ],
    "mysql": [
        (r"mysql://[^:]+:([^@]+)@", "MySQL Connection String with Password"),
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
    "site-packages", ".eggs", "*.egg-info", "artifacts", "build-info",
    ".next", ".nuxt", ".cache", "coverage", ".coverage", ".nyc_output",
    "target", "bin", "obj", ".idea", ".vscode", ".vs", ".gradle", ".mvn"
}
EXCLUDED_FILENAMES = {"aegis-report.json", "report.json", "*.pyc", "*.pyo", "*.class", "*.o", "*.so", "*.dylib"}
IAC_EXTENSIONS = {".tf", ".tf.json", ".json", ".yaml", ".yml", ".hcl", ".tfvars"}
SECRET_TEXT_EXTENSIONS = {".env", ".ini", ".cfg", ".conf", ".txt", ".json", ".yaml", ".yml", ".properties", ".toml", ".config"}

AGENT_VERSION = "kratos-comply-agent-2.7.0"  # Enhanced AI: 500+ patterns, top-k ensemble matching, improved generalization

SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}


