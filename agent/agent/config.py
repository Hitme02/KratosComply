"""Shared configuration constants for the Kratos agent."""
from __future__ import annotations

from pathlib import Path

DEFAULT_KEYSTORE = Path("~/.kratos/keys").expanduser()
PRIVATE_KEY_FILENAME = "priv.key"
PUBLIC_KEY_FILENAME = "pub.key"

SECRET_KEYWORDS = ("PASSWORD", "API_KEY", "TOKEN", "SECRET")
PUBLIC_ACL_MARKER = "public-read"

EXCLUDED_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}
EXCLUDED_FILENAMES = {"aegis-report.json"}
IAC_EXTENSIONS = {".tf", ".tf.json", ".json", ".yaml", ".yml"}
SECRET_TEXT_EXTENSIONS = {".env", ".ini", ".cfg", ".txt", ".json", ".yaml", ".yml"}

AGENT_VERSION = "kratos-agent-demo-0.1"

SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}


