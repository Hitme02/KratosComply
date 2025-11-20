"""Pytest configuration for KratosComply."""
from __future__ import annotations

import sys
from pathlib import Path

SAMPLE_APP_PATH = Path(__file__).resolve().parent / "examples" / "sample-app"

if str(SAMPLE_APP_PATH) not in sys.path:
    sys.path.append(str(SAMPLE_APP_PATH))


