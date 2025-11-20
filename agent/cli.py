"""Compatibility shim for `python -m agent.cli`."""
from __future__ import annotations

from .agent.cli import app, run  # noqa: F401

if __name__ == "__main__":
    run()

