"""Compatibility shim to expose the packaged `agent` module at repo root."""
from __future__ import annotations

from importlib import import_module
import sys
from typing import Iterable

_INNER_PACKAGE = import_module(".agent", __name__)


def _export_all() -> None:
    inner_all: Iterable[str] = getattr(_INNER_PACKAGE, "__all__", ())
    globals().update({name: getattr(_INNER_PACKAGE, name) for name in inner_all})


def _expose_submodules() -> None:
    module_names = (
        "cli",
        "config",
        "detectors",
        "findings",
        "keystore",
        "merkle",
        "reporting",
        "signature",
    )
    for name in module_names:
        sys.modules[f"{__name__}.{name}"] = import_module(f".agent.{name}", __name__)


_export_all()
_expose_submodules()

