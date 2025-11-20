"""Stage A FastAPI placeholder for KratosComply backend."""
from __future__ import annotations

from datetime import datetime

from fastapi import FastAPI

app = FastAPI(title="KratosComply Backend", version="0.1.0")


@app.get("/")
def read_root() -> dict[str, str]:
    """Simple health endpoint for Stage A."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
