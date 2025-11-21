"""Database utilities for the KratosComply backend."""
from __future__ import annotations

import os
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Support both DATABASE_URL (standard) and KRATOS_DB_URL (legacy)
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("KRATOS_DB_URL", "sqlite:///./kratos.db")

connect_args: dict[str, object] = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
elif DATABASE_URL.startswith("postgresql"):
    # PostgreSQL connection pooling settings
    connect_args = {
        "connect_timeout": 10,
        "application_name": "kratoscomply",
    }

# Configure engine with appropriate pool settings
engine_kwargs: dict[str, object] = {"connect_args": connect_args}
if DATABASE_URL.startswith("postgresql"):
    engine_kwargs.update(
        {
            "pool_size": 5,
            "max_overflow": 10,
            "pool_pre_ping": True,  # Verify connections before using
        }
    )

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope():
    """Context manager used by scripts/tests."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:  # pragma: no cover - defensive
        session.rollback()
        raise
    finally:
        session.close()

