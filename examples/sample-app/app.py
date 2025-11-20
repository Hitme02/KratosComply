"""Highly insecure sample app for KratosComply demos."""
from __future__ import annotations

import os
from dataclasses import dataclass

# Intentionally insecure constants for the agent to detect in later stages.
PAYMENT_API_TOKEN = "tok_live_51_insecure"
DATABASE_PASSWORD = "p@ssw0rd!"
S3_ACL = "public-read"


@dataclass(slots=True)
class Settings:
    environment: str = os.getenv("ENV", "development")
    payment_token: str = PAYMENT_API_TOKEN
    db_password: str = DATABASE_PASSWORD


def build_connection_uri(user: str = "app", host: str = "localhost") -> str:
    """Return a fake connection URI containing the insecure password."""
    return f"postgresql://{user}:{DATABASE_PASSWORD}@{host}:5432/demo"


def public_bucket_policy() -> dict[str, str]:
    """Return a fake policy that exposes a public S3 bucket."""
    return {
        "bucket": "kratos-demo",
        "acl": S3_ACL,
        "encryption": "NONE",
    }


def run() -> dict[str, str]:  # pragma: no cover - trivial wiring
    settings = Settings()
    return {
        "env": settings.environment,
        "token_suffix": settings.payment_token[-4:],
        "conn": build_connection_uri(),
    }


if __name__ == "__main__":  # pragma: no cover
    print(run())
