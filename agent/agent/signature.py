"\"\"\"Signing helpers for Kratos reports.\"\"\""
from __future__ import annotations

import json
from typing import Any

from nacl import signing


def canonical_json(data: Any) -> str:
    """Return a canonical JSON string with sorted keys."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_report(payload: dict[str, Any], signing_key: signing.SigningKey) -> str:
    """Sign the canonical JSON serialization of ``payload``."""
    canonical = canonical_json(payload)
    signature = signing_key.sign(canonical.encode("utf-8"))
    return signature.signature.hex()


def verify_report(payload: dict[str, Any], signature_hex: str, public_key_hex: str) -> bool:
    """Verify that ``signature_hex`` matches ``payload`` with the provided public key."""
    verify_key = signing.VerifyKey(bytes.fromhex(public_key_hex))
    canonical = canonical_json(payload).encode("utf-8")
    try:
        verify_key.verify(canonical, bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False


