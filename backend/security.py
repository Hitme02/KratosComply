"""Cryptographic helpers shared by backend endpoints."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Iterable

from nacl import signing


def canonical_json(data: Any) -> str:
    """Return deterministic JSON for signing and verification."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify_signature(payload: Any, signature_hex: str, public_key_hex: str) -> bool:
    """Return True if the ed25519 signature matches the payload."""
    try:
        verify_key = signing.VerifyKey(bytes.fromhex(public_key_hex))
        verify_key.verify(canonical_json(payload).encode("utf-8"), bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False


def build_merkle_root(leaves: Iterable[str]) -> str:
    """Recompute the deterministic Merkle root for the provided hex leaves."""
    leaf_bytes = []
    for leaf in leaves:
        try:
            leaf_bytes.append(bytes.fromhex(leaf))
        except ValueError:
            raise ValueError(f"Invalid evidence hash: {leaf}") from None
    if not leaf_bytes:
        return sha256(b"").hexdigest()
    nodes = list(leaf_bytes)
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [
            sha256(left + right).digest()
            for left, right in zip(nodes[0::2], nodes[1::2])
        ]
    return nodes[0].hex()

