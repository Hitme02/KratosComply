"""Deterministic SHA256 Merkle tree builder."""
from __future__ import annotations

from hashlib import sha256
from typing import Iterable


def build_merkle_root(leaves: Iterable[str]) -> str:
    """Return the Merkle root for the provided hex leaves."""
    leaf_list = list(leaves)
    if not leaf_list:
        return sha256(b"").hexdigest()

    nodes = [bytes.fromhex(leaf) for leaf in leaf_list]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        paired: list[bytes] = []
        for left, right in zip(nodes[0::2], nodes[1::2]):
            paired.append(sha256(left + right).digest())
        nodes = paired
    return nodes[0].hex()


