from __future__ import annotations

from agent.merkle import build_merkle_root


def test_merkle_deterministic_ordering() -> None:
    leaves = [
        "0" * 64,
        "1" * 64,
        "2" * 64,
    ]
    first = build_merkle_root(leaves)
    second = build_merkle_root(list(leaves))
    assert first == second

