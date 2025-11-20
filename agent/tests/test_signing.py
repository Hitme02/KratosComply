from __future__ import annotations

from pathlib import Path

from agent.keystore import generate_keypair, load_public_key_hex, load_signing_key
from agent.signature import sign_report, verify_report


def test_sign_and_verify_roundtrip(tmp_path: Path) -> None:
    generate_keypair(tmp_path)
    signing_key = load_signing_key(tmp_path)
    public_key_hex = load_public_key_hex(tmp_path)

    payload = {"project": "demo", "value": 42}
    signature = sign_report(payload, signing_key)

    assert verify_report(payload, signature, public_key_hex)

