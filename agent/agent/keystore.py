"""Key management utilities for the Kratos agent."""
from __future__ import annotations

from pathlib import Path
import os
import stat

from nacl import signing

from .config import PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME


class KeystoreError(RuntimeError):
    """Raised when key operations fail."""


def generate_keypair(directory: Path) -> tuple[Path, Path]:
    """Generate an ed25519 keypair and persist it under ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    signing_key = signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    priv_path = directory / PRIVATE_KEY_FILENAME
    pub_path = directory / PUBLIC_KEY_FILENAME

    priv_path.write_text(signing_key.encode().hex(), encoding="utf-8")
    pub_path.write_text(verify_key.encode().hex(), encoding="utf-8")

    _lock_down_permissions(priv_path)
    _lock_down_permissions(pub_path)

    return priv_path, pub_path


def load_signing_key(directory: Path) -> signing.SigningKey:
    """Load the signing key from ``directory``."""
    priv_path = directory / PRIVATE_KEY_FILENAME
    if not priv_path.exists():
        raise KeystoreError(
            f"Private key not found at {priv_path}. "
            "Run `kratos generate-key` first."
        )
    data = priv_path.read_text(encoding="utf-8").strip()
    try:
        signing_key = signing.SigningKey(bytes.fromhex(data))
    except Exception as exc:  # pragma: no cover - defensive
        raise KeystoreError(f"Invalid key material in {priv_path}") from exc
    return signing_key


def load_public_key_hex(directory: Path) -> str:
    """Return the stored public key hex string."""
    pub_path = directory / PUBLIC_KEY_FILENAME
    if not pub_path.exists():
        raise KeystoreError(
            f"Public key not found at {pub_path}. "
            "Run `kratos generate-key` first."
        )
    return pub_path.read_text(encoding="utf-8").strip()


def _lock_down_permissions(path: Path) -> None:
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


