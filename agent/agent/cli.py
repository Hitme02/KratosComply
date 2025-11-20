"""CLI entry-points for the Kratos agent."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import typer

from .config import DEFAULT_KEYSTORE
from .keystore import KeystoreError, generate_keypair, load_public_key_hex, load_signing_key
from .reporting import generate_report
from .signature import sign_report

app = typer.Typer(help="KratosComply agent CLI")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@app.command("generate-key")
def generate_key(
    keystore: str = typer.Option(
        str(DEFAULT_KEYSTORE),
        "--keystore",
        "-k",
        help="Directory where keys should be stored",
    )
) -> None:
    """Generate a deterministic ed25519 keypair."""
    keystore_path = Path(keystore).expanduser()
    priv, pub = generate_keypair(keystore_path)
    typer.echo(f"Private key written to {priv}")
    typer.echo(f"Public key written to {pub}")


@app.command()
def scan(
    path: str = typer.Argument(...),
    output: str = typer.Option(..., "--output", "-o", help="Report destination"),
    keystore: str = typer.Option(
        str(DEFAULT_KEYSTORE),
        "--keystore",
        "-k",
        help="Directory containing priv.key / pub.key",
    ),
    project_name: Optional[str] = typer.Option(
        None, "--project-name", help="Override project.name in the report"
    ),
) -> None:
    """Scan a workspace, build a report, and sign it."""
    path = Path(path).expanduser().resolve()
    output_path = Path(output).expanduser()
    keystore_path = Path(keystore).expanduser()

    if not path.exists():
        raise typer.BadParameter(f"Target path {path} does not exist")
    if not path.is_dir():
        raise typer.BadParameter("Scan target must be a directory")

    try:
        signing_key = load_signing_key(keystore_path)
    except KeystoreError as exc:  # pragma: no cover - CLI feedback
        raise typer.BadParameter(str(exc))
    findings, report = generate_report(path, project_name)
    payload_to_sign = {k: v for k, v in report.items() if k != "agent_signature"}
    signature = sign_report(payload_to_sign, signing_key)
    report["agent_signature"] = signature

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    typer.echo(f"Report written to {output_path}")
    typer.echo(
        f"Findings: {len(findings)} | Merkle root: {report['merkle_root']} | Signature: {signature[:16]}..."
    )


@app.command("public-key")
def public_key(
    keystore: str = typer.Option(
        str(DEFAULT_KEYSTORE),
        "--keystore",
        "-k",
        help="Directory containing keys",
    )
) -> None:
    """Print the stored public key hex string."""
    try:
        key_hex = load_public_key_hex(Path(keystore).expanduser())
    except KeystoreError as exc:  # pragma: no cover - CLI feedback
        raise typer.BadParameter(str(exc))
    typer.echo(key_hex)


def run() -> None:
    """Entry point for `python -m agent.cli`."""
    app()


if __name__ == "__main__":
    run()
