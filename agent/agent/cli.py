"""CLI entry-points for the Kratos agent."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import typer

from .config import DEFAULT_KEYSTORE
from .keystore import KeystoreError, generate_keypair, load_public_key_hex, load_signing_key
from .patch_ops import PatchApplicationError, apply_patch_file
from .patcher import PatchManager
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
    generate_patches: bool = typer.Option(
        False,
        "--generate-patches",
        help="Generate auto-fix patches for supported findings",
    ),
    patches_dir: Optional[str] = typer.Option(
        None,
        "--patches-dir",
        help="Directory to store generated patch diffs (defaults to <path>/patches)",
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
    findings, raw_lookup, report = generate_report(path, project_name)
    payload_to_sign = {k: v for k, v in report.items() if k != "agent_signature"}
    signature = sign_report(payload_to_sign, signing_key)
    report["agent_signature"] = signature

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    typer.echo(f"Report written to {output_path}")
    typer.echo(
        f"Findings: {len(findings)} | Merkle root: {report['merkle_root']} | Signature: {signature[:16]}..."
    )
    if generate_patches:
        patches_path = Path(patches_dir).expanduser() if patches_dir else path / "patches"
        manager = PatchManager(path, patches_path)
        results = manager.generate(findings, raw_lookup)
        for result in results:
            status = "safe" if result.safe else "unsafe"
            typer.echo(f"Patch {result.patch_path.name} [{status}]")
        if not results:
            typer.echo("No auto-fixable findings detected; no patches generated.")


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


@app.command("apply-patch")
def apply_patch_cmd(
    patch_file: str = typer.Argument(..., help="Path to the diff file produced by kratos"),
    workspace: str = typer.Option(
        ...,
        "--workspace",
        "-w",
        help="Workspace root where the patch should be applied",
    ),
) -> None:
    """Apply a generated patch to a workspace."""
    patch_path = Path(patch_file).expanduser()
    workspace_path = Path(workspace).expanduser()
    try:
        success, log = apply_patch_file(patch_path, workspace_path)
    except PatchApplicationError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(log.strip())
    if not success:
        raise typer.Exit(code=1)


def run() -> None:
    """Entry point for `python -m agent.cli`."""
    app()


if __name__ == "__main__":
    run()
