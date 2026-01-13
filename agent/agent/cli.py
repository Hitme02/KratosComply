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
    workers: int = typer.Option(
        4,
        "--workers",
        "-w",
        help="Number of parallel workers for file scanning (default: 4)",
    ),
    progress: bool = typer.Option(
        False,
        "--progress",
        "-p",
        help="Show progress indicators during scan",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format: json, csv, or html (default: json)",
    ),
) -> None:
    """Scan a workspace, build a report, and sign it."""
    import time
    scan_start = time.time()
    
    path = Path(path).expanduser().resolve()
    output_path = Path(output).expanduser()
    keystore_path = Path(keystore).expanduser()

    if not path.exists():
        raise typer.BadParameter(f"Target path {path} does not exist")
    if not path.is_dir():
        raise typer.BadParameter("Scan target must be a directory")
    
    if format not in ("json", "csv", "html"):
        raise typer.BadParameter(f"Invalid format: {format}. Must be json, csv, or html")

    try:
        signing_key = load_signing_key(keystore_path)
    except KeystoreError as exc:  # pragma: no cover - CLI feedback
        raise typer.BadParameter(str(exc))
    
    # Pass workers and progress to scan_workspace
    from .detectors import scan_workspace
    raw_findings = scan_workspace(path, max_workers=workers, show_progress=progress)
    
    # Generate report with raw findings
    findings, raw_lookup, report = generate_report(path, project_name, raw_findings=raw_findings)
    payload_to_sign = {k: v for k, v in report.items() if k != "agent_signature"}
    signature = sign_report(payload_to_sign, signing_key)
    report["agent_signature"] = signature
    
    # Add scan statistics to report
    scan_time = time.time() - scan_start
    report["scan_statistics"] = {
        "total_findings": len(findings),
        "scan_duration_seconds": round(scan_time, 2),
        "workers_used": workers,
        "files_scanned": len(raw_findings) if raw_findings else 0,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Export in requested format
    if format == "json":
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    elif format == "csv":
        _export_csv(findings, output_path)
    elif format == "html":
        _export_html(findings, report, output_path)
    
    typer.echo(f"Report written to {output_path} ({format.upper()})")
    typer.echo(
        f"Findings: {len(findings)} | Merkle root: {report['merkle_root']} | Signature: {signature[:16]}... | Time: {scan_time:.2f}s"
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


def _export_csv(findings: list, output_path: Path) -> None:
    """Export findings to CSV format."""
    import csv
    from .findings import Finding
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID", "Type", "File", "Line", "Severity", "Confidence", 
            "Control ID", "Control Category", "Compliance Frameworks"
        ])
        
        for finding in findings:
            if isinstance(finding, Finding):
                writer.writerow([
                    finding.id,
                    finding.type,
                    finding.file,
                    finding.line or "",
                    finding.severity,
                    finding.confidence,
                    finding.control_id,
                    finding.control_category,
                    ", ".join(finding.compliance_frameworks_affected),
                ])


def _export_html(findings: list, report: dict, output_path: Path) -> None:
    """Export findings to HTML format."""
    from .findings import Finding
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>KratosComply Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .stats {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
    </style>
</head>
<body>
    <h1>KratosComply Compliance Scan Report</h1>
    <div class="stats">
        <h2>Scan Statistics</h2>
        <p><strong>Total Findings:</strong> {len(findings)}</p>
        <p><strong>Scan Duration:</strong> {report.get('scan_statistics', {}).get('scan_duration_seconds', 'N/A')}s</p>
        <p><strong>Merkle Root:</strong> <code>{report.get('merkle_root', 'N/A')}</code></p>
        <p><strong>Signature:</strong> <code>{report.get('agent_signature', 'N/A')[:32]}...</code></p>
    </div>
    <h2>Findings</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Type</th>
            <th>File</th>
            <th>Line</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Control ID</th>
            <th>Frameworks</th>
        </tr>
"""
    
    for finding in findings:
        if isinstance(finding, Finding):
            severity_class = finding.severity.lower()
            html += f"""
        <tr>
            <td>{finding.id}</td>
            <td>{finding.type}</td>
            <td>{finding.file}</td>
            <td>{finding.line or ""}</td>
            <td class="{severity_class}">{finding.severity}</td>
            <td>{finding.confidence:.2f}</td>
            <td>{finding.control_id}</td>
            <td>{", ".join(finding.compliance_frameworks_affected)}</td>
        </tr>
"""
    
    html += """
    </table>
</body>
</html>
"""
    
    output_path.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    run()
