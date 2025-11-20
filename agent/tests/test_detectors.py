from __future__ import annotations

from pathlib import Path

from agent.detectors import scan_workspace


def test_python_secret_detector(tmp_path: Path) -> None:
    (tmp_path / "leak.py").write_text(
        "DB_PASSWORD = 'supersecret'\napi_token = 'should flag'\n",
        encoding="utf-8",
    )
    findings = scan_workspace(tmp_path)
    assert any(f.type == "hardcoded_secret" for f in findings)


def test_public_acl_detector(tmp_path: Path) -> None:
    (tmp_path / "bucket.tf").write_text(
        'resource "aws_s3_bucket" "demo" { acl = "public-read" }',
        encoding="utf-8",
    )
    findings = scan_workspace(tmp_path)
    assert any(f.type == "insecure_acl" for f in findings)

