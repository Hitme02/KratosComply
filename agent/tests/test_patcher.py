from __future__ import annotations

from pathlib import Path

from agent.findings import Finding, RawFinding
from agent.patcher import PatchManager


def _workspace_with_test(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "module.py").write_text(
        'DB_PASSWORD = "supersecret"\n', encoding="utf-8"
    )
    tests_dir = workspace / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_dummy.py").write_text(
        "def test_dummy():\n    assert True\n", encoding="utf-8"
    )
    return workspace


def test_patch_manager_generates_safe_patch(tmp_path: Path) -> None:
    workspace = _workspace_with_test(tmp_path)
    finding = Finding(
        id="F001",
        type="hardcoded_secret",
        file="module.py",
        line=1,
        snippet='DB_PASSWORD = "supersecret"',
        severity="high",
        confidence=0.98,
        evidence_hash="0" * 64,
    )
    raw = RawFinding(
        type="hardcoded_secret",
        file="module.py",
        line=1,
        snippet='DB_PASSWORD = "supersecret"',
        severity="high",
        confidence=0.98,
        metadata={"var_name": "DB_PASSWORD", "literal": "supersecret"},
    )
    manager = PatchManager(workspace, workspace / "patches")
    results = manager.generate([finding], {"F001": raw})

    assert results
    patch_file = results[0].patch_path
    assert patch_file.exists()
    contents = patch_file.read_text(encoding="utf-8")
    assert "os.getenv('DB_PASSWORD'" in contents
    assert results[0].safe

