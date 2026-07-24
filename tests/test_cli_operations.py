from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.change_risk import classify_patch_risk
from rygnal.cli import build_parser
from rygnal.local_runtime import (
    LocalRuntimeDependencies,
    create_local_runtime_dependencies,
)
from rygnal.patch_approval import (
    create_patch_approval_request,
)
from rygnal.patch_artifact import bind_artifact_to_approval
from rygnal.patch_diff import generate_patch_diff


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def create_repo(path: Path) -> Path:
    path.mkdir()

    git(path, "init")
    git(path, "config", "user.email", "cli@example.com")
    git(path, "config", "user.name", "CLI Test")

    (path / "docs").mkdir()
    (path / "docs" / "usage.md").write_text(
        "before\n",
        encoding="utf-8",
    )

    git(path, "add", ".")
    git(path, "commit", "-m", "baseline")

    return path


def seed_pending(
    tmp_path: Path,
) -> tuple[
    LocalRuntimeDependencies,
    Path,
    str,
    str,
]:
    data_dir = tmp_path / "data"
    dependencies = create_local_runtime_dependencies(data_dir=data_dir)

    baseline = create_repo(tmp_path / "baseline")
    trusted = tmp_path / "trusted"
    workspace = tmp_path / "workspace"

    shutil.copytree(baseline, trusted)
    shutil.copytree(baseline, workspace)

    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "cli-approved"\n',
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        workspace,
        git(workspace, "rev-parse", "HEAD"),
    )
    risk = classify_patch_risk(patch)
    gate = evaluate_guarded_change_gate(
        patch,
        risk_report=risk,
    )
    request = create_patch_approval_request(
        patch,
        requested_by="agent_user",
        agent_id="agent",
        environment="test",
        risk_report=risk,
        gate_decision=gate,
        trace_id="trace-cli-operations",
    )
    artifact = dependencies.artifact_store.persist(
        patch_diff=patch,
        run_id="run-cli-operations",
        trace_id="trace-cli-operations",
        approval_request=request,
        trusted_repo_path=trusted,
        risk_report=risk,
    )
    bound = bind_artifact_to_approval(
        request,
        artifact,
    )
    dependencies.approval_queue.submit(bound)

    return (
        dependencies,
        trusted,
        bound.approval_id,
        artifact.artifact_id,
    )


def run_cli(
    *args: str,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            ("from rygnal.cli import main; raise SystemExit(main())"),
            *args,
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def test_parser_registers_operational_commands() -> None:
    parser = build_parser()

    approvals = parser.parse_args(["approvals", "list", "--json"])
    artifacts = parser.parse_args(
        [
            "artifacts",
            "apply",
            "artifact-id",
            "--repo",
            ".",
        ]
    )

    assert approvals.approval_command == "list"
    assert artifacts.artifact_command == "apply"


def test_cli_lists_and_inspects_pending_approval(
    tmp_path: Path,
) -> None:
    dependencies, _trusted, approval_id, artifact_id = seed_pending(tmp_path)

    listed = run_cli(
        "approvals",
        "list",
        "--json",
        "--data-dir",
        str(dependencies.paths.root),
        cwd=tmp_path,
    )
    shown = run_cli(
        "artifacts",
        "show",
        artifact_id,
        "--json",
        "--data-dir",
        str(dependencies.paths.root),
        cwd=tmp_path,
    )

    assert listed.returncode == 0, listed.stderr
    assert shown.returncode == 0, shown.stderr

    list_payload = json.loads(listed.stdout)
    show_payload = json.loads(shown.stdout)

    assert list_payload["returned_count"] == 1
    assert list_payload["approvals"][0]["approval"]["approval_id"] == approval_id
    assert show_payload["artifact"]["artifact_id"] == artifact_id
    assert "diff --git" not in listed.stdout
    assert "cli-approved" not in shown.stdout


def test_cli_approve_and_apply_end_to_end(
    tmp_path: Path,
) -> None:
    dependencies, trusted, approval_id, artifact_id = seed_pending(tmp_path)

    approved = run_cli(
        "approvals",
        "approve",
        approval_id,
        "--decided-by",
        "security_reviewer",
        "--reason",
        "Reviewed through the operational CLI.",
        "--json",
        "--data-dir",
        str(dependencies.paths.root),
        cwd=tmp_path,
    )

    assert approved.returncode == 0, approved.stderr
    assert json.loads(approved.stdout)["approval"]["status"] == "approved"

    applied = run_cli(
        "artifacts",
        "apply",
        artifact_id,
        "--repo",
        str(trusted),
        "--json",
        "--data-dir",
        str(dependencies.paths.root),
        cwd=tmp_path,
    )

    assert applied.returncode == 0, applied.stderr
    assert json.loads(applied.stdout)["applied"] is True
    assert (trusted / "pyproject.toml").read_text(
        encoding="utf-8"
    ) == '[project]\nname = "cli-approved"\n'


def test_cli_rejected_artifact_cannot_apply(
    tmp_path: Path,
) -> None:
    dependencies, trusted, approval_id, artifact_id = seed_pending(tmp_path)

    rejected = run_cli(
        "approvals",
        "reject",
        approval_id,
        "--decided-by",
        "security_reviewer",
        "--reason",
        "Rejected through the operational CLI.",
        "--json",
        "--data-dir",
        str(dependencies.paths.root),
        cwd=tmp_path,
    )

    assert rejected.returncode == 0, rejected.stderr

    applied = run_cli(
        "artifacts",
        "apply",
        artifact_id,
        "--repo",
        str(trusted),
        "--json",
        "--data-dir",
        str(dependencies.paths.root),
        cwd=tmp_path,
    )

    assert applied.returncode == 1
    assert "status is 'rejected'" in applied.stderr
    assert not (trusted / "pyproject.toml").exists()
