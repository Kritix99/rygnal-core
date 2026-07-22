from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.change_risk import classify_patch_risk
from rygnal.local_app import create_local_app
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
    git(path, "config", "user.email", "api@example.com")
    git(path, "config", "user.name", "API Test")

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
    *,
    token: str = "operator-secret",
):
    data_dir = tmp_path / "data"
    app = create_local_app(
        data_dir=data_dir,
        environ={
            "RYGNAL_OPERATOR_TOKEN": token,
        },
    )
    dependencies = app.state.rygnal_local_dependencies

    baseline = create_repo(tmp_path / "baseline")
    trusted = tmp_path / "trusted"
    workspace = tmp_path / "workspace"

    shutil.copytree(baseline, trusted)
    shutil.copytree(baseline, workspace)

    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "api-approved"\n',
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
        trace_id="trace-api-operations",
    )
    artifact = dependencies.artifact_store.persist(
        patch_diff=patch,
        run_id="run-api-operations",
        trace_id="trace-api-operations",
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
        app,
        trusted,
        bound.approval_id,
        artifact.artifact_id,
        token,
    )


def test_patch_operation_api_lists_without_raw_patch(
    tmp_path: Path,
) -> None:
    app, _trusted, approval_id, artifact_id, _token = seed_pending(tmp_path)

    with TestClient(app) as client:
        listed = client.get("/v1/patch-approvals")
        shown = client.get(f"/v1/patch-artifacts/{artifact_id}")

    assert listed.status_code == 200
    assert shown.status_code == 200

    listed_payload = listed.json()
    shown_payload = shown.json()

    assert listed_payload["returned_count"] == 1
    assert listed_payload["approvals"][0]["approval"]["approval_id"] == approval_id
    assert shown_payload["artifact"]["artifact_id"] == artifact_id
    assert "diff --git" not in listed.text
    assert "api-approved" not in shown.text


def test_patch_operation_api_requires_operator_token(
    tmp_path: Path,
) -> None:
    app, _trusted, approval_id, _artifact_id, token = seed_pending(tmp_path)

    with TestClient(app) as client:
        missing = client.post(
            f"/v1/patch-approvals/{approval_id}/approve",
            json={
                "decided_by": "security_reviewer",
                "reason": "Reviewed.",
            },
        )
        wrong = client.post(
            f"/v1/patch-approvals/{approval_id}/approve",
            headers={
                "x-rygnal-operator-token": "wrong",
            },
            json={
                "decided_by": "security_reviewer",
                "reason": "Reviewed.",
            },
        )
        valid = client.post(
            f"/v1/patch-approvals/{approval_id}/approve",
            headers={
                "x-rygnal-operator-token": token,
            },
            json={
                "decided_by": "security_reviewer",
                "reason": "Reviewed.",
            },
        )

    assert missing.status_code == 403
    assert wrong.status_code == 403
    assert valid.status_code == 200
    assert valid.json()["approval"]["status"] == "approved"


def test_patch_operation_api_approve_and_apply(
    tmp_path: Path,
) -> None:
    app, trusted, approval_id, artifact_id, token = seed_pending(tmp_path)
    headers = {
        "x-rygnal-operator-token": token,
    }

    with TestClient(app) as client:
        approved = client.post(
            f"/v1/patch-approvals/{approval_id}/approve",
            headers=headers,
            json={
                "decided_by": "security_reviewer",
                "reason": "Approved for API application.",
            },
        )
        applied = client.post(
            f"/v1/patch-artifacts/{artifact_id}/apply",
            headers=headers,
            json={
                "target_repo_path": str(trusted),
            },
        )

    assert approved.status_code == 200
    assert applied.status_code == 200
    assert applied.json()["applied"] is True
    assert (trusted / "pyproject.toml").read_text(
        encoding="utf-8"
    ) == '[project]\nname = "api-approved"\n'


def test_patch_operation_api_reject_blocks_apply(
    tmp_path: Path,
) -> None:
    app, trusted, approval_id, artifact_id, token = seed_pending(tmp_path)
    headers = {
        "x-rygnal-operator-token": token,
    }

    with TestClient(app) as client:
        rejected = client.post(
            f"/v1/patch-approvals/{approval_id}/reject",
            headers=headers,
            json={
                "decided_by": "security_reviewer",
                "reason": "Rejected after review.",
            },
        )
        applied = client.post(
            f"/v1/patch-artifacts/{artifact_id}/apply",
            headers=headers,
            json={
                "target_repo_path": str(trusted),
            },
        )

    assert rejected.status_code == 200
    assert applied.status_code == 409
    assert not (trusted / "pyproject.toml").exists()
