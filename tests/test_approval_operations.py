from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from rygnal.approval_queue import (
    ApprovalDeniedError,
    SQLiteApprovalQueue,
)
from rygnal.approval_receipt import ReceiptStatus, verify_approval_receipt
from rygnal.approval_service import (
    ApprovalArtifactService,
    ApprovalOperationError,
    ApprovalOperationStateError,
)
from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.change_risk import classify_patch_risk
from rygnal.models import ApprovalStatus
from rygnal.patch_approval import create_patch_approval_request
from rygnal.patch_artifact import (
    PATCH_ARTIFACT_STATE_CONSUMED,
    PatchArtifactStore,
    bind_artifact_to_approval,
)
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
    git(path, "config", "user.email", "ops@example.com")
    git(path, "config", "user.name", "Operations Test")

    (path / "docs").mkdir()
    (path / "docs" / "usage.md").write_text(
        "before\n",
        encoding="utf-8",
    )

    git(path, "add", ".")
    git(path, "commit", "-m", "baseline")

    return path


def pending_service(
    tmp_path: Path,
    *,
    requested_by: str = "agent_user",
):
    baseline = create_repo(tmp_path / "baseline")
    trusted = tmp_path / "trusted"
    workspace = tmp_path / "workspace"

    shutil.copytree(baseline, trusted)
    shutil.copytree(baseline, workspace)

    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "approved-change"\n',
        encoding="utf-8",
    )

    baseline_sha = git(workspace, "rev-parse", "HEAD")
    patch = generate_patch_diff(workspace, baseline_sha)
    risk = classify_patch_risk(patch)
    gate = evaluate_guarded_change_gate(
        patch,
        risk_report=risk,
    )

    request = create_patch_approval_request(
        patch,
        requested_by=requested_by,
        agent_id="agent",
        environment="test",
        risk_report=risk,
        gate_decision=gate,
        trace_id="trace-operations",
    )

    artifact_store = PatchArtifactStore(tmp_path / "artifacts")
    artifact = artifact_store.persist(
        patch_diff=patch,
        run_id="run-operations",
        trace_id="trace-operations",
        approval_request=request,
        trusted_repo_path=trusted,
        risk_report=risk,
    )

    bound_request = bind_artifact_to_approval(
        request,
        artifact,
    )

    queue_path = tmp_path / "approvals.db"
    queue = SQLiteApprovalQueue(queue_path)
    queue.submit(bound_request)

    logger = AuditLogger(tmp_path / "audit.jsonl")
    service = ApprovalArtifactService(
        approval_queue=queue,
        artifact_store=artifact_store,
        audit_logger=logger,
    )

    return {
        "service": service,
        "queue": queue,
        "queue_path": queue_path,
        "store": artifact_store,
        "artifact": artifact,
        "request": bound_request,
        "trusted": trusted,
        "logger": logger,
    }


def test_signed_approval_decision_persists_across_restart(
    tmp_path: Path,
) -> None:
    fixture = pending_service(tmp_path)
    service = fixture["service"]
    request = fixture["request"]

    view = service.approve(
        request.approval_id,
        decided_by="security_reviewer",
        reason="Reviewed and approved.",
    )

    assert view.approval_status == "approved"
    assert view.decision_status == "approved"

    reopened = SQLiteApprovalQueue(fixture["queue_path"])
    queued = reopened.get(request.approval_id)

    assert queued.status == ApprovalStatus.APPROVED
    assert queued.decision is not None
    assert (
        verify_approval_receipt(
            queued.request,
            queued.decision,
        )
        == ReceiptStatus.VALID
    )


def test_approval_view_never_contains_raw_patch(
    tmp_path: Path,
) -> None:
    fixture = pending_service(tmp_path)
    view = fixture["service"].inspect_approval(fixture["request"].approval_id)

    payload = json.dumps(
        view.to_dict(),
        sort_keys=True,
    )

    assert view.artifact_state == "pending"
    assert view.patch_sha256
    assert view.changed_file_count == 1
    assert "diff --git" not in payload
    assert "approved-change" not in payload


def test_approve_then_apply_consumes_artifact(
    tmp_path: Path,
) -> None:
    fixture = pending_service(tmp_path)
    service = fixture["service"]
    request = fixture["request"]
    artifact = fixture["artifact"]
    trusted = fixture["trusted"]

    service.approve(
        request.approval_id,
        decided_by="security_reviewer",
        reason="Approved for trusted application.",
    )

    result = service.apply_artifact(
        artifact.artifact_id,
        trusted,
    )

    assert result.applied is True
    assert (trusted / "pyproject.toml").read_text(
        encoding="utf-8"
    ) == '[project]\nname = "approved-change"\n'

    consumed = fixture["store"].load(
        artifact.artifact_id,
        allow_consumed=True,
    )

    assert consumed.state == PATCH_ARTIFACT_STATE_CONSUMED
    assert consumed.consumed_at is not None

    with pytest.raises(
        ApprovalOperationError,
        match="already been consumed",
    ):
        service.apply_artifact(
            artifact.artifact_id,
            trusted,
        )


def test_rejected_approval_cannot_apply_artifact(
    tmp_path: Path,
) -> None:
    fixture = pending_service(tmp_path)
    service = fixture["service"]
    request = fixture["request"]
    artifact = fixture["artifact"]
    trusted = fixture["trusted"]

    view = service.reject(
        request.approval_id,
        decided_by="security_reviewer",
        reason="Rejected after review.",
    )

    assert view.approval_status == "rejected"

    with pytest.raises(
        ApprovalOperationStateError,
        match="status is 'rejected'",
    ):
        service.apply_artifact(
            artifact.artifact_id,
            trusted,
        )

    assert not (trusted / "pyproject.toml").exists()
    assert (
        git(
            trusted,
            "status",
            "--porcelain",
            "--untracked-files=all",
        )
        == ""
    )


def test_self_approval_remains_denied(
    tmp_path: Path,
) -> None:
    fixture = pending_service(
        tmp_path,
        requested_by="agent_user",
    )

    with pytest.raises(
        ApprovalOperationError,
        match="own approval request",
    ):
        fixture["service"].approve(
            fixture["request"].approval_id,
            decided_by="agent_user",
            reason="Self approval attempt.",
        )

    queued = fixture["queue"].get(fixture["request"].approval_id)

    assert queued.status == ApprovalStatus.PENDING
    assert queued.decision is None


def test_queue_record_decision_rejects_unauthorized_decision(
    tmp_path: Path,
) -> None:
    fixture = pending_service(
        tmp_path,
        requested_by="agent_user",
    )
    queue = fixture["queue"]
    request = fixture["request"]

    from rygnal.patch_approval import approve_patch_request

    decision = approve_patch_request(
        request,
        decided_by="agent_user",
        patch_sha256=fixture["artifact"].patch_sha256,
    )

    with pytest.raises(ApprovalDeniedError):
        queue.record_decision(
            request.approval_id,
            approval_decision=decision,
        )
