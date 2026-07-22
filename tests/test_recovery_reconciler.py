from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from rygnal.approval_queue import SQLiteApprovalQueue
from rygnal.approval_service import ApprovalArtifactService
from rygnal.approved_apply import apply_approved_patch
from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.change_risk import classify_patch_risk
from rygnal.models import ApprovalStatus
from rygnal.patch_approval import (
    create_patch_approval_request,
)
from rygnal.patch_artifact import (
    PATCH_ARTIFACT_STATE_CONSUMED,
    PATCH_ARTIFACT_STATE_PENDING,
    PatchArtifactStore,
    bind_artifact_to_approval,
)
from rygnal.patch_diff import generate_patch_diff
from rygnal.recovery_reconciler import (
    ARTIFACT_LOCK_SCHEMA,
    RecoveryFindingStatus,
    RecoveryReconciler,
)
from rygnal.recovery_session import (
    CleanupStatus,
    RecoverySessionConfig,
    create_recovery_session,
    destroy_recovery_session,
)


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def create_repo(path: Path) -> Path:
    path.mkdir()

    git(path, "init")
    git(path, "config", "user.email", "recovery@example.com")
    git(path, "config", "user.name", "Recovery Test")

    (path / "docs").mkdir()
    (path / "docs" / "usage.md").write_text(
        "before\n",
        encoding="utf-8",
    )

    git(path, "add", ".")
    git(path, "commit", "-m", "baseline")

    return path


def empty_reconciler(
    tmp_path: Path,
) -> tuple[
    RecoveryReconciler,
    ApprovalArtifactService,
    AuditLogger,
    Path,
]:
    run_root = tmp_path / "runs"
    store = PatchArtifactStore(tmp_path / "artifacts")
    queue = SQLiteApprovalQueue(tmp_path / "approvals.db")
    logger = AuditLogger(tmp_path / "audit.jsonl")
    service = ApprovalArtifactService(
        approval_queue=queue,
        artifact_store=store,
        audit_logger=logger,
    )

    return (
        RecoveryReconciler(
            run_root=run_root,
            approval_service=service,
            audit_logger=logger,
        ),
        service,
        logger,
        run_root,
    )


def pending_artifact(
    tmp_path: Path,
    *,
    ttl_seconds: int = 3600,
    submit: bool = True,
):
    reconciler, service, logger, run_root = empty_reconciler(tmp_path)

    baseline = create_repo(tmp_path / "baseline")
    trusted = tmp_path / "trusted"
    workspace = tmp_path / "workspace"

    shutil.copytree(baseline, trusted)
    shutil.copytree(baseline, workspace)

    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "recovered"\n',
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
        trace_id="trace-recovery",
    )
    artifact = service.artifact_store.persist(
        patch_diff=patch,
        run_id="run-recovery",
        trace_id="trace-recovery",
        approval_request=request,
        trusted_repo_path=trusted,
        risk_report=risk,
        ttl_seconds=ttl_seconds,
    )
    bound = bind_artifact_to_approval(
        request,
        artifact,
    )

    if submit:
        service.approval_queue.submit(bound)

    return {
        "reconciler": reconciler,
        "service": service,
        "logger": logger,
        "run_root": run_root,
        "trusted": trusted,
        "artifact": artifact,
        "request": bound,
    }


def test_recovers_registered_owned_worktree(
    tmp_path: Path,
) -> None:
    reconciler, _service, logger, run_root = empty_reconciler(tmp_path)
    trusted = create_repo(tmp_path / "trusted")

    config = RecoverySessionConfig(
        trusted_repo_path=trusted,
        rygnal_run_root=run_root,
        audit_logger=logger,
    )
    session = create_recovery_session(config)

    assert session.workspace_path.exists()
    assert session.workspace_path.as_posix() in git(
        trusted,
        "worktree",
        "list",
        "--porcelain",
    )

    report = reconciler.reconcile(trace_id="recover-worktree")

    assert report.unresolved_count == 0
    assert report.mutated_count == 1
    assert not session.workspace_path.exists()
    assert session.workspace_path.as_posix() not in git(
        trusted,
        "worktree",
        "list",
        "--porcelain",
    )
    assert logger.verify_integrity() is True


def test_invalid_owner_marker_is_never_deleted(
    tmp_path: Path,
) -> None:
    reconciler, _service, logger, run_root = empty_reconciler(tmp_path)
    trusted = create_repo(tmp_path / "trusted")
    config = RecoverySessionConfig(
        trusted_repo_path=trusted,
        rygnal_run_root=run_root,
        audit_logger=logger,
    )
    session = create_recovery_session(config)
    marker = session.workspace_path.parent / ".rygnal-owner"
    original = marker.read_text(encoding="utf-8")
    marker.write_text(
        "schema=forged\n",
        encoding="utf-8",
    )

    try:
        report = reconciler.reconcile(trace_id="invalid-marker")

        assert report.unresolved_count == 1
        assert report.mutated_count == 0
        assert session.workspace_path.exists()
        assert marker.exists()
    finally:
        marker.write_text(
            original,
            encoding="utf-8",
        )
        cleanup = destroy_recovery_session(
            session,
            config,
        )
        assert cleanup.status in {
            CleanupStatus.CLEANED_GIT,
            CleanupStatus.CLEANED_FALLBACK,
        }


def test_stale_guarded_lock_removed_active_retained(
    tmp_path: Path,
) -> None:
    reconciler, _service, _logger, run_root = empty_reconciler(tmp_path)
    trusted = create_repo(tmp_path / "trusted")
    lock_root = run_root / ".rygnal-locks"
    lock_root.mkdir(parents=True)

    stale = lock_root / "stale.lock"
    stale.write_text(
        "pid=99999999\n"
        "trace_id=stale\n"
        f"trusted_repo_path={trusted}\n"
        "lock_identity=stale\n"
        "created_at_unix=1\n",
        encoding="utf-8",
    )

    active = lock_root / "active.lock"
    active.write_text(
        f"pid={os.getpid()}\n"
        "trace_id=active\n"
        f"trusted_repo_path={trusted}\n"
        "lock_identity=active\n"
        f"created_at_unix={time.time()}\n",
        encoding="utf-8",
    )

    try:
        report = reconciler.reconcile(trace_id="locks")

        assert not stale.exists()
        assert active.exists()
        assert any(
            item.identifier == "stale" and item.status == RecoveryFindingStatus.RECOVERED
            for item in report.findings
        )
        assert any(
            item.identifier == "active" and item.status == RecoveryFindingStatus.ACTIVE
            for item in report.findings
        )
    finally:
        active.unlink(missing_ok=True)


def test_stale_artifact_lock_is_recovered(
    tmp_path: Path,
) -> None:
    reconciler, service, _logger, _run_root = empty_reconciler(tmp_path)
    artifact_id = "deadbeef"
    lock_path = service.artifact_store.root / f".{artifact_id}.lock"
    lock_path.write_text(
        f"schema={ARTIFACT_LOCK_SCHEMA}\n"
        "pid=99999999\n"
        f"artifact_id={artifact_id}\n"
        "created_at_unix=1\n",
        encoding="utf-8",
    )

    report = reconciler.reconcile(trace_id="artifact-lock")

    assert not lock_path.exists()
    assert any(
        item.kind == "artifact_lock" and item.status == RecoveryFindingStatus.RECOVERED
        for item in report.findings
    )


def test_orphan_artifact_is_quarantined_idempotently(
    tmp_path: Path,
) -> None:
    fixture = pending_artifact(
        tmp_path,
        submit=False,
    )
    reconciler = fixture["reconciler"]
    artifact = fixture["artifact"]
    source = fixture["service"].artifact_store.root / f"{artifact.artifact_id}.json"

    first = reconciler.reconcile(trace_id="orphan-first")

    quarantine = fixture["service"].artifact_store.root / "quarantine" / source.name

    assert first.mutated_count == 1
    assert not source.exists()
    assert quarantine.exists()

    second = reconciler.reconcile(trace_id="orphan-second")

    assert second.mutated_count == 0
    assert quarantine.exists()


def test_interrupted_apply_is_marked_consumed(
    tmp_path: Path,
) -> None:
    fixture = pending_artifact(tmp_path)
    service = fixture["service"]
    artifact = fixture["artifact"]
    request = fixture["request"]
    trusted = fixture["trusted"]
    logger = fixture["logger"]

    service.approve(
        request.approval_id,
        decided_by="security_reviewer",
        reason="Approved before simulated crash.",
    )
    queued = service.approval_queue.get(request.approval_id)
    assert queued.decision is not None

    apply_approved_patch(
        artifact.to_patch_diff(),
        trusted,
        approval_request=queued.request,
        approval_decision=queued.decision,
        risk_report=artifact.to_risk_report(),
        logger=logger,
    )

    pending = service.artifact_store.load(
        artifact.artifact_id,
        allow_consumed=True,
    )
    assert pending.state == PATCH_ARTIFACT_STATE_PENDING

    report = fixture["reconciler"].reconcile(trace_id="interrupted-apply")

    recovered = service.artifact_store.load(
        artifact.artifact_id,
        allow_consumed=True,
    )

    assert recovered.state == PATCH_ARTIFACT_STATE_CONSUMED
    assert report.mutated_count == 1
    assert any(item.status == RecoveryFindingStatus.MARKED_CONSUMED for item in report.findings)

    second = fixture["reconciler"].reconcile(trace_id="interrupted-apply-second")
    assert second.mutated_count == 0


def test_expired_pending_approval_is_rejected(
    tmp_path: Path,
) -> None:
    fixture = pending_artifact(
        tmp_path,
        ttl_seconds=1,
    )

    time.sleep(1.1)

    report = fixture["reconciler"].reconcile(trace_id="expired")
    queued = fixture["service"].approval_queue.get(fixture["request"].approval_id)

    assert queued.status == ApprovalStatus.REJECTED
    assert report.mutated_count == 1
    assert any(item.status == RecoveryFindingStatus.EXPIRED_REJECTED for item in report.findings)
    assert fixture["logger"].verify_integrity() is True


def test_active_guarded_lock_preserves_registered_worktree(
    tmp_path: Path,
) -> None:
    reconciler, _service, logger, run_root = empty_reconciler(tmp_path)
    trusted = create_repo(tmp_path / "trusted")
    config = RecoverySessionConfig(
        trusted_repo_path=trusted,
        rygnal_run_root=run_root,
        audit_logger=logger,
    )
    session = create_recovery_session(config)

    lock_root = run_root / ".rygnal-locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    lock_path = lock_root / "active.lock"
    lock_path.write_text(
        f"pid={os.getpid()}\n"
        "trace_id=active-recovery-test\n"
        f"trusted_repo_path={trusted.resolve()}\n"
        "lock_identity=active\n"
        f"created_at_unix={time.time()}\n",
        encoding="utf-8",
    )

    try:
        report = reconciler.reconcile(trace_id="active-workspace-lock")

        assert session.workspace_path.exists()
        assert report.active_count >= 1
        assert report.mutated_count == 0
    finally:
        lock_path.unlink(missing_ok=True)
        cleanup = destroy_recovery_session(
            session,
            config,
        )
        assert cleanup.status in {
            CleanupStatus.CLEANED_GIT,
            CleanupStatus.CLEANED_FALLBACK,
        }


def test_malformed_guarded_lock_fails_closed(
    tmp_path: Path,
) -> None:
    reconciler, _service, logger, run_root = empty_reconciler(tmp_path)
    trusted = create_repo(tmp_path / "trusted")
    config = RecoverySessionConfig(
        trusted_repo_path=trusted,
        rygnal_run_root=run_root,
        audit_logger=logger,
    )
    session = create_recovery_session(config)

    lock_root = run_root / ".rygnal-locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    lock_path = lock_root / "malformed.lock"
    lock_path.write_text(
        "pid=not-a-pid\n",
        encoding="utf-8",
    )

    try:
        report = reconciler.reconcile(trace_id="malformed-workspace-lock")

        assert session.workspace_path.exists()
        assert report.unresolved_count >= 1
        assert report.mutated_count == 0
        assert lock_path.exists()
    finally:
        lock_path.unlink(missing_ok=True)
        cleanup = destroy_recovery_session(
            session,
            config,
        )
        assert cleanup.status in {
            CleanupStatus.CLEANED_GIT,
            CleanupStatus.CLEANED_FALLBACK,
        }


def test_active_artifact_lock_prevents_orphan_quarantine(
    tmp_path: Path,
) -> None:
    fixture = pending_artifact(
        tmp_path,
        submit=False,
    )
    artifact = fixture["artifact"]
    store = fixture["service"].artifact_store
    artifact_path = store.root / f"{artifact.artifact_id}.json"
    lock_path = store.root / f".{artifact.artifact_id}.lock"

    lock_path.write_text(
        f"schema={ARTIFACT_LOCK_SCHEMA}\n"
        f"pid={os.getpid()}\n"
        f"artifact_id={artifact.artifact_id}\n"
        f"created_at_unix={time.time()}\n",
        encoding="utf-8",
    )

    try:
        report = fixture["reconciler"].reconcile(trace_id="active-artifact-lock")

        assert artifact_path.exists()
        assert report.active_count >= 1
        assert report.mutated_count == 0
    finally:
        lock_path.unlink(missing_ok=True)


def test_oversized_lock_metadata_is_not_removed(
    tmp_path: Path,
) -> None:
    fixture = pending_artifact(
        tmp_path,
        submit=False,
    )
    artifact = fixture["artifact"]
    store = fixture["service"].artifact_store
    artifact_path = store.root / f"{artifact.artifact_id}.json"
    lock_path = store.root / f".{artifact.artifact_id}.lock"

    lock_path.write_bytes(b"x" * (16 * 1024 + 1))

    try:
        report = fixture["reconciler"].reconcile(trace_id="oversized-lock")

        assert report.unresolved_count >= 1
        assert report.mutated_count == 0
        assert artifact_path.exists()
        assert lock_path.exists()
    finally:
        lock_path.unlink(missing_ok=True)


def test_future_lock_timestamp_fails_closed(
    tmp_path: Path,
) -> None:
    reconciler, _service, logger, run_root = empty_reconciler(tmp_path)
    trusted = create_repo(tmp_path / "trusted")
    config = RecoverySessionConfig(
        trusted_repo_path=trusted,
        rygnal_run_root=run_root,
        audit_logger=logger,
    )
    session = create_recovery_session(config)

    lock_root = run_root / ".rygnal-locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    lock_path = lock_root / "future.lock"
    lock_path.write_text(
        "pid=99999999\n"
        "trace_id=future-lock\n"
        f"trusted_repo_path={trusted.resolve()}\n"
        "lock_identity=future\n"
        f"created_at_unix={time.time() + 10000}\n",
        encoding="utf-8",
    )

    try:
        report = reconciler.reconcile(trace_id="future-lock")

        assert report.unresolved_count >= 1
        assert report.mutated_count == 0
        assert session.workspace_path.exists()
        assert lock_path.exists()
    finally:
        lock_path.unlink(missing_ok=True)
        cleanup = destroy_recovery_session(
            session,
            config,
        )
        assert cleanup.status in {
            CleanupStatus.CLEANED_GIT,
            CleanupStatus.CLEANED_FALLBACK,
        }


def test_approved_expired_artifact_requires_resolution(
    tmp_path: Path,
) -> None:
    fixture = pending_artifact(
        tmp_path,
        ttl_seconds=1,
    )
    service = fixture["service"]
    request = fixture["request"]
    artifact = fixture["artifact"]

    service.approve(
        request.approval_id,
        decided_by="security_reviewer",
        reason="Approved before expiration.",
    )

    time.sleep(1.1)

    report = fixture["reconciler"].reconcile(trace_id="approved-expired")
    reloaded = service.artifact_store.load(
        artifact.artifact_id,
        allow_expired=True,
        allow_consumed=True,
    )

    assert report.unresolved_count >= 1
    assert reloaded.state == PATCH_ARTIFACT_STATE_PENDING
    assert any("expired before trusted application" in item.message for item in report.findings)
