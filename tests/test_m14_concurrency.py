from __future__ import annotations

import multiprocessing
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from rygnal.approval_queue import (
    ApprovalStateConflictError,
    SQLiteApprovalQueue,
)
from rygnal.approval_service import (
    ApprovalOperationStateError,
)
from rygnal.audit_logger import AuditLogger
from rygnal.audit_storage import SQLiteAuditStore
from rygnal.change_gate import (
    evaluate_guarded_change_gate,
)
from rygnal.change_risk import classify_patch_risk
from rygnal.local_runtime import (
    create_local_runtime_dependencies,
)
from rygnal.models import (
    ApprovalRequest,
    ApprovalStatus,
    Decision,
    PolicyDecision,
    Severity,
    ToolRequest,
)
from rygnal.operation_store import (
    OperationRecoveryStatus,
    SQLiteOperationStore,
)
from rygnal.patch_approval import (
    create_patch_approval_request,
)
from rygnal.patch_artifact import (
    bind_artifact_to_approval,
)
from rygnal.patch_diff import generate_patch_diff


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
    git(
        path,
        "config",
        "user.email",
        "m14@example.com",
    )
    git(
        path,
        "config",
        "user.name",
        "M14 Test",
    )

    (path / "docs").mkdir()
    (path / "docs" / "usage.md").write_text(
        "before\n",
        encoding="utf-8",
    )

    git(path, "add", ".")
    git(path, "commit", "-m", "baseline")
    return path


def approval_request() -> ApprovalRequest:
    return ApprovalRequest(
        requested_by="agent_user",
        agent_id="agent",
        environment="test",
        tool_name="guarded_workspace",
        action="approve_patch_apply",
        target="a" * 64,
        policy_id=("guarded-workspace-risky-patch-approval"),
        reason="Approval race test.",
        severity=Severity.HIGH,
    )


def approval_worker(
    db_path: str,
    approval_id: str,
    status: str,
    start_event: Any,
    output: Any,
) -> None:
    start_event.wait(10)
    queue = SQLiteApprovalQueue(db_path)

    try:
        if status == "approved":
            item = queue.approve(
                approval_id,
                decided_by="security_reviewer",
                reason="Concurrent decision.",
            )
        else:
            item = queue.reject(
                approval_id,
                decided_by="security_reviewer",
                reason="Concurrent decision.",
            )

        output.put(
            {
                "ok": True,
                "status": item.status.value,
                "decided_at": (item.decision.decided_at if item.decision else None),
            }
        )
    except Exception as exc:
        output.put(
            {
                "ok": False,
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )


def audit_worker(
    db_path: str,
    jsonl_path: str,
    worker_id: int,
    event_count: int,
    start_event: Any,
    output: Any,
) -> None:
    logger = AuditLogger(
        jsonl_path,
        storage_backend=SQLiteAuditStore(db_path),
    )
    start_event.wait(10)

    try:
        for index in range(event_count):
            request = ToolRequest(
                tool_name="m14_test",
                action="append",
                target=f"{worker_id}:{index}",
                input=None,
                user_id=f"user-{worker_id}",
                agent_id=f"agent-{worker_id}",
                environment="test",
                metadata={"trace_id": (f"trace-{worker_id}-{index}")},
            )
            decision = PolicyDecision(
                decision=Decision.ALLOW,
                allowed=True,
                severity=Severity.LOW,
                policy_id="m14-audit-test",
                reason="Concurrent audit append.",
            )
            logger.log_decision(
                request,
                decision,
            )

        output.put({"ok": True})
    except Exception as exc:
        output.put(
            {
                "ok": False,
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )


def apply_worker(
    data_dir: str,
    trusted_repo: str,
    artifact_id: str,
    start_event: Any,
    output: Any,
) -> None:
    runtime = create_local_runtime_dependencies(data_dir=data_dir)
    start_event.wait(10)

    try:
        result = runtime.approval_service.apply_artifact(
            artifact_id,
            trusted_repo,
        )
        output.put(
            {
                "ok": True,
                "applied": result.applied,
                "patch_sha256": (result.patch_sha256),
            }
        )
    except Exception as exc:
        output.put(
            {
                "ok": False,
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )


def seed_artifact(
    tmp_path: Path,
) -> tuple[
    Path,
    Path,
    str,
    str,
]:
    data_dir = tmp_path / "data"
    runtime = create_local_runtime_dependencies(data_dir=data_dir)

    baseline = create_repo(tmp_path / "baseline")
    trusted = tmp_path / "trusted"
    workspace = tmp_path / "workspace"

    shutil.copytree(baseline, trusted)
    shutil.copytree(baseline, workspace)

    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "m14-applied"\n',
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
        trace_id="trace-m14-apply",
    )
    artifact = runtime.artifact_store.persist(
        patch_diff=patch,
        run_id="run-m14-apply",
        trace_id="trace-m14-apply",
        approval_request=request,
        trusted_repo_path=trusted,
        risk_report=risk,
    )
    bound = bind_artifact_to_approval(
        request,
        artifact,
    )
    runtime.approval_queue.submit(bound)
    runtime.approval_service.approve(
        bound.approval_id,
        decided_by="security_reviewer",
        reason="Approved for M14 race test.",
    )

    return (
        data_dir,
        trusted,
        bound.approval_id,
        artifact.artifact_id,
    )


def collect_process_results(
    processes: list[Any],
    output: Any,
) -> list[dict[str, Any]]:
    for process in processes:
        process.join(30)
        assert process.exitcode == 0

    return [output.get(timeout=5) for _process in processes]


def test_sqlite_pragmas_are_hardened(
    tmp_path: Path,
) -> None:
    queue = SQLiteApprovalQueue(tmp_path / "approvals.db")
    audit = SQLiteAuditStore(tmp_path / "audit.db")
    operations = SQLiteOperationStore(tmp_path / "operations.db")

    for snapshot in (
        queue.pragma_snapshot(),
        audit.pragma_snapshot(),
        operations.pragma_snapshot(),
    ):
        assert str(snapshot["journal_mode"]).lower() == "wal"
        assert int(snapshot["synchronous"]) == 2
        assert int(snapshot["busy_timeout"]) >= 10_000
        assert int(snapshot["foreign_keys"]) == 1


def test_concurrent_identical_approvals_are_idempotent(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    db_path = tmp_path / "approvals.db"
    queue = SQLiteApprovalQueue(db_path)
    request = approval_request()
    queue.submit(request)

    start = context.Event()
    output = context.Queue()
    processes = [
        context.Process(
            target=approval_worker,
            args=(
                str(db_path),
                request.approval_id,
                "approved",
                start,
                output,
            ),
        )
        for _index in range(2)
    ]

    for process in processes:
        process.start()

    start.set()
    results = collect_process_results(
        processes,
        output,
    )

    assert all(result["ok"] for result in results)
    assert {result["status"] for result in results} == {"approved"}
    assert len({result["decided_at"] for result in results}) == 1

    persisted = SQLiteApprovalQueue(db_path).get(request.approval_id)

    assert persisted.status == ApprovalStatus.APPROVED


def test_concurrent_approve_reject_has_one_winner(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    db_path = tmp_path / "approvals.db"
    queue = SQLiteApprovalQueue(db_path)
    request = approval_request()
    queue.submit(request)

    start = context.Event()
    output = context.Queue()
    processes = [
        context.Process(
            target=approval_worker,
            args=(
                str(db_path),
                request.approval_id,
                status,
                start,
                output,
            ),
        )
        for status in ("approved", "rejected")
    ]

    for process in processes:
        process.start()

    start.set()
    results = collect_process_results(
        processes,
        output,
    )

    assert sum(bool(result["ok"]) for result in results) == 1
    assert any(result.get("type") == ApprovalStateConflictError.__name__ for result in results)

    persisted = SQLiteApprovalQueue(db_path).get(request.approval_id)

    assert persisted.status in {
        ApprovalStatus.APPROVED,
        ApprovalStatus.REJECTED,
    }


def test_concurrent_audit_writers_preserve_hash_chain(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    database = tmp_path / "audit.db"
    jsonl = tmp_path / "audit.jsonl"
    start = context.Event()
    output = context.Queue()

    processes = [
        context.Process(
            target=audit_worker,
            args=(
                str(database),
                str(jsonl),
                worker_id,
                20,
                start,
                output,
            ),
        )
        for worker_id in range(4)
    ]

    for process in processes:
        process.start()

    start.set()
    results = collect_process_results(
        processes,
        output,
    )

    assert all(result["ok"] for result in results)

    store = SQLiteAuditStore(database)
    logger = AuditLogger(
        jsonl,
        storage_backend=store,
    )

    assert store.count_events() == 80
    assert logger.verify_integrity() is True


def test_concurrent_artifact_apply_mutates_once(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    (
        data_dir,
        trusted,
        _approval_id,
        artifact_id,
    ) = seed_artifact(tmp_path)

    start = context.Event()
    output = context.Queue()
    processes = [
        context.Process(
            target=apply_worker,
            args=(
                str(data_dir),
                str(trusted),
                artifact_id,
                start,
                output,
            ),
        )
        for _index in range(2)
    ]

    for process in processes:
        process.start()

    start.set()
    results = collect_process_results(
        processes,
        output,
    )

    successes = [result for result in results if result["ok"]]
    failures = [result for result in results if not result["ok"]]

    assert len(successes) >= 1
    assert all(result["applied"] is True for result in successes)
    assert all(
        result["type"]
        in {
            ApprovalOperationStateError.__name__,
        }
        for result in failures
    )

    assert (trusted / "pyproject.toml").read_text(
        encoding="utf-8"
    ) == '[project]\nname = "m14-applied"\n'

    runtime = create_local_runtime_dependencies(data_dir=data_dir)
    replay = runtime.approval_service.apply_artifact(
        artifact_id,
        trusted,
    )

    assert replay.applied is True
    assert replay.patch_sha256 == successes[0]["patch_sha256"]


def test_stale_pre_mutation_operation_is_released(
    tmp_path: Path,
) -> None:
    (
        data_dir,
        trusted,
        approval_id,
        artifact_id,
    ) = seed_artifact(tmp_path)
    runtime = create_local_runtime_dependencies(data_dir=data_dir)
    artifact = runtime.artifact_store.load(
        artifact_id,
        allow_consumed=True,
    )

    reservation = runtime.operation_store.reserve_artifact_apply(
        artifact_id=artifact_id,
        approval_id=approval_id,
        patch_sha256=artifact.patch_sha256,
        baseline_commit_sha=(artifact.baseline_commit_sha),
        target_repo_path=trusted,
    )

    with runtime.operation_store._connect() as connection:
        connection.execute(
            """
            UPDATE operations
            SET owner_pid = ?,
                owner_start_token = ?
            WHERE operation_key = ?
            """,
            (
                99_999_999,
                "dead-process-token",
                reservation.record.operation_key,
            ),
        )
        connection.execute(
            """
            UPDATE resource_leases
            SET owner_pid = ?,
                owner_start_token = ?
            WHERE operation_key = ?
            """,
            (
                99_999_999,
                "dead-process-token",
                reservation.record.operation_key,
            ),
        )

    recovered = runtime.operation_store.reconcile_incomplete(
        has_apply_evidence=lambda _record: False
    )

    assert len(recovered) == 1
    assert recovered[0].status == OperationRecoveryStatus.RELEASED

    retry = runtime.operation_store.reserve_artifact_apply(
        artifact_id=artifact_id,
        approval_id=approval_id,
        patch_sha256=artifact.patch_sha256,
        baseline_commit_sha=(artifact.baseline_commit_sha),
        target_repo_path=trusted,
    )

    assert retry.acquired is True


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX crash injection uses os._exit.",
)
def test_crashed_applying_operation_is_reconciled(
    tmp_path: Path,
) -> None:
    (
        data_dir,
        trusted,
        approval_id,
        artifact_id,
    ) = seed_artifact(tmp_path)
    runtime = create_local_runtime_dependencies(data_dir=data_dir)

    script = """
import os
import sys
from rygnal.local_runtime import create_local_runtime_dependencies

data_dir, trusted, artifact_id, approval_id = sys.argv[1:]
runtime = create_local_runtime_dependencies(data_dir=data_dir)
artifact = runtime.artifact_store.load(
    artifact_id,
    allow_consumed=True,
)
reservation = runtime.operation_store.reserve_artifact_apply(
    artifact_id=artifact_id,
    approval_id=approval_id,
    patch_sha256=artifact.patch_sha256,
    baseline_commit_sha=artifact.baseline_commit_sha,
    target_repo_path=trusted,
)
runtime.operation_store.mark_applying(reservation)
os._exit(73)
"""

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(data_dir),
            str(trusted),
            artifact_id,
            approval_id,
        ],
        check=False,
    )

    assert completed.returncode == 73

    report = runtime.recovery_reconciler.reconcile(trace_id="m14-crashed-operation")

    assert report.unresolved_count == 0
    assert any(
        item.kind == "artifact_apply_operation" and item.status.value == "recovered"
        for item in report.findings
    )

    result = runtime.approval_service.apply_artifact(
        artifact_id,
        trusted,
    )

    assert result.applied is True
