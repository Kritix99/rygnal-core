from __future__ import annotations

from pathlib import Path

from rygnal.local_runtime import (
    create_local_runtime_dependencies,
)


def test_local_runtime_exposes_crash_reconciler(
    tmp_path: Path,
) -> None:
    dependencies = create_local_runtime_dependencies(data_dir=tmp_path / "data")

    assert dependencies.recovery_reconciler.run_root == dependencies.paths.runs_dir.resolve()
    assert dependencies.recovery_reconciler.approval_service is dependencies.approval_service
    assert dependencies.recovery_reconciler.audit_logger is dependencies.audit_logger


def test_local_recovery_is_restart_safe_and_idempotent(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"

    first_runtime = create_local_runtime_dependencies(data_dir=data_dir)
    first = first_runtime.recovery_reconciler.reconcile(trace_id="first-empty-recovery")

    second_runtime = create_local_runtime_dependencies(data_dir=data_dir)
    second = second_runtime.recovery_reconciler.reconcile(trace_id="second-empty-recovery")

    assert first.successful is True
    assert second.successful is True
    assert first.mutated_count == 0
    assert second.mutated_count == 0
    assert second_runtime.audit_logger.verify_integrity()
