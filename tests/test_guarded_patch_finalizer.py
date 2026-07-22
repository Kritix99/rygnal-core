from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

from rygnal.approval_queue import (
    ApprovalQueueError,
    InMemoryApprovalQueue,
)
from rygnal.audit_logger import AuditLogger
from rygnal.change_risk import classify_patch_risk
from rygnal.guarded_patch_finalizer import (
    GuardedPatchApplyOutcome,
    GuardedPatchFinalizationRequest,
    GuardedPatchFinalStatus,
    finalize_guarded_patch,
)
from rygnal.patch_approval import approve_patch_request
from rygnal.patch_artifact import PatchArtifactStore
from rygnal.patch_diff import generate_patch_diff


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    return result.stdout.strip()


def create_fixture(
    tmp_path: Path,
) -> tuple[Path, Path]:
    baseline = tmp_path / "baseline"
    baseline.mkdir()

    git(baseline, "init")
    git(
        baseline,
        "config",
        "user.email",
        "test@example.com",
    )
    git(
        baseline,
        "config",
        "user.name",
        "Test User",
    )

    (baseline / "docs").mkdir()

    (baseline / "docs" / "usage.md").write_text(
        "Before\n",
        encoding="utf-8",
    )

    git(baseline, "add", ".")
    git(
        baseline,
        "commit",
        "-m",
        "baseline",
    )

    trusted = tmp_path / "trusted"
    workspace = tmp_path / "workspace"

    shutil.copytree(
        baseline,
        trusted,
    )
    shutil.copytree(
        baseline,
        workspace,
    )

    return trusted, workspace


def request_for(
    *,
    tmp_path: Path,
    trusted: Path,
    patch,
    risk,
    current_status: str = "completed",
    exit_code: int | None = 0,
    timed_out: bool = False,
    intent=None,
    queue=None,
) -> GuardedPatchFinalizationRequest:
    return GuardedPatchFinalizationRequest(
        current_status=current_status,
        run_id="run-finalizer",
        trace_id="trace-finalizer",
        trusted_repo_path=trusted,
        run_root=tmp_path / "runs",
        user_id="tester",
        agent_id="agent",
        environment="test",
        command_exit_code=exit_code,
        command_timed_out=timed_out,
        patch_diff=patch,
        risk_report=risk,
        intent_fallback_evaluation=intent,
        approval_queue=queue,
    )


def test_low_risk_docs_patch_applies_once(
    tmp_path: Path,
) -> None:
    trusted, workspace = create_fixture(tmp_path)

    (workspace / "docs" / "usage.md").write_text(
        "After\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        workspace,
        git(
            workspace,
            "rev-parse",
            "HEAD",
        ),
    )
    risk = classify_patch_risk(patch)

    result = finalize_guarded_patch(
        request_for(
            tmp_path=tmp_path,
            trusted=trusted,
            patch=patch,
            risk=risk,
        )
    )

    assert result.status == GuardedPatchFinalStatus.COMPLETED
    assert result.apply_outcome == GuardedPatchApplyOutcome.APPLIED
    assert result.applied is True

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "After\n"


def test_dependency_patch_persists_before_queue_submission(
    tmp_path: Path,
) -> None:
    trusted, workspace = create_fixture(tmp_path)

    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "changed"\n',
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        workspace,
        git(
            workspace,
            "rev-parse",
            "HEAD",
        ),
    )
    risk = classify_patch_risk(patch)
    queue = InMemoryApprovalQueue()

    result = finalize_guarded_patch(
        request_for(
            tmp_path=tmp_path,
            trusted=trusted,
            patch=patch,
            risk=risk,
            queue=queue,
        )
    )

    assert result.status == GuardedPatchFinalStatus.APPROVAL_REQUIRED
    assert result.apply_outcome == GuardedPatchApplyOutcome.PENDING_APPROVAL
    assert result.artifact_id is not None
    assert result.approval_request is not None

    assert result.approval_request.metadata["artifact_id"] == result.artifact_id

    assert len(queue.list()) == 1

    stored = PatchArtifactStore(tmp_path / "runs" / "artifacts").load(result.artifact_id)

    assert stored.patch_sha256 == patch.patch_sha256
    assert stored.baseline_commit_sha == patch.baseline_commit_sha
    assert stored.approval_request_id == result.approval_request.approval_id

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


def test_failed_command_never_applies_or_persists(
    tmp_path: Path,
) -> None:
    trusted, workspace = create_fixture(tmp_path)

    (workspace / "docs" / "usage.md").write_text(
        "After\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        workspace,
        git(
            workspace,
            "rev-parse",
            "HEAD",
        ),
    )
    risk = classify_patch_risk(patch)

    result = finalize_guarded_patch(
        request_for(
            tmp_path=tmp_path,
            trusted=trusted,
            patch=patch,
            risk=risk,
            current_status="failed",
            exit_code=1,
        )
    )

    assert result.status == GuardedPatchFinalStatus.FAILED
    assert result.apply_outcome == GuardedPatchApplyOutcome.NOT_APPLIED

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"

    assert not (tmp_path / "runs" / "artifacts").exists()


def test_timeout_never_applies_or_persists(
    tmp_path: Path,
) -> None:
    trusted, workspace = create_fixture(tmp_path)

    (workspace / "docs" / "usage.md").write_text(
        "After\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        workspace,
        git(
            workspace,
            "rev-parse",
            "HEAD",
        ),
    )
    risk = classify_patch_risk(patch)

    result = finalize_guarded_patch(
        request_for(
            tmp_path=tmp_path,
            trusted=trusted,
            patch=patch,
            risk=risk,
            current_status="timed_out",
            exit_code=None,
            timed_out=True,
        )
    )

    assert result.status == GuardedPatchFinalStatus.TIMED_OUT
    assert result.apply_outcome == GuardedPatchApplyOutcome.NOT_APPLIED

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"


def test_intent_approval_overrides_low_risk_auto_apply(
    tmp_path: Path,
) -> None:
    trusted, workspace = create_fixture(tmp_path)

    (workspace / "docs" / "usage.md").write_text(
        "After\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        workspace,
        git(
            workspace,
            "rev-parse",
            "HEAD",
        ),
    )
    risk = classify_patch_risk(patch)

    intent = SimpleNamespace(
        should_block=False,
        requires_approval=True,
        match_state=SimpleNamespace(value="drift"),
        recommended_hint=SimpleNamespace(value="require_approval"),
        effective_hint=SimpleNamespace(value="require_approval"),
        reason_codes=("scope-drift",),
    )

    result = finalize_guarded_patch(
        request_for(
            tmp_path=tmp_path,
            trusted=trusted,
            patch=patch,
            risk=risk,
            intent=intent,
        )
    )

    assert result.status == GuardedPatchFinalStatus.APPROVAL_REQUIRED
    assert result.apply_outcome == GuardedPatchApplyOutcome.PENDING_APPROVAL
    assert result.approval_request is not None

    assert result.approval_request.metadata["forced_approval"] is True

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"


def test_intent_block_prevents_artifact_and_apply(
    tmp_path: Path,
) -> None:
    trusted, workspace = create_fixture(tmp_path)

    (workspace / "docs" / "usage.md").write_text(
        "After\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        workspace,
        git(
            workspace,
            "rev-parse",
            "HEAD",
        ),
    )
    risk = classify_patch_risk(patch)

    intent = SimpleNamespace(
        should_block=True,
        requires_approval=False,
        match_state=SimpleNamespace(value="hard_sensitive"),
        recommended_hint=SimpleNamespace(value="block"),
        effective_hint=SimpleNamespace(value="block"),
        reason_codes=("sensitive-boundary",),
    )

    result = finalize_guarded_patch(
        request_for(
            tmp_path=tmp_path,
            trusted=trusted,
            patch=patch,
            risk=risk,
            intent=intent,
        )
    )

    assert result.status == GuardedPatchFinalStatus.BLOCKED
    assert result.apply_outcome == GuardedPatchApplyOutcome.NOT_APPLIED

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"

    assert not (tmp_path / "runs" / "artifacts").exists()


def test_queue_failure_removes_orphan_artifact_and_fails_closed(
    tmp_path: Path,
) -> None:
    trusted, workspace = create_fixture(tmp_path)

    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "changed"\n',
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        workspace,
        git(
            workspace,
            "rev-parse",
            "HEAD",
        ),
    )
    risk = classify_patch_risk(patch)

    class FailingQueue:
        def submit(
            self,
            approval_request,
        ):
            raise ApprovalQueueError(f"forced queue failure for {approval_request.approval_id}")

    result = finalize_guarded_patch(
        request_for(
            tmp_path=tmp_path,
            trusted=trusted,
            patch=patch,
            risk=risk,
            queue=FailingQueue(),
        )
    )

    assert result.status == GuardedPatchFinalStatus.FAILED
    assert result.apply_outcome == GuardedPatchApplyOutcome.APPLY_FAILED
    assert result.artifact_id is None

    artifact_root = tmp_path / "runs" / "artifacts"

    assert not tuple(artifact_root.glob("*.json"))

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


def test_intent_forced_approval_can_apply_through_canonical_boundary(
    tmp_path: Path,
) -> None:
    trusted, workspace = create_fixture(tmp_path)

    (workspace / "docs" / "usage.md").write_text(
        "After approval\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        workspace,
        git(workspace, "rev-parse", "HEAD"),
    )
    risk = classify_patch_risk(patch)

    intent = SimpleNamespace(
        should_block=False,
        requires_approval=True,
        match_state=SimpleNamespace(value="drift"),
        recommended_hint=SimpleNamespace(value="require_approval"),
        effective_hint=SimpleNamespace(value="require_approval"),
        reason_codes=("target-scope-drift",),
    )

    result = finalize_guarded_patch(
        request_for(
            tmp_path=tmp_path,
            trusted=trusted,
            patch=patch,
            risk=risk,
            intent=intent,
        )
    )

    assert result.approval_request is not None
    assert result.artifact_id is not None

    decision = approve_patch_request(
        result.approval_request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    logger = AuditLogger(tmp_path / "approved-audit.jsonl")

    applied = PatchArtifactStore(tmp_path / "runs" / "artifacts").apply_approved(
        result.artifact_id,
        trusted,
        approval_request=result.approval_request,
        approval_decision=decision,
        logger=logger,
    )

    assert applied.applied is True
    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "After approval\n"
    assert logger.verify_integrity() is True
