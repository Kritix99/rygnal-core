import shutil
import subprocess
from pathlib import Path

import pytest

import rygnal.approved_apply as approved_apply_module
from rygnal.approved_apply import ApprovedPatchApplyError, apply_approved_patch
from rygnal.audit_logger import AuditLogger
from rygnal.audit_storage import SQLiteAuditStore
from rygnal.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    Severity,
    utc_now_iso,
)
from rygnal.patch_approval import (
    approve_patch_request,
    create_patch_approval_request,
    reject_patch_request,
)
from rygnal.patch_diff import generate_patch_diff


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def create_repo(path: Path) -> Path:
    path.mkdir()

    run_git(path, "init")
    run_git(path, "config", "user.email", "test@example.com")
    run_git(path, "config", "user.name", "Test User")

    (path / "README.md").write_text("# Project\n", encoding="utf-8")
    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "baseline")

    return path


def clone_fixture(tmp_path: Path) -> tuple[Path, Path]:
    baseline = create_repo(tmp_path / "baseline")
    guarded = tmp_path / "guarded"
    trusted = tmp_path / "trusted"

    shutil.copytree(baseline, guarded)
    shutil.copytree(baseline, trusted)

    return guarded, trusted


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def make_source_patch(repo: Path):
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return generate_patch_diff(repo, baseline_sha(repo))


def test_applies_approved_source_patch_to_trusted_repo(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )
    logger = AuditLogger(tmp_path / "audit.jsonl")

    result = apply_approved_patch(
        patch,
        trusted,
        approval_request=request,
        approval_decision=decision,
        logger=logger,
    )

    assert result.applied is True
    assert (trusted / "src" / "app.py").read_text(encoding="utf-8") == "print('hello')\n"
    assert result.files == ("src/app.py",)

    events = logger.read_events()
    assert len(events) == 1
    assert events[0].decision == "allow"
    assert events[0].policy_id == "guarded-workspace-approved-patch-apply"
    assert logger.verify_integrity() is True


def test_approved_apply_requires_audit_logger_for_durable_replay_protection(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    with pytest.raises(ApprovedPatchApplyError, match="audit logger"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / "src" / "app.py").exists()


def test_rejected_approval_does_not_apply_patch(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = reject_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    with pytest.raises(ApprovedPatchApplyError, match="not granted"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / "src" / "app.py").exists()


def test_approval_digest_mismatch_does_not_apply_patch(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    other_guarded = tmp_path / "other_guarded"
    shutil.copytree(trusted, other_guarded)
    src = other_guarded / "src"
    src.mkdir()
    (src / "other.py").write_text("print('other')\n", encoding="utf-8")
    other_patch = generate_patch_diff(other_guarded, baseline_sha(other_guarded))

    with pytest.raises(ApprovedPatchApplyError, match="bound"):
        apply_approved_patch(
            other_patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / "src").exists()


def test_low_risk_patch_uses_auto_apply_not_approved_apply(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    docs = guarded / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("After\n", encoding="utf-8")
    patch = generate_patch_diff(guarded, baseline_sha(guarded))

    request = ApprovalRequest(
        requested_by="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_low_risk",
        tool_name="guarded_workspace",
        action="approve_patch_apply",
        target=patch.patch_sha256,
        policy_id="guarded-workspace-risky-patch-approval",
        reason="Not actually required.",
        severity=Severity.LOW,
    )
    decision = ApprovalDecision(
        approval_id=request.approval_id,
        status=ApprovalStatus.APPROVED,
        approved=True,
        decided_by="reviewer",
        decided_at=utc_now_iso(),
        reason="Approved",
        metadata={"patch_sha256": patch.patch_sha256},
    )

    with pytest.raises(ApprovedPatchApplyError, match="safe auto-apply"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / "docs" / "usage.md").exists()


def test_blocked_patch_cannot_be_applied_even_with_forged_approval(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    (guarded / ".env").write_text("TOKEN=example\n", encoding="utf-8")
    patch = generate_patch_diff(guarded, baseline_sha(guarded))

    request = ApprovalRequest(
        requested_by="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_forged",
        tool_name="guarded_workspace",
        action="approve_patch_apply",
        target=patch.patch_sha256,
        policy_id="guarded-workspace-risky-patch-approval",
        reason="Forged approval.",
        severity=Severity.CRITICAL,
    )
    decision = ApprovalDecision(
        approval_id=request.approval_id,
        status=ApprovalStatus.APPROVED,
        approved=True,
        decided_by="reviewer",
        decided_at=utc_now_iso(),
        reason="Forged",
        metadata={"patch_sha256": patch.patch_sha256},
    )

    with pytest.raises(ApprovedPatchApplyError, match="Blocked"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / ".env").exists()


def test_dirty_target_repo_rejects_before_apply(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )
    (trusted / "README.md").write_text("# Dirty\n", encoding="utf-8")

    with pytest.raises(ApprovedPatchApplyError, match="clean"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / "src" / "app.py").exists()


def test_stale_target_baseline_rejects_before_apply(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    (trusted / "README.md").write_text("# New trusted commit\n", encoding="utf-8")
    run_git(trusted, "add", ".")
    run_git(trusted, "commit", "-m", "trusted diverged")

    with pytest.raises(ApprovedPatchApplyError, match="baseline"):
        apply_approved_patch(
            patch,
            trusted,
            approval_request=request,
            approval_decision=decision,
        )

    assert not (trusted / "src" / "app.py").exists()


def test_non_repo_target_rejects(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )
    not_repo = tmp_path / "not-repo"
    not_repo.mkdir()

    with pytest.raises(ApprovedPatchApplyError):
        apply_approved_patch(
            patch,
            not_repo,
            approval_request=request,
            approval_decision=decision,
        )


def test_reused_approval_is_rejected_before_second_apply(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    second_trusted = tmp_path / "second_trusted"
    shutil.copytree(trusted, second_trusted)

    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    logger = AuditLogger(tmp_path / "audit.jsonl")

    first_result = apply_approved_patch(
        patch,
        trusted,
        approval_request=request,
        approval_decision=decision,
        logger=logger,
    )

    assert first_result.applied is True

    with pytest.raises(ApprovedPatchApplyError, match="already been used|reused"):
        apply_approved_patch(
            patch,
            second_trusted,
            approval_request=request,
            approval_decision=decision,
            logger=logger,
        )

    assert not (second_trusted / "src" / "app.py").exists()


def test_reused_approval_is_rejected_from_sqlite_audit_storage_after_restart(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    second_trusted = tmp_path / "second_trusted"
    shutil.copytree(trusted, second_trusted)

    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )
    store = SQLiteAuditStore(tmp_path / "audit.db")
    first_logger = AuditLogger(tmp_path / "first-audit.jsonl", storage_backend=store)

    first_result = apply_approved_patch(
        patch,
        trusted,
        approval_request=request,
        approval_decision=decision,
        logger=first_logger,
    )
    assert first_result.applied is True

    approved_apply_module._USED_PATCH_APPROVALS.clear()
    second_logger = AuditLogger(tmp_path / "second-audit.jsonl", storage_backend=store)

    with pytest.raises(ApprovedPatchApplyError, match="already been used|reused"):
        apply_approved_patch(
            patch,
            second_trusted,
            approval_request=request,
            approval_decision=decision,
            logger=second_logger,
        )

    assert not (second_trusted / "src" / "app.py").exists()


def test_reused_approval_is_rejected_from_audit_history_after_restart(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    second_trusted = tmp_path / "second_trusted"
    shutil.copytree(trusted, second_trusted)

    patch = make_source_patch(guarded)
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )
    logger = AuditLogger(tmp_path / "audit.jsonl")

    first_result = apply_approved_patch(
        patch,
        trusted,
        approval_request=request,
        approval_decision=decision,
        logger=logger,
    )
    assert first_result.applied is True

    approved_apply_module._USED_PATCH_APPROVALS.clear()

    with pytest.raises(ApprovedPatchApplyError, match="already been used|reused"):
        apply_approved_patch(
            patch,
            second_trusted,
            approval_request=request,
            approval_decision=decision,
            logger=logger,
        )

    assert not (second_trusted / "src" / "app.py").exists()
