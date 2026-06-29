from pathlib import Path

import pytest

from rygnal.approved_apply import ApprovedPatchApplyError, apply_approved_patch
from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.change_risk import classify_patch_risk
from rygnal.guarded_runner import GuardedRunStatus, run_guarded
from rygnal.patch_approval import (
    PatchApprovalError,
    approve_patch_request,
    create_patch_approval_request,
)
from rygnal.safe_apply import SafePatchApplyOutcome, auto_apply_safe_patch
from tests.guarded_runner_helpers import (
    audit_actions,
    audit_text,
    commit_all,
    create_trusted_repo,
    git_status_porcelain,
    head_sha,
    py_command,
    unsafe_runner_config,
)


def run_git(repo: Path, *args: str) -> None:
    import subprocess

    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_runner_docs_patch_auto_applies_only_after_runner_completes(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    audit = AuditLogger(tmp_path / "audit.jsonl")
    baseline = head_sha(trusted)

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; Path('docs/usage.md').write_text('updated docs\\n')"
            ),
            audit_logger=audit,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.baseline_commit_sha == baseline
    assert result.patch_diff is not None
    assert git_status_porcelain(trusted) == "M docs/usage.md"
    run_git(trusted, "reset", "--hard", "HEAD")
    run_git(trusted, "clean", "-fd")
    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "before docs\n"

    apply_result = auto_apply_safe_patch(
        result.patch_diff,
        trusted,
        logger=audit,
        trace_id="trace_integration",
    )

    assert apply_result.outcome == SafePatchApplyOutcome.APPLIED
    assert apply_result.applied is True
    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "updated docs\n"
    assert audit.verify_integrity()


def test_runner_dependency_patch_requires_approval_before_apply(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('pyproject.toml').write_text("
                "'[project]\\nname = \"changed\"\\n'"
                ")"
            ),
            audit_logger=audit,
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.approval_request is not None
    assert result.approval_request.target == result.patch_diff.patch_sha256
    assert git_status_porcelain(trusted) == "?? pyproject.toml"
    run_git(trusted, "reset", "--hard", "HEAD")
    run_git(trusted, "clean", "-fd")

    safe_result = auto_apply_safe_patch(
        result.patch_diff,
        trusted,
        risk_report=result.change_risk_report,
        logger=audit,
        trace_id="trace_integration",
    )

    assert safe_result.outcome == SafePatchApplyOutcome.SKIPPED
    assert safe_result.applied is False
    assert not (trusted / "pyproject.toml").exists()

    approval_decision = approve_patch_request(
        result.approval_request,
        decided_by="test_reviewer",
        patch_sha256=result.patch_diff.patch_sha256,
    )

    approved_result = apply_approved_patch(
        result.patch_diff,
        trusted,
        approval_request=result.approval_request,
        approval_decision=approval_decision,
        risk_report=result.change_risk_report,
        logger=audit,
    )

    assert approved_result.applied is True
    assert (trusted / "pyproject.toml").read_text(
        encoding="utf-8"
    ) == '[project]\nname = "changed"\n'
    assert audit.verify_integrity()


def test_runner_dangerous_secret_patch_is_blocked_by_existing_gate(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    audit = AuditLogger(tmp_path / "audit.jsonl")
    fake_secret = "RYGNAL_FAKE_SECRET_VALUE"

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                f"from pathlib import Path; Path('.env').write_text('TOKEN={fake_secret}\\n')"
            ),
            audit_logger=audit,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.blocked_reason is not None
    assert (trusted / ".env").exists()
    assert git_status_porcelain(trusted) == "?? .env"

    risk_report = classify_patch_risk(result.patch_diff)
    gate = evaluate_guarded_change_gate(result.patch_diff, risk_report=risk_report)

    assert gate.blocked is True

    with pytest.raises(PatchApprovalError, match="Blocked patches cannot be approved"):
        create_patch_approval_request(
            result.patch_diff,
            requested_by="test_reviewer",
            risk_report=risk_report,
            gate_decision=gate,
            trace_id="trace_integration",
        )

    assert (trusted / ".env").exists()
    assert fake_secret not in audit_text(tmp_path / "audit.jsonl")
    assert audit.verify_integrity()


def test_runner_patch_stale_baseline_rejected_by_approved_apply(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('pyproject.toml').write_text("
                "'[project]\\nname = \"changed\"\\n'"
                ")"
            ),
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.approval_request is not None

    approval_decision = approve_patch_request(
        result.approval_request,
        decided_by="test_reviewer",
        patch_sha256=result.patch_diff.patch_sha256,
    )

    (trusted / "docs" / "usage.md").write_text("different trusted commit\n", encoding="utf-8")
    commit_all(trusted, "advance trusted repo")

    with pytest.raises(
        ApprovedPatchApplyError,
        match="HEAD does not match guarded patch baseline",
    ):
        apply_approved_patch(
            result.patch_diff,
            trusted,
            approval_request=result.approval_request,
            approval_decision=approval_decision,
            risk_report=result.change_risk_report,
        )


def test_runner_emits_expected_audit_order_for_successful_integration_run(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command("from pathlib import Path; Path('docs/audit.md').write_text('audit\\n')"),
            audit_logger=audit,
        )
    )

    actions = audit_actions(audit)

    assert result.status == GuardedRunStatus.COMPLETED
    assert actions.index("guarded_run.requested") < actions.index("guarded_run.backend_selected")
    assert actions.index("guarded_run.backend_selected") < actions.index(
        "guarded_run.workspace_created"
    )
    assert actions.index("guarded_run.workspace_created") < actions.index(
        "guarded_run.command_started"
    )
    assert actions.index("guarded_run.command_started") < actions.index(
        "guarded_run.command_completed"
    )
    assert actions.index("guarded_run.command_completed") < actions.index(
        "guarded_run.changed_files_detected"
    )
    assert actions.index("guarded_run.changed_files_detected") < actions.index(
        "guarded_run.patch_generated"
    )
    assert "guarded_run.cleanup_completed" in actions
    assert audit.verify_integrity()
