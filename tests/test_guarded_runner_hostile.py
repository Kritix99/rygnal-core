import os
import time
from pathlib import Path

import pytest

from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.change_risk import classify_patch_risk
from rygnal.guarded_runner import GuardedRunStatus, run_guarded
from rygnal.safe_apply import SafePatchApplyOutcome, auto_apply_safe_patch
from tests.guarded_runner_helpers import (
    audit_text,
    create_trusted_repo,
    git_status_porcelain,
    head_sha,
    py_command,
    unsafe_runner_config,
)


def test_hostile_parent_path_write_does_not_mutate_trusted_repo(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    baseline = head_sha(trusted)

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('../escape.txt').write_text('outside workspace in unsafe local\\n')"
            ),
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.backend_name == "unsafe_local"
    assert result.containment_verified is False
    assert any("Unsafe local execution" in warning for warning in result.warnings)
    assert head_sha(trusted) == baseline
    assert git_status_porcelain(trusted) == ""
    assert not (trusted / "escape.txt").exists()


def test_hostile_absolute_path_write_in_unsafe_local_is_not_trusted_repo_mutation(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    outside = tmp_path / "outside-host-write.txt"
    baseline = head_sha(trusted)

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                f"Path({outside.as_posix()!r}).write_text('unsafe local host write\\n')"
            ),
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert outside.exists()
    assert head_sha(trusted) == baseline
    assert git_status_porcelain(trusted) == ""
    assert not (trusted / "outside-host-write.txt").exists()


@pytest.mark.skipif(
    not hasattr(os, "symlink"),
    reason="symlink not supported on this platform",
)
def test_hostile_symlink_to_outside_repo_is_reported_and_blocked_by_gate(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    target = tmp_path / "outside-target.txt"
    target.write_text("outside\n", encoding="utf-8")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(f"import os; os.symlink({target.as_posix()!r}, 'outside_link')"),
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.blocked_reason is not None

    risk_report = classify_patch_risk(result.patch_diff)
    gate = evaluate_guarded_change_gate(result.patch_diff, risk_report=risk_report)

    assert gate.blocked is True
    assert git_status_porcelain(trusted) == ""


def test_hostile_large_change_skips_auto_apply(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('docs/huge.md').write_text('\\n'.join(str(i) for i in range(2000)))"
            ),
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.blocked_reason is not None

    risk_report = classify_patch_risk(result.patch_diff)
    apply_result = auto_apply_safe_patch(
        result.patch_diff,
        trusted,
        risk_report=risk_report,
    )

    assert apply_result.outcome == SafePatchApplyOutcome.SKIPPED
    assert any(
        reason.code.startswith("large-diff-") or reason.code == "not-low-risk"
        for reason in apply_result.skip_reasons
    )
    assert not (trusted / "docs" / "huge.md").exists()
    assert git_status_porcelain(trusted) == ""


def test_hostile_dependency_manifest_change_remains_visible_and_skips_auto_apply(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('requirements.txt').write_text('fastapi\\nmalicious-package\\n')"
            ),
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.blocked_reason is not None
    assert any(file.path == "requirements.txt" for file in result.patch_diff.files)

    risk_report = classify_patch_risk(result.patch_diff)
    apply_result = auto_apply_safe_patch(
        result.patch_diff,
        trusted,
        risk_report=risk_report,
    )

    assert apply_result.outcome == SafePatchApplyOutcome.SKIPPED
    assert "malicious-package" not in (trusted / "requirements.txt").read_text(encoding="utf-8")


def test_hostile_fake_secret_not_written_to_audit(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(audit_path)
    fake_secret = "FAKE_SECRET_FOR_AUDIT_TEST"

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(f"from pathlib import Path; Path('secret.txt').write_text({fake_secret!r})"),
            audit_logger=audit,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.blocked_reason is not None
    assert fake_secret in result.patch_diff.patch
    assert fake_secret not in audit_text(audit_path)
    assert audit.verify_integrity()


def test_hostile_failed_command_after_changes_keeps_evidence_and_cleans(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('before_fail.txt').write_text('evidence'); "
                "raise SystemExit(7)"
            ),
        )
    )

    assert result.status == GuardedRunStatus.FAILED
    assert result.command_result.exit_code == 7
    assert result.changed_file_report is not None
    assert any(file.path == "before_fail.txt" for file in result.changed_file_report.files)
    assert result.patch_diff is not None
    assert git_status_porcelain(trusted) == ""
    assert not Path(result.workspace_path).exists()


def test_hostile_timeout_after_changes_keeps_evidence_and_cleans(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; import time; "
                "Path('before_timeout.txt').write_text('evidence'); "
                "time.sleep(30)"
            ),
            timeout_seconds=1,
        )
    )

    assert result.status == GuardedRunStatus.TIMED_OUT
    assert result.command_result.exit_code is None
    assert result.command_result.timed_out is True
    assert result.changed_file_report is not None
    assert any(file.path == "before_timeout.txt" for file in result.changed_file_report.files)
    assert git_status_porcelain(trusted) == ""
    assert not Path(result.workspace_path).exists()


def test_hostile_child_process_attempt_does_not_mark_trusted_repo_dirty(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    baseline = head_sha(trusted)

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "import subprocess, sys; "
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1)']); "
                "print('parent exits')"
            ),
            timeout_seconds=3,
        )
    )

    time.sleep(1.2)

    assert result.status == GuardedRunStatus.COMPLETED
    assert head_sha(trusted) == baseline
    assert git_status_porcelain(trusted) == ""


def test_hostile_attempt_common_secret_path_in_workspace_is_captured_not_applied(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "from pathlib import Path; "
                "Path('.aws').mkdir(); "
                "Path('.aws/credentials').write_text('aws_secret_access_key=fake\\n')"
            ),
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.blocked_reason is not None
    assert any(file.path == ".aws/credentials" for file in result.patch_diff.files)

    risk_report = classify_patch_risk(result.patch_diff)
    gate = evaluate_guarded_change_gate(result.patch_diff, risk_report=risk_report)

    assert gate.blocked is True
    assert not (trusted / ".aws" / "credentials").exists()
    assert git_status_porcelain(trusted) == ""


@pytest.mark.skipif(os.name != "posix", reason="process-group cleanup is POSIX-specific")
def test_timeout_kills_same_process_group_child_before_late_host_write(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    sentinel = tmp_path / "child-survived.txt"

    child_code = (
        "import time; "
        "time.sleep(2); "
        f"open({sentinel.as_posix()!r}, 'w', encoding='utf-8').write('survived')"
    )

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "import subprocess, sys, time; "
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                "time.sleep(30)"
            ),
            timeout_seconds=1,
        )
    )

    time.sleep(2.5)

    assert result.status == GuardedRunStatus.TIMED_OUT
    assert result.command_result is not None
    assert result.command_result.timed_out is True
    assert git_status_porcelain(trusted) == ""
    assert result.workspace_path is not None
    assert not Path(result.workspace_path).exists()
    assert not sentinel.exists()


@pytest.mark.skipif(os.name != "posix", reason="process-group cleanup is POSIX-specific")
def test_timeout_escalates_sigterm_ignoring_child_to_force_kill(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    ready = tmp_path / "sigterm-ignoring-child-ready.txt"
    sentinel = tmp_path / "sigterm-ignoring-child-survived.txt"

    child_code = (
        "import signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({ready.as_posix()!r}, 'w', encoding='utf-8').write('ready'); "
        "time.sleep(3); "
        f"open({sentinel.as_posix()!r}, 'w', encoding='utf-8').write('survived')"
    )

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command(
                "import subprocess, sys, time; "
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                "time.sleep(30)"
            ),
            timeout_seconds=1,
        )
    )

    time.sleep(3.5)

    assert result.status == GuardedRunStatus.TIMED_OUT
    assert result.command_result is not None
    assert result.command_result.timed_out is True
    assert ready.exists()
    assert not sentinel.exists()
    assert git_status_porcelain(trusted) == ""


def test_timeout_preserves_partial_stdout_before_process_cleanup(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_guarded(
        unsafe_runner_config(
            trusted,
            py_command("import time; print('before-timeout', flush=True); time.sleep(30)"),
            timeout_seconds=1,
        )
    )

    assert result.status == GuardedRunStatus.TIMED_OUT
    assert result.command_result is not None
    assert result.command_result.timed_out is True
    assert "before-timeout" in result.command_result.stdout
    assert git_status_porcelain(trusted) == ""
