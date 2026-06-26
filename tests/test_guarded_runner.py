import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import rygnal.guarded_runner as guarded_runner
from rygnal.api import create_app
from rygnal.approval_queue import InMemoryApprovalQueue, SQLiteApprovalQueue
from rygnal.audit_logger import AuditLogger
from rygnal.execution_backend import HostBackendCapabilities
from rygnal.guarded_runner import (
    UNSAFE_LOCAL_WARNING,
    GuardedRunConfig,
    GuardedRunStatus,
    _guarded_run_concurrency_lock_path,
    run_guarded,
)
from rygnal.models import ApprovalStatus
from rygnal.risk_engine import RiskLevel
from rygnal.untracked_files import UntrackedFilePolicy
from rygnal.workspace_cleanup import CleanupResult, CleanupStatus


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
    (path / "delete_me.txt").write_text("delete me\n", encoding="utf-8")
    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "baseline")

    return path


def py_command(code: str) -> tuple[str, ...]:
    return (sys.executable, "-c", code)


def unsafe_config(
    repo: Path,
    command: tuple[str, ...],
    *,
    audit_logger: AuditLogger | None = None,
    approval_queue: InMemoryApprovalQueue | None = None,
    preserve_workspace: bool = False,
    timeout_seconds: int = 5,
    allow_dirty_override: bool = False,
    untracked_policy: UntrackedFilePolicy = UntrackedFilePolicy.BLOCK,
) -> GuardedRunConfig:
    return GuardedRunConfig(
        trusted_repo_path=repo,
        command=command,
        timeout_seconds=timeout_seconds,
        rygnal_run_root=repo.parent / "rygnal-runs",
        allow_dirty_override=allow_dirty_override,
        untracked_policy=untracked_policy,
        preserve_workspace=preserve_workspace,
        unsafe_local_requested=True,
        trace_id="trace_test",
        audit_logger=audit_logger,
        approval_queue=approval_queue,
    )


def audit_actions(logger: AuditLogger) -> list[str | None]:
    return [event.action for event in logger.read_events()]


def audit_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def no_backend_capabilities() -> HostBackendCapabilities:
    return HostBackendCapabilities(
        os_name="linux",
        has_bwrap=False,
        bwrap_namespace_probe_passed=False,
        signed_sandbox_helper_probe_passed=False,
        has_systemd_run=False,
        verified_rootless_container_available=False,
        unsafe_local_requested=False,
    )


def systemd_only_capabilities() -> HostBackendCapabilities:
    return HostBackendCapabilities(
        os_name="linux",
        has_bwrap=False,
        bwrap_namespace_probe_passed=False,
        signed_sandbox_helper_probe_passed=False,
        has_systemd_run=True,
        verified_rootless_container_available=False,
        unsafe_local_requested=False,
    )


def bwrap_probe_available() -> bool:
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return False

    result = subprocess.run(
        [
            bwrap,
            "--unshare-user",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "true",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    return result.returncode == 0


def test_macos_without_verified_backend_blocks_as_guarded_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    def macos_capabilities(*, env=None):
        unsafe_requested = (env or {}).get("RYGNAL_UNSAFE_LOCAL") == "1"
        return HostBackendCapabilities(
            os_name="darwin",
            configured_container_backend=None,
            verified_rootless_container_available=False,
            unsafe_local_requested=unsafe_requested,
        )

    monkeypatch.setattr(
        guarded_runner,
        "detect_host_backend_capabilities",
        macos_capabilities,
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command(
                "from pathlib import Path; Path('should_not_run.txt').write_text('should not run')"
            ),
            rygnal_run_root=tmp_path / "runs",
            trace_id="trace_macos_blocked",
            audit_logger=audit,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.workspace_path is None
    assert result.command_result is None
    assert result.patch_diff is None
    assert result.change_risk_report is None
    assert result.blocked_reason is not None
    assert "macOS is recognized" in result.blocked_reason
    assert "Seatbelt containment is planned" in result.blocked_reason
    assert "verified rootless container backend" in result.blocked_reason
    assert "supported Linux backend" in result.blocked_reason
    assert not (repo / "should_not_run.txt").exists()
    assert "guarded_run.backend_blocked" in audit_actions(audit)
    assert audit.verify_integrity()


def test_macos_explicit_unsafe_local_escape_hatch_still_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")

    def macos_capabilities(*, env=None):
        unsafe_requested = (env or {}).get("RYGNAL_UNSAFE_LOCAL") == "1"
        return HostBackendCapabilities(
            os_name="darwin",
            configured_container_backend=None,
            verified_rootless_container_available=False,
            unsafe_local_requested=unsafe_requested,
        )

    monkeypatch.setattr(
        guarded_runner,
        "detect_host_backend_capabilities",
        macos_capabilities,
    )

    result = run_guarded(unsafe_config(repo, py_command("print('ok')")))

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.backend_name == "unsafe_local"
    assert result.backend_safe_by_default is False
    assert result.containment_verified is False
    assert UNSAFE_LOCAL_WARNING in result.warnings


def test_guarded_run_concurrency_lock_fails_closed(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(audit_path)
    config = unsafe_config(
        repo,
        py_command("print('should not run')"),
        audit_logger=audit,
    )

    lock_path = _guarded_run_concurrency_lock_path(repo, config.rygnal_run_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(f"pid={os.getpid()}\n", encoding="utf-8")

    result = run_guarded(config)

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.workspace_path is None
    assert result.command_result is None
    assert result.blocked_reason is not None
    assert "guarded_run_concurrency_conflict" in result.blocked_reason
    assert "guarded_run.concurrency_blocked" in audit_actions(audit)

    audit_body = audit_text(audit_path)
    assert lock_path.as_posix() in audit_body
    assert lock_path.stem in audit_body

    lock_path.unlink()


def test_guarded_run_recovers_stale_concurrency_lock(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(audit_path)
    config = unsafe_config(repo, py_command("print('ok')"), audit_logger=audit)
    lock_path = _guarded_run_concurrency_lock_path(repo, config.rygnal_run_root)

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("pid=0\ntrace_id=stale\n", encoding="utf-8")

    result = run_guarded(config)

    assert result.status == GuardedRunStatus.COMPLETED
    assert not lock_path.exists()
    assert "guarded_run.stale_lock_recovered" in audit_actions(audit)

    audit_body = audit_text(audit_path)
    assert lock_path.as_posix() in audit_body
    assert lock_path.stem in audit_body


def test_guarded_run_concurrency_lock_released_after_unhandled_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")
    config = unsafe_config(repo, py_command("print('ok')"))
    lock_path = _guarded_run_concurrency_lock_path(repo, config.rygnal_run_root)

    def raise_after_command(*args: object, **kwargs: object) -> None:
        raise RuntimeError("forced guarded runner crash")

    monkeypatch.setattr(guarded_runner, "detect_changed_files", raise_after_command)

    with pytest.raises(RuntimeError, match="forced guarded runner crash"):
        run_guarded(config)

    assert not lock_path.exists()


def test_guarded_run_concurrency_lock_is_released_after_run(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    config = unsafe_config(repo, py_command("print('ok')"))
    lock_path = _guarded_run_concurrency_lock_path(repo, config.rygnal_run_root)

    result = run_guarded(config)

    assert result.status == GuardedRunStatus.COMPLETED
    assert not lock_path.exists()


def test_empty_command_is_blocked(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=(),
            rygnal_run_root=tmp_path / "runs",
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.workspace_path is None
    assert "empty" in result.blocked_reason.lower()


def test_shell_string_command_is_blocked(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        GuardedRunConfig(  # type: ignore[arg-type]
            trusted_repo_path=repo,
            command="echo unsafe",
            rygnal_run_root=tmp_path / "runs",
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert "shell string" in result.blocked_reason


def test_non_string_command_item_is_blocked(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        GuardedRunConfig(  # type: ignore[arg-type]
            trusted_repo_path=repo,
            command=(sys.executable, 123),
            rygnal_run_root=tmp_path / "runs",
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert "string" in result.blocked_reason


def test_non_positive_timeout_is_blocked(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command("print('x')"),
            timeout_seconds=0,
            rygnal_run_root=tmp_path / "runs",
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert "Timeout" in result.blocked_reason


def test_missing_trusted_repo_path_is_blocked(tmp_path: Path) -> None:
    missing_repo = tmp_path / "missing"

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=missing_repo,
            command=py_command("print('should not run')"),
            rygnal_run_root=tmp_path / "runs",
            unsafe_local_requested=True,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.workspace_path is None
    assert "does not exist" in result.blocked_reason


def test_non_git_trusted_repo_path_is_blocked(tmp_path: Path) -> None:
    not_git = tmp_path / "not-git"
    not_git.mkdir()

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=not_git,
            command=py_command("print('should not run')"),
            rygnal_run_root=tmp_path / "runs",
            unsafe_local_requested=True,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.workspace_path is None
    assert result.command_result is None


def test_dirty_trusted_repo_is_blocked_by_default(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    (repo / "README.md").write_text("dirty\n", encoding="utf-8")

    result = run_guarded(unsafe_config(repo, py_command("print('should not run')")))

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.workspace_path is None
    assert "Tracked uncommitted changes" in result.blocked_reason


def test_dirty_override_is_explicit_and_audited(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")
    (repo / "README.md").write_text("dirty\n", encoding="utf-8")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("from pathlib import Path; Path('agent.txt').write_text('ok')"),
            audit_logger=audit,
            allow_dirty_override=True,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert any("Dirty trusted repository override" in warning for warning in result.warnings)
    assert audit.verify_integrity()


def test_sensitive_untracked_file_blocks_run(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    (repo / ".env").write_text("TOKEN=secret\n", encoding="utf-8")

    result = run_guarded(unsafe_config(repo, py_command("print('should not run')")))

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.workspace_path is None


def test_normal_untracked_file_blocks_under_default_policy(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    (repo / "notes.txt").write_text("local note\n", encoding="utf-8")

    result = run_guarded(unsafe_config(repo, py_command("print('should not run')")))

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.workspace_path is None


def test_preserve_untracked_policy_does_not_copy_unrelated_trusted_file(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")
    (repo / "notes.txt").write_text("local note\n", encoding="utf-8")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("from pathlib import Path; Path('agent.txt').write_text('ok')"),
            preserve_workspace=True,
            untracked_policy=UntrackedFilePolicy.PRESERVE_AND_WARN,
        )
    )

    workspace = Path(result.workspace_path)

    assert result.status == GuardedRunStatus.COMPLETED
    assert workspace.exists()
    assert (workspace / "agent.txt").exists()
    assert not (workspace / "notes.txt").exists()
    assert (repo / "notes.txt").exists()


def test_no_verified_backend_blocks_without_unsafe_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")
    monkeypatch.setattr(
        "rygnal.guarded_runner.detect_host_backend_capabilities",
        lambda env=None: no_backend_capabilities(),
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command("print('blocked')"),
            rygnal_run_root=tmp_path / "runs",
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.backend_name is None
    assert result.containment_verified is False
    assert result.workspace_path is None


def test_unsupported_selected_backend_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")
    monkeypatch.setattr(
        "rygnal.guarded_runner.detect_host_backend_capabilities",
        lambda env=None: systemd_only_capabilities(),
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command("print('blocked')"),
            rygnal_run_root=tmp_path / "runs",
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.backend_name == "linux_systemd_user"
    assert "not implemented" in result.blocked_reason


@pytest.mark.parametrize(
    ("expected_backend_name", "capability_kwargs"),
    (
        (
            "linux_bubblewrap_helper",
            {
                "os_name": "linux",
                "bwrap_namespace_probe_passed": False,
                "signed_sandbox_helper_probe_passed": True,
                "has_systemd_run": False,
                "verified_rootless_container_available": False,
            },
        ),
        (
            "linux_systemd_user",
            {
                "os_name": "linux",
                "bwrap_namespace_probe_passed": False,
                "signed_sandbox_helper_probe_passed": False,
                "has_systemd_run": True,
                "verified_rootless_container_available": False,
            },
        ),
        (
            "configured_container",
            {
                "os_name": "linux",
                "bwrap_namespace_probe_passed": False,
                "signed_sandbox_helper_probe_passed": False,
                "has_systemd_run": False,
                "configured_container_backend": "podman",
                "verified_rootless_container_available": True,
            },
        ),
    ),
)
def test_unimplemented_selected_safe_backends_block_before_command_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expected_backend_name: str,
    capability_kwargs: dict[str, object],
) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    def selected_capabilities(*, env=None):
        unsafe_requested = (env or {}).get("RYGNAL_UNSAFE_LOCAL") == "1"
        return HostBackendCapabilities(
            unsafe_local_requested=unsafe_requested,
            **capability_kwargs,
        )

    monkeypatch.setattr(
        guarded_runner,
        "detect_host_backend_capabilities",
        selected_capabilities,
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command(
                "from pathlib import Path; Path('should_not_run.txt').write_text('ran')"
            ),
            rygnal_run_root=tmp_path / "runs",
            trace_id=f"trace_{expected_backend_name}",
            audit_logger=audit,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.backend_name == expected_backend_name
    assert result.command_result is None
    assert result.workspace_path is None
    assert "not implemented" in (result.blocked_reason or "")
    assert not (repo / "should_not_run.txt").exists()
    assert "guarded_run.backend_blocked" in audit_actions(audit)
    assert audit.verify_integrity()


def test_unsafe_local_requires_explicit_opt_in(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("print('ok')"),
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.backend_name == "unsafe_local"
    assert result.backend_safe_by_default is False
    assert result.containment_verified is False
    assert UNSAFE_LOCAL_WARNING in result.warnings


def test_command_runs_with_guarded_workspace_cwd(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; Path('cwd.txt').write_text(Path.cwd().as_posix())"
            ),
            preserve_workspace=True,
        )
    )

    workspace = Path(result.workspace_path)

    assert result.status == GuardedRunStatus.COMPLETED
    assert workspace.exists()
    assert (workspace / "cwd.txt").read_text(encoding="utf-8") == workspace.as_posix()
    assert not (repo / "cwd.txt").exists()


def test_successful_command_captures_stdout_stderr_and_duration(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("import sys; print('stdout-ok'); print('stderr-ok', file=sys.stderr)"),
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.command_result.exit_code == 0
    assert "stdout-ok" in result.command_result.stdout
    assert "stderr-ok" in result.command_result.stderr
    assert result.command_result.duration_ms >= 0


def test_failed_command_still_captures_changed_file_evidence(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; import sys; "
                "Path('failed.txt').write_text('evidence'); "
                "sys.exit(7)"
            ),
        )
    )

    assert result.status == GuardedRunStatus.FAILED
    assert result.command_result.exit_code == 7
    assert result.changed_file_report is not None
    assert any(file.path == "failed.txt" for file in result.changed_file_report.files)
    assert result.patch_diff is not None
    assert result.patch_diff.patch_sha256


def test_timeout_returns_structured_result_and_keeps_evidence(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; import time; "
                "Path('timeout.txt').write_text('evidence'); "
                "time.sleep(5)"
            ),
            timeout_seconds=1,
        )
    )

    assert result.status == GuardedRunStatus.TIMED_OUT
    assert result.command_result.exit_code is None
    assert result.command_result.timed_out is True
    assert result.changed_file_report is not None
    assert any(file.path == "timeout.txt" for file in result.changed_file_report.files)


def test_added_modified_deleted_files_are_detected_and_patch_is_generated(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; "
                "Path('new.txt').write_text('new'); "
                "Path('README.md').write_text('modified'); "
                "Path('delete_me.txt').unlink()"
            ),
        )
    )

    paths = {file.path for file in result.changed_file_report.files}

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert {"new.txt", "README.md", "delete_me.txt"}.issubset(paths)
    assert result.patch_diff is not None
    assert result.change_risk_report is not None
    assert result.blocked_reason is not None
    assert result.patch_diff.patch_sha256
    assert result.patch_diff.patch_size_bytes > 0


def test_raw_patch_content_is_not_written_to_audit_log(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(audit_path)
    marker = "raw-patch-secret-marker"

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(f"from pathlib import Path; Path('secret.txt').write_text('{marker}')"),
            audit_logger=audit,
        )
    )

    assert result.patch_diff is not None
    assert marker in result.patch_diff.patch
    assert marker not in audit_text(audit_path)
    assert audit.verify_integrity()


def test_cleanup_removes_workspace_by_default(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("from pathlib import Path; Path('agent.txt').write_text('ok')"),
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.cleanup_performed is True
    assert result.cleanup_status in {"cleaned_git", "cleaned_fallback"}
    assert not Path(result.workspace_path).exists()


def test_preserve_workspace_is_explicit(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("from pathlib import Path; Path('agent.txt').write_text('ok')"),
            preserve_workspace=True,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.cleanup_performed is False
    assert result.cleanup_status == "reset_success"
    assert Path(result.workspace_path).exists()


def test_cleanup_failure_is_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")

    def fake_destroy(worktree, config):
        return CleanupResult(
            status=CleanupStatus.CLEANUP_FAILED,
            message="simulated cleanup failure",
        )

    monkeypatch.setattr("rygnal.guarded_runner.destroy_worktree", fake_destroy)

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("from pathlib import Path; Path('agent.txt').write_text('ok')"),
        )
    )

    assert result.status == GuardedRunStatus.CLEANUP_FAILED
    assert result.cleanup_status == "cleanup_failed"
    assert any("simulated cleanup failure" in warning for warning in result.warnings)


def test_audit_lifecycle_events_and_hash_chain(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("from pathlib import Path; Path('agent.txt').write_text('ok')"),
            audit_logger=audit,
        )
    )

    actions = audit_actions(audit)

    assert result.status == GuardedRunStatus.COMPLETED
    assert "guarded_run.requested" in actions
    assert "guarded_run.backend_selected" in actions
    assert "guarded_run.workspace_created" in actions
    assert "guarded_run.command_started" in actions
    assert "guarded_run.command_completed" in actions
    assert "guarded_run.changed_files_detected" in actions
    assert "guarded_run.patch_generated" in actions
    assert "guarded_run.cleanup_started" in actions
    assert "guarded_run.cleanup_completed" in actions
    assert audit.verify_integrity()


def test_blocked_run_is_audited(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=(),
            rygnal_run_root=tmp_path / "runs",
            audit_logger=audit,
            trace_id="trace_test",
        )
    )

    actions = audit_actions(audit)

    assert result.status == GuardedRunStatus.BLOCKED
    assert "guarded_run.blocked" in actions
    assert audit.verify_integrity()


def test_bubblewrap_workspace_bind_uses_workspace_mount_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rygnal.guarded_runner as guarded_runner_module

    monkeypatch.setattr(
        guarded_runner_module.shutil,
        "which",
        lambda name: "/usr/bin/bwrap" if name == "bwrap" else None,
    )

    command = guarded_runner_module._build_bubblewrap_command(
        ("python", "-c", "print('ok')"),
        tmp_path,
    )

    writable_binds = [
        tuple(command[index + 1 : index + 3])
        for index, item in enumerate(command)
        if item == "--bind"
    ]

    assert writable_binds == [(tmp_path.resolve().as_posix(), "/workspace")]


@pytest.mark.skipif(
    not bwrap_probe_available(),
    reason="bubblewrap not installed or namespace probe unavailable",
)
def test_bubblewrap_backend_can_run_simple_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")

    monkeypatch.setattr(
        "rygnal.guarded_runner.detect_host_backend_capabilities",
        lambda env=None: HostBackendCapabilities(
            os_name="linux",
            has_bwrap=True,
            bwrap_namespace_probe_passed=True,
            signed_sandbox_helper_probe_passed=False,
            has_systemd_run=False,
            verified_rootless_container_available=False,
            unsafe_local_requested=False,
        ),
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command("from pathlib import Path; Path('bwrap.txt').write_text('ok')"),
            timeout_seconds=5,
            rygnal_run_root=tmp_path / "runs",
            preserve_workspace=True,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.backend_name == "linux_bubblewrap"
    assert result.containment_verified is True
    assert Path(result.workspace_path, "bwrap.txt").read_text(encoding="utf-8") == "ok"
    assert not (repo / "bwrap.txt").exists()


def test_high_risk_dependency_patch_requires_approval_before_completion(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; "
                "Path('pyproject.toml').write_text('[project]\\nname = \"changed\"\\n')"
            ),
            audit_logger=audit,
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.patch_diff is not None
    assert result.approval_request is not None
    assert result.approval_request.target == result.patch_diff.patch_sha256
    assert result.approval_request.requested_by == "local_user"
    assert result.approval_request.agent_id == "local_agent"
    assert result.approval_request.environment == "local"
    assert result.change_risk_report is not None
    assert result.change_risk_report.overall_risk_level == RiskLevel.HIGH
    assert "requires approval" in result.blocked_reason
    assert "guarded_run.patch_classified" in audit_actions(audit)
    assert "guarded_run.patch_approval_required" in audit_actions(audit)
    assert "guarded_run.patch_blocked" not in audit_actions(audit)
    assert result.cleanup_performed is True
    assert not Path(result.workspace_path).exists()
    assert audit.verify_integrity()


def test_high_risk_dependency_patch_submits_approval_to_configured_queue(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")
    queue = InMemoryApprovalQueue()

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; "
                "Path('pyproject.toml').write_text('[project]\\nname = \"changed\"\\n')"
            ),
            approval_queue=queue,
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.approval_request is not None

    queued = queue.get(result.approval_request.approval_id)
    assert queued.status == ApprovalStatus.PENDING
    assert queued.request == result.approval_request


def test_api_can_approve_guarded_run_request_from_shared_sqlite_queue(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")
    db_path = tmp_path / "approval_queue.db"
    client = TestClient(create_app(approval_queue_db_path=db_path))

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; "
                "Path('pyproject.toml').write_text('[project]\\nname = \"changed\"\\n')"
            ),
            approval_queue=SQLiteApprovalQueue(db_path),
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.approval_request is not None

    approval_id = result.approval_request.approval_id

    get_response = client.get(f"/v1/approvals/{approval_id}")
    assert get_response.status_code == 200
    pending = get_response.json()["approval"]
    assert pending["approval_id"] == approval_id
    assert pending["status"] == ApprovalStatus.PENDING.value
    assert pending["request"]["approval_id"] == approval_id

    approve_response = client.post(
        f"/v1/approvals/{approval_id}/approve",
        json={
            "decided_by": "security_reviewer",
            "reason": "Reviewed guarded patch through shared approval queue.",
        },
    )
    assert approve_response.status_code == 200
    approved = approve_response.json()["approval"]
    assert approved["approval_id"] == approval_id
    assert approved["status"] == ApprovalStatus.APPROVED.value
    assert approved["approval_decision"]["approval_id"] == approval_id

    reloaded = SQLiteApprovalQueue(db_path).get(approval_id)
    assert reloaded.status == ApprovalStatus.APPROVED
    assert reloaded.decision is not None
    assert reloaded.decision.decided_by == "security_reviewer"


def test_critical_secret_patch_is_blocked_before_completion(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; "
                "Path('.env').write_text('OPENAI_API_KEY=sk-testsecret000000000000\\n')"
            ),
            audit_logger=audit,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.patch_diff is not None
    assert result.approval_request is None
    assert result.change_risk_report is not None
    assert result.change_risk_report.overall_risk_level == RiskLevel.CRITICAL
    assert "blocked" in result.blocked_reason
    assert "critical risk" in result.blocked_reason
    assert "guarded_run.patch_blocked" in audit_actions(audit)
    assert result.cleanup_performed is True
    assert not Path(result.workspace_path).exists()
    assert audit.verify_integrity()


def test_subjective_locked_file_blocks_guarded_patch(tmp_path: Path) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    locked_file = repo / "src" / "payment.py"
    locked_file.parent.mkdir()
    locked_file.write_text(
        "# rygnal:lock\ndef charge():\n    return True\n",
        encoding="utf-8",
    )
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "add locked payment code")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; "
                "Path('src/payment.py').write_text("
                "'# rygnal:lock\\n"
                "def charge():\\n"
                "    return False\\n'"
                ")"
            ),
            audit_logger=audit,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.patch_diff is not None
    assert result.approval_request is None
    assert result.change_risk_report is not None
    assert result.change_risk_report.overall_risk_level == RiskLevel.CRITICAL
    assert result.blocked_reason is not None
    assert "critical risk" in result.blocked_reason

    report_reason_codes = {reason.code for reason in result.change_risk_report.report_reasons}
    assert "subjective-human-context-risk" in report_reason_codes

    subjective_reason = next(
        reason
        for reason in result.change_risk_report.report_reasons
        if reason.code == "subjective-human-context-risk"
    )
    evidence = dict(subjective_reason.evidence)

    assert evidence["path"] == "src/payment.py"
    assert evidence["judgment"] == "block"
    assert evidence["total_criticality"] == 10.0

    assert "guarded_run.patch_blocked" in audit_actions(audit)
    assert "guarded_run.patch_approval_required" not in audit_actions(audit)
    assert result.cleanup_performed is True
    assert not Path(result.workspace_path).exists()
    assert audit.verify_integrity()


def test_bubblewrap_command_contains_production_hardening_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rygnal.guarded_runner as guarded_runner_module

    monkeypatch.setattr(
        guarded_runner_module.shutil,
        "which",
        lambda name: "/usr/bin/bwrap" if name == "bwrap" else None,
    )

    command = guarded_runner_module._build_bubblewrap_command(
        ("python", "-c", "print('ok')"),
        tmp_path,
    )

    assert "--unshare-user" in command
    assert "--unshare-pid" in command
    assert "--unshare-ipc" in command
    assert "--unshare-uts" in command
    assert "--unshare-net" in command
    assert "--die-with-parent" in command
    assert "--clearenv" in command
    assert ["--proc", "/proc"] == command[command.index("--proc") : command.index("--proc") + 2]
    assert ["--dev", "/dev"] == command[command.index("--dev") : command.index("--dev") + 2]
    assert "/tmp" in [command[index + 1] for index, item in enumerate(command) if item == "--tmpfs"]
    assert "/var/tmp" in [
        command[index + 1] for index, item in enumerate(command) if item == "--tmpfs"
    ]


def test_bubblewrap_command_masks_host_identity_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rygnal.guarded_runner as guarded_runner_module

    monkeypatch.setattr(
        guarded_runner_module.shutil,
        "which",
        lambda name: "/usr/bin/bwrap" if name == "bwrap" else None,
    )

    command = guarded_runner_module._build_bubblewrap_command(
        ("python", "-c", "print('ok')"),
        tmp_path,
    )

    ro_binds = [
        tuple(command[index + 1 : index + 3])
        for index, item in enumerate(command)
        if item == "--ro-bind"
    ]

    passwd_sources = [source for source, dest in ro_binds if dest == "/etc/passwd"]
    group_sources = [source for source, dest in ro_binds if dest == "/etc/group"]

    assert passwd_sources
    assert group_sources
    assert "/etc/passwd" not in passwd_sources
    assert "/etc/group" not in group_sources

    passwd_text = Path(passwd_sources[0]).read_text(encoding="utf-8")
    group_text = Path(group_sources[0]).read_text(encoding="utf-8")

    assert "rygnal:x:" in passwd_text
    assert "Rygnal Sandbox User" in passwd_text
    assert "rygnal:x:" in group_text


def test_bubblewrap_command_binds_only_workspace_as_writable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rygnal.guarded_runner as guarded_runner_module

    monkeypatch.setattr(
        guarded_runner_module.shutil,
        "which",
        lambda name: "/usr/bin/bwrap" if name == "bwrap" else None,
    )

    command = guarded_runner_module._build_bubblewrap_command(
        ("python", "-c", "print('ok')"),
        tmp_path,
    )

    writable_binds = [
        tuple(command[index + 1 : index + 3])
        for index, item in enumerate(command)
        if item == "--bind"
    ]

    assert writable_binds == [(tmp_path.resolve().as_posix(), "/workspace")]
    assert ["--chdir", "/workspace"] == command[
        command.index("--chdir") : command.index("--chdir") + 2
    ]


@pytest.mark.skipif(
    not bwrap_probe_available(),
    reason="bubblewrap not installed or namespace probe unavailable",
)
def test_bubblewrap_backend_blocks_network_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")

    monkeypatch.setattr(
        "rygnal.guarded_runner.detect_host_backend_capabilities",
        lambda env=None: HostBackendCapabilities(
            os_name="linux",
            has_bwrap=True,
            bwrap_namespace_probe_passed=True,
            signed_sandbox_helper_probe_passed=False,
            has_systemd_run=False,
            verified_rootless_container_available=False,
            unsafe_local_requested=False,
        ),
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command(
                "import socket; "
                "blocked = False; "
                "s = socket.socket(); "
                "s.settimeout(1); "
                "\\ntry:\\n"
                "    s.connect(('1.1.1.1', 443))\\n"
                "except OSError:\\n"
                "    blocked = True\\n"
                "print('network-blocked' if blocked else 'network-open')"
            ),
            timeout_seconds=5,
            rygnal_run_root=tmp_path / "runs",
            preserve_workspace=True,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.command_result is not None
    assert "network-blocked" in result.command_result.stdout


@pytest.mark.skipif(
    not bwrap_probe_available(),
    reason="bubblewrap not installed or namespace probe unavailable",
)
def test_bubblewrap_backend_clears_host_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")
    monkeypatch.setenv("RYGNAL_TEST_SECRET", "super_secret_value")

    monkeypatch.setattr(
        "rygnal.guarded_runner.detect_host_backend_capabilities",
        lambda env=None: HostBackendCapabilities(
            os_name="linux",
            has_bwrap=True,
            bwrap_namespace_probe_passed=True,
            signed_sandbox_helper_probe_passed=False,
            has_systemd_run=False,
            verified_rootless_container_available=False,
            unsafe_local_requested=False,
        ),
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command(
                "import os; "
                "print("
                "'secret-visible' if 'RYGNAL_TEST_SECRET' in os.environ "
                "else 'secret-cleared'"
                ")"
            ),
            timeout_seconds=5,
            rygnal_run_root=tmp_path / "runs",
            preserve_workspace=True,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.command_result is not None
    assert "secret-cleared" in result.command_result.stdout


@pytest.mark.skipif(
    not bwrap_probe_available(),
    reason="bubblewrap not installed or namespace probe unavailable",
)
def test_bubblewrap_backend_keeps_tmp_paths_sandbox_local(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")
    marker = f"rygnal_tmp_escape_{tmp_path.name}"

    host_tmp = Path("/tmp") / marker
    host_var_tmp = Path("/var/tmp") / marker

    host_tmp.unlink(missing_ok=True)
    host_var_tmp.unlink(missing_ok=True)

    monkeypatch.setattr(
        "rygnal.guarded_runner.detect_host_backend_capabilities",
        lambda env=None: HostBackendCapabilities(
            os_name="linux",
            has_bwrap=True,
            bwrap_namespace_probe_passed=True,
            signed_sandbox_helper_probe_passed=False,
            has_systemd_run=False,
            verified_rootless_container_available=False,
            unsafe_local_requested=False,
        ),
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command(
                "from pathlib import Path; "
                f"Path('/tmp/{marker}').write_text('tmp', encoding='utf-8'); "
                f"Path('/var/tmp/{marker}').write_text('var_tmp', encoding='utf-8'); "
                "print('tmp-private')"
            ),
            timeout_seconds=5,
            rygnal_run_root=tmp_path / "runs",
            preserve_workspace=True,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.command_result is not None
    assert "tmp-private" in result.command_result.stdout
    assert not host_tmp.exists()
    assert not host_var_tmp.exists()


@pytest.mark.skipif(
    not bwrap_probe_available(),
    reason="bubblewrap not installed or namespace probe unavailable",
)
def test_bubblewrap_backend_blocks_outside_workspace_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_repo(tmp_path / "repo")

    monkeypatch.setattr(
        "rygnal.guarded_runner.detect_host_backend_capabilities",
        lambda env=None: HostBackendCapabilities(
            os_name="linux",
            has_bwrap=True,
            bwrap_namespace_probe_passed=True,
            signed_sandbox_helper_probe_passed=False,
            has_systemd_run=False,
            verified_rootless_container_available=False,
            unsafe_local_requested=False,
        ),
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=py_command(
                "from pathlib import Path; "
                "\\ntry:\\n"
                "    Path('/etc/rygnal_escape').write_text('bad', encoding='utf-8')\\n"
                "    print('outside-write-open')\\n"
                "except OSError:\\n"
                "    print('outside-write-blocked')"
            ),
            timeout_seconds=5,
            rygnal_run_root=tmp_path / "runs",
            preserve_workspace=True,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.command_result is not None
    assert "outside-write-blocked" in result.command_result.stdout


def test_guarded_run_audits_command_intent_before_execution_for_dirty_repo(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")
    (repo / "README.md").write_text("# dirty\n", encoding="utf-8")

    result = run_guarded(
        unsafe_config(
            repo,
            ("rm", "-rf", "tmp"),
            audit_logger=audit,
        )
    )

    actions = audit_actions(audit)
    intent_event = next(
        event
        for event in audit.read_events()
        if event.action == "guarded_run.command_intent_classified"
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.command_result is None
    assert "guarded_run.command_intent_classified" in actions
    assert "guarded_run.command_started" not in actions
    assert actions.index("guarded_run.command_intent_classified") < actions.index(
        "guarded_run.blocked"
    )
    assert "filesystem_destructive" in intent_event.metadata["intent_codes"]
    assert intent_event.metadata["max_severity"] == "critical"
    assert intent_event.metadata["recommended_action"] == "block"
    assert intent_event.metadata["intents"]
    assert audit.verify_integrity()


def test_guarded_run_records_normalized_command_before_dirty_repo_block(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")
    (repo / "README.md").write_text("# dirty\n", encoding="utf-8")

    result = run_guarded(
        unsafe_config(
            repo,
            ("rm", "-rf", "dist"),
            audit_logger=audit,
        )
    )

    actions = audit_actions(audit)
    normalized_event = next(
        event
        for event in audit.read_events()
        if event.action == "guarded_run.normalized_command_prepared"
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.normalized_actions
    assert result.normalized_actions[0].operation.value == "delete_folder"
    assert "guarded_run.normalized_command_prepared" in actions
    assert "guarded_run.command_started" not in actions
    assert actions.index("guarded_run.normalized_command_prepared") < actions.index(
        "guarded_run.blocked"
    )
    assert normalized_event.metadata["normalized_actions"]["action_count"] == 1
    assert normalized_event.metadata["normalized_actions"]["operation_counts"] == {
        "delete_folder": 1
    }


def test_guarded_run_records_normalized_actions_for_noop_run(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")
    audit = AuditLogger(tmp_path / "audit.jsonl")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("print('noop')"),
            audit_logger=audit,
        )
    )

    normalized_event = next(
        event
        for event in audit.read_events()
        if event.action == "guarded_run.normalized_actions_recorded"
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert len(result.normalized_actions) == 1
    assert result.normalized_actions[0].source.value == "command"
    assert normalized_event.metadata["normalized_actions"]["action_count"] == 1
    assert normalized_event.metadata["changed_files_detected"] is True
    assert normalized_event.metadata["patch_generated"] is False
    assert audit.verify_integrity()


def test_failed_guarded_run_exposes_normalized_file_effects(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; import sys; "
                "Path('failed_normalized.py').write_text('evidence'); "
                "sys.exit(7)"
            ),
        )
    )

    assert result.status == GuardedRunStatus.FAILED
    assert any(
        action.operation.value == "create" and action.affected_paths == ("failed_normalized.py",)
        for action in result.normalized_actions
    )


def test_timeout_guarded_run_exposes_normalized_file_effects(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command(
                "from pathlib import Path; import time; "
                "Path('timeout_normalized.py').write_text('evidence'); "
                "time.sleep(5)"
            ),
            timeout_seconds=1,
        )
    )

    assert result.status == GuardedRunStatus.TIMED_OUT
    assert any(
        action.operation.value == "create" and action.affected_paths == ("timeout_normalized.py",)
        for action in result.normalized_actions
    )


def test_guarded_run_normalized_actions_include_patch_metadata(
    tmp_path: Path,
) -> None:
    repo = create_repo(tmp_path / "repo")

    result = run_guarded(
        unsafe_config(
            repo,
            py_command("from pathlib import Path; Path('normalized_patch.py').write_text('x')"),
        )
    )

    file_actions = [
        action
        for action in result.normalized_actions
        if action.source.value == "filesystem" and action.affected_paths == ("normalized_patch.py",)
    ]

    assert result.patch_diff is not None
    assert file_actions
    assert file_actions[0].diff_metadata["file_patch_present"] is True
    assert file_actions[0].diff_metadata["patch_sha256"] == result.patch_diff.patch_sha256
