from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import rygnal.guarded_runner as guarded_runner
from rygnal.audit_logger import AuditLogger
from rygnal.guarded_runner import (
    GuardedRunConfig,
    GuardedRunStatus,
    _build_bubblewrap_command,
    run_guarded,
)
from rygnal.production_containment import (
    BubblewrapVerification,
    ExecutionSecurityMode,
    ProductionContainmentLimits,
    execution_security_mode,
    production_bubblewrap_hardening_flags,
    run_bounded_process,
    verify_production_bubblewrap,
)
from rygnal.resource_limited_exec import (
    _bounded_soft_limit,
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
    git(
        path,
        "config",
        "user.email",
        "m15@example.com",
    )
    git(
        path,
        "config",
        "user.name",
        "M15 Test",
    )

    (path / "README.md").write_text(
        "# M15\n",
        encoding="utf-8",
    )

    git(path, "add", ".")
    git(path, "commit", "-m", "baseline")
    return path


def ineligible(
    reason: str = "verification unavailable",
) -> BubblewrapVerification:
    return BubblewrapVerification(
        eligible=False,
        platform_name="darwin",
        executable_path=None,
        executable_sha256=None,
        version=None,
        reasons=(reason,),
        features={
            "production_mode": True,
            "linux_host": False,
        },
    )


def eligible() -> BubblewrapVerification:
    return BubblewrapVerification(
        eligible=True,
        platform_name="linux",
        executable_path="/usr/bin/bwrap",
        executable_sha256="a" * 64,
        version="0.11.0",
        reasons=(),
        features={
            "production_mode": True,
            "linux_host": True,
            "secure_executable": True,
            "version_verified": True,
            "required_flags_verified": True,
            "behavioral_self_test": True,
            "user_namespace": True,
            "pid_namespace": True,
            "ipc_namespace": True,
            "uts_namespace": True,
            "net_namespace": True,
            "cgroup_namespace": True,
            "capabilities_dropped": True,
            "no_new_privileges": True,
            "host_environment_cleared": True,
            "host_tmp_hidden": True,
            "resource_limits_enforced": True,
            "output_bounded": True,
            "inherited_fds_closed": True,
        },
    )


def test_execution_mode_is_explicit() -> None:
    assert execution_security_mode("production") == ExecutionSecurityMode.PRODUCTION
    assert execution_security_mode("PRODUCTION") == ExecutionSecurityMode.PRODUCTION
    assert execution_security_mode("local") == ExecutionSecurityMode.DEVELOPMENT


def test_non_linux_production_verification_fails_closed() -> None:
    result = verify_production_bubblewrap(
        platform_name="Darwin",
        executable_path=None,
    )

    assert result.eligible is False
    assert result.features["linux_host"] is False
    assert "Linux" in result.reason


def test_production_mode_blocks_before_command_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = create_repo(tmp_path / "repo")
    outside = tmp_path / "must-not-exist"

    monkeypatch.setattr(
        guarded_runner,
        "verify_production_bubblewrap",
        lambda: ineligible("Bubblewrap unavailable on this host."),
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repository,
            command=(
                sys.executable,
                "-c",
                (f"from pathlib import Path; Path({str(outside)!r}).write_text('bad')"),
            ),
            rygnal_run_root=tmp_path / "runs",
            environment="production",
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.command_result is None
    assert not outside.exists()
    assert "Production containment unavailable" in (result.blocked_reason or "")


def test_unsafe_local_is_prohibited_in_production(
    tmp_path: Path,
) -> None:
    repository = create_repo(tmp_path / "repo")

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repository,
            command=(
                sys.executable,
                "-c",
                "print('must not run')",
            ),
            rygnal_run_root=tmp_path / "runs",
            environment="production",
            unsafe_local_requested=True,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.command_result is None
    assert "prohibited" in (result.blocked_reason or "").lower()


def test_production_failure_is_audited(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = create_repo(tmp_path / "repo")
    logger = AuditLogger(tmp_path / "audit.jsonl")

    monkeypatch.setattr(
        guarded_runner,
        "verify_production_bubblewrap",
        lambda: ineligible("Behavioral probe failed."),
    )

    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repository,
            command=(
                sys.executable,
                "-c",
                "print('blocked')",
            ),
            rygnal_run_root=tmp_path / "runs",
            environment="production",
            audit_logger=logger,
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert logger.verify_integrity() is True

    events = logger.read_events()

    assert any("Behavioral probe failed" in event.reason for event in events)


def test_production_bubblewrap_flags_are_mandatory() -> None:
    flags = production_bubblewrap_hardening_flags()

    for required in (
        "--die-with-parent",
        "--new-session",
        "--unshare-cgroup",
        "--cap-drop",
        "ALL",
    ):
        assert required in flags


def test_production_command_contains_hardening_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monkeypatch.setattr(
        guarded_runner.shutil,
        "which",
        lambda name: "/usr/bin/bwrap" if name == "bwrap" else None,
    )

    command = _build_bubblewrap_command(
        ("/bin/true",),
        workspace,
        production=True,
    )

    for required in (
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-net",
        "--unshare-cgroup",
        "--cap-drop",
        "ALL",
        "--clearenv",
    ):
        assert required in command


def test_production_command_has_only_workspace_writable_bind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monkeypatch.setattr(
        guarded_runner.shutil,
        "which",
        lambda name: "/usr/bin/bwrap" if name == "bwrap" else None,
    )

    command = _build_bubblewrap_command(
        ("/bin/true",),
        workspace,
        production=True,
    )

    writable: list[tuple[str, str]] = []

    for index, value in enumerate(command):
        if value == "--bind":
            writable.append(
                (
                    command[index + 1],
                    command[index + 2],
                )
            )

    assert writable == [
        (
            workspace.resolve().as_posix(),
            "/workspace",
        )
    ]


def test_containment_limits_reject_invalid_values() -> None:
    with pytest.raises(ValueError):
        ProductionContainmentLimits(cpu_seconds=0)

    with pytest.raises(ValueError):
        ProductionContainmentLimits(
            file_size_bytes=1024,
            max_output_bytes=2048,
        )


@pytest.mark.skipif(
    os.name != "posix",
    reason="Resource-limit test requires POSIX.",
)
def test_output_capture_is_bounded(
    tmp_path: Path,
) -> None:
    limits = ProductionContainmentLimits(
        cpu_seconds=10,
        address_space_bytes=512 * 1024**2,
        file_size_bytes=2 * 1024**2,
        open_files=128,
        processes=32,
        max_output_bytes=4096,
    )

    result = run_bounded_process(
        (
            sys.executable,
            "-c",
            ("import sys; sys.stdout.write('x' * 100000); sys.stderr.write('y' * 100000)"),
        ),
        cwd=tmp_path,
        timeout_seconds=10,
        limits=limits,
    )

    assert result.timed_out is False
    assert result.output_truncated is True
    assert (
        len(
            result.stdout.encode(
                "utf-8",
                errors="replace",
            )
        )
        <= limits.max_output_bytes
    )
    assert "truncated" in result.stderr.lower()


@pytest.mark.skipif(
    os.name != "posix",
    reason="Timeout tree cleanup requires POSIX.",
)
def test_bounded_process_timeout_returns_partial_output(
    tmp_path: Path,
) -> None:
    limits = ProductionContainmentLimits(
        cpu_seconds=10,
        address_space_bytes=512 * 1024**2,
        file_size_bytes=2 * 1024**2,
        open_files=128,
        processes=32,
        max_output_bytes=4096,
    )

    result = run_bounded_process(
        (
            sys.executable,
            "-c",
            ("import sys, time; print('before-timeout', flush=True); time.sleep(10)"),
        ),
        cwd=tmp_path,
        timeout_seconds=1,
        limits=limits,
    )

    assert result.timed_out is True
    assert "before-timeout" in result.stdout


def test_fake_old_bubblewrap_is_rejected(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "bwrap"
    executable.write_text(
        "#!/bin/sh\nexit 0\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)

    def runner(
        command: Any,
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        if "--version" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="bubblewrap 0.7.0\n",
                stderr="",
            )

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=" ".join(
                (
                    "--die-with-parent",
                    "--new-session",
                    "--unshare-user",
                    "--unshare-pid",
                    "--unshare-ipc",
                    "--unshare-uts",
                    "--unshare-net",
                    "--unshare-cgroup",
                    "--cap-drop",
                    "--clearenv",
                    "--proc",
                    "--dev",
                    "--tmpfs",
                    "--ro-bind",
                    "--bind",
                    "--setenv",
                    "--chdir",
                )
            ),
            stderr="",
        )

    result = verify_production_bubblewrap(
        platform_name="Linux",
        executable_path=executable,
        command_runner=runner,
    )

    assert result.eligible is False
    assert "older" in result.reason


def test_group_writable_bubblewrap_is_rejected(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "bwrap"
    executable.write_text(
        "#!/bin/sh\nexit 0\n",
        encoding="utf-8",
    )
    executable.chmod(0o720)

    result = verify_production_bubblewrap(
        platform_name="Linux",
        executable_path=executable,
    )

    assert result.eligible is False
    assert "writable" in result.reason


@pytest.mark.skipif(
    platform.system() != "Linux" or shutil.which("bwrap") is None,
    reason=("Actual production containment requires Linux and Bubblewrap."),
)
def test_actual_linux_production_containment(
    tmp_path: Path,
) -> None:
    verification = verify_production_bubblewrap()

    assert verification.eligible is True, f"Failed reasons: {verification.reasons}"
    assert verification.features["behavioral_self_test"]
    assert verification.features["net_namespace"]
    assert verification.features["cgroup_namespace"]
    assert verification.features["capabilities_dropped"]
    assert verification.features["no_new_privileges"]
    assert verification.features["host_environment_cleared"]


def test_resource_launcher_never_changes_hard_ceiling() -> None:
    assert (
        _bounded_soft_limit(
            requested=2048,
            current_soft=1024,
            current_hard=4096,
            infinity=-1,
        )
        == 1024
    )
    assert (
        _bounded_soft_limit(
            requested=2048,
            current_soft=-1,
            current_hard=4096,
            infinity=-1,
        )
        == 2048
    )
    assert (
        _bounded_soft_limit(
            requested=2048,
            current_soft=-1,
            current_hard=-1,
            infinity=-1,
        )
        == 2048
    )


def test_zero_soft_limit_is_supported_for_core_dumps() -> None:
    assert (
        _bounded_soft_limit(
            requested=0,
            current_soft=1024,
            current_hard=4096,
            infinity=-1,
        )
        == 0
    )

    try:
        _bounded_soft_limit(
            requested=-1,
            current_soft=1024,
            current_hard=4096,
            infinity=-1,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Negative resource limit was accepted.")
