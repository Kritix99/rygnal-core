from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from rygnal.recovery_session import (
    CleanupStatus,
    RecoverySession,
    RecoverySessionConfig,
    RecoverySessionError,
    create_recovery_session,
    destroy_recovery_session,
)
from rygnal.untracked_files import UntrackedFilePolicy


def git(repo: Path, *args: str) -> str:
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
    git(path, "init")
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "user.name", "Test User")
    (path / "README.md").write_text("baseline\n", encoding="utf-8")
    git(path, "add", ".")
    git(path, "commit", "-m", "baseline")
    return path.resolve()


def registered_worktrees(repo: Path) -> tuple[Path, ...]:
    output = git(repo, "worktree", "list", "--porcelain")
    return tuple(
        Path(line.removeprefix("worktree ")).resolve()
        for line in output.splitlines()
        if line.startswith("worktree ")
    )


def test_create_recovery_session_creates_detached_worktree_under_run_root(
    tmp_path: Path,
) -> None:
    trusted = create_repo(tmp_path / "trusted")
    run_root = tmp_path / "run-root"
    baseline = git(trusted, "rev-parse", "HEAD")

    session = create_recovery_session(
        RecoverySessionConfig(
            trusted_repo_path=trusted,
            rygnal_run_root=run_root,
        )
    )

    try:
        assert session.trusted_repo_path == trusted
        assert session.workspace_path != trusted
        assert session.workspace_path.is_dir()
        assert run_root.resolve() in session.workspace_path.parents
        assert session.baseline_commit_sha == baseline
        assert git(session.workspace_path, "rev-parse", "HEAD") == baseline

        symbolic_ref = subprocess.run(
            ["git", "symbolic-ref", "-q", "HEAD"],
            cwd=session.workspace_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert symbolic_ref.returncode != 0
        assert session.workspace_path in registered_worktrees(trusted)
        assert session.owner_marker_path is not None
        assert session.owner_marker_path.is_file()
        assert session.timeline_dir.parent == run_root.resolve() / "timelines"
    finally:
        result = destroy_recovery_session(
            session,
            RecoverySessionConfig(
                trusted_repo_path=trusted,
                rygnal_run_root=run_root,
            ),
        )

    assert result.status == CleanupStatus.CLEANED_GIT
    assert not session.workspace_path.exists()
    assert session.workspace_path not in registered_worktrees(trusted)
    assert trusted.is_dir()
    assert (trusted / "README.md").read_text(encoding="utf-8") == "baseline\n"


def test_trusted_untracked_file_is_not_exposed_to_preserved_policy_workspace(
    tmp_path: Path,
) -> None:
    trusted = create_repo(tmp_path / "trusted")
    run_root = tmp_path / "run-root"
    secret = trusted / "scratch.txt"
    secret.write_text("trusted-only\n", encoding="utf-8")

    session = create_recovery_session(
        RecoverySessionConfig(
            trusted_repo_path=trusted,
            rygnal_run_root=run_root,
            untracked_policy=UntrackedFilePolicy.PRESERVE_AND_WARN,
        )
    )

    try:
        assert secret.exists()
        assert not (session.workspace_path / "scratch.txt").exists()
    finally:
        result = destroy_recovery_session(
            session,
            RecoverySessionConfig(
                trusted_repo_path=trusted,
                rygnal_run_root=run_root,
                untracked_policy=UntrackedFilePolicy.PRESERVE_AND_WARN,
            ),
        )

    assert result.status == CleanupStatus.CLEANED_GIT
    assert secret.read_text(encoding="utf-8") == "trusted-only\n"


def test_cleanup_refuses_workspace_outside_controlled_root(
    tmp_path: Path,
) -> None:
    trusted = create_repo(tmp_path / "trusted")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("do-not-delete\n", encoding="utf-8")

    fake_session = RecoverySession(
        run_id="fake-run",
        trusted_repo_path=trusted,
        execution_path=outside,
        baseline_commit_sha=git(trusted, "rev-parse", "HEAD"),
        timeline_dir=tmp_path / "timeline",
        owner_marker_path=None,
        run_root=tmp_path / "run-root",
    )

    result = destroy_recovery_session(
        fake_session,
        RecoverySessionConfig(
            trusted_repo_path=trusted,
            rygnal_run_root=tmp_path / "run-root",
        ),
    )

    assert result.status == CleanupStatus.CLEANUP_FAILED
    assert outside.is_dir()
    assert sentinel.read_text(encoding="utf-8") == "do-not-delete\n"


def test_create_recovery_session_blocks_run_root_inside_trusted_repo(
    tmp_path: Path,
) -> None:
    trusted = create_repo(tmp_path / "trusted")

    with pytest.raises(RecoverySessionError, match="inside the trusted"):
        create_recovery_session(
            RecoverySessionConfig(
                trusted_repo_path=trusted,
                rygnal_run_root=trusted / ".rygnal" / "runs",
            )
        )


def test_create_recovery_session_blocks_git_submodules(
    tmp_path: Path,
) -> None:
    trusted = create_repo(tmp_path / "trusted")
    child = create_repo(tmp_path / "child")

    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            child.as_posix(),
            "vendor/child",
        ],
        cwd=trusted,
        check=True,
        capture_output=True,
        text=True,
    )
    git(trusted, "commit", "-am", "add submodule")

    with pytest.raises(RecoverySessionError, match="submodules"):
        create_recovery_session(
            RecoverySessionConfig(
                trusted_repo_path=trusted,
                rygnal_run_root=tmp_path / "run-root",
            )
        )
