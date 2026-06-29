import subprocess
from pathlib import Path

import pytest

from rygnal.audit_logger import AuditLogger
from rygnal.recovery_session import (
    RecoverySessionConfig,
    RecoverySessionError,
    create_recovery_session,
)
from rygnal.untracked_files import (
    UntrackedFileDecision,
    UntrackedFilePolicy,
    UntrackedFilesError,
    detect_untracked_files,
    verify_untracked_files_handled,
)


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def trusted_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "trusted"
    repo.mkdir()

    run_git(repo, "init")
    run_git(repo, "config", "user.email", "test@example.com")
    run_git(repo, "config", "user.name", "Test User")

    (repo / "README.md").write_text("# Project\n", encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "baseline")

    return repo


def test_detects_untracked_files_with_machine_safe_paths(trusted_repo: Path) -> None:
    (trusted_repo / "notes with spaces.txt").write_text("draft\n", encoding="utf-8")

    report = detect_untracked_files(trusted_repo)

    assert report.has_untracked_files is True
    assert report.blocked is True
    assert report.files[0].path == "notes with spaces.txt"
    assert report.files[0].decision == UntrackedFileDecision.BLOCK


def test_preserve_and_warn_policy_does_not_block_normal_untracked_file(
    trusted_repo: Path,
) -> None:
    (trusted_repo / "scratch.txt").write_text("draft\n", encoding="utf-8")

    report = verify_untracked_files_handled(
        trusted_repo,
        policy=UntrackedFilePolicy.PRESERVE_AND_WARN,
    )

    assert report.blocked is False
    assert report.preserved[0].path == "scratch.txt"
    assert report.preserved[0].decision == UntrackedFileDecision.PRESERVE_IN_TRUSTED_REPO


def test_sensitive_untracked_file_blocks_even_with_preserve_policy(
    trusted_repo: Path,
) -> None:
    (trusted_repo / ".env").write_text("TOKEN=example\n", encoding="utf-8")

    with pytest.raises(UntrackedFilesError):
        verify_untracked_files_handled(
            trusted_repo,
            policy=UntrackedFilePolicy.PRESERVE_AND_WARN,
        )


def test_gitignored_untracked_file_is_not_reported(trusted_repo: Path) -> None:
    (trusted_repo / ".gitignore").write_text("cache/\n", encoding="utf-8")
    run_git(trusted_repo, "add", ".gitignore")
    run_git(trusted_repo, "commit", "-m", "ignore cache")

    cache = trusted_repo / "cache"
    cache.mkdir()
    (cache / "generated.txt").write_text("generated\n", encoding="utf-8")

    report = detect_untracked_files(trusted_repo)

    assert report.has_untracked_files is False
    assert report.files == ()


def test_untracked_file_audit_records_preserve_decision(
    trusted_repo: Path,
    tmp_path: Path,
) -> None:
    (trusted_repo / "scratch.txt").write_text("draft\n", encoding="utf-8")
    logger = AuditLogger(tmp_path / "audit.jsonl")

    report = verify_untracked_files_handled(
        trusted_repo,
        policy=UntrackedFilePolicy.PRESERVE_AND_WARN,
        logger=logger,
        user_id="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_untracked",
    )

    events = logger.read_events()

    assert report.blocked is False
    assert len(events) == 1
    assert events[0].decision == "allow"
    assert events[0].policy_id == "guarded-workspace-untracked-file-handling"
    assert logger.verify_integrity() is True


def test_default_recovery_session_creation_blocks_untracked_files(
    trusted_repo: Path,
    tmp_path: Path,
) -> None:
    (trusted_repo / "scratch.txt").write_text("draft\n", encoding="utf-8")
    run_root = tmp_path / "runs"

    with pytest.raises(RecoverySessionError, match="untracked"):
        create_recovery_session(
            RecoverySessionConfig(
                trusted_repo_path=trusted_repo,
                rygnal_run_root=run_root,
            )
        )

    assert (trusted_repo / "scratch.txt").exists()
    assert not run_root.exists()


def test_preserve_policy_creates_worktree_without_copying_untracked_file(
    trusted_repo: Path,
    tmp_path: Path,
) -> None:
    (trusted_repo / "scratch.txt").write_text("draft\n", encoding="utf-8")
    logger = AuditLogger(tmp_path / "audit.jsonl")

    worktree = create_recovery_session(
        RecoverySessionConfig(
            trusted_repo_path=trusted_repo,
            rygnal_run_root=tmp_path / "runs",
            untracked_policy=UntrackedFilePolicy.PRESERVE_AND_WARN,
            audit_logger=logger,
        )
    )

    assert (trusted_repo / "scratch.txt").exists()
    assert (worktree.workspace_path / "scratch.txt").exists()
    assert logger.verify_integrity() is True


def test_sensitive_untracked_file_blocks_worktree_creation(
    trusted_repo: Path,
    tmp_path: Path,
) -> None:
    (trusted_repo / ".env").write_text("TOKEN=example\n", encoding="utf-8")

    with pytest.raises(RecoverySessionError):
        create_recovery_session(
            RecoverySessionConfig(
                trusted_repo_path=trusted_repo,
                rygnal_run_root=tmp_path / "runs",
                untracked_policy=UntrackedFilePolicy.PRESERVE_AND_WARN,
            )
        )
