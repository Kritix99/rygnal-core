"""In-repo recovery session foundation for Rygnal."""

from __future__ import annotations

import os
import subprocess  # nosec B404
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from rygnal.audit_logger import AuditLogger
from rygnal.untracked_files import UntrackedFilePolicy


class RecoverySessionError(Exception):
    """Raised when recovery session creation or validation fails."""


@dataclass(frozen=True)
class RecoverySessionConfig:
    """Configuration for creating an in-repo recovery session."""

    trusted_repo_path: Path
    untracked_policy: UntrackedFilePolicy = UntrackedFilePolicy.BLOCK
    audit_logger: AuditLogger | None = None
    rygnal_run_root: Path | None = None


@dataclass(frozen=True)
class RecoverySession:
    """Metadata for an active in-repo Rygnal recovery session."""

    run_id: str
    trusted_repo_path: Path
    execution_path: Path
    baseline_commit_sha: str
    timeline_dir: Path

    @property
    def workspace_path(self) -> Path:
        """Backward-compatible path for old guarded runner fields."""
        return self.execution_path


def _run_git(args: list[str], cwd: Path) -> str:
    env = os.environ.copy()
    env.pop("GIT_WORK_TREE", None)
    env.pop("GIT_DIR", None)

    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        error_msg = exc.stderr.strip() or exc.stdout.strip()
        raise RecoverySessionError(f"Git operation failed: {error_msg}") from exc


def detect_trusted_repo_root(cwd: Path | str) -> Path:
    target = Path(cwd).resolve()
    try:
        root_str = _run_git(["rev-parse", "--show-toplevel"], cwd=target)
        return Path(root_str).resolve()
    except RecoverySessionError as exc:
        raise RecoverySessionError(f"Directory is not a valid Git repository: {target}") from exc


def _untracked_paths(repo_root: Path) -> tuple[str, ...]:
    """Return untracked repo paths using Git porcelain output."""
    status = _run_git(
        ["status", "--porcelain", "--untracked-files=normal"],
        cwd=repo_root,
    )
    return tuple(
        line[3:].strip()
        for line in status.splitlines()
        if line.startswith("?? ")
    )


_SENSITIVE_UNTRACKED_NAMES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".npmrc",
    ".pypirc",
}


def _is_sensitive_untracked_path(path: str) -> bool:
    name = Path(path).name
    return name in _SENSITIVE_UNTRACKED_NAMES or "secret" in name.lower()


def create_recovery_session(config: RecoverySessionConfig) -> RecoverySession:
    repo_root = config.trusted_repo_path.resolve()

    if not repo_root.is_dir():
        raise RecoverySessionError(f"Trusted repository path does not exist: {repo_root}")

    try:
        is_bare = _run_git(["rev-parse", "--is-bare-repository"], cwd=repo_root)
    except RecoverySessionError as exc:
        raise RecoverySessionError(
            f"Trusted repository not found or invalid at: {repo_root}"
        ) from exc

    if is_bare == "true":
        raise RecoverySessionError("Bare repositories are not supported for recovery sessions.")

    if config.untracked_policy == UntrackedFilePolicy.BLOCK:
        untracked_paths = _untracked_paths(repo_root)
        if untracked_paths:
            listed = ", ".join(untracked_paths[:5])
            suffix = (
                "" if len(untracked_paths) <= 5 else f", and {len(untracked_paths) - 5} more"
            )
            raise RecoverySessionError(
                "untracked files must be committed, ignored, or explicitly preserved "
                f"before running Rygnal: {listed}{suffix}"
            )

    untracked_paths = _untracked_paths(repo_root)
    sensitive_untracked_paths = tuple(
        path for path in untracked_paths if _is_sensitive_untracked_path(path)
    )
    if sensitive_untracked_paths:
        listed = ", ".join(sensitive_untracked_paths[:5])
        suffix = (
            ""
            if len(sensitive_untracked_paths) <= 5
            else f", and {len(sensitive_untracked_paths) - 5} more"
        )
        raise RecoverySessionError(
            "untracked sensitive files must be committed, ignored, or removed "
            f"before running Rygnal: {listed}{suffix}"
        )

    baseline_sha = _run_git(["rev-parse", "HEAD"], cwd=repo_root)
    if len(baseline_sha) != 40:
        raise RecoverySessionError(
            f"Failed to capture valid baseline commit SHA: {baseline_sha}"
        )

    run_id = str(uuid.uuid4())
    timeline_dir = repo_root / ".rygnal" / "timeline" / run_id
    # Timeline directory is created lazily when timeline entries are written.

    return RecoverySession(
        run_id=run_id,
        trusted_repo_path=repo_root,
        execution_path=repo_root,
        baseline_commit_sha=baseline_sha,
        timeline_dir=timeline_dir,
    )


class CleanupStatus(StrEnum):
    """Compatibility cleanup status for the in-repo recovery model."""

    CLEANED_GIT = "recovery_session_preserved"
    CLEANED_FALLBACK = "recovery_session_preserved"
    RESET_SUCCESS = "reset_success"
    CLEANUP_FAILED = "cleanup_failed"


@dataclass(frozen=True)
class CleanupResult:
    """Compatibility cleanup result for the in-repo recovery model."""

    status: CleanupStatus
    message: str
    prune_attempted: bool = False


def destroy_recovery_session(
    recovery_session: RecoverySession,
    config: RecoverySessionConfig,
) -> CleanupResult:
    """No-op cleanup for in-repo recovery sessions.

    The trusted repository must never be deleted. Recovery timeline cleanup
    will be handled separately after commit/push.
    """
    return CleanupResult(
        status=CleanupStatus.CLEANED_GIT,
        message="In-repo recovery session preserved; no worktree cleanup required.",
    )
