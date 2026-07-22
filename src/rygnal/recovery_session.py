"""Disposable Git worktree lifecycle for guarded Rygnal execution."""

from __future__ import annotations

import os
import subprocess  # nosec B404
import tempfile
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
    """Configuration for creating a disposable guarded worktree."""

    trusted_repo_path: Path
    untracked_policy: UntrackedFilePolicy = UntrackedFilePolicy.BLOCK
    audit_logger: AuditLogger | None = None
    rygnal_run_root: Path | None = None


@dataclass(frozen=True)
class RecoverySession:
    """Metadata for one Rygnal-owned disposable Git worktree."""

    run_id: str
    trusted_repo_path: Path
    execution_path: Path
    baseline_commit_sha: str
    timeline_dir: Path
    owner_marker_path: Path | None = None
    run_root: Path | None = None

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
    return tuple(line[3:].strip() for line in status.splitlines() if line.startswith("?? "))


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


def _default_run_root() -> Path:
    """Return the default root for disposable Rygnal execution state."""
    return Path(tempfile.gettempdir()).joinpath("rygnal-runs").resolve()


def _resolved_run_root(config: RecoverySessionConfig) -> Path:
    candidate = (
        Path(config.rygnal_run_root).expanduser()
        if config.rygnal_run_root is not None
        else _default_run_root()
    )
    return candidate.resolve(strict=False)


def _strict_descendant(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False

    return path != root


def _ensure_private_directory(path: Path) -> Path:
    """Create one private directory and reject symlink substitution."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)

    if path.is_symlink():
        raise RecoverySessionError(f"Refusing to use a symlink as a Rygnal directory: {path}")

    if not path.is_dir():
        raise RecoverySessionError(f"Rygnal path is not a directory: {path}")

    try:
        path.chmod(0o700)
    except OSError as exc:
        raise RecoverySessionError(
            f"Unable to secure Rygnal directory permissions: {path}"
        ) from exc

    return path.resolve()


def _assert_roots_do_not_overlap(repo_root: Path, run_root: Path) -> None:
    if repo_root == run_root:
        raise RecoverySessionError("Rygnal run root must not be the trusted repository.")

    if _strict_descendant(run_root, repo_root):
        raise RecoverySessionError("Rygnal run root must not be inside the trusted repository.")

    if _strict_descendant(repo_root, run_root):
        raise RecoverySessionError("Trusted repository must not be inside the Rygnal run root.")


def _submodule_paths(repo_root: Path, baseline_sha: str) -> tuple[str, ...]:
    """Return Gitlink entries without initializing or downloading them."""
    output = _run_git(
        ["ls-tree", "-r", "--full-tree", baseline_sha],
        cwd=repo_root,
    )
    submodules: list[str] = []

    for line in output.splitlines():
        metadata, separator, path = line.partition("\t")
        if not separator:
            continue

        if metadata.startswith("160000 commit "):
            submodules.append(path)

    return tuple(submodules)


def _owner_marker_payload(
    *,
    run_id: str,
    trusted_repo_path: Path,
    baseline_commit_sha: str,
    workspace_path: Path,
) -> str:
    return "\n".join(
        (
            "schema=rygnal-worktree-owner.v1",
            f"run_id={run_id}",
            f"trusted_repo_path={trusted_repo_path.as_posix()}",
            f"baseline_commit_sha={baseline_commit_sha}",
            f"workspace_path={workspace_path.as_posix()}",
            "",
        )
    )


def _write_owner_marker(
    marker_path: Path,
    *,
    run_id: str,
    trusted_repo_path: Path,
    baseline_commit_sha: str,
    workspace_path: Path,
) -> None:
    payload = _owner_marker_payload(
        run_id=run_id,
        trusted_repo_path=trusted_repo_path,
        baseline_commit_sha=baseline_commit_sha,
        workspace_path=workspace_path,
    )

    try:
        descriptor = os.open(
            marker_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except OSError as exc:
        raise RecoverySessionError(
            f"Unable to create Rygnal ownership marker: {marker_path}"
        ) from exc

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            marker_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _registered_worktree_paths(repo_root: Path) -> tuple[Path, ...]:
    output = _run_git(["worktree", "list", "--porcelain"], cwd=repo_root)
    paths: list[Path] = []

    for line in output.splitlines():
        if not line.startswith("worktree "):
            continue

        raw_path = line.removeprefix("worktree ").strip()
        if raw_path:
            paths.append(Path(raw_path).resolve(strict=False))

    return tuple(paths)


def _validate_created_worktree(
    *,
    repo_root: Path,
    workspace_path: Path,
    baseline_sha: str,
) -> None:
    if workspace_path == repo_root:
        raise RecoverySessionError("Disposable workspace resolved to the trusted repository.")

    workspace_root = detect_trusted_repo_root(workspace_path)
    if workspace_root != workspace_path:
        raise RecoverySessionError("Disposable worktree root does not match its execution path.")

    workspace_head = _run_git(["rev-parse", "HEAD"], cwd=workspace_path)
    if workspace_head != baseline_sha:
        raise RecoverySessionError("Disposable worktree HEAD does not match the captured baseline.")

    symbolic_ref = subprocess.run(
        ["git", "symbolic-ref", "-q", "HEAD"],
        cwd=workspace_path,
        capture_output=True,
        text=True,
        check=False,
        env={
            key: value
            for key, value in os.environ.items()
            if key not in {"GIT_DIR", "GIT_WORK_TREE"}
        },
    )

    if symbolic_ref.returncode == 0:
        raise RecoverySessionError("Disposable worktree must use detached HEAD.")

    if workspace_path not in _registered_worktree_paths(repo_root):
        raise RecoverySessionError("Disposable workspace is not registered as a Git worktree.")


def create_recovery_session(config: RecoverySessionConfig) -> RecoverySession:
    """Create a detached disposable Git worktree at the trusted HEAD."""
    repo_root = config.trusted_repo_path.expanduser().resolve()

    if not repo_root.is_dir():
        raise RecoverySessionError(f"Trusted repository path does not exist: {repo_root}")

    try:
        is_bare = _run_git(
            ["rev-parse", "--is-bare-repository"],
            cwd=repo_root,
        )
    except RecoverySessionError as exc:
        raise RecoverySessionError(
            f"Trusted repository not found or invalid at: {repo_root}"
        ) from exc

    if is_bare == "true":
        raise RecoverySessionError("Bare repositories are not supported for recovery sessions.")

    if detect_trusted_repo_root(repo_root) != repo_root:
        raise RecoverySessionError("Trusted repository path must be the Git repository root.")

    if config.untracked_policy == UntrackedFilePolicy.BLOCK:
        untracked_paths = _untracked_paths(repo_root)
        if untracked_paths:
            listed = ", ".join(untracked_paths[:5])
            suffix = "" if len(untracked_paths) <= 5 else f", and {len(untracked_paths) - 5} more"
            raise RecoverySessionError(
                "untracked files must be committed, ignored, or explicitly "
                f"preserved before running Rygnal: {listed}{suffix}"
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
            "untracked sensitive files must be committed, ignored, or "
            f"removed before running Rygnal: {listed}{suffix}"
        )

    baseline_sha = _run_git(["rev-parse", "HEAD"], cwd=repo_root)

    if len(baseline_sha) != 40 or any(
        character not in "0123456789abcdefABCDEF" for character in baseline_sha
    ):
        raise RecoverySessionError(f"Failed to capture valid baseline commit SHA: {baseline_sha}")

    submodules = _submodule_paths(repo_root, baseline_sha)
    if submodules:
        listed = ", ".join(submodules[:5])
        suffix = "" if len(submodules) <= 5 else f", and {len(submodules) - 5} more"
        raise RecoverySessionError(
            "Repositories containing Git submodules are blocked until "
            "Rygnal has an explicit offline submodule materialization "
            f"policy: {listed}{suffix}"
        )

    run_root = _resolved_run_root(config)
    _assert_roots_do_not_overlap(repo_root, run_root)
    _ensure_private_directory(run_root)

    workspaces_root = _ensure_private_directory(run_root.joinpath("workspaces"))
    timelines_root = _ensure_private_directory(run_root.joinpath("timelines"))
    _ensure_private_directory(run_root.joinpath("quarantine"))

    run_id = uuid.uuid4().hex
    session_root = workspaces_root.joinpath(run_id)
    workspace_path = session_root.joinpath("workspace")
    timeline_dir = timelines_root.joinpath(run_id)
    marker_path = session_root.joinpath(".rygnal-owner")

    if workspace_path.exists() or session_root.exists():
        raise RecoverySessionError(f"Rygnal run path already exists unexpectedly: {session_root}")

    session_root.mkdir(mode=0o700, parents=False)
    session_root.chmod(0o700)

    if not _strict_descendant(workspace_path, workspaces_root):
        raise RecoverySessionError("Disposable workspace escaped the controlled workspaces root.")

    _write_owner_marker(
        marker_path,
        run_id=run_id,
        trusted_repo_path=repo_root,
        baseline_commit_sha=baseline_sha,
        workspace_path=workspace_path,
    )

    try:
        _run_git(
            [
                "worktree",
                "add",
                "--detach",
                workspace_path.as_posix(),
                baseline_sha,
            ],
            cwd=repo_root,
        )
        workspace_path.chmod(0o700)
        _validate_created_worktree(
            repo_root=repo_root,
            workspace_path=workspace_path.resolve(),
            baseline_sha=baseline_sha,
        )
    except Exception as exc:
        try:
            if workspace_path.exists():
                _run_git(
                    [
                        "worktree",
                        "remove",
                        "--force",
                        workspace_path.as_posix(),
                    ],
                    cwd=repo_root,
                )
        except Exception:
            pass

        try:
            marker_path.unlink(missing_ok=True)
            session_root.rmdir()
        except OSError:
            pass

        if isinstance(exc, RecoverySessionError):
            raise

        raise RecoverySessionError(f"Failed to create disposable Git worktree: {exc}") from exc

    return RecoverySession(
        run_id=run_id,
        trusted_repo_path=repo_root,
        execution_path=workspace_path.resolve(),
        baseline_commit_sha=baseline_sha.lower(),
        timeline_dir=timeline_dir,
        owner_marker_path=marker_path.resolve(),
        run_root=run_root,
    )


class CleanupStatus(StrEnum):
    """Outcome of disposable worktree cleanup."""

    CLEANED_GIT = "worktree_removed"
    CLEANED_FALLBACK = "worktree_quarantined"
    RESET_SUCCESS = "worktree_removed"
    CLEANUP_FAILED = "cleanup_failed"


@dataclass(frozen=True)
class CleanupResult:
    """Verified disposable-worktree cleanup result."""

    status: CleanupStatus
    message: str
    prune_attempted: bool = False
    quarantined: bool = False
    workspace_path: str | None = None
    quarantine_path: str | None = None


def _expected_owner_marker(recovery_session: RecoverySession) -> str:
    return _owner_marker_payload(
        run_id=recovery_session.run_id,
        trusted_repo_path=recovery_session.trusted_repo_path,
        baseline_commit_sha=recovery_session.baseline_commit_sha,
        workspace_path=recovery_session.workspace_path,
    )


def _validate_cleanup_ownership(
    recovery_session: RecoverySession,
    config: RecoverySessionConfig,
) -> tuple[Path, Path, Path]:
    repo_root = recovery_session.trusted_repo_path.resolve()
    workspace = recovery_session.workspace_path.resolve(strict=False)
    run_root = _resolved_run_root(config)
    workspaces_root = run_root.joinpath("workspaces").resolve(strict=False)
    expected_session_root = workspaces_root.joinpath(recovery_session.run_id).resolve(strict=False)
    expected_workspace = expected_session_root.joinpath("workspace").resolve(strict=False)
    marker_path = expected_session_root.joinpath(".rygnal-owner")

    if workspace == repo_root:
        raise RecoverySessionError("Refusing cleanup because workspace equals trusted repository.")

    if not _strict_descendant(workspace, workspaces_root):
        raise RecoverySessionError(
            "Refusing cleanup outside the controlled Rygnal workspaces root."
        )

    if workspace != expected_workspace:
        raise RecoverySessionError(
            "Refusing cleanup because workspace path does not match run identity."
        )

    if expected_session_root.is_symlink() or workspace.is_symlink():
        raise RecoverySessionError("Refusing cleanup through a symlinked Rygnal workspace path.")

    if not marker_path.is_file() or marker_path.is_symlink():
        raise RecoverySessionError(
            "Refusing cleanup because the Rygnal ownership marker is missing."
        )

    marker_payload = marker_path.read_text(encoding="utf-8")
    if marker_payload != _expected_owner_marker(recovery_session):
        raise RecoverySessionError("Refusing cleanup because the ownership marker is invalid.")

    registered_paths = _registered_worktree_paths(repo_root)
    if workspace not in registered_paths:
        raise RecoverySessionError("Refusing cleanup because Git does not register the workspace.")

    return run_root, expected_session_root, marker_path


def _quarantine_worktree(
    recovery_session: RecoverySession,
    *,
    run_root: Path,
    marker_path: Path,
    removal_error: str,
) -> CleanupResult:
    repo_root = recovery_session.trusted_repo_path.resolve()
    workspace = recovery_session.workspace_path.resolve(strict=False)
    quarantine_root = _ensure_private_directory(run_root.joinpath("quarantine"))
    quarantine_session_root = quarantine_root.joinpath(recovery_session.run_id)
    quarantine_workspace = quarantine_session_root.joinpath("workspace")
    quarantine_marker = quarantine_session_root.joinpath(".rygnal-owner")

    if quarantine_session_root.exists():
        return CleanupResult(
            status=CleanupStatus.CLEANUP_FAILED,
            message=(
                "Worktree removal failed and quarantine destination "
                f"already exists: {quarantine_session_root}"
            ),
            quarantined=True,
            workspace_path=workspace.as_posix(),
        )

    quarantine_session_root.mkdir(mode=0o700)
    quarantine_session_root.chmod(0o700)

    try:
        _run_git(
            [
                "worktree",
                "move",
                workspace.as_posix(),
                quarantine_workspace.as_posix(),
            ],
            cwd=repo_root,
        )
        marker_payload = marker_path.read_text(encoding="utf-8")
        quarantine_marker.write_text(marker_payload, encoding="utf-8")
        quarantine_marker.chmod(0o600)
        marker_path.unlink(missing_ok=True)

        try:
            marker_path.parent.rmdir()
        except OSError:
            pass

        return CleanupResult(
            status=CleanupStatus.CLEANED_FALLBACK,
            message=(
                "Disposable worktree removal failed; the Rygnal-owned "
                f"workspace was quarantined. Original error: {removal_error}"
            ),
            quarantined=True,
            workspace_path=workspace.as_posix(),
            quarantine_path=quarantine_workspace.as_posix(),
        )
    except Exception as quarantine_error:
        try:
            quarantine_session_root.rmdir()
        except OSError:
            pass

        return CleanupResult(
            status=CleanupStatus.CLEANUP_FAILED,
            message=(
                "Disposable worktree removal failed and quarantine also "
                f"failed. Removal error: {removal_error}. "
                f"Quarantine error: {quarantine_error}"
            ),
            quarantined=True,
            workspace_path=workspace.as_posix(),
        )


def destroy_recovery_session(
    recovery_session: RecoverySession,
    config: RecoverySessionConfig,
) -> CleanupResult:
    """Remove only a verified Rygnal-owned linked Git worktree."""
    try:
        run_root, session_root, marker_path = _validate_cleanup_ownership(
            recovery_session,
            config,
        )
    except RecoverySessionError as exc:
        return CleanupResult(
            status=CleanupStatus.CLEANUP_FAILED,
            message=str(exc),
            quarantined=False,
            workspace_path=recovery_session.workspace_path.as_posix(),
        )

    repo_root = recovery_session.trusted_repo_path.resolve()
    workspace = recovery_session.workspace_path.resolve(strict=False)

    try:
        _run_git(
            [
                "worktree",
                "remove",
                "--force",
                workspace.as_posix(),
            ],
            cwd=repo_root,
        )
    except RecoverySessionError as exc:
        return _quarantine_worktree(
            recovery_session,
            run_root=run_root,
            marker_path=marker_path,
            removal_error=str(exc),
        )

    if workspace.exists():
        return CleanupResult(
            status=CleanupStatus.CLEANUP_FAILED,
            message=(
                "Git reported successful worktree removal, but the "
                f"workspace still exists: {workspace}"
            ),
            quarantined=True,
            workspace_path=workspace.as_posix(),
        )

    residual_entries = tuple(entry for entry in session_root.iterdir() if entry != marker_path)

    if residual_entries:
        quarantine_root = _ensure_private_directory(run_root.joinpath("quarantine"))
        quarantine_session = quarantine_root.joinpath(f"{recovery_session.run_id}-residual")

        if quarantine_session.exists():
            return CleanupResult(
                status=CleanupStatus.CLEANUP_FAILED,
                message=(
                    "Residual workspace data was detected, but its "
                    "quarantine destination already exists."
                ),
                quarantined=True,
                workspace_path=session_root.as_posix(),
            )

        try:
            os.replace(
                session_root,
                quarantine_session,
            )
        except OSError as exc:
            return CleanupResult(
                status=CleanupStatus.CLEANUP_FAILED,
                message=(
                    "Disposable worktree was removed, but residual "
                    f"session data could not be quarantined: {exc}"
                ),
                quarantined=True,
                workspace_path=session_root.as_posix(),
            )

        return CleanupResult(
            status=CleanupStatus.CLEANED_FALLBACK,
            message=(
                "The registered worktree was removed and residual "
                "out-of-workspace data was quarantined."
            ),
            prune_attempted=False,
            quarantined=True,
            workspace_path=workspace.as_posix(),
            quarantine_path=quarantine_session.as_posix(),
        )

    try:
        marker_path.unlink(missing_ok=True)
        session_root.rmdir()
    except OSError as exc:
        return CleanupResult(
            status=CleanupStatus.CLEANUP_FAILED,
            message=(
                "Disposable worktree was removed, but Rygnal ownership "
                f"metadata cleanup failed: {exc}"
            ),
            workspace_path=workspace.as_posix(),
        )

    if workspace in _registered_worktree_paths(repo_root):
        return CleanupResult(
            status=CleanupStatus.CLEANUP_FAILED,
            message=(f"Disposable workspace remains registered after cleanup: {workspace}"),
            workspace_path=workspace.as_posix(),
        )

    return CleanupResult(
        status=CleanupStatus.CLEANED_GIT,
        message="Verified disposable Git worktree removed successfully.",
        workspace_path=workspace.as_posix(),
    )


__all__ = [
    "CleanupResult",
    "CleanupStatus",
    "RecoverySession",
    "RecoverySessionConfig",
    "RecoverySessionError",
    "create_recovery_session",
    "destroy_recovery_session",
    "detect_trusted_repo_root",
]
