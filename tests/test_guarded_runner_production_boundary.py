from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from rygnal.approval_queue import (
    InMemoryApprovalQueue,
)
from rygnal.guarded_runner import (
    GuardedRunConfig,
    GuardedRunStatus,
    run_guarded,
)
from rygnal.patch_artifact import PatchArtifactStore


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
    git(
        path,
        "config",
        "user.email",
        "boundary@example.com",
    )
    git(
        path,
        "config",
        "user.name",
        "Boundary Test",
    )

    (path / "docs").mkdir()

    (path / "README.md").write_text(
        "baseline\n",
        encoding="utf-8",
    )
    (path / "docs" / "usage.md").write_text(
        "before\n",
        encoding="utf-8",
    )

    git(path, "add", ".")
    git(
        path,
        "commit",
        "-m",
        "baseline",
    )

    return path.resolve()


def snapshot(repo: Path) -> tuple[str, str, bytes]:
    return (
        git(repo, "rev-parse", "HEAD"),
        git(
            repo,
            "status",
            "--porcelain",
            "--untracked-files=all",
        ),
        (repo / "README.md").read_bytes(),
    )


def config(
    repo: Path,
    run_root: Path,
    code: str,
    *,
    queue=None,
    preserve: bool = False,
) -> GuardedRunConfig:
    return GuardedRunConfig(
        trusted_repo_path=repo,
        command=(
            sys.executable,
            "-c",
            code,
        ),
        timeout_seconds=5,
        rygnal_run_root=run_root,
        preserve_workspace=preserve,
        unsafe_local_requested=True,
        trace_id="production-boundary",
        approval_queue=queue,
    )


def test_failed_agent_cannot_mutate_trusted_repository(
    tmp_path: Path,
) -> None:
    trusted = create_repo(tmp_path / "trusted")
    before = snapshot(trusted)

    result = run_guarded(
        config(
            trusted,
            tmp_path / "runs",
            (
                "from pathlib import Path; "
                "Path('failed.txt').write_text('x'); "
                "Path('README.md').write_text('mutated'); "
                "raise SystemExit(9)"
            ),
        )
    )

    assert result.status == GuardedRunStatus.FAILED
    assert result.patch_diff is not None
    assert result.patch_apply_outcome == "not_applied"
    assert snapshot(trusted) == before
    assert not (trusted / "failed.txt").exists()
    assert result.workspace_path is not None
    assert not Path(result.workspace_path).exists()


def test_blocked_secret_never_reaches_trusted_repository(
    tmp_path: Path,
) -> None:
    trusted = create_repo(tmp_path / "trusted")
    before = snapshot(trusted)

    result = run_guarded(
        config(
            trusted,
            tmp_path / "runs",
            ("from pathlib import Path; Path('.env').write_text('TOKEN=not-a-real-secret')"),
        )
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert result.patch_apply_outcome == "not_applied"
    assert result.patch_artifact_id is None
    assert snapshot(trusted) == before
    assert not (trusted / ".env").exists()


def test_approval_patch_survives_workspace_cleanup_as_artifact(
    tmp_path: Path,
) -> None:
    trusted = create_repo(tmp_path / "trusted")
    before = snapshot(trusted)
    run_root = tmp_path / "runs"
    queue = InMemoryApprovalQueue()

    result = run_guarded(
        config(
            trusted,
            run_root,
            (
                "from pathlib import Path; "
                "Path('pyproject.toml').write_text("
                "'[project]\\nname=\"approval\"\\n')"
            ),
            queue=queue,
        )
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.patch_apply_outcome == "pending_approval"
    assert result.patch_artifact_id is not None
    assert result.approval_request is not None
    assert snapshot(trusted) == before
    assert result.workspace_path is not None
    assert not Path(result.workspace_path).exists()

    artifact = PatchArtifactStore(run_root / "artifacts").load(result.patch_artifact_id)

    assert artifact.patch_sha256 == result.patch_diff.patch_sha256
    assert len(queue.list()) == 1


def test_preserved_workspace_is_never_trusted_repository(
    tmp_path: Path,
) -> None:
    trusted = create_repo(tmp_path / "trusted")
    run_root = tmp_path / "runs"

    result = run_guarded(
        config(
            trusted,
            run_root,
            ("from pathlib import Path; Path('docs/preserved.md').write_text('preserved')"),
            preserve=True,
        )
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.workspace_path is not None

    workspace = Path(result.workspace_path)

    assert workspace.exists()
    assert workspace != trusted
    assert run_root.resolve() in workspace.parents
    assert (workspace / "docs" / "preserved.md").exists()
    assert (trusted / "docs" / "preserved.md").exists()
