import pytest

from rygnal.workspace_mounts import (
    MountContract,
    MountKind,
    MountSecurityError,
    WorkspaceMountPlan,
    normalize_sandbox_path,
)


def test_path_normalization_rejects_traversal() -> None:
    with pytest.raises(MountSecurityError):
        normalize_sandbox_path("../etc/shadow")

    with pytest.raises(MountSecurityError):
        normalize_sandbox_path("/workspace/../etc/shadow")


def test_path_normalization_rejects_absolute_path_outside_sandbox_root() -> None:
    with pytest.raises(MountSecurityError):
        normalize_sandbox_path("/var/run/docker.sock")


def test_path_normalization_accepts_relative_paths_under_workspace() -> None:
    assert normalize_sandbox_path(".env") == "/workspace/.env"
    assert normalize_sandbox_path("packages/api") == "/workspace/packages/api"


def test_mount_plan_sorts_parents_before_children() -> None:
    masked_env = MountContract(
        sandbox_path="/workspace/.env",
        kind=MountKind.MASKED_PATH,
    )
    repo_bind = MountContract(
        sandbox_path="/workspace",
        kind=MountKind.READ_ONLY_BIND,
        host_source="/repo",
    )

    plan = WorkspaceMountPlan(mounts=(masked_env, repo_bind))

    assert [mount.sandbox_path for mount in plan.mounts] == [
        "/workspace",
        "/workspace/.env",
    ]


def test_masked_path_requires_no_host_source() -> None:
    with pytest.raises(MountSecurityError):
        MountContract(
            sandbox_path="/workspace/.env",
            kind=MountKind.MASKED_PATH,
            host_source="/repo/.env",
        )


def test_tmpfs_requires_no_host_source() -> None:
    with pytest.raises(MountSecurityError):
        MountContract(
            sandbox_path="/workspace/node_modules",
            kind=MountKind.EPHEMERAL_TMPFS,
            host_source="/repo/node_modules",
        )


def test_read_only_bind_requires_host_source() -> None:
    with pytest.raises(MountSecurityError):
        MountContract(
            sandbox_path="/workspace",
            kind=MountKind.READ_ONLY_BIND,
        )


def test_mount_plan_rejects_duplicate_sandbox_paths() -> None:
    first = MountContract(
        sandbox_path="/workspace",
        kind=MountKind.READ_ONLY_BIND,
        host_source="/repo",
    )
    second = MountContract(
        sandbox_path="/workspace",
        kind=MountKind.EPHEMERAL_TMPFS,
    )

    with pytest.raises(MountSecurityError):
        WorkspaceMountPlan(mounts=(first, second))


def test_writable_bind_requires_host_source() -> None:
    with pytest.raises(MountSecurityError):
        MountContract(
            sandbox_path="/workspace",
            kind=MountKind.WRITABLE_BIND,
        )


def test_writable_bind_accepts_workspace_root() -> None:
    mount = MountContract(
        sandbox_path="/workspace",
        kind=MountKind.WRITABLE_BIND,
        host_source="/repo",
    )

    assert mount.sandbox_path == "/workspace"
    assert mount.kind == MountKind.WRITABLE_BIND
    assert mount.host_source == "/repo"
