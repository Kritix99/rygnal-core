"""Workspace mount contract modeling for Bubblewrap guarded execution.

This module models mount intent only. It does not execute Bubblewrap, perform
host filesystem mounts, or resolve real symlinks. Runtime code must still apply
realpath/no-follow checks before using host paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath

SANDBOX_ROOT = PurePosixPath("/workspace")


class MountSecurityError(ValueError):
    """Raised when a workspace mount contract is unsafe or ambiguous."""


class MountKind(StrEnum):
    READ_ONLY_BIND = "read_only_bind"
    WRITABLE_BIND = "writable_bind"
    EPHEMERAL_TMPFS = "ephemeral_tmpfs"
    MASKED_PATH = "masked_path"


@dataclass(frozen=True)
class MountContract:
    """Validated mount contract for a single sandbox path."""

    sandbox_path: str
    kind: MountKind
    host_source: str | None = None

    def __post_init__(self) -> None:
        normalized_path = normalize_sandbox_path(self.sandbox_path)
        object.__setattr__(self, "sandbox_path", normalized_path)

        kind = MountKind(self.kind)
        object.__setattr__(self, "kind", kind)

        if kind in {MountKind.READ_ONLY_BIND, MountKind.WRITABLE_BIND}:
            if self.host_source is None or not str(self.host_source).strip():
                raise MountSecurityError(f"{kind.value} mounts require host_source.")
            return

        if self.host_source is not None:
            raise MountSecurityError(f"{kind.value} mounts must not define host_source.")


@dataclass(frozen=True)
class WorkspaceMountPlan:
    """Sorted mount plan with parent mounts before child mounts."""

    mounts: tuple[MountContract, ...]

    def __post_init__(self) -> None:
        seen_paths: set[str] = set()
        for mount in self.mounts:
            if mount.sandbox_path in seen_paths:
                raise MountSecurityError(f"Duplicate sandbox mount path: {mount.sandbox_path}")
            seen_paths.add(mount.sandbox_path)

        ordered_mounts = tuple(sorted(self.mounts, key=_mount_sort_key))
        object.__setattr__(self, "mounts", ordered_mounts)


def normalize_sandbox_path(
    sandbox_path: str,
    *,
    sandbox_root: PurePosixPath = SANDBOX_ROOT,
) -> str:
    """Normalize a sandbox path while keeping it inside the sandbox root.

    This is string-only validation. Runtime code must still enforce host-side
    symlink, realpath, and no-follow checks before applying mounts.
    """

    root = PurePosixPath(str(sandbox_root).replace("\\", "/"))
    if not root.is_absolute():
        raise MountSecurityError(f"Sandbox root must be absolute: {sandbox_root}")

    raw_path = sandbox_path.replace("\\", "/").strip()
    if not raw_path:
        raise MountSecurityError("Sandbox mount path must not be empty.")

    candidate = PurePosixPath(raw_path)

    if any(part == ".." for part in candidate.parts):
        raise MountSecurityError(f"Sandbox path must not traverse: {sandbox_path}")

    if not candidate.is_absolute():
        candidate = root / candidate

    if any(part == ".." for part in candidate.parts):
        raise MountSecurityError(f"Sandbox path must not traverse: {sandbox_path}")

    if not _is_within_or_equal(candidate, root):
        raise MountSecurityError(f"Sandbox path must stay under {root.as_posix()}: {sandbox_path}")

    return candidate.as_posix()


def _is_within_or_equal(path: PurePosixPath, parent: PurePosixPath) -> bool:
    path_parts = path.parts
    parent_parts = parent.parts
    return path_parts == parent_parts or path_parts[: len(parent_parts)] == parent_parts


def _mount_sort_key(mount: MountContract) -> tuple[int, str]:
    path = PurePosixPath(mount.sandbox_path)
    return len(path.parts), mount.sandbox_path
