"""Private local filesystem paths used by Rygnal."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

RYGNAL_DATA_DIR_ENV = "RYGNAL_DATA_DIR"
_PRIVATE_DIRECTORY_MODE = 0o700


class LocalPathError(RuntimeError):
    """Raised when local Rygnal paths cannot be safely prepared."""


@dataclass(frozen=True, slots=True)
class LocalPaths:
    """Resolved filesystem locations for a local Rygnal installation."""

    root: Path
    audit_dir: Path
    audit_jsonl: Path
    audit_db: Path
    approvals_dir: Path
    approval_db: Path
    runs_dir: Path
    artifacts_dir: Path
    logs_dir: Path
    runtime_dir: Path

    def directories(self) -> tuple[Path, ...]:
        """Return directories forming the local storage layout."""
        return (
            self.root,
            self.audit_dir,
            self.approvals_dir,
            self.runs_dir,
            self.artifacts_dir,
            self.logs_dir,
            self.runtime_dir,
        )


def resolve_local_paths(
    *,
    data_dir: str | Path | None = None,
    create: bool = False,
    environ: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> LocalPaths:
    """Resolve Rygnal paths without performing import-time filesystem writes."""
    environment = os.environ if environ is None else environ
    platform_name = sys.platform if platform is None else platform
    home_directory = _normalize_home(home)

    if data_dir is not None:
        root = _absolute_override(
            data_dir,
            source="data_dir",
            home=home_directory,
        )
    elif RYGNAL_DATA_DIR_ENV in environment:
        root = _absolute_override(
            environment[RYGNAL_DATA_DIR_ENV],
            source=RYGNAL_DATA_DIR_ENV,
            home=home_directory,
        )
    else:
        root = _platform_default_root(
            platform=platform_name,
            environ=environment,
            home=home_directory,
        )

    paths = LocalPaths(
        root=root,
        audit_dir=root / "audit",
        audit_jsonl=root / "audit" / "audit.jsonl",
        audit_db=root / "audit" / "audit.db",
        approvals_dir=root / "approvals",
        approval_db=root / "approvals" / "approvals.db",
        runs_dir=root / "runs",
        artifacts_dir=root / "artifacts",
        logs_dir=root / "logs",
        runtime_dir=root / "runtime",
    )

    if create:
        _create_private_layout(paths)

    return paths


def _normalize_home(home: Path | None) -> Path:
    candidate = Path.home() if home is None else Path(home)

    if not candidate.is_absolute():
        raise LocalPathError(f"Home directory must be absolute: {candidate}")

    return _normalize_absolute(candidate)


def _absolute_override(
    value: str | Path,
    *,
    source: str,
    home: Path,
) -> Path:
    raw_value = os.fspath(value)

    if not raw_value.strip():
        raise LocalPathError(f"{source} must not be empty.")

    if raw_value == "~":
        candidate = home
    elif raw_value.startswith("~/") or raw_value.startswith("~\\"):
        candidate = home / raw_value[2:]
    elif raw_value.startswith("~"):
        raise LocalPathError(f"{source} cannot expand another user's home directory: {raw_value!r}")
    else:
        candidate = Path(raw_value)

    if not candidate.is_absolute():
        raise LocalPathError(f"{source} must be an absolute path, received: {raw_value!r}")

    return _normalize_absolute(candidate)


def _platform_default_root(
    *,
    platform: str,
    environ: Mapping[str, str],
    home: Path,
) -> Path:
    platform_name = platform.lower()

    if platform_name == "darwin":
        return _normalize_absolute(home / "Library" / "Application Support" / "Rygnal")

    if platform_name.startswith("win"):
        local_app_data = environ.get("LOCALAPPDATA")

        if local_app_data:
            return (
                _absolute_override(
                    local_app_data,
                    source="LOCALAPPDATA",
                    home=home,
                )
                / "Rygnal"
            )

        return _normalize_absolute(home / "AppData" / "Local" / "Rygnal")

    xdg_data_home = environ.get("XDG_DATA_HOME")

    if xdg_data_home:
        return (
            _absolute_override(
                xdg_data_home,
                source="XDG_DATA_HOME",
                home=home,
            )
            / "rygnal"
        )

    return _normalize_absolute(home / ".local" / "share" / "rygnal")


def _normalize_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.normpath(os.fspath(path))))


def _create_private_layout(paths: LocalPaths) -> None:
    for directory in paths.directories():
        _ensure_private_directory(directory)


def _ensure_private_directory(directory: Path) -> None:
    if directory.is_symlink():
        raise LocalPathError(f"Refusing to use a symlink as a Rygnal directory: {directory}")

    if directory.exists() and not directory.is_dir():
        raise LocalPathError(f"Rygnal path is not a directory: {directory}")

    try:
        directory.mkdir(
            mode=_PRIVATE_DIRECTORY_MODE,
            parents=True,
            exist_ok=True,
        )
    except OSError as exc:
        raise LocalPathError(f"Unable to create Rygnal directory {directory}: {exc}") from exc

    if directory.is_symlink():
        raise LocalPathError(f"Refusing to use a symlink as a Rygnal directory: {directory}")

    if os.name != "nt":
        try:
            directory.chmod(_PRIVATE_DIRECTORY_MODE)
        except OSError as exc:
            raise LocalPathError(f"Unable to secure Rygnal directory {directory}: {exc}") from exc


__all__ = [
    "LocalPathError",
    "LocalPaths",
    "RYGNAL_DATA_DIR_ENV",
    "resolve_local_paths",
]
