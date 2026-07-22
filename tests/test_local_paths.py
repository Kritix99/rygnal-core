from pathlib import Path

import pytest

from rygnal.local_paths import LocalPathError, resolve_local_paths
from rygnal.local_runtime import create_local_runtime_dependencies


def test_explicit_path_has_highest_precedence(tmp_path: Path):
    explicit = tmp_path / "explicit"

    paths = resolve_local_paths(
        data_dir=explicit,
        environ={
            "RYGNAL_DATA_DIR": str(tmp_path / "environment"),
            "XDG_DATA_HOME": str(tmp_path / "xdg"),
        },
        platform="linux",
        home=tmp_path / "home",
    )

    assert paths.root == explicit


def test_environment_override_precedes_default(tmp_path: Path):
    override = tmp_path / "override"

    paths = resolve_local_paths(
        environ={"RYGNAL_DATA_DIR": str(override)},
        platform="linux",
        home=tmp_path / "home",
    )

    assert paths.root == override


def test_macos_default(tmp_path: Path):
    home = tmp_path / "home"

    paths = resolve_local_paths(
        environ={},
        platform="darwin",
        home=home,
    )

    assert paths.root == (home / "Library" / "Application Support" / "Rygnal")


def test_linux_xdg_default(tmp_path: Path):
    xdg = tmp_path / "xdg"

    paths = resolve_local_paths(
        environ={"XDG_DATA_HOME": str(xdg)},
        platform="linux",
        home=tmp_path / "home",
    )

    assert paths.root == xdg / "rygnal"


def test_linux_fallback(tmp_path: Path):
    home = tmp_path / "home"

    paths = resolve_local_paths(
        environ={},
        platform="linux",
        home=home,
    )

    assert paths.root == home / ".local" / "share" / "rygnal"


def test_windows_local_app_data(tmp_path: Path):
    local_app_data = tmp_path / "LocalAppData"

    paths = resolve_local_paths(
        environ={"LOCALAPPDATA": str(local_app_data)},
        platform="win32",
        home=tmp_path / "home",
    )

    assert paths.root == local_app_data / "Rygnal"


def test_create_false_performs_no_writes(tmp_path: Path):
    root = tmp_path / "rygnal-data"

    paths = resolve_local_paths(
        data_dir=root,
        create=False,
        environ={},
    )

    assert paths.root == root
    assert not root.exists()


def test_create_true_builds_complete_layout(tmp_path: Path):
    paths = resolve_local_paths(
        data_dir=tmp_path / "rygnal-data",
        create=True,
        environ={},
    )

    for directory in paths.directories():
        assert directory.is_dir()


@pytest.mark.parametrize(
    "value",
    ["", "   ", "relative/path"],
)
def test_invalid_override_is_rejected(value: str):
    with pytest.raises(LocalPathError):
        resolve_local_paths(
            data_dir=value,
            environ={},
        )


def test_regular_file_collision_is_rejected(tmp_path: Path):
    root = tmp_path / "rygnal-data"
    root.write_text("file", encoding="utf-8")

    with pytest.raises(LocalPathError, match="not a directory"):
        resolve_local_paths(
            data_dir=root,
            create=True,
            environ={},
        )


def test_symlink_root_is_rejected(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"

    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("Symlinks are unavailable.")

    with pytest.raises(LocalPathError, match="symlink"):
        resolve_local_paths(
            data_dir=link,
            create=True,
            environ={},
        )


def test_local_dependencies_use_resolved_paths(
    tmp_path: Path,
):
    root = tmp_path / "rygnal-data"

    dependencies = create_local_runtime_dependencies(
        data_dir=root,
        environ={},
    )

    assert dependencies.paths.root == root
    assert dependencies.audit_logger.log_path == (root / "audit" / "audit.jsonl")
    assert dependencies.audit_store.db_path == (root / "audit" / "audit.db")
    assert dependencies.approval_queue.db_path == (root / "approvals" / "approvals.db")

    assert dependencies.paths.audit_db.is_file()
    assert dependencies.paths.approval_db.is_file()
