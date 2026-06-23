"""Version helpers for Rygnal Core."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

PACKAGE_NAME = "rygnal-core"
FALLBACK_VERSION = "0.1.0"


def package_version() -> str:
    """Return the installed Rygnal Core package version.

    The fallback keeps editable/source-tree test runs deterministic when package
    metadata is unavailable.
    """
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        return FALLBACK_VERSION
