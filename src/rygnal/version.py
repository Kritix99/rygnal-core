"""Version helpers for Rygnal Core."""

from __future__ import annotations

import logging
from importlib.metadata import PackageNotFoundError, version

PACKAGE_NAME = "rygnal-core"
UNRESOLVED_SOURCE_BUILD_VERSION = "unresolved-source-build"

logger = logging.getLogger(__name__)


def package_version() -> str:
    """Return the installed Rygnal Core package version.

    When package metadata is unavailable, return an explicit unresolved marker
    instead of a release-looking fallback so audit reviewers can identify
    source-tree or unpackaged runs.
    """
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        logger.warning(
            "Rygnal package metadata is unavailable; audit events will use %s.",
            UNRESOLVED_SOURCE_BUILD_VERSION,
        )
        return UNRESOLVED_SOURCE_BUILD_VERSION
