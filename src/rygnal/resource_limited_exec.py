"""Internal launcher that applies limits before exec.

This module intentionally uses only the Python standard library.
It runs as a separate process so Rygnal never relies on
``subprocess.Popen(preexec_fn=...)`` in a possibly multithreaded
service process.
"""

from __future__ import annotations

import json
import os
import platform
import resource
import sys
from collections.abc import Mapping, Sequence
from typing import Any

RESOURCE_SETUP_FAILURE_PREFIX = "RYGNAL_RESOURCE_SETUP_FAILED:"


def _bounded_soft_limit(
    *,
    requested: int,
    current_soft: int,
    current_hard: int,
    infinity: int,
) -> int:
    """Lower a soft limit without raising it or changing hard.

    Zero is valid for resource classes such as RLIMIT_CORE,
    where it explicitly disables the resource.
    """
    if requested < 0:
        raise ValueError("Requested resource limit must be non-negative.")

    candidates = [requested]

    if current_soft != infinity:
        candidates.append(current_soft)

    if current_hard != infinity:
        candidates.append(current_hard)

    target = min(candidates)

    if target < 0:
        raise ValueError("Computed resource limit is invalid.")

    return target


def _set_soft_limit(
    name: str,
    requested: int,
) -> None:
    limit = getattr(resource, name, None)

    if limit is None:
        return

    current_soft, current_hard = resource.getrlimit(limit)
    target = _bounded_soft_limit(
        requested=requested,
        current_soft=current_soft,
        current_hard=current_hard,
        infinity=resource.RLIM_INFINITY,
    )

    resource.setrlimit(
        limit,
        (
            target,
            current_hard,
        ),
    )


def _apply_limits(
    values: Mapping[str, Any],
) -> None:
    os.umask(0o077)

    _set_soft_limit(
        "RLIMIT_CORE",
        int(values["core_bytes"]),
    )
    _set_soft_limit(
        "RLIMIT_CPU",
        int(values["cpu_seconds"]),
    )
    _set_soft_limit(
        "RLIMIT_FSIZE",
        int(values["file_size_bytes"]),
    )
    _set_soft_limit(
        "RLIMIT_NOFILE",
        int(values["open_files"]),
    )

    # Production containment is Linux-only. RLIMIT_AS and
    # RLIMIT_NPROC have materially different behavior on macOS
    # and are therefore not claimed or enforced there.
    if platform.system() == "Linux":
        _set_soft_limit(
            "RLIMIT_AS",
            int(values["address_space_bytes"]),
        )
        _set_soft_limit(
            "RLIMIT_NPROC",
            int(values["processes"]),
        )


def _parse_arguments(
    arguments: Sequence[str],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    if len(arguments) < 3 or arguments[1] != "--":
        raise ValueError("Resource launcher arguments are malformed.")

    raw_limits = json.loads(arguments[0])

    if not isinstance(raw_limits, dict):
        raise ValueError("Resource limits must be a JSON object.")

    command = tuple(arguments[2:])

    if not command or not command[0]:
        raise ValueError("Resource launcher command is empty.")

    required = {
        "address_space_bytes",
        "core_bytes",
        "cpu_seconds",
        "file_size_bytes",
        "open_files",
        "processes",
    }

    if set(raw_limits) != required:
        raise ValueError("Resource limit fields are incomplete or unsupported.")

    for key in required:
        value = raw_limits[key]

        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Resource limit '{key}' is invalid.")

    return raw_limits, command


def main(
    arguments: Sequence[str] | None = None,
) -> int:
    argv = tuple(sys.argv[1:]) if arguments is None else tuple(arguments)

    try:
        limits, command = _parse_arguments(argv)
        _apply_limits(limits)

        os.execvpe(
            command[0],
            command,
            dict(os.environ),
        )
    except (
        json.JSONDecodeError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            RESOURCE_SETUP_FAILURE_PREFIX,
            str(exc),
            file=sys.stderr,
            flush=True,
        )
        return 125

    return 125


if __name__ == "__main__":
    raise SystemExit(main())
