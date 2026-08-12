"""Execution backend selection for guarded workspace runs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class ExecutionBackendName(StrEnum):
    """Known execution backend names."""

    CONFIGURED_CONTAINER = "configured_container"
    UNSAFE_LOCAL = "unsafe_local"


class ExecutionBackendSelectionError(RuntimeError):
    """Raised when guarded execution has no verified safe backend."""


@dataclass(frozen=True)
class ExecutionBackendSelection:
    """Selected backend and its safety metadata."""

    name: ExecutionBackendName
    safe_by_default: bool
    reason: str
    warning: str | None = None


class HostBackendCapabilities:
    """Host capabilities used by backend selection."""

    def __init__(
        self,
        *,
        env: Mapping[str, str] | None = None,
        configured_container_backend: str | None = None,
        verified_rootless_container_available: bool | None = None,
        unsafe_local_requested: bool | None = None,
    ) -> None:
        self._env = os.environ if env is None else env
        self.configured_container_backend = (
            configured_container_backend
            if configured_container_backend is not None
            else self._env.get("RYGNAL_CONFIGURED_CONTAINER_BACKEND")
        )
        self.unsafe_local_requested = (
            unsafe_local_requested
            if unsafe_local_requested is not None
            else self._env.get("RYGNAL_UNSAFE_LOCAL") == "1"
        )
        self._verified_rootless_container_override = (
            verified_rootless_container_available
        )

    @property
    def verified_rootless_container_available(self) -> bool:
        if self._verified_rootless_container_override is not None:
            return self._verified_rootless_container_override
        return _probe_verified_rootless_container(self.configured_container_backend)


def select_execution_backend(
    capabilities: HostBackendCapabilities,
) -> ExecutionBackendSelection:
    """Select a supported execution backend deterministically."""

    if capabilities.unsafe_local_requested:
        return ExecutionBackendSelection(
            name=ExecutionBackendName.UNSAFE_LOCAL,
            safe_by_default=False,
            reason="Unsafe local execution was explicitly requested.",
            warning=(
                "Unsafe local execution is not a containment backend and must "
                "never be selected by default."
            ),
        )

    if capabilities.verified_rootless_container_available:
        return ExecutionBackendSelection(
            name=ExecutionBackendName.CONFIGURED_CONTAINER,
            safe_by_default=True,
            reason=(
                "Verified rootless container backend is available: "
                f"{capabilities.configured_container_backend}."
            ),
        )

    if capabilities.configured_container_backend is not None:
        raise ExecutionBackendSelectionError(
            "Configured containment backend is not verified: "
            f"{capabilities.configured_container_backend}."
        )

    raise ExecutionBackendSelectionError(
        "No verified containment backend is available for guarded execution. "
        "Configure a supported rootless container backend; Rygnal will not "
        "silently degrade to unsafe local execution."
    )


def detect_host_backend_capabilities(
    *,
    env: Mapping[str, str] | None = None,
) -> HostBackendCapabilities:
    """Return host capability detector."""

    return HostBackendCapabilities(env=env)


def _probe_verified_rootless_container(backend_name: str | None) -> bool:
    if backend_name == "podman":
        return _probe_podman_rootless()
    if backend_name == "docker":
        return _probe_docker_rootless()
    return False


def _probe_podman_rootless() -> bool:
    executable = shutil.which("podman")
    if executable is None:
        return False
    try:
        result = subprocess.run(  # nosec B603
            [executable, "info", "--format", "{{.Host.Security.Rootless}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip().lower() == "true"


def _probe_docker_rootless() -> bool:
    executable = shutil.which("docker")
    if executable is None:
        return False
    try:
        result = subprocess.run(  # nosec B603
            [executable, "info", "--format", "{{.SecurityOptions}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    try:
        security_options = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    if not isinstance(security_options, list):
        return False
    return any(option == "name=rootless" for option in security_options)
