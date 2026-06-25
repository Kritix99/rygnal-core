"""Execution backend selection for guarded workspace runs.

This module defines the first M1 backend-routing contract. It does not run
agents yet. It decides which containment backend is safe to use and fails
closed when no verified backend is available.
"""

from __future__ import annotations

import json
import os
import platform
import shutil

# Intentional fixed-argv backend probes; all subprocess calls use shell=False.
import subprocess  # nosec B404
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property


class ExecutionBackendName(StrEnum):
    """Known execution backend names."""

    LINUX_BUBBLEWRAP = "linux_bubblewrap"
    LINUX_BUBBLEWRAP_HELPER = "linux_bubblewrap_helper"
    LINUX_SYSTEMD_USER = "linux_systemd_user"
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
    """Lazy-evaluated host capabilities for backend selection.

    Expensive probes only run when the router reaches that backend candidate.
    Test overrides let unit tests prove routing without launching subprocesses.
    """

    def __init__(
        self,
        *,
        env: Mapping[str, str] | None = None,
        os_name: str | None = None,
        has_bwrap: bool | None = None,
        bwrap_namespace_probe_passed: bool | None = None,
        official_rygnal_ci_image: bool | None = None,
        signed_sandbox_helper_probe_passed: bool | None = None,
        has_systemd_run: bool | None = None,
        configured_container_backend: str | None = None,
        verified_rootless_container_available: bool | None = None,
        unsafe_local_requested: bool | None = None,
    ) -> None:
        self._env = os.environ if env is None else env
        self.os_name = (os_name or platform.system()).lower()

        self._has_bwrap_override = has_bwrap
        self._bwrap_namespace_probe_override = bwrap_namespace_probe_passed
        self._signed_sandbox_helper_probe_override = signed_sandbox_helper_probe_passed
        self._has_systemd_run_override = has_systemd_run
        self._verified_rootless_container_override = verified_rootless_container_available

        self.official_rygnal_ci_image = (
            official_rygnal_ci_image
            if official_rygnal_ci_image is not None
            else self._env.get("RYGNAL_OFFICIAL_CI_IMAGE") == "1"
        )
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

    @cached_property
    def has_bwrap(self) -> bool:
        if self._has_bwrap_override is not None:
            return self._has_bwrap_override
        return shutil.which("bwrap") is not None

    @cached_property
    def bwrap_namespace_probe_passed(self) -> bool:
        if self._bwrap_namespace_probe_override is not None:
            return self._bwrap_namespace_probe_override
        if self.os_name != "linux" or not self.has_bwrap:
            return False
        return _probe_bubblewrap_namespaces()

    @cached_property
    def signed_sandbox_helper_probe_passed(self) -> bool:
        if self._signed_sandbox_helper_probe_override is not None:
            return self._signed_sandbox_helper_probe_override
        return _probe_sandbox_helper()

    @cached_property
    def has_systemd_run(self) -> bool:
        if self._has_systemd_run_override is not None:
            return self._has_systemd_run_override
        return shutil.which("systemd-run") is not None

    @cached_property
    def verified_rootless_container_available(self) -> bool:
        if self._verified_rootless_container_override is not None:
            return self._verified_rootless_container_override
        return _probe_verified_rootless_container(self.configured_container_backend)


def select_execution_backend(
    capabilities: HostBackendCapabilities,
) -> ExecutionBackendSelection:
    """Select an execution backend deterministically."""

    if capabilities.unsafe_local_requested:
        return ExecutionBackendSelection(
            name=ExecutionBackendName.UNSAFE_LOCAL,
            safe_by_default=False,
            reason="Unsafe local execution was explicitly requested.",
            warning=(
                "Unsafe local execution is not a containment backend and must never "
                "be selected by default."
            ),
        )

    os_name = capabilities.os_name

    if os_name == "linux":
        if capabilities.official_rygnal_ci_image and capabilities.bwrap_namespace_probe_passed:
            return ExecutionBackendSelection(
                name=ExecutionBackendName.LINUX_BUBBLEWRAP,
                safe_by_default=True,
                reason="Official Rygnal CI image provides verified Bubblewrap support.",
            )

        if capabilities.bwrap_namespace_probe_passed:
            return ExecutionBackendSelection(
                name=ExecutionBackendName.LINUX_BUBBLEWRAP,
                safe_by_default=True,
                reason="Bubblewrap active namespace probe passed.",
            )

        if capabilities.signed_sandbox_helper_probe_passed:
            return ExecutionBackendSelection(
                name=ExecutionBackendName.LINUX_BUBBLEWRAP_HELPER,
                safe_by_default=True,
                reason="Signed sandbox helper probe passed for helper-backed Bubblewrap.",
            )

        if capabilities.has_systemd_run:
            return ExecutionBackendSelection(
                name=ExecutionBackendName.LINUX_SYSTEMD_USER,
                safe_by_default=True,
                reason="systemd-run --user is available as an optional Linux backend.",
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

    if os_name == "darwin":
        raise ExecutionBackendSelectionError(
            "macOS is recognized, but Seatbelt containment is planned and not yet "
            "active. Configure a verified rootless container backend before guarded "
            "execution, for example RYGNAL_CONFIGURED_CONTAINER_BACKEND=docker "
            "or RYGNAL_CONFIGURED_CONTAINER_BACKEND=podman with rootless container "
            "support enabled. Alternatively run on a supported Linux backend with "
            "Bubblewrap. Use --unsafe-local only as an explicit non-contained "
            "development/test escape hatch."
        )

    if os_name == "windows":
        raise ExecutionBackendSelectionError(
            "Windows is recognized, but native Windows containment is not supported. "
            "Run Rygnal inside a supported WSL2/Linux backend or configure a "
            "verified rootless container backend."
        )

    raise ExecutionBackendSelectionError(
        "No verified containment backend is available for guarded execution. "
        "Install Bubblewrap or configure a supported backend; Rygnal will not "
        "silently degrade to unsafe local execution."
    )


def detect_host_backend_capabilities(
    *,
    env: Mapping[str, str] | None = None,
) -> HostBackendCapabilities:
    """Return lazy host capability detector."""

    return HostBackendCapabilities(env=env)


def _probe_bubblewrap_namespaces() -> bool:
    bwrap_path = shutil.which("bwrap")
    if bwrap_path is None:
        return False

    try:
        # Fixed probe argv; shell=False.
        result = subprocess.run(  # nosec B603
            [
                bwrap_path,
                "--unshare-user",
                "--unshare-pid",
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False

    return result.returncode == 0


def _probe_sandbox_helper() -> bool:
    helper_path = shutil.which("rygnal-sandbox-helper")
    if helper_path is None:
        return False

    try:
        # Fixed probe argv; shell=False.
        result = subprocess.run(  # nosec B603
            [helper_path, "probe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False

    return result.returncode == 0


def _probe_verified_rootless_container(backend_name: str | None) -> bool:
    if backend_name == "podman":
        return _probe_podman_rootless()

    if backend_name == "docker":
        return _probe_docker_rootless()

    return False


def _probe_podman_rootless() -> bool:
    podman_path = shutil.which("podman")
    if podman_path is None:
        return False

    try:
        # Fixed probe argv; shell=False.
        result = subprocess.run(  # nosec B603
            [podman_path, "info", "--format", "{{.Host.Security.Rootless}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False

    return result.returncode == 0 and result.stdout.strip().lower() == "true"


def _probe_docker_rootless() -> bool:
    docker_path = shutil.which("docker")
    if docker_path is None:
        return False

    try:
        # Fixed probe argv; shell=False.
        result = subprocess.run(  # nosec B603
            [docker_path, "info", "--format", "{{json .SecurityOptions}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=8,
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
