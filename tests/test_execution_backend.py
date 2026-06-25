from types import SimpleNamespace

import pytest

import rygnal.execution_backend as backend_module
from rygnal.execution_backend import (
    ExecutionBackendName,
    ExecutionBackendSelectionError,
    HostBackendCapabilities,
    detect_host_backend_capabilities,
    select_execution_backend,
)


def test_detect_host_backend_capabilities_is_lazy(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_probe(*args: object, **kwargs: object) -> bool:
        raise AssertionError("probe should not run during capability construction")

    monkeypatch.setattr(backend_module, "_probe_bubblewrap_namespaces", fail_probe)
    monkeypatch.setattr(backend_module, "_probe_sandbox_helper", fail_probe)
    monkeypatch.setattr(backend_module, "_probe_verified_rootless_container", fail_probe)

    capabilities = detect_host_backend_capabilities(
        env={"RYGNAL_CONFIGURED_CONTAINER_BACKEND": "podman"}
    )

    assert capabilities.configured_container_backend == "podman"


def test_official_ci_image_reason_is_not_shadowed_by_general_bubblewrap() -> None:
    selection = select_execution_backend(
        HostBackendCapabilities(
            os_name="Linux",
            official_rygnal_ci_image=True,
            bwrap_namespace_probe_passed=True,
            has_systemd_run=True,
            configured_container_backend="podman",
            verified_rootless_container_available=True,
        )
    )

    assert selection.name == ExecutionBackendName.LINUX_BUBBLEWRAP
    assert selection.safe_by_default is True
    assert "Official Rygnal CI image" in selection.reason


def test_bubblewrap_route_does_not_probe_later_container_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_container_probe(backend_name: str | None) -> bool:
        raise AssertionError(f"container probe should not run: {backend_name}")

    monkeypatch.setattr(
        backend_module,
        "_probe_verified_rootless_container",
        fail_container_probe,
    )

    selection = select_execution_backend(
        HostBackendCapabilities(
            os_name="linux",
            bwrap_namespace_probe_passed=True,
            configured_container_backend="podman",
        )
    )

    assert selection.name == ExecutionBackendName.LINUX_BUBBLEWRAP


def test_os_name_is_normalized_before_routing() -> None:
    selection = select_execution_backend(
        HostBackendCapabilities(
            os_name="LiNuX",
            bwrap_namespace_probe_passed=True,
        )
    )

    assert selection.name == ExecutionBackendName.LINUX_BUBBLEWRAP


def test_failed_sandbox_helper_falls_through_to_systemd() -> None:
    selection = select_execution_backend(
        HostBackendCapabilities(
            os_name="linux",
            bwrap_namespace_probe_passed=False,
            signed_sandbox_helper_probe_passed=False,
            has_systemd_run=True,
        )
    )

    assert selection.name == ExecutionBackendName.LINUX_SYSTEMD_USER
    assert selection.safe_by_default is True


def test_fake_container_env_does_not_authorize_safe_backend() -> None:
    with pytest.raises(ExecutionBackendSelectionError) as exc_info:
        select_execution_backend(
            HostBackendCapabilities(
                os_name="linux",
                bwrap_namespace_probe_passed=False,
                signed_sandbox_helper_probe_passed=False,
                has_systemd_run=False,
                configured_container_backend="fake_engine",
                verified_rootless_container_available=False,
            )
        )

    assert "No verified containment backend" in str(exc_info.value)


def test_configured_container_requires_verified_rootless_probe() -> None:
    with pytest.raises(ExecutionBackendSelectionError):
        select_execution_backend(
            HostBackendCapabilities(
                os_name="linux",
                bwrap_namespace_probe_passed=False,
                signed_sandbox_helper_probe_passed=False,
                has_systemd_run=False,
                configured_container_backend="podman",
                verified_rootless_container_available=False,
            )
        )


def test_verified_rootless_container_can_be_selected_on_linux() -> None:
    selection = select_execution_backend(
        HostBackendCapabilities(
            os_name="linux",
            bwrap_namespace_probe_passed=False,
            signed_sandbox_helper_probe_passed=False,
            has_systemd_run=False,
            configured_container_backend="podman",
            verified_rootless_container_available=True,
        )
    )

    assert selection.name == ExecutionBackendName.CONFIGURED_CONTAINER
    assert selection.safe_by_default is True
    assert "Verified rootless container backend" in selection.reason


@pytest.mark.parametrize("os_name", ["linux", "darwin", "windows"])
def test_unsafe_local_is_explicit_cross_platform_dev_escape_hatch(os_name: str) -> None:
    selection = select_execution_backend(
        HostBackendCapabilities(
            os_name=os_name,
            unsafe_local_requested=True,
        )
    )

    assert selection.name == ExecutionBackendName.UNSAFE_LOCAL
    assert selection.safe_by_default is False
    assert selection.warning is not None
    assert "must never be selected by default" in selection.warning


def test_invalid_container_env_on_macos_still_gets_tailored_platform_error() -> None:
    with pytest.raises(ExecutionBackendSelectionError) as exc_info:
        select_execution_backend(
            HostBackendCapabilities(
                os_name="darwin",
                configured_container_backend="fake_engine",
                verified_rootless_container_available=False,
            )
        )

    message = str(exc_info.value)

    assert "macOS is recognized" in message
    assert "Seatbelt containment is planned" in message
    assert "RYGNAL_CONFIGURED_CONTAINER_BACKEND=docker" in message
    assert "RYGNAL_CONFIGURED_CONTAINER_BACKEND=podman" in message
    assert "supported Linux backend with Bubblewrap" in message
    assert "--unsafe-local only as an explicit non-contained" in message


def test_invalid_container_env_on_windows_still_gets_tailored_platform_error() -> None:
    with pytest.raises(ExecutionBackendSelectionError) as exc_info:
        select_execution_backend(
            HostBackendCapabilities(
                os_name="windows",
                configured_container_backend="fake_engine",
                verified_rootless_container_available=False,
            )
        )

    assert "Windows is recognized" in str(exc_info.value)
    assert "WSL2/Linux backend" in str(exc_info.value)


def test_docker_rootless_probe_rejects_naive_substring_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_module.shutil,
        "which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    monkeypatch.setattr(
        backend_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='["name=allow-rootless-escalation"]',
        ),
    )

    assert backend_module._probe_docker_rootless() is False


def test_docker_rootless_probe_accepts_exact_security_option(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend_module.shutil,
        "which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    monkeypatch.setattr(
        backend_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='["name=rootless"]',
        ),
    )

    assert backend_module._probe_docker_rootless() is True
