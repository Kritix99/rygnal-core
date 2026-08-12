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


def test_detect_host_backend_capabilities_is_lazy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_probe(*args: object, **kwargs: object) -> bool:
        raise AssertionError("probe should not run during capability construction")

    monkeypatch.setattr(
        backend_module,
        "_probe_verified_rootless_container",
        fail_probe,
    )

    capabilities = detect_host_backend_capabilities(
        env={"RYGNAL_CONFIGURED_CONTAINER_BACKEND": "podman"}
    )

    assert capabilities.configured_container_backend == "podman"


def test_fake_container_env_does_not_authorize_safe_backend() -> None:
    with pytest.raises(ExecutionBackendSelectionError) as exc_info:
        select_execution_backend(
            HostBackendCapabilities(
                configured_container_backend="fake_engine",
                verified_rootless_container_available=False,
            )
        )

    assert "Configured containment backend is not verified" in str(exc_info.value)


def test_configured_container_requires_verified_rootless_probe() -> None:
    with pytest.raises(ExecutionBackendSelectionError):
        select_execution_backend(
            HostBackendCapabilities(
                configured_container_backend="podman",
                verified_rootless_container_available=False,
            )
        )


def test_verified_rootless_container_can_be_selected() -> None:
    selection = select_execution_backend(
        HostBackendCapabilities(
            configured_container_backend="podman",
            verified_rootless_container_available=True,
        )
    )

    assert selection.name == ExecutionBackendName.CONFIGURED_CONTAINER
    assert selection.safe_by_default is True
    assert "Verified rootless container backend" in selection.reason


@pytest.mark.parametrize("unsafe_local_requested", [True, False])
def test_unsafe_local_is_explicit_dev_escape_hatch(
    unsafe_local_requested: bool,
) -> None:
    if not unsafe_local_requested:
        return

    selection = select_execution_backend(
        HostBackendCapabilities(unsafe_local_requested=True)
    )

    assert selection.name == ExecutionBackendName.UNSAFE_LOCAL
    assert selection.safe_by_default is False
    assert selection.warning is not None
    assert "must never be selected by default" in selection.warning


def test_missing_backend_fails_closed() -> None:
    with pytest.raises(ExecutionBackendSelectionError) as exc_info:
        select_execution_backend(HostBackendCapabilities())

    assert "No verified containment backend" in str(exc_info.value)


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
