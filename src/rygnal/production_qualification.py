"""Machine-readable Linux production qualification.

This module converts production containment, configuration, storage,
installed-package and API behavior into bounded release evidence.

A qualification report is evidence from one execution environment. It is
not a portable assertion that every host is qualified.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any

from rygnal.guarded_runner import (
    BubblewrapCommandBackend,
)
from rygnal.local_app import create_local_app
from rygnal.production_containment import (
    BubblewrapVerification,
    ProductionContainmentLimits,
    verify_production_bubblewrap,
)
from rygnal.runtime_config import (
    RuntimeEnvironment,
    load_runtime_config,
)
from rygnal.sqlite_migrations import (
    approval_schema_ready,
    audit_schema_ready,
    operation_schema_ready,
)

QUALIFICATION_SCHEMA_VERSION = "rygnal.production-qualification.v1"
MAX_QUALIFICATION_REPORT_BYTES = 128 * 1024
MAX_QUALIFICATION_CHECKS = 64
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIRECTORY_MODE = 0o700

_SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,95}$")
_SAFE_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,95}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")

_REQUIRED_REPORT_KEYS = {
    "schema_version",
    "generated_at",
    "qualified",
    "platform",
    "package",
    "bubblewrap",
    "features",
    "checks",
}
_REQUIRED_PLATFORM_KEYS = {
    "system",
    "release",
    "machine",
    "python",
}
_REQUIRED_PACKAGE_KEYS = {
    "version",
    "commit_sha",
    "wheel_sha256",
    "installed_boundary_verified",
}
_REQUIRED_BUBBLEWRAP_KEYS = {
    "version",
    "executable_sha256",
}
_REQUIRED_CHECK_KEYS = {
    "name",
    "passed",
    "required",
    "code",
    "duration_ms",
}


class ProductionQualificationError(RuntimeError):
    """Raised when qualification evidence is unsafe or invalid."""


@dataclass(frozen=True, slots=True)
class QualificationCheck:
    """One stable, non-secret qualification assertion."""

    name: str
    passed: bool
    required: bool
    code: str
    duration_ms: int

    def __post_init__(self) -> None:
        if not _SAFE_NAME_RE.fullmatch(self.name):
            raise ValueError("Qualification check name is invalid.")

        if not _SAFE_CODE_RE.fullmatch(self.code):
            raise ValueError("Qualification result code is invalid.")

        if isinstance(self.duration_ms, bool) or not 0 <= self.duration_ms <= 600_000:
            raise ValueError("Qualification duration is invalid.")

    def to_dict(self) -> dict[str, Any]:
        """Return the stable public check contract."""
        return {
            "name": self.name,
            "passed": self.passed,
            "required": self.required,
            "code": self.code,
            "duration_ms": self.duration_ms,
        }


@dataclass(frozen=True, slots=True)
class ProductionQualificationReport:
    """Bounded production qualification evidence."""

    generated_at: str
    qualified: bool
    platform_system: str
    platform_release: str
    platform_machine: str
    python_version: str
    package_version: str
    commit_sha: str
    wheel_sha256: str | None
    installed_boundary_verified: bool
    bubblewrap_version: str | None
    bubblewrap_sha256: str | None
    features: dict[str, bool]
    checks: tuple[QualificationCheck, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return the versioned JSON contract."""
        return {
            "schema_version": (QUALIFICATION_SCHEMA_VERSION),
            "generated_at": self.generated_at,
            "qualified": self.qualified,
            "platform": {
                "system": self.platform_system,
                "release": self.platform_release,
                "machine": self.platform_machine,
                "python": self.python_version,
            },
            "package": {
                "version": self.package_version,
                "commit_sha": self.commit_sha,
                "wheel_sha256": self.wheel_sha256,
                "installed_boundary_verified": (self.installed_boundary_verified),
            },
            "bubblewrap": {
                "version": self.bubblewrap_version,
                "executable_sha256": (self.bubblewrap_sha256),
            },
            "features": {key: bool(value) for key, value in sorted(self.features.items())},
            "checks": [check.to_dict() for check in self.checks],
        }


def qualify_production_host(
    *,
    config_path: str | Path,
    data_dir: str | Path,
    wheel_path: str | Path | None = None,
    commit_sha: str | None = None,
    checkout_root: str | Path | None = None,
    require_installed_package: bool = False,
    verification: BubblewrapVerification | None = None,
) -> ProductionQualificationReport:
    """Run all required production qualification checks."""
    checks: list[QualificationCheck] = []
    started = time.monotonic()

    platform_system = platform.system().lower()
    normalized_commit = _normalize_commit_sha(
        commit_sha or os.environ.get("GITHUB_SHA") or "unknown"
    )
    wheel_digest = (
        _sha256_file(
            _validated_regular_file(
                Path(wheel_path),
                purpose="wheel",
            )
        )
        if wheel_path is not None
        else None
    )
    installed_boundary = (
        _installed_package_boundary(checkout_root=checkout_root)
        if require_installed_package
        else True
    )

    checks.append(
        _check(
            name="host.linux",
            passed=platform_system == "linux",
            code=("ok" if platform_system == "linux" else "non_linux_host"),
            started=started,
        )
    )

    checks.append(
        QualificationCheck(
            name="package.wheel_identity",
            passed=(wheel_digest is not None if require_installed_package else True),
            required=require_installed_package,
            code=(
                "ok"
                if wheel_digest is not None
                else ("not_required" if not require_installed_package else "wheel_missing")
            ),
            duration_ms=0,
        )
    )
    checks.append(
        QualificationCheck(
            name="package.installed_boundary",
            passed=installed_boundary,
            required=require_installed_package,
            code=("ok" if installed_boundary else "source_checkout_import"),
            duration_ms=0,
        )
    )

    active_verification = (
        verification if verification is not None else verify_production_bubblewrap()
    )
    checks.append(
        _check(
            name="bubblewrap.behavioral_verification",
            passed=active_verification.eligible,
            code=("ok" if active_verification.eligible else "behavioral_verification_failed"),
            started=started,
        )
    )

    config = None

    try:
        config = load_runtime_config(
            config_path=config_path,
            environ={},
            allow_implicit_development=False,
        )
        production_config_valid = (
            config.environment == RuntimeEnvironment.PRODUCTION
            and config.api.auth_required
            and not config.api.docs_enabled
            and config.api.operator_token_value() is not None
        )
    except Exception:
        production_config_valid = False

    checks.append(
        _check(
            name="runtime.production_config",
            passed=production_config_valid,
            code=("ok" if production_config_valid else "production_config_invalid"),
            started=started,
        )
    )

    hostile_passed = False
    output_passed = False
    timeout_passed = False
    api_passed = False

    if active_verification.eligible:
        hostile_passed = _run_hostile_boundary_probe(active_verification)
        output_passed = _run_output_bound_probe(active_verification)
        timeout_passed = _run_timeout_tree_probe(active_verification)

        if production_config_valid and config is not None:
            api_passed = asyncio.run(
                _run_production_api_probe(
                    config_path=Path(config_path),
                    data_dir=Path(data_dir),
                )
            )

    checks.extend(
        (
            _check(
                name="sandbox.hostile_boundary",
                passed=hostile_passed,
                code=("ok" if hostile_passed else "hostile_boundary_failed"),
                started=started,
            ),
            _check(
                name="sandbox.output_bounded",
                passed=output_passed,
                code=("ok" if output_passed else "output_bound_failed"),
                started=started,
            ),
            _check(
                name="sandbox.descendant_timeout_cleanup",
                passed=timeout_passed,
                code=("ok" if timeout_passed else "timeout_cleanup_failed"),
                started=started,
            ),
            _check(
                name="runtime.production_api_startup",
                passed=api_passed,
                code=("ok" if api_passed else "production_startup_failed"),
                started=started,
            ),
        )
    )

    qualified = all(check.passed for check in checks if check.required)

    return ProductionQualificationReport(
        generated_at=datetime.now(UTC).isoformat(),
        qualified=qualified,
        platform_system=platform.system().lower(),
        platform_release=_bounded_text(
            platform.release(),
            maximum=128,
        ),
        platform_machine=_bounded_text(
            platform.machine(),
            maximum=64,
        ),
        python_version=platform.python_version(),
        package_version=_installed_package_version(),
        commit_sha=normalized_commit,
        wheel_sha256=wheel_digest,
        installed_boundary_verified=(installed_boundary),
        bubblewrap_version=(active_verification.version),
        bubblewrap_sha256=(active_verification.executable_sha256),
        features={key: bool(value) for key, value in active_verification.features.items()},
        checks=tuple(checks),
    )


def write_qualification_report(
    report: ProductionQualificationReport,
    destination: str | Path,
) -> str:
    """Atomically write private bounded evidence."""
    path = Path(destination).expanduser()

    if not path.is_absolute():
        path = path.absolute()

    _reject_symlink_components(path)
    _ensure_private_directory(path.parent)

    if path.is_symlink():
        raise ProductionQualificationError("Qualification report path is a symlink.")

    payload = (
        json.dumps(
            report.to_dict(),
            sort_keys=True,
            indent=2,
        ).encode("utf-8")
        + b"\n"
    )

    if len(payload) > MAX_QUALIFICATION_REPORT_BYTES:
        raise ProductionQualificationError("Qualification report exceeds its size limit.")

    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")

    if temporary.exists() or temporary.is_symlink():
        raise ProductionQualificationError("Temporary qualification path already exists.")

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = os.open(
        temporary,
        flags,
        _PRIVATE_FILE_MODE,
    )

    try:
        _write_all(
            descriptor,
            payload,
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    os.replace(
        temporary,
        path,
    )

    if os.name != "nt":
        os.chmod(
            path,
            _PRIVATE_FILE_MODE,
        )

    return hashlib.sha256(payload).hexdigest()


def validate_qualification_report(
    report_path: str | Path,
    *,
    expected_commit_sha: str | None = None,
    expected_wheel_sha256: str | None = None,
    require_qualified: bool = True,
) -> dict[str, Any]:
    """Validate strict evidence before a release gate."""
    path = _validated_regular_file(
        Path(report_path),
        purpose="qualification-report",
        maximum_bytes=(MAX_QUALIFICATION_REPORT_BYTES),
    )

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise ProductionQualificationError("Qualification report could not be parsed.") from None

    if not isinstance(payload, dict):
        raise ProductionQualificationError("Qualification report root is invalid.")

    if set(payload) != _REQUIRED_REPORT_KEYS:
        raise ProductionQualificationError("Qualification report fields are invalid.")

    if payload.get("schema_version") != QUALIFICATION_SCHEMA_VERSION:
        raise ProductionQualificationError("Qualification report schema is unsupported.")

    if not isinstance(payload.get("qualified"), bool):
        raise ProductionQualificationError("Qualification status is invalid.")

    platform_payload = payload.get("platform")
    package_payload = payload.get("package")
    bubblewrap_payload = payload.get("bubblewrap")
    features_payload = payload.get("features")
    checks_payload = payload.get("checks")

    if not isinstance(platform_payload, dict) or set(platform_payload) != _REQUIRED_PLATFORM_KEYS:
        raise ProductionQualificationError("Qualification platform metadata is invalid.")

    if not isinstance(package_payload, dict) or set(package_payload) != _REQUIRED_PACKAGE_KEYS:
        raise ProductionQualificationError("Qualification package metadata is invalid.")

    if (
        not isinstance(bubblewrap_payload, dict)
        or set(bubblewrap_payload) != _REQUIRED_BUBBLEWRAP_KEYS
    ):
        raise ProductionQualificationError("Qualification Bubblewrap metadata is invalid.")

    if not isinstance(features_payload, dict):
        raise ProductionQualificationError("Qualification features are invalid.")

    if not all(
        isinstance(key, str) and isinstance(value, bool) for key, value in features_payload.items()
    ):
        raise ProductionQualificationError("Qualification feature values are invalid.")

    if (
        not isinstance(checks_payload, list)
        or not checks_payload
        or len(checks_payload) > MAX_QUALIFICATION_CHECKS
    ):
        raise ProductionQualificationError("Qualification checks are invalid.")

    names: set[str] = set()
    required_passed = True

    for check in checks_payload:
        if not isinstance(check, dict) or set(check) != _REQUIRED_CHECK_KEYS:
            raise ProductionQualificationError("Qualification check contract is invalid.")

        name = check.get("name")
        code = check.get("code")
        passed = check.get("passed")
        required = check.get("required")
        duration = check.get("duration_ms")

        if not isinstance(name, str) or not _SAFE_NAME_RE.fullmatch(name) or name in names:
            raise ProductionQualificationError("Qualification check name is invalid.")

        names.add(name)

        if not isinstance(code, str) or not _SAFE_CODE_RE.fullmatch(code):
            raise ProductionQualificationError("Qualification check code is invalid.")

        if not isinstance(passed, bool) or not isinstance(required, bool):
            raise ProductionQualificationError("Qualification check status is invalid.")

        if (
            isinstance(duration, bool)
            or not isinstance(duration, int)
            or not 0 <= duration <= 600_000
        ):
            raise ProductionQualificationError("Qualification check duration is invalid.")

        if required and not passed:
            required_passed = False

    if payload["qualified"] != required_passed:
        raise ProductionQualificationError("Qualification summary conflicts with checks.")

    commit_value = package_payload.get("commit_sha")
    wheel_value = package_payload.get("wheel_sha256")

    if expected_commit_sha is not None:
        expected_commit = _normalize_commit_sha(expected_commit_sha)

        if commit_value != expected_commit:
            raise ProductionQualificationError("Qualification commit does not match.")

    if expected_wheel_sha256 is not None:
        expected_wheel = expected_wheel_sha256.strip().lower()

        if not _SHA256_RE.fullmatch(expected_wheel):
            raise ProductionQualificationError("Expected wheel digest is invalid.")

        if wheel_value != expected_wheel:
            raise ProductionQualificationError("Qualification wheel does not match.")

    if require_qualified and not payload["qualified"]:
        raise ProductionQualificationError("Production qualification did not pass.")

    return payload


def _run_hostile_boundary_probe(
    verification: BubblewrapVerification,
) -> bool:
    limits = _qualification_limits()

    with tempfile.TemporaryDirectory(prefix="rygnal-m18-boundary-") as temporary:
        root = Path(temporary).resolve()
        workspace = root / "workspace"
        workspace.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        host_secret = root / "host-secret"
        host_secret.write_text(
            "M18_HOST_SECRET_MUST_NOT_LEAK",
            encoding="utf-8",
        )
        host_write_target = root / "host-write-target"

        descriptor = os.open(
            host_secret,
            os.O_RDONLY,
        )
        previous_environment = os.environ.get("RYGNAL_M18_HOST_SECRET")

        try:
            os.set_inheritable(
                descriptor,
                True,
            )
            os.environ["RYGNAL_M18_HOST_SECRET"] = "M18_ENV_SECRET_MUST_NOT_LEAK"

            script = "\n".join(
                (
                    "set -eu",
                    "printf 'workspace-ok' > workspace-write.txt",
                    "[ \"$(cat workspace-write.txt)\" = 'workspace-ok' ]",
                    (f"[ ! -e {shlex.quote(host_secret.as_posix())} ]"),
                    (
                        "if printf 'forbidden' > "
                        f"{shlex.quote(host_write_target.as_posix())} "
                        "2>/dev/null; then exit 21; fi"
                    ),
                    (
                        "if printf 'forbidden' > "
                        "/usr/bin/rygnal-m18-write "
                        "2>/dev/null; then exit 22; fi"
                    ),
                    ('[ -z "${RYGNAL_M18_HOST_SECRET:-}" ]'),
                    (f"[ ! -e /proc/self/fd/{descriptor} ]"),
                    "set -- /proc/[0-9]*",
                    '[ "$#" -le 4 ]',
                    ("command -v /usr/bin/getent >/dev/null 2>&1"),
                    ("command -v /usr/bin/timeout >/dev/null 2>&1"),
                    (
                        "if /usr/bin/timeout 2 "
                        "/usr/bin/getent ahosts "
                        "example.com >/dev/null 2>&1; "
                        "then exit 23; fi"
                    ),
                    "open_limit=$(ulimit -n)",
                    (f'[ "$open_limit" -le {limits.open_files} ]'),
                    "printf 'M18_BOUNDARY_OK\\n'",
                )
            )

            backend = BubblewrapCommandBackend(
                production_verification=verification,
                limits=limits,
            )
            result = backend.run(
                (
                    "/bin/sh",
                    "-c",
                    script,
                ),
                workspace,
                15,
            )
        except Exception:
            return False
        finally:
            os.close(descriptor)

            if previous_environment is None:
                os.environ.pop(
                    "RYGNAL_M18_HOST_SECRET",
                    None,
                )
            else:
                os.environ["RYGNAL_M18_HOST_SECRET"] = previous_environment

        return (
            result.exit_code == 0
            and not result.timed_out
            and not result.sandbox_setup_failed
            and "M18_BOUNDARY_OK" in result.stdout
            and "M18_HOST_SECRET_MUST_NOT_LEAK" not in result.stdout
            and "M18_ENV_SECRET_MUST_NOT_LEAK" not in result.stdout
            and (workspace / "workspace-write.txt").read_text(encoding="utf-8") == "workspace-ok"
            and not host_write_target.exists()
        )


def _run_output_bound_probe(
    verification: BubblewrapVerification,
) -> bool:
    limits = _qualification_limits()
    awk_path = shutil.which("awk")

    if awk_path is None:
        return False

    awk_executable = Path(awk_path).resolve(strict=False).as_posix()

    with tempfile.TemporaryDirectory(prefix="rygnal-m18-output-") as temporary:
        workspace = Path(temporary).resolve() / "workspace"
        workspace.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        backend = BubblewrapCommandBackend(
            production_verification=verification,
            limits=limits,
        )

        try:
            result = backend.run(
                (
                    awk_executable,
                    ('BEGIN { for (i = 0; i < 100000; i++) printf "x" }'),
                ),
                workspace,
                15,
            )
        except Exception:
            return False

        return (
            result.exit_code == 0
            and not result.timed_out
            and result.output_truncated
            and len(
                result.stdout.encode(
                    "utf-8",
                    errors="replace",
                )
            )
            <= limits.max_output_bytes
        )


def _run_timeout_tree_probe(
    verification: BubblewrapVerification,
) -> bool:
    limits = _qualification_limits()

    with tempfile.TemporaryDirectory(prefix="rygnal-m18-timeout-") as temporary:
        workspace = Path(temporary).resolve() / "workspace"
        workspace.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        backend = BubblewrapCommandBackend(
            production_verification=verification,
            limits=limits,
        )
        script = (
            "(sleep 3; "
            "printf 'survived' > timeout-survived) & "
            "printf 'started' > timeout-started; "
            "wait"
        )

        try:
            result = backend.run(
                (
                    "/bin/sh",
                    "-c",
                    script,
                ),
                workspace,
                1,
            )
        except Exception:
            return False

        time.sleep(3.5)

        return (
            result.timed_out
            and result.exit_code is None
            and (workspace / "timeout-started").is_file()
            and not (workspace / "timeout-survived").exists()
        )


async def _run_production_api_probe(
    *,
    config_path: Path,
    data_dir: Path,
) -> bool:
    try:
        config = load_runtime_config(
            config_path=config_path,
            environ={},
            allow_implicit_development=False,
        )
        token = config.api.operator_token_value()

        if token is None:
            return False

        app = create_local_app(
            data_dir=data_dir.resolve(strict=False),
            environ={},
            runtime_config=config,
        )

        health = await _asgi_request(
            app,
            method="GET",
            path="/health",
        )
        ready = await _asgi_request(
            app,
            method="GET",
            path="/ready",
        )
        payload = json.dumps(
            {
                "tool_name": "file_read",
                "action": "read",
                "target": "README.md",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        denied = await _asgi_request(
            app,
            method="POST",
            path="/v1/evaluate",
            body=payload,
        )
        accepted = await _asgi_request(
            app,
            method="POST",
            path="/v1/evaluate",
            body=payload,
            authorization=f"Bearer {token}",
        )
        dependencies = app.state.rygnal_local_dependencies

        return (
            health[0] == 200
            and ready[0] == 200
            and denied[0] == 401
            and accepted[0] == 200
            and (health[1].get("x-content-type-options") == "nosniff")
            and (health[1].get("x-frame-options") == "DENY")
            and (json.loads(ready[2]).get("status") == "ready")
            and audit_schema_ready(dependencies.paths.audit_db)
            and approval_schema_ready(dependencies.paths.approval_db)
            and operation_schema_ready(dependencies.operation_store.db_path)
        )
    except Exception:
        return False


async def _asgi_request(
    app: Any,
    *,
    method: str,
    path: str,
    body: bytes = b"",
    authorization: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Issue one bounded in-process ASGI request."""
    delivered = False
    messages: list[dict[str, Any]] = []
    headers: list[tuple[bytes, bytes]] = [
        (
            b"host",
            b"127.0.0.1",
        ),
        (
            b"connection",
            b"close",
        ),
    ]

    if body:
        headers.extend(
            (
                (
                    b"content-type",
                    b"application/json",
                ),
                (
                    b"content-length",
                    str(len(body)).encode("ascii"),
                ),
            )
        )

    if authorization is not None:
        headers.append(
            (
                b"authorization",
                authorization.encode("ascii"),
            )
        )

    async def receive() -> dict[str, Any]:
        nonlocal delivered

        if not delivered:
            delivered = True

            return {
                "type": "http.request",
                "body": body,
                "more_body": False,
            }

        return {
            "type": "http.disconnect",
        }

    async def send(
        message: dict[str, Any],
    ) -> None:
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {
            "version": "3.0",
            "spec_version": "2.3",
        },
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": (
            "127.0.0.1",
            49152,
        ),
        "server": (
            "127.0.0.1",
            8787,
        ),
        "state": {},
    }

    await app(
        scope,
        receive,
        send,
    )

    starts = [message for message in messages if message.get("type") == "http.response.start"]

    if len(starts) != 1:
        raise ProductionQualificationError("ASGI qualification response was invalid.")

    start_message = starts[0]
    response_headers = {
        bytes(name).decode("latin-1").lower(): bytes(value).decode("latin-1")
        for name, value in start_message.get("headers", [])
    }
    response_body = b"".join(
        bytes(message.get("body", b""))
        for message in messages
        if message.get("type") == "http.response.body"
    )

    return (
        int(start_message["status"]),
        response_headers,
        response_body,
    )


def _qualification_limits() -> ProductionContainmentLimits:
    return ProductionContainmentLimits(
        cpu_seconds=10,
        address_space_bytes=512 * 1024**2,
        file_size_bytes=2 * 1024**2,
        open_files=64,
        processes=512,
        max_output_bytes=4096,
        termination_grace_seconds=1.0,
    )


def _check(
    *,
    name: str,
    passed: bool,
    code: str,
    started: float,
) -> QualificationCheck:
    return QualificationCheck(
        name=name,
        passed=passed,
        required=True,
        code=code,
        duration_ms=min(
            int((time.monotonic() - started) * 1000),
            600_000,
        ),
    )


def _installed_package_boundary(
    *,
    checkout_root: str | Path | None,
) -> bool:
    if checkout_root is None:
        return False

    checkout = Path(checkout_root).expanduser().resolve(strict=True)
    module = Path(__file__).resolve(strict=True)

    return "site-packages" in module.parts and not module.is_relative_to(checkout)


def _installed_package_version() -> str:
    try:
        return _bounded_text(
            package_version("rygnal-core"),
            maximum=64,
        )
    except PackageNotFoundError:
        return "source-tree"


def _normalize_commit_sha(
    value: str,
) -> str:
    normalized = value.strip().lower()

    if normalized == "unknown":
        return normalized

    if not _COMMIT_RE.fullmatch(normalized):
        raise ProductionQualificationError("Commit identity is invalid.")

    return normalized


def _validated_regular_file(
    path: Path,
    *,
    purpose: str,
    maximum_bytes: int | None = None,
) -> Path:
    candidate = path.expanduser()

    if not candidate.is_absolute():
        candidate = candidate.absolute()

    _reject_symlink_components(candidate)

    if candidate.is_symlink():
        raise ProductionQualificationError(f"{purpose} path is a symlink.")

    try:
        metadata = candidate.stat(follow_symlinks=False)
    except OSError:
        raise ProductionQualificationError(f"{purpose} file is unavailable.") from None

    if not stat.S_ISREG(metadata.st_mode):
        raise ProductionQualificationError(f"{purpose} path is not a regular file.")

    if maximum_bytes is not None and metadata.st_size > maximum_bytes:
        raise ProductionQualificationError(f"{purpose} file exceeds its size limit.")

    return candidate


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def _bounded_text(
    value: str,
    *,
    maximum: int,
) -> str:
    cleaned = "".join(character for character in value if character.isprintable()).strip()

    return cleaned[:maximum] or "unknown"


def _ensure_private_directory(
    path: Path,
) -> None:
    _reject_symlink_components(path)

    if path.is_symlink():
        raise ProductionQualificationError("Qualification directory is a symlink.")

    path.mkdir(
        mode=_PRIVATE_DIRECTORY_MODE,
        parents=True,
        exist_ok=True,
    )

    if not path.is_dir():
        raise ProductionQualificationError("Qualification path is not a directory.")

    if os.name != "nt":
        os.chmod(
            path,
            _PRIVATE_DIRECTORY_MODE,
        )


def _reject_symlink_components(
    path: Path,
) -> None:
    absolute = path if path.is_absolute() else path.absolute()
    current = Path(absolute.anchor)

    for component in absolute.parts[1:-1]:
        current /= component

        if current.is_symlink():
            raise ProductionQualificationError("Qualification path traverses a symlink.")


def _write_all(
    descriptor: int,
    payload: bytes,
) -> None:
    view = memoryview(payload)

    while view:
        written = os.write(
            descriptor,
            view,
        )

        if written <= 0:
            raise ProductionQualificationError("Qualification report write failed.")

        view = view[written:]


def _failure_report(
    *,
    commit_sha: str,
    wheel_path: str | Path | None,
) -> ProductionQualificationReport:
    wheel_digest = None

    try:
        if wheel_path is not None:
            wheel_digest = _sha256_file(
                _validated_regular_file(
                    Path(wheel_path),
                    purpose="wheel",
                )
            )
    except Exception:
        wheel_digest = None

    return ProductionQualificationReport(
        generated_at=datetime.now(UTC).isoformat(),
        qualified=False,
        platform_system=platform.system().lower(),
        platform_release=_bounded_text(
            platform.release(),
            maximum=128,
        ),
        platform_machine=_bounded_text(
            platform.machine(),
            maximum=64,
        ),
        python_version=platform.python_version(),
        package_version=_installed_package_version(),
        commit_sha=commit_sha,
        wheel_sha256=wheel_digest,
        installed_boundary_verified=False,
        bubblewrap_version=None,
        bubblewrap_sha256=None,
        features={},
        checks=(
            QualificationCheck(
                name="qualification.internal_execution",
                passed=False,
                required=True,
                code="internal_execution_failed",
                duration_ms=0,
            ),
        ),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m rygnal.production_qualification")
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    qualify = subparsers.add_parser("qualify")
    qualify.add_argument(
        "--output",
        required=True,
    )
    qualify.add_argument(
        "--config",
        required=True,
    )
    qualify.add_argument(
        "--data-dir",
        required=True,
    )
    qualify.add_argument(
        "--wheel",
    )
    qualify.add_argument(
        "--commit",
        default=os.environ.get(
            "GITHUB_SHA",
            "unknown",
        ),
    )
    qualify.add_argument(
        "--checkout-root",
    )
    qualify.add_argument(
        "--require-installed",
        action="store_true",
    )

    verify = subparsers.add_parser("verify-report")
    verify.add_argument(
        "--report",
        required=True,
    )
    verify.add_argument(
        "--commit",
    )
    verify.add_argument(
        "--wheel-sha256",
    )
    verify.add_argument(
        "--allow-unqualified",
        action="store_true",
    )

    return parser


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """Run qualification or enforce an evidence gate."""
    parser = _build_parser()
    arguments = parser.parse_args(list(argv) if argv is not None else None)

    if arguments.command == "verify-report":
        try:
            payload = validate_qualification_report(
                arguments.report,
                expected_commit_sha=arguments.commit,
                expected_wheel_sha256=(arguments.wheel_sha256),
                require_qualified=(not arguments.allow_unqualified),
            )
        except ProductionQualificationError:
            print(
                "Production qualification gate failed.",
                file=sys.stderr,
            )
            return 2

        print(
            json.dumps(
                {
                    "schema_version": payload["schema_version"],
                    "qualified": payload["qualified"],
                    "commit_sha": payload["package"]["commit_sha"],
                    "wheel_sha256": payload["package"]["wheel_sha256"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    commit = _normalize_commit_sha(arguments.commit)

    try:
        report = qualify_production_host(
            config_path=arguments.config,
            data_dir=arguments.data_dir,
            wheel_path=arguments.wheel,
            commit_sha=commit,
            checkout_root=arguments.checkout_root,
            require_installed_package=(arguments.require_installed),
        )
    except Exception:
        report = _failure_report(
            commit_sha=commit,
            wheel_path=arguments.wheel,
        )

    try:
        report_sha256 = write_qualification_report(
            report,
            arguments.output,
        )
    except ProductionQualificationError:
        print(
            "Unable to write production qualification evidence.",
            file=sys.stderr,
        )
        return 3

    print(
        json.dumps(
            {
                "schema_version": (QUALIFICATION_SCHEMA_VERSION),
                "qualified": report.qualified,
                "report_sha256": report_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )

    return 0 if report.qualified else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_QUALIFICATION_REPORT_BYTES",
    "ProductionQualificationError",
    "ProductionQualificationReport",
    "QUALIFICATION_SCHEMA_VERSION",
    "QualificationCheck",
    "main",
    "qualify_production_host",
    "validate_qualification_report",
    "write_qualification_report",
]
