"""Verified Linux production containment for guarded execution."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import stat
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO

MINIMUM_BUBBLEWRAP_VERSION = (0, 8, 0)

REQUIRED_BUBBLEWRAP_FLAGS = (
    "--die-with-parent",
    "--new-session",
    "--unshare-user",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-net",
    "--unshare-cgroup",
    "--cap-drop",
    "--clearenv",
    "--proc",
    "--dev",
    "--tmpfs",
    "--ro-bind",
    "--bind",
    "--setenv",
    "--chdir",
)

PRODUCTION_BUBBLEWRAP_HARDENING_FLAGS = (
    "--die-with-parent",
    "--new-session",
    "--unshare-cgroup",
    "--cap-drop",
    "ALL",
)

_ALLOWED_PROBE_ENVIRONMENT = {
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "PATH",
    "PWD",
    "RYGNAL_HOST_SECRET",
    "RYGNAL_PROBE",
    "TMPDIR",
    "USER",
}

_NAMESPACE_NAMES = (
    "user",
    "pid",
    "ipc",
    "uts",
    "net",
    "cgroup",
)


class ExecutionSecurityMode(StrEnum):
    """Runtime policy applied to guarded execution."""

    DEVELOPMENT = "development"
    PRODUCTION = "production"


@dataclass(frozen=True, slots=True)
class ProductionContainmentLimits:
    """Resource and output bounds for production commands."""

    cpu_seconds: int = 120
    address_space_bytes: int = 2 * 1024**3
    file_size_bytes: int = 64 * 1024**2
    open_files: int = 256
    processes: int = 128
    max_output_bytes: int = 1024**2
    termination_grace_seconds: float = 1.0

    def __post_init__(self) -> None:
        integer_values = {
            "cpu_seconds": self.cpu_seconds,
            "address_space_bytes": (self.address_space_bytes),
            "file_size_bytes": self.file_size_bytes,
            "open_files": self.open_files,
            "processes": self.processes,
            "max_output_bytes": self.max_output_bytes,
        }

        for name, value in integer_values.items():
            if isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer.")

        if not math.isfinite(self.termination_grace_seconds) or self.termination_grace_seconds <= 0:
            raise ValueError("termination_grace_seconds must be positive and finite.")

        if self.max_output_bytes > self.file_size_bytes:
            raise ValueError("max_output_bytes cannot exceed file_size_bytes.")


@dataclass(frozen=True, slots=True)
class BubblewrapVerification:
    """Structured eligibility result for production mode."""

    eligible: bool
    platform_name: str
    executable_path: str | None
    executable_sha256: str | None
    version: str | None
    reasons: tuple[str, ...]
    features: dict[str, bool]

    @property
    def reason(self) -> str:
        if self.eligible:
            return "Bubblewrap passed production containment verification."

        return "; ".join(self.reasons) or ("Production containment verification failed.")


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    """Bounded process result independent of guarded models."""

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int
    output_truncated: bool
    sandbox_setup_failed: bool


@dataclass(slots=True)
class _StreamCapture:
    retained: bytearray
    total_bytes: int = 0
    truncated: bool = False


def execution_security_mode(
    environment: str,
) -> ExecutionSecurityMode:
    """Map the existing environment field to execution policy."""
    normalized = str(environment).strip().lower()

    if normalized == "production":
        return ExecutionSecurityMode.PRODUCTION

    return ExecutionSecurityMode.DEVELOPMENT


def production_bubblewrap_hardening_flags() -> tuple[str, ...]:
    """Return additional flags required in production mode."""
    return PRODUCTION_BUBBLEWRAP_HARDENING_FLAGS


def minimal_launcher_environment() -> dict[str, str]:
    """Return a deterministic environment for launching bwrap."""
    return {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": "rygnal",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "USER": "rygnal",
    }


def clear_production_containment_cache() -> None:
    """Clear the host verification cache for tests."""
    _cached_host_verification.cache_clear()


def verify_production_bubblewrap(
    *,
    platform_name: str | None = None,
    executable_path: str | Path | None = None,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> BubblewrapVerification:
    """Verify actual Bubblewrap behavior, not mere presence."""
    if platform_name is None and executable_path is None and command_runner is None:
        return _cached_host_verification()

    return _verify_production_bubblewrap(
        platform_name=(platform.system() if platform_name is None else platform_name),
        executable_path=executable_path,
        command_runner=command_runner or subprocess.run,
    )


@lru_cache(maxsize=1)
def _cached_host_verification() -> BubblewrapVerification:
    return _verify_production_bubblewrap(
        platform_name=platform.system(),
        executable_path=None,
        command_runner=subprocess.run,
    )


def _verify_production_bubblewrap(
    *,
    platform_name: str,
    executable_path: str | Path | None,
    command_runner: Callable[..., subprocess.CompletedProcess[str]],
) -> BubblewrapVerification:
    normalized_platform = platform_name.strip().lower()
    reasons: list[str] = []
    features = {
        "production_mode": True,
        "linux_host": normalized_platform == "linux",
        "secure_executable": False,
        "version_verified": False,
        "required_flags_verified": False,
        "behavioral_self_test": False,
        "user_namespace": False,
        "pid_namespace": False,
        "ipc_namespace": False,
        "uts_namespace": False,
        "net_namespace": False,
        "cgroup_namespace": False,
        "capabilities_dropped": False,
        "no_new_privileges": False,
        "host_environment_cleared": False,
        "host_tmp_hidden": False,
        "resource_limits_enforced": True,
        "output_bounded": True,
        "inherited_fds_closed": True,
    }

    if normalized_platform != "linux":
        reasons.append("Production guarded execution is supported only on verified Linux hosts.")
        return BubblewrapVerification(
            eligible=False,
            platform_name=normalized_platform,
            executable_path=None,
            executable_sha256=None,
            version=None,
            reasons=tuple(reasons),
            features=features,
        )

    raw_path = (
        Path(executable_path)
        if executable_path is not None
        else (Path(found) if (found := shutil.which("bwrap")) else None)
    )

    if raw_path is None:
        reasons.append("Bubblewrap executable was not found.")
        return BubblewrapVerification(
            eligible=False,
            platform_name=normalized_platform,
            executable_path=None,
            executable_sha256=None,
            version=None,
            reasons=tuple(reasons),
            features=features,
        )

    try:
        resolved_path = _validate_executable(raw_path)
    except OSError as exc:
        reasons.append(str(exc))
        return BubblewrapVerification(
            eligible=False,
            platform_name=normalized_platform,
            executable_path=raw_path.as_posix(),
            executable_sha256=None,
            version=None,
            reasons=tuple(reasons),
            features=features,
        )

    features["secure_executable"] = True
    executable_digest = _sha256_file(resolved_path)

    version_result = _run_probe_command(
        command_runner,
        (
            resolved_path.as_posix(),
            "--version",
        ),
    )

    if version_result.returncode != 0:
        reasons.append("Bubblewrap version probe failed.")
        version = None
    else:
        version = _parse_bubblewrap_version(version_result.stdout or version_result.stderr)

        if version is None:
            reasons.append("Bubblewrap version output was not recognized.")
        elif version < MINIMUM_BUBBLEWRAP_VERSION:
            reasons.append(
                "Bubblewrap is older than Rygnal's "
                f"required version "
                f"{_format_version(MINIMUM_BUBBLEWRAP_VERSION)}."
            )
        else:
            features["version_verified"] = True

    version_text = _format_version(version) if version is not None else None

    help_result = _run_probe_command(
        command_runner,
        (
            resolved_path.as_posix(),
            "--help",
        ),
    )
    help_text = (help_result.stdout or "") + "\n" + (help_result.stderr or "")

    missing_flags = tuple(flag for flag in REQUIRED_BUBBLEWRAP_FLAGS if flag not in help_text)

    if help_result.returncode != 0:
        reasons.append("Bubblewrap help probe failed.")
    elif missing_flags:
        reasons.append("Bubblewrap lacks required production flags: " + ", ".join(missing_flags))
    else:
        features["required_flags_verified"] = True

    if features["version_verified"] and features["required_flags_verified"]:
        probe_features, probe_reasons = _run_behavioral_probe(
            resolved_path,
            command_runner=command_runner,
        )
        features.update(probe_features)
        reasons.extend(probe_reasons)

    required_features = (
        "secure_executable",
        "version_verified",
        "required_flags_verified",
        "behavioral_self_test",
        "user_namespace",
        "pid_namespace",
        "ipc_namespace",
        "uts_namespace",
        "net_namespace",
        "cgroup_namespace",
        "capabilities_dropped",
        "no_new_privileges",
        "host_environment_cleared",
        "host_tmp_hidden",
        "resource_limits_enforced",
        "output_bounded",
        "inherited_fds_closed",
    )

    eligible = not reasons and all(features.get(name, False) for name in required_features)

    return BubblewrapVerification(
        eligible=eligible,
        platform_name=normalized_platform,
        executable_path=resolved_path.as_posix(),
        executable_sha256=executable_digest,
        version=version_text,
        reasons=tuple(reasons),
        features=features,
    )


def run_bounded_process(
    command: Sequence[str],
    *,
    cwd: str | Path,
    timeout_seconds: int,
    limits: ProductionContainmentLimits,
    environment: Mapping[str, str] | None = None,
) -> BoundedProcessResult:
    """Run through a dedicated resource-limit exec launcher."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive.")

    command_tuple = tuple(str(item) for item in command)

    if not command_tuple:
        raise ValueError("Command must not be empty.")

    cwd_path = Path(cwd).expanduser().resolve()

    if not cwd_path.is_dir():
        raise ValueError("Process working directory must exist.")

    launcher_command = _resource_limited_launcher_command(
        command_tuple,
        limits,
    )

    started = time.monotonic()
    stdout_capture = _StreamCapture(bytearray())
    stderr_capture = _StreamCapture(bytearray())
    cleanup_messages: list[str] = []

    try:
        process = subprocess.Popen(  # nosec B603
            launcher_command,
            cwd=cwd_path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=(os.name == "posix"),
            env=dict(minimal_launcher_environment() if environment is None else environment),
        )
    except OSError as exc:
        raise RuntimeError(f"Failed to start contained process: {exc}") from exc

    assert process.stdout is not None
    assert process.stderr is not None

    readers = (
        threading.Thread(
            target=_capture_stream,
            args=(
                process.stdout,
                stdout_capture,
                limits.max_output_bytes,
            ),
            daemon=True,
        ),
        threading.Thread(
            target=_capture_stream,
            args=(
                process.stderr,
                stderr_capture,
                limits.max_output_bytes,
            ),
            daemon=True,
        ),
    )

    for reader in readers:
        reader.start()

    timed_out = False

    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        cleanup_messages.extend(
            _terminate_process_tree(
                process,
                grace_seconds=(limits.termination_grace_seconds),
            )
        )
    finally:
        for reader in readers:
            reader.join(timeout=(limits.termination_grace_seconds))

        _close_binary_stream(process.stdout)
        _close_binary_stream(process.stderr)

    duration_ms = int((time.monotonic() - started) * 1000)

    stdout = bytes(stdout_capture.retained).decode(
        "utf-8",
        errors="replace",
    )
    stderr = bytes(stderr_capture.retained).decode(
        "utf-8",
        errors="replace",
    )

    truncated = stdout_capture.truncated or stderr_capture.truncated

    if truncated:
        stderr = _append_message(
            stderr,
            f"Rygnal truncated command output at {limits.max_output_bytes} bytes per stream.",
        )

    for message in cleanup_messages:
        stderr = _append_message(
            stderr,
            message,
        )

    return BoundedProcessResult(
        exit_code=(None if timed_out else process.returncode),
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        duration_ms=duration_ms,
        output_truncated=truncated,
        sandbox_setup_failed=(
            not timed_out
            and process.returncode not in (None, 0)
            and _looks_like_bubblewrap_setup_failure(stderr)
        ),
    )


def _run_behavioral_probe(
    executable: Path,
    *,
    command_runner: Callable[..., subprocess.CompletedProcess[str]],
) -> tuple[dict[str, bool], tuple[str, ...]]:
    features = {
        "behavioral_self_test": False,
        "user_namespace": False,
        "pid_namespace": False,
        "ipc_namespace": False,
        "uts_namespace": False,
        "net_namespace": False,
        "cgroup_namespace": False,
        "capabilities_dropped": False,
        "no_new_privileges": False,
        "host_environment_cleared": False,
        "host_tmp_hidden": False,
    }
    reasons: list[str] = []

    host_namespaces: dict[str, str] = {}

    for name in _NAMESPACE_NAMES:
        namespace_path = Path(f"/proc/self/ns/{name}")

        try:
            host_namespaces[name] = os.readlink(namespace_path)
        except OSError:
            reasons.append(f"Host {name} namespace identity could not be inspected.")

    if reasons:
        return features, tuple(reasons)

    shell_path = _first_existing(
        "/bin/sh",
        "/usr/bin/sh",
    )
    readlink_path = _first_existing(
        "/usr/bin/readlink",
        "/bin/readlink",
    )
    env_path = _first_existing(
        "/usr/bin/env",
        "/bin/env",
    )
    awk_path = _first_existing(
        "/usr/bin/awk",
        "/bin/awk",
    )

    required_tools = {
        "shell": shell_path,
        "readlink": readlink_path,
        "env": env_path,
        "awk": awk_path,
    }

    missing_tools = tuple(name for name, path in required_tools.items() if path is None)

    if missing_tools:
        reasons.append("Production self-test tools are unavailable: " + ", ".join(missing_tools))
        return features, tuple(reasons)

    assert shell_path is not None
    assert readlink_path is not None
    assert env_path is not None
    assert awk_path is not None

    with tempfile.TemporaryDirectory(prefix="rygnal-containment-probe-") as temporary:
        secret_path = Path(temporary) / "host-secret"
        secret_path.write_text(
            "must-not-be-visible",
            encoding="utf-8",
        )

        command: list[str] = [
            executable.as_posix(),
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-net",
            "--unshare-cgroup",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/var",
            "--tmpfs",
            "/var/tmp",
            "--tmpfs",
            "/run",
            "--dir",
            "/etc",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "USER",
            "rygnal",
            "--setenv",
            "LOGNAME",
            "rygnal",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "RYGNAL_PROBE",
            "1",
            "--setenv",
            "RYGNAL_HOST_SECRET",
            secret_path.as_posix(),
        ]

        command.extend(_runtime_read_only_mounts())

        script = (
            "set -eu\n"
            f"for ns in {' '.join(_NAMESPACE_NAMES)}; do\n"
            f"  printf 'ns:%s=%s\\n' \"$ns\" "
            f'"$({readlink_path} /proc/self/ns/$ns)"\n'
            "done\n"
            f"{awk_path} "
            '\'/^CapEff:/ {print "cap_eff=" $2} '
            "/^NoNewPrivs:/ "
            '{print "no_new_privs=" $2}\' '
            "/proc/self/status\n"
            'if [ -e "$RYGNAL_HOST_SECRET" ]; then\n'
            "  echo 'secret_visible=yes'\n"
            "else\n"
            "  echo 'secret_visible=no'\n"
            "fi\n"
            "echo 'ENV_BEGIN'\n"
            f"{env_path}\n"
            "echo 'ENV_END'\n"
        )

        command.extend(
            (
                "--",
                shell_path,
                "-c",
                script,
            )
        )

        probe_environment = minimal_launcher_environment()
        probe_environment["RYGNAL_SHOULD_NOT_LEAK"] = "host-secret-value"

        result = _run_probe_command(
            command_runner,
            tuple(command),
            environment=probe_environment,
            timeout_seconds=8,
        )

    if result.returncode != 0:
        detail = (
            result.stderr.strip() or result.stdout.strip() or "unknown Bubblewrap probe failure"
        )
        reasons.append("Bubblewrap behavioral self-test failed: " + detail[:500])
        return features, tuple(reasons)

    parsed = _parse_probe_output(result.stdout)

    namespace_values = parsed["namespaces"]

    for name in _NAMESPACE_NAMES:
        isolated = namespace_values.get(name) != host_namespaces.get(name)
        features[f"{name}_namespace"] = isolated

        if not isolated:
            reasons.append(f"Bubblewrap did not isolate the {name} namespace.")

    cap_eff = str(parsed.get("cap_eff", "")).lower()
    features["capabilities_dropped"] = bool(cap_eff) and set(cap_eff) <= {"0"}

    if not features["capabilities_dropped"]:
        reasons.append("Effective Linux capabilities were not empty.")

    features["no_new_privileges"] = parsed.get("no_new_privs") == "1"

    if not features["no_new_privileges"]:
        reasons.append("NoNewPrivs was not enabled inside Bubblewrap.")

    environment_names = {item.partition("=")[0] for item in parsed["environment"] if "=" in item}

    unexpected_environment = environment_names - _ALLOWED_PROBE_ENVIRONMENT

    features["host_environment_cleared"] = (
        "RYGNAL_SHOULD_NOT_LEAK" not in environment_names and not unexpected_environment
    )

    if not features["host_environment_cleared"]:
        reasons.append(
            "Host environment variables leaked into the Bubblewrap self-test. "
            f"Unexpected: {unexpected_environment}, "
            f"RYGNAL_SHOULD_NOT_LEAK in env: {'RYGNAL_SHOULD_NOT_LEAK' in environment_names}"
        )

    features["host_tmp_hidden"] = parsed.get("secret_visible") == "no"

    if not features["host_tmp_hidden"]:
        reasons.append("Host temporary files remained visible.")

    features["behavioral_self_test"] = not reasons

    return features, tuple(reasons)


def _parse_probe_output(
    output: str,
) -> dict[str, object]:
    namespaces: dict[str, str] = {}
    environment: list[str] = []
    values: dict[str, object] = {
        "namespaces": namespaces,
        "environment": environment,
    }
    in_environment = False

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if line == "ENV_BEGIN":
            in_environment = True
            continue

        if line == "ENV_END":
            in_environment = False
            continue

        if in_environment:
            environment.append(line)
            continue

        if line.startswith("ns:"):
            key, separator, value = line.removeprefix("ns:").partition("=")

            if separator:
                namespaces[key] = value
            continue

        key, separator, value = line.partition("=")

        if separator:
            values[key] = value

    return values


def _validate_executable(path: Path) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    metadata = resolved.stat()

    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("Bubblewrap path is not a regular file.")

    if not os.access(resolved, os.X_OK):
        raise OSError("Bubblewrap path is not executable.")

    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise OSError("Bubblewrap executable is group- or world-writable.")

    allowed_owners = {
        0,
        os.getuid() if hasattr(os, "getuid") else 0,
    }

    if metadata.st_uid not in allowed_owners:
        raise OSError("Bubblewrap executable has an untrusted owner.")

    return resolved


def _parse_bubblewrap_version(
    output: str,
) -> tuple[int, int, int] | None:
    match = re.search(
        r"\bbubblewrap\s+(\d+)\.(\d+)\.(\d+)\b",
        output,
        flags=re.IGNORECASE,
    )

    if match is None:
        return None

    return tuple(int(value) for value in match.groups())  # type: ignore[return-value]


def _format_version(
    version: tuple[int, int, int] | None,
) -> str:
    if version is None:
        return "unknown"

    return ".".join(str(value) for value in version)


def _run_probe_command(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    command: tuple[str, ...],
    *,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: int = 5,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(
            command,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
            timeout=timeout_seconds,
            env=dict(minimal_launcher_environment() if environment is None else environment),
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
    ) as exc:
        return subprocess.CompletedProcess(
            command,
            returncode=127,
            stdout="",
            stderr=str(exc),
        )


def _runtime_read_only_mounts() -> list[str]:
    arguments: list[str] = []

    for path in (
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/lib32",
    ):
        candidate = Path(path)

        if candidate.exists():
            arguments.extend(
                (
                    "--ro-bind",
                    path,
                    path,
                )
            )

    for path in (
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
    ):
        candidate = Path(path)

        if candidate.exists():
            arguments.extend(
                (
                    "--ro-bind",
                    path,
                    path,
                )
            )

    return arguments


def _first_existing(
    *paths: str,
) -> str | None:
    for value in paths:
        if Path(value).exists():
            return os.path.realpath(value)

    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def _resource_limited_launcher_command(
    command: tuple[str, ...],
    limits: ProductionContainmentLimits,
) -> tuple[str, ...]:
    """Wrap a command without using unsafe preexec_fn."""
    if os.name != "posix":
        return command

    launcher = Path(__file__).with_name("resource_limited_exec.py").resolve()

    if not launcher.is_file() or launcher.is_symlink():
        raise RuntimeError("Resource-limit launcher is unavailable or unsafe.")

    payload = json.dumps(
        {
            "address_space_bytes": (limits.address_space_bytes),
            "core_bytes": 0,
            "cpu_seconds": limits.cpu_seconds,
            "file_size_bytes": (limits.file_size_bytes),
            "open_files": limits.open_files,
            "processes": limits.processes,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    return (
        sys.executable,
        launcher.as_posix(),
        payload,
        "--",
        *command,
    )


def _capture_stream(
    stream: BinaryIO,
    capture: _StreamCapture,
    maximum_bytes: int,
) -> None:
    while True:
        try:
            chunk = stream.read(64 * 1024)
        except OSError:
            return

        if not chunk:
            return

        capture.total_bytes += len(chunk)
        remaining = maximum_bytes - len(capture.retained)

        if remaining > 0:
            capture.retained.extend(chunk[:remaining])

        if capture.total_bytes > maximum_bytes:
            capture.truncated = True


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float,
) -> list[str]:
    messages: list[str] = []

    if process.poll() is not None:
        return messages

    if os.name == "posix" and hasattr(os, "killpg"):
        try:
            os.killpg(
                process.pid,
                signal.SIGTERM,
            )
        except ProcessLookupError:
            return messages
        except OSError as exc:
            messages.append(f"Failed to terminate process group: {exc}")
    else:
        try:
            process.terminate()
        except OSError as exc:
            messages.append(f"Failed to terminate process: {exc}")

    try:
        process.wait(timeout=grace_seconds)
        return messages
    except subprocess.TimeoutExpired:
        pass

    if os.name == "posix" and hasattr(os, "killpg"):
        try:
            os.killpg(
                process.pid,
                signal.SIGKILL,
            )
        except ProcessLookupError:
            return messages
        except OSError as exc:
            messages.append(f"Failed to force-kill process group: {exc}")
    else:
        try:
            process.kill()
        except OSError as exc:
            messages.append(f"Failed to force-kill process: {exc}")

    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        messages.append("Process did not exit after force-kill.")

    return messages


def _close_binary_stream(
    stream: BinaryIO | None,
) -> None:
    if stream is None:
        return

    try:
        stream.close()
    except OSError:
        pass


def _looks_like_bubblewrap_setup_failure(
    stderr: str,
) -> bool:
    lowered = stderr.lower()

    if "rygnal_resource_setup_failed:" in lowered:
        return True

    return "bwrap:" in lowered and any(
        marker in lowered
        for marker in (
            "creating new namespace",
            "operation not permitted",
            "permission denied",
            "unknown option",
            "failed to",
            "cannot",
            "no such file",
        )
    )


def _append_message(
    value: str,
    message: str,
) -> str:
    if not message:
        return value

    if not value:
        return message + "\n"

    separator = "" if value.endswith("\n") else "\n"
    return value + separator + message + "\n"


__all__ = [
    "BoundedProcessResult",
    "BubblewrapVerification",
    "ExecutionSecurityMode",
    "MINIMUM_BUBBLEWRAP_VERSION",
    "ProductionContainmentLimits",
    "REQUIRED_BUBBLEWRAP_FLAGS",
    "clear_production_containment_cache",
    "execution_security_mode",
    "minimal_launcher_environment",
    "production_bubblewrap_hardening_flags",
    "run_bounded_process",
    "verify_production_bubblewrap",
]
