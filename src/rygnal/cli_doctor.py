"""Environment diagnostics for the local Rygnal CLI."""

from __future__ import annotations

import importlib.util
import json
import platform
import shutil
import subprocess  # nosec B404
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from rygnal.execution_backend import (
    ExecutionBackendSelectionError,
    detect_host_backend_capabilities,
    select_execution_backend,
)
from rygnal.local_paths import LocalPathError, resolve_local_paths
from rygnal.models import RuntimeMode
from rygnal.policy_engine import load_default_policy_engine
from rygnal.rust_kernel import is_rust_kernel_available
from rygnal.version import package_version


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One local readiness check."""

    name: str
    status: str
    detail: str
    required: bool


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Complete local readiness report."""

    version: str
    platform: str
    data_directory: str | None
    ready: bool
    checks: tuple[DoctorCheck, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return {
            "version": self.version,
            "platform": self.platform,
            "data_directory": self.data_directory,
            "ready": self.ready,
            "checks": [asdict(check) for check in self.checks],
        }


def collect_doctor_report(
    *,
    data_dir: str | Path | None = None,
    skip_containment: bool = False,
) -> DoctorReport:
    """Inspect local dependencies without modifying repositories."""
    checks: list[DoctorCheck] = []
    resolved_data_directory: str | None = None

    python_supported = sys.version_info >= (3, 11)
    checks.append(
        DoctorCheck(
            name="python",
            status="ok" if python_supported else "error",
            detail=(f"{platform.python_implementation()} {platform.python_version()}"),
            required=True,
        )
    )

    git_path = shutil.which("git")
    if git_path is None:
        checks.append(
            DoctorCheck(
                name="git",
                status="error",
                detail="Git executable was not found on PATH.",
                required=True,
            )
        )
    else:
        try:
            result = subprocess.run(  # nosec B603
                [git_path, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            git_ok = result.returncode == 0
            detail = (
                result.stdout.strip() if git_ok else result.stderr.strip() or "Git probe failed."
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            git_ok = False
            detail = f"Git probe failed: {exc}"

        checks.append(
            DoctorCheck(
                name="git",
                status="ok" if git_ok else "error",
                detail=detail,
                required=True,
            )
        )

    try:
        default_engine = load_default_policy_engine()
        production_engine = load_default_policy_engine(RuntimeMode.PRODUCTION_SAFE)
        checks.append(
            DoctorCheck(
                name="policies",
                status="ok",
                detail=(
                    f"Default rules: {len(default_engine.rules)}; "
                    f"production-safe rules: "
                    f"{len(production_engine.rules)}."
                ),
                required=True,
            )
        )
    except Exception as exc:
        checks.append(
            DoctorCheck(
                name="policies",
                status="error",
                detail=f"Policy loading failed: {exc}",
                required=True,
            )
        )

    try:
        paths = resolve_local_paths(
            data_dir=data_dir,
            create=False,
        )
        resolved_data_directory = str(paths.root)
        checks.append(
            DoctorCheck(
                name="local_storage",
                status="ok",
                detail=(
                    f"Resolved private data directory: {paths.root}. "
                    "No directory was created by this check."
                ),
                required=True,
            )
        )
    except LocalPathError as exc:
        checks.append(
            DoctorCheck(
                name="local_storage",
                status="error",
                detail=str(exc),
                required=True,
            )
        )

    fastapi_available = importlib.util.find_spec("fastapi") is not None
    checks.append(
        DoctorCheck(
            name="fastapi",
            status="ok" if fastapi_available else "error",
            detail=("FastAPI is installed." if fastapi_available else "FastAPI is not installed."),
            required=True,
        )
    )

    uvicorn_available = importlib.util.find_spec("uvicorn") is not None
    checks.append(
        DoctorCheck(
            name="uvicorn",
            status="ok" if uvicorn_available else "error",
            detail=(
                "Uvicorn is installed."
                if uvicorn_available
                else "Uvicorn is required for `rygnal serve`."
            ),
            required=True,
        )
    )

    rust_available = is_rust_kernel_available()
    checks.append(
        DoctorCheck(
            name="rust_kernel",
            status="ok" if rust_available else "warning",
            detail=(
                "Optional Rust kernel is available."
                if rust_available
                else ("Optional Rust kernel is unavailable; Python fallback remains active.")
            ),
            required=False,
        )
    )

    if skip_containment:
        checks.append(
            DoctorCheck(
                name="containment",
                status="warning",
                detail="Containment probe was skipped.",
                required=False,
            )
        )
    else:
        try:
            selection = select_execution_backend(detect_host_backend_capabilities())
            checks.append(
                DoctorCheck(
                    name="containment",
                    status=("ok" if selection.safe_by_default else "warning"),
                    detail=(f"{selection.name.value}: {selection.reason}"),
                    required=False,
                )
            )
        except ExecutionBackendSelectionError as exc:
            checks.append(
                DoctorCheck(
                    name="containment",
                    status="warning",
                    detail=str(exc),
                    required=False,
                )
            )

    ready = not any(check.required and check.status == "error" for check in checks)

    return DoctorReport(
        version=package_version(),
        platform=platform.platform(),
        data_directory=resolved_data_directory,
        ready=ready,
        checks=tuple(checks),
    )


def run_doctor_cli(args: object) -> int:
    """Run the local environment diagnostic command."""
    report = collect_doctor_report(
        data_dir=getattr(args, "data_dir", None),
        skip_containment=bool(getattr(args, "skip_containment", False)),
    )

    if bool(getattr(args, "json", False)):
        print(
            json.dumps(
                report.to_dict(),
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if report.ready else 1

    print(f"Rygnal {report.version}")
    print(f"Platform: {report.platform}")
    print("Status: " + ("READY" if report.ready else "NOT READY"))
    print()

    labels = {
        "ok": "OK",
        "warning": "WARN",
        "error": "ERROR",
    }

    for check in report.checks:
        print(f"[{labels[check.status]:5}] {check.name}: {check.detail}")

    if report.data_directory is not None:
        print()
        print(f"Data directory: {report.data_directory}")

    return 0 if report.ready else 1


__all__ = [
    "DoctorCheck",
    "DoctorReport",
    "collect_doctor_report",
    "run_doctor_cli",
]
