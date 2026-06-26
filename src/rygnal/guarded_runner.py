from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess  # nosec B404
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Protocol

from rygnal.action_intent import (
    ActionIntentReport,
    ActionIntentSeverity,
    classify_command_intent,
)
from rygnal.action_normalizer import (
    normalize_command_action,
    normalize_guarded_actions,
    normalized_actions_audit_summary,
)
from rygnal.approval_queue import ApprovalQueueError, InMemoryApprovalQueue
from rygnal.audit_logger import AuditLogger
from rygnal.change_risk import (
    ChangeRiskClassificationError,
    ChangeRiskReason,
    ChangeRiskReport,
    classify_patch_risk,
)
from rygnal.changed_files import ChangedFileDetectionError, ChangedFileReport, detect_changed_files
from rygnal.execution_backend import (
    ExecutionBackendName,
    ExecutionBackendSelection,
    ExecutionBackendSelectionError,
    detect_host_backend_capabilities,
    select_execution_backend,
)
from rygnal.guarded_worktree import (
    GuardedWorktree,
    GuardedWorktreeConfig,
    GuardedWorktreeError,
    create_guarded_worktree,
    detect_trusted_repo_root,
)
from rygnal.intent_contract import IntentContract, NormalizedAction
from rygnal.models import (
    ApprovalRequest,
    Decision,
    PolicyDecision,
    Severity,
    ToolRequest,
    new_trace_id,
)
from rygnal.patch_approval import PatchApprovalError, create_patch_approval_request
from rygnal.patch_diff import PatchDiff, PatchDiffGenerationError, generate_patch_diff_from_report
from rygnal.process_containment import (
    LifecycleEvent,
    build_lifecycle_result,
    evaluate_containment_capabilities,
)
from rygnal.repo_state import DirtyRepositoryError, get_uncommitted_changes
from rygnal.risk_engine import RiskLevel
from rygnal.subjective_risk import (
    SubjectiveRiskCollectionError,
    collect_subjective_patch_reasons,
)
from rygnal.untracked_files import UntrackedFilePolicy
from rygnal.workspace_cleanup import CleanupResult, CleanupStatus, destroy_worktree
from rygnal.workspace_mounts import MountContract, MountKind, WorkspaceMountPlan

UNSAFE_LOCAL_WARNING = "Unsafe local execution is not a containment backend."
_IMPLEMENTED_COMMAND_BACKENDS = frozenset(
    {
        ExecutionBackendName.LINUX_BUBBLEWRAP,
        ExecutionBackendName.UNSAFE_LOCAL,
    }
)
# Keep timeout cleanup bounded. This is lifecycle cleanup, not verified containment.
_PROCESS_GROUP_TERMINATION_GRACE_SECONDS = 1.0
_PROCESS_OUTPUT_DRAIN_GRACE_SECONDS = 1.0
_SIGNAL_NAMES_FOR_PROCESS_CLEANUP = ("SIGINT", "SIGTERM", "SIGHUP")
_SANDBOX_WORKSPACE = PurePosixPath("/").joinpath("workspace")
_SANDBOX_TMP = PurePosixPath("/").joinpath("tmp")
_SANDBOX_VAR_TMP = PurePosixPath("/").joinpath("var", "tmp")
_SANDBOX_RUN = PurePosixPath("/").joinpath("run")
_SANDBOX_ETC = PurePosixPath("/").joinpath("etc")
_GUARDED_RUN_LOCK_DIR_NAME = ".rygnal-locks"
_GUARDED_RUN_CONCURRENCY_REASON_CODE = "guarded_run_concurrency_conflict"


class GuardedRunStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"
    APPROVAL_REQUIRED = "approval_required"
    CLEANUP_FAILED = "cleanup_failed"


class GuardedRunnerError(RuntimeError):
    """Base exception for guarded runner failures."""


class GuardedRunBlockedError(GuardedRunnerError):
    """Raised internally for safety precondition failures."""


class GuardedCommandExecutionError(GuardedRunnerError):
    """Raised when a backend cannot start or supervise the command."""


@dataclass(frozen=True)
class GuardedRunConfig:
    trusted_repo_path: Path
    command: tuple[str, ...]
    timeout_seconds: int = 300
    rygnal_run_root: Path = Path("/tmp/rygnal-runs")  # nosec B108
    allow_dirty_override: bool = False
    untracked_policy: UntrackedFilePolicy = UntrackedFilePolicy.BLOCK
    preserve_workspace: bool = False
    unsafe_local_requested: bool = False
    environment: str = "local"
    user_id: str = "local_user"
    agent_id: str = "local_agent"
    trace_id: str | None = None
    intent_contract: IntentContract | None = None
    audit_logger: AuditLogger | None = None
    approval_queue: InMemoryApprovalQueue | None = None


@dataclass(frozen=True)
class GuardedCommandResult:
    command: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int


@dataclass(frozen=True)
class GuardedRunResult:
    status: GuardedRunStatus
    run_id: str | None
    trusted_repo_path: str
    workspace_path: str | None
    baseline_commit_sha: str | None

    backend_name: str | None
    backend_safe_by_default: bool
    containment_verified: bool

    cleanup_performed: bool
    cleanup_status: str | None

    command_result: GuardedCommandResult | None
    changed_file_report: ChangedFileReport | None
    patch_diff: PatchDiff | None
    change_risk_report: ChangeRiskReport | None

    blocked_reason: str | None
    warnings: tuple[str, ...]
    normalized_actions: tuple[NormalizedAction, ...] = ()
    approval_request: ApprovalRequest | None = None
    containment_features: dict[str, bool] = field(default_factory=dict)


@dataclass(frozen=True)
class PatchRiskDecision:
    allowed: bool
    risk_level: RiskLevel
    reason: str
    report: ChangeRiskReport

    @property
    def audit_summary(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "risk_level": self.risk_level.value,
            "reason": self.reason,
            "report": self.report.audit_summary,
        }


class CommandBackend(Protocol):
    def run(
        self,
        command: tuple[str, ...],
        cwd: Path,
        timeout_seconds: int,
    ) -> GuardedCommandResult: ...


@dataclass(frozen=True)
class UnsafeLocalCommandBackend:
    """Explicit developer/test backend.

    This backend is intentionally not a containment boundary. It still runs the
    command inside the guarded worktree, never inside the trusted repository.
    """

    def run(
        self,
        command: tuple[str, ...],
        cwd: Path,
        timeout_seconds: int,
    ) -> GuardedCommandResult:
        return _run_subprocess(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
        )


@dataclass(frozen=True)
class BubblewrapCommandBackend:
    """Conservative Bubblewrap command backend."""

    def run(
        self,
        command: tuple[str, ...],
        cwd: Path,
        timeout_seconds: int,
    ) -> GuardedCommandResult:
        bwrap_command = _build_bubblewrap_command(command, cwd)
        return _run_subprocess(
            tuple(bwrap_command),
            cwd=cwd,
            timeout_seconds=timeout_seconds,
        )


@dataclass(frozen=True)
class UnsupportedCommandBackend:
    reason: str

    def run(
        self,
        command: tuple[str, ...],
        cwd: Path,
        timeout_seconds: int,
    ) -> GuardedCommandResult:
        raise GuardedCommandExecutionError(self.reason)


@dataclass(frozen=True)
class GuardedRunConcurrencyState:
    lock_path: Path
    lock_identity: str
    blocked_reason: str | None = None
    active_lock_pid: int | None = None
    recovered_stale_lock: bool = False
    stale_lock_pid: int | None = None


def _guarded_run_concurrency_lock_path(
    trusted_repo_path: Path,
    run_root: Path,
) -> Path:
    trusted_repo = Path(trusted_repo_path).expanduser().resolve()
    resolved_run_root = Path(run_root).expanduser().resolve()

    key = f"{trusted_repo.as_posix()}\0{resolved_run_root.as_posix()}".encode()
    lock_name = f"{hashlib.sha256(key).hexdigest()}.lock"

    return resolved_run_root / _GUARDED_RUN_LOCK_DIR_NAME / lock_name


def _read_guarded_run_lock_metadata(lock_path: Path) -> dict[str, str]:
    try:
        lines = lock_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}

    metadata: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        metadata[key.strip()] = value.strip()

    return metadata


def _parse_lock_pid(raw_pid: str | None) -> int | None:
    if raw_pid is None:
        return None

    try:
        return int(raw_pid)
    except ValueError:
        return None


def _process_is_alive(pid: int | None) -> bool:
    if pid is None or pid <= 0:
        return False

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False

    return True


@contextmanager
def _guarded_run_concurrency_guard(
    *,
    trusted_repo_path: Path,
    run_root: Path,
    trace_id: str,
):
    lock_path = _guarded_run_concurrency_lock_path(trusted_repo_path, run_root)
    trusted_repo = Path(trusted_repo_path).expanduser().resolve()
    lock_identity = lock_path.stem
    recovered_stale_lock = False
    stale_lock_pid: int | None = None

    while True:
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            metadata = _read_guarded_run_lock_metadata(lock_path)
            active_lock_pid = _parse_lock_pid(metadata.get("pid"))

            if not _process_is_alive(active_lock_pid):
                stale_lock_pid = active_lock_pid
                try:
                    lock_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    yield GuardedRunConcurrencyState(
                        lock_path=lock_path,
                        lock_identity=lock_identity,
                        blocked_reason=(
                            "guarded_run_concurrency_lock_unavailable: failed to "
                            f"remove stale guarded run lock at {lock_path.as_posix()}: {exc}"
                        ),
                        active_lock_pid=active_lock_pid,
                    )
                    return

                recovered_stale_lock = True
                continue

            yield GuardedRunConcurrencyState(
                lock_path=lock_path,
                lock_identity=lock_identity,
                blocked_reason=(
                    f"{_GUARDED_RUN_CONCURRENCY_REASON_CODE}: guarded run already active "
                    f"for trusted repository {trusted_repo.as_posix()}."
                ),
                active_lock_pid=active_lock_pid,
            )
            return
        except OSError as exc:
            yield GuardedRunConcurrencyState(
                lock_path=lock_path,
                lock_identity=lock_identity,
                blocked_reason=(
                    "guarded_run_concurrency_lock_unavailable: failed to acquire guarded "
                    f"run lock at {lock_path.as_posix()}: {exc}"
                ),
            )
            return

    with os.fdopen(lock_fd, "w", encoding="utf-8") as lock_file:
        lock_file.write(
            f"pid={os.getpid()}\n"
            f"trace_id={trace_id}\n"
            f"trusted_repo_path={trusted_repo.as_posix()}\n"
            f"lock_identity={lock_identity}\n"
            f"created_at_unix={time.time()}\n"
        )

    try:
        yield GuardedRunConcurrencyState(
            lock_path=lock_path,
            lock_identity=lock_identity,
            recovered_stale_lock=recovered_stale_lock,
            stale_lock_pid=stale_lock_pid,
        )
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def run_guarded(config: GuardedRunConfig) -> GuardedRunResult:
    """Run a command inside a disposable guarded workspace."""

    trace_id = config.trace_id or new_trace_id()
    warnings: list[str] = []
    trusted_repo_label = str(config.trusted_repo_path)
    normalized_actions = _safe_normalized_command_actions(config.command)

    try:
        command = _validate_command(config.command)
        _validate_timeout(config.timeout_seconds)
        trusted_repo_input = _validate_trusted_repo_path(config.trusted_repo_path)
        trusted_repo_label = trusted_repo_input.as_posix()
    except ValueError as exc:
        return _blocked_result(
            config=config,
            trace_id=trace_id,
            trusted_repo_path=trusted_repo_label,
            reason=str(exc),
            warnings=warnings,
            normalized_actions=normalized_actions
            or _safe_normalized_command_actions(config.command),
        )

    normalized_actions = (normalize_command_action(command),)

    _audit(
        config,
        trace_id=trace_id,
        event_type="guarded_run.requested",
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        reason="Guarded run requested.",
        metadata={
            "command": _command_audit_summary(command),
            "timeout_seconds": config.timeout_seconds,
            "preserve_workspace": config.preserve_workspace,
            "unsafe_local_requested": config.unsafe_local_requested,
        },
    )
    _audit_normalized_actions(
        config,
        trace_id=trace_id,
        event_type="guarded_run.normalized_command_prepared",
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        reason="Guarded command normalized before execution.",
        actions=normalized_actions,
        metadata={"phase": "pre_execution"},
    )
    _audit_command_intent(config, trace_id=trace_id, command=command)

    try:
        trusted_repo = detect_trusted_repo_root(trusted_repo_input)
        _verify_trusted_repo_state(
            trusted_repo,
            allow_dirty_override=config.allow_dirty_override,
            warnings=warnings,
        )
    except (GuardedWorktreeError, DirtyRepositoryError, RuntimeError, OSError) as exc:
        return _blocked_result(
            config=config,
            trace_id=trace_id,
            trusted_repo_path=trusted_repo_label,
            reason=str(exc),
            warnings=warnings,
            normalized_actions=normalized_actions
            or _safe_normalized_command_actions(config.command),
        )

    backend_selection: ExecutionBackendSelection | None = None
    backend_name: str | None = None
    backend_safe_by_default = False
    containment_verified = False
    containment_features: dict[str, bool] = {}

    try:
        backend_selection = _select_backend(config)
        backend_name = backend_selection.name.value
        backend_safe_by_default = backend_selection.safe_by_default

        containment = evaluate_containment_capabilities(backend_selection.name)
        containment_result = build_lifecycle_result(containment, LifecycleEvent.STARTED)
        containment_verified = containment_result.containment_verified
        containment_features = containment.isolation_features

        if backend_selection.warning:
            warnings.append(backend_selection.warning)

        warnings.extend(containment.limitations)

        if containment.unsafe_local:
            warnings.append(UNSAFE_LOCAL_WARNING)

        command_backend = _command_backend_for(backend_selection.name)
        if isinstance(command_backend, UnsupportedCommandBackend):
            return _blocked_result(
                config=config,
                trace_id=trace_id,
                trusted_repo_path=trusted_repo.as_posix(),
                reason=command_backend.reason,
                warnings=warnings,
                backend_name=backend_name,
                backend_safe_by_default=backend_safe_by_default,
                containment_verified=containment_verified,
                containment_features=containment_features,
                event_type="guarded_run.backend_blocked",
            )

        if containment.unsafe_local and not config.unsafe_local_requested:
            return _blocked_result(
                config=config,
                trace_id=trace_id,
                trusted_repo_path=trusted_repo.as_posix(),
                reason="Unsafe local execution was not explicitly requested.",
                warnings=warnings,
                backend_name=backend_name,
                backend_safe_by_default=backend_safe_by_default,
                containment_verified=containment_verified,
                containment_features=containment_features,
            )

        if not containment_verified and not containment.unsafe_local:
            return _blocked_result(
                config=config,
                trace_id=trace_id,
                trusted_repo_path=trusted_repo.as_posix(),
                reason="Selected backend does not provide verified containment.",
                warnings=warnings,
                backend_name=backend_name,
                backend_safe_by_default=backend_safe_by_default,
                containment_verified=containment_verified,
                containment_features=containment_features,
            )

        _audit(
            config,
            trace_id=trace_id,
            event_type="guarded_run.backend_selected",
            decision=Decision.ALLOW,
            allowed=True,
            severity=Severity.LOW,
            reason="Execution backend selected.",
            metadata={
                "backend_name": backend_name,
                "backend_safe_by_default": backend_safe_by_default,
                "containment_verified": containment_verified,
                "containment_features": containment_features,
                "selection_reason": backend_selection.reason,
                "warnings": tuple(warnings),
            },
        )
    except ExecutionBackendSelectionError as exc:
        return _blocked_result(
            config=config,
            trace_id=trace_id,
            trusted_repo_path=trusted_repo.as_posix(),
            reason=str(exc),
            warnings=warnings,
            event_type="guarded_run.backend_blocked",
        )

    with _guarded_run_concurrency_guard(
        trusted_repo_path=trusted_repo,
        run_root=config.rygnal_run_root,
        trace_id=trace_id,
    ) as concurrency_state:
        if concurrency_state.recovered_stale_lock:
            _audit(
                config,
                trace_id=trace_id,
                event_type="guarded_run.stale_lock_recovered",
                decision=Decision.ALLOW,
                allowed=True,
                severity=Severity.MEDIUM,
                reason="Recovered stale guarded run concurrency lock.",
                metadata={
                    "lock_path": concurrency_state.lock_path.as_posix(),
                    "lock_identity": concurrency_state.lock_identity,
                    "stale_lock_pid": concurrency_state.stale_lock_pid,
                    "trusted_repo_path": trusted_repo.as_posix(),
                    "run_root": Path(config.rygnal_run_root).resolve().as_posix(),
                },
            )

        if concurrency_state.blocked_reason is not None:
            _audit(
                config,
                trace_id=trace_id,
                event_type="guarded_run.concurrency_blocked",
                decision=Decision.BLOCK,
                allowed=False,
                severity=Severity.HIGH,
                reason=concurrency_state.blocked_reason,
                metadata={
                    "lock_path": concurrency_state.lock_path.as_posix(),
                    "lock_identity": concurrency_state.lock_identity,
                    "active_lock_pid": concurrency_state.active_lock_pid,
                    "trusted_repo_path": trusted_repo.as_posix(),
                    "run_root": Path(config.rygnal_run_root).resolve().as_posix(),
                },
            )

            return _blocked_result(
                config=config,
                trace_id=trace_id,
                trusted_repo_path=trusted_repo.as_posix(),
                reason=concurrency_state.blocked_reason,
                warnings=warnings,
                backend_name=backend_name,
                backend_safe_by_default=backend_safe_by_default,
                containment_verified=containment_verified,
                containment_features=containment_features,
                event_type="guarded_run.blocked",
            )

        worktree_config = GuardedWorktreeConfig(
            trusted_repo_path=trusted_repo,
            rygnal_run_root=config.rygnal_run_root,
            untracked_policy=config.untracked_policy,
            audit_logger=config.audit_logger,
        )

        worktree: GuardedWorktree | None = None
        command_result: GuardedCommandResult | None = None
        changed_file_report: ChangedFileReport | None = None
        patch_diff: PatchDiff | None = None
        change_risk_report: ChangeRiskReport | None = None
        cleanup_result: CleanupResult | None = None
        cleanup_performed = False
        blocked_reason: str | None = None
        approval_request: ApprovalRequest | None = None
        status = GuardedRunStatus.FAILED

        try:
            worktree = create_guarded_worktree(worktree_config)
        except GuardedWorktreeError as exc:
            return _blocked_result(
                config=config,
                trace_id=trace_id,
                trusted_repo_path=trusted_repo.as_posix(),
                reason=str(exc),
                warnings=warnings,
                backend_name=backend_name,
                backend_safe_by_default=backend_safe_by_default,
                containment_verified=containment_verified,
                event_type="guarded_run.blocked",
            )

        try:
            _audit(
                config,
                trace_id=trace_id,
                event_type="guarded_run.workspace_created",
                decision=Decision.ALLOW,
                allowed=True,
                severity=Severity.LOW,
                reason="Guarded workspace created.",
                metadata=_worktree_metadata(worktree, backend_name, containment_verified),
            )

            _audit(
                config,
                trace_id=trace_id,
                event_type="guarded_run.command_started",
                decision=Decision.ALLOW,
                allowed=True,
                severity=Severity.LOW,
                reason="Guarded command started.",
                metadata={
                    **_worktree_metadata(worktree, backend_name, containment_verified),
                    "command": _command_audit_summary(command),
                    "timeout_seconds": config.timeout_seconds,
                },
            )

            command_result = command_backend.run(
                command,
                cwd=worktree.workspace_path,
                timeout_seconds=config.timeout_seconds,
            )

            if command_result.timed_out:
                status = GuardedRunStatus.TIMED_OUT
                event_type = "guarded_run.command_timed_out"
                event_reason = "Guarded command timed out."
                event_severity = Severity.HIGH
                event_decision = Decision.BLOCK
                event_allowed = False
            elif command_result.exit_code == 0:
                status = GuardedRunStatus.COMPLETED
                event_type = "guarded_run.command_completed"
                event_reason = "Guarded command completed successfully."
                event_severity = Severity.LOW
                event_decision = Decision.ALLOW
                event_allowed = True
            else:
                status = GuardedRunStatus.FAILED
                event_type = "guarded_run.command_failed"
                event_reason = "Guarded command exited with a non-zero status."
                event_severity = Severity.MEDIUM
                event_decision = Decision.BLOCK
                event_allowed = False

            _audit(
                config,
                trace_id=trace_id,
                event_type=event_type,
                decision=event_decision,
                allowed=event_allowed,
                severity=event_severity,
                reason=event_reason,
                metadata={
                    **_worktree_metadata(worktree, backend_name, containment_verified),
                    **_command_metadata(command_result),
                },
            )

            changed_file_report = detect_changed_files(
                worktree.workspace_path,
                worktree.baseline_commit_sha,
            )

            _audit(
                config,
                trace_id=trace_id,
                event_type="guarded_run.changed_files_detected",
                decision=Decision.ALLOW,
                allowed=True,
                severity=Severity.LOW,
                reason="Guarded workspace changed files detected.",
                metadata={
                    **_worktree_metadata(worktree, backend_name, containment_verified),
                    "changed_file_count": len(changed_file_report.files),
                    "ignored_file_count": len(changed_file_report.ignored_files),
                    "changed_paths": tuple(file.path for file in changed_file_report.files),
                    "ignored_paths": tuple(file.path for file in changed_file_report.ignored_files),
                },
            )

            if changed_file_report.files:
                patch_diff = generate_patch_diff_from_report(changed_file_report)
                patch_decision = classify_and_decide_patch(patch_diff)
                change_risk_report = patch_decision.report

                _audit(
                    config,
                    trace_id=trace_id,
                    event_type="guarded_run.patch_classified",
                    decision=Decision.ALLOW if patch_decision.allowed else Decision.BLOCK,
                    allowed=patch_decision.allowed,
                    severity=(
                        Severity.CRITICAL
                        if patch_decision.risk_level == RiskLevel.CRITICAL
                        else Severity.HIGH
                        if patch_decision.risk_level == RiskLevel.HIGH
                        else Severity.MEDIUM
                        if patch_decision.risk_level == RiskLevel.MEDIUM
                        else Severity.LOW
                    ),
                    reason=patch_decision.reason,
                    metadata={
                        **_worktree_metadata(worktree, backend_name, containment_verified),
                        "patch_risk": patch_decision.audit_summary,
                    },
                )

                if not patch_decision.allowed:
                    approval_required = patch_decision.risk_level == RiskLevel.HIGH
                    status = (
                        GuardedRunStatus.APPROVAL_REQUIRED
                        if approval_required
                        else GuardedRunStatus.BLOCKED
                    )
                    blocked_reason = patch_decision.reason
                    warnings.append(patch_decision.reason)

                    if approval_required:
                        try:
                            approval_request = create_patch_approval_request(
                                patch_diff,
                                risk_report=change_risk_report,
                                requested_by=config.user_id,
                                agent_id=config.agent_id,
                                environment=config.environment,
                                trace_id=trace_id,
                            )
                            _submit_patch_approval_request(config, approval_request)
                        except PatchApprovalError as exc:
                            approval_required = False
                            status = GuardedRunStatus.BLOCKED
                            blocked_reason = (
                                f"Failed to create guarded patch approval request: {exc}"
                            )
                            warnings.append(blocked_reason)

                    _audit(
                        config,
                        trace_id=trace_id,
                        event_type=(
                            "guarded_run.patch_approval_required"
                            if approval_required
                            else "guarded_run.patch_blocked"
                        ),
                        decision=Decision.REQUIRE_APPROVAL if approval_required else Decision.BLOCK,
                        allowed=False,
                        severity=(
                            Severity.CRITICAL
                            if patch_decision.risk_level == RiskLevel.CRITICAL
                            else Severity.HIGH
                        ),
                        reason=blocked_reason or patch_decision.reason,
                        metadata={
                            **_worktree_metadata(worktree, backend_name, containment_verified),
                            "patch_risk": patch_decision.audit_summary,
                            "approval_request": (
                                approval_request.model_dump(mode="json")
                                if approval_request is not None
                                else None
                            ),
                        },
                    )

            _audit(
                config,
                trace_id=trace_id,
                event_type="guarded_run.patch_generated",
                decision=Decision.ALLOW,
                allowed=True,
                severity=Severity.LOW,
                reason="Guarded workspace patch metadata generated.",
                metadata={
                    **_worktree_metadata(worktree, backend_name, containment_verified),
                    "patch_generated": patch_diff is not None,
                    "patch": patch_diff.audit_summary if patch_diff is not None else None,
                },
            )

        except (GuardedWorktreeError, GuardedCommandExecutionError) as exc:
            blocked_reason = str(exc)
            status = GuardedRunStatus.FAILED
            warnings.append(blocked_reason)
            _audit(
                config,
                trace_id=trace_id,
                event_type="guarded_run.command_failed",
                decision=Decision.BLOCK,
                allowed=False,
                severity=Severity.HIGH,
                reason=blocked_reason,
                metadata={
                    "backend_name": backend_name,
                    "containment_verified": containment_verified,
                    "workspace_path": worktree.workspace_path.as_posix() if worktree else None,
                    "baseline_commit_sha": worktree.baseline_commit_sha if worktree else None,
                },
            )
        except (
            ChangedFileDetectionError,
            PatchDiffGenerationError,
            ChangeRiskClassificationError,
        ) as exc:
            blocked_reason = str(exc)
            status = GuardedRunStatus.FAILED
            warnings.append(blocked_reason)
            _audit(
                config,
                trace_id=trace_id,
                event_type="guarded_run.patch_generated",
                decision=Decision.BLOCK,
                allowed=False,
                severity=Severity.HIGH,
                reason=blocked_reason,
                metadata={
                    "backend_name": backend_name,
                    "containment_verified": containment_verified,
                    "workspace_path": worktree.workspace_path.as_posix() if worktree else None,
                    "baseline_commit_sha": worktree.baseline_commit_sha if worktree else None,
                },
            )
        finally:
            if worktree is not None:
                normalized_actions = normalize_guarded_actions(
                    command,
                    changed_file_report=changed_file_report,
                    patch_diff=patch_diff,
                )
                _audit_normalized_actions(
                    config,
                    trace_id=trace_id,
                    event_type="guarded_run.normalized_actions_recorded",
                    decision=Decision.ALLOW,
                    allowed=True,
                    severity=Severity.LOW,
                    reason="Guarded run normalized action telemetry recorded.",
                    actions=normalized_actions,
                    metadata={
                        **_worktree_metadata(worktree, backend_name, containment_verified),
                        "run_status": status.value,
                        "changed_files_detected": changed_file_report is not None,
                        "patch_generated": patch_diff is not None,
                    },
                )

                if config.preserve_workspace:
                    warnings.append("Guarded workspace was preserved by explicit configuration.")
                    cleanup_result = CleanupResult(
                        status=CleanupStatus.RESET_SUCCESS,
                        message="Workspace preserved by explicit configuration.",
                    )
                    _audit(
                        config,
                        trace_id=trace_id,
                        event_type="guarded_run.cleanup_completed",
                        decision=Decision.ALLOW,
                        allowed=True,
                        severity=Severity.LOW,
                        reason="Guarded workspace preserved by explicit configuration.",
                        metadata={
                            **_worktree_metadata(worktree, backend_name, containment_verified),
                            "cleanup_performed": False,
                            "cleanup_status": "preserved",
                        },
                    )
                else:
                    cleanup_performed = True
                    _audit(
                        config,
                        trace_id=trace_id,
                        event_type="guarded_run.cleanup_started",
                        decision=Decision.ALLOW,
                        allowed=True,
                        severity=Severity.LOW,
                        reason="Guarded workspace cleanup started.",
                        metadata=_worktree_metadata(worktree, backend_name, containment_verified),
                    )

                    cleanup_result = destroy_worktree(worktree, worktree_config)

                    if cleanup_result.status == CleanupStatus.CLEANUP_FAILED:
                        status = GuardedRunStatus.CLEANUP_FAILED
                        warnings.append(cleanup_result.message)
                        _audit(
                            config,
                            trace_id=trace_id,
                            event_type="guarded_run.cleanup_failed",
                            decision=Decision.BLOCK,
                            allowed=False,
                            severity=Severity.HIGH,
                            reason=cleanup_result.message,
                            metadata={
                                **_worktree_metadata(worktree, backend_name, containment_verified),
                                "cleanup_status": cleanup_result.status.value,
                                "cleanup_message": cleanup_result.message,
                            },
                        )
                    else:
                        _audit(
                            config,
                            trace_id=trace_id,
                            event_type="guarded_run.cleanup_completed",
                            decision=Decision.ALLOW,
                            allowed=True,
                            severity=Severity.LOW,
                            reason=cleanup_result.message,
                            metadata={
                                **_worktree_metadata(worktree, backend_name, containment_verified),
                                "cleanup_status": cleanup_result.status.value,
                                "cleanup_message": cleanup_result.message,
                            },
                        )

        return GuardedRunResult(
            status=status,
            run_id=worktree.run_id if worktree else None,
            trusted_repo_path=trusted_repo.as_posix(),
            workspace_path=worktree.workspace_path.as_posix() if worktree else None,
            baseline_commit_sha=worktree.baseline_commit_sha if worktree else None,
            backend_name=backend_name,
            backend_safe_by_default=backend_safe_by_default,
            containment_verified=containment_verified,
            cleanup_performed=cleanup_performed,
            cleanup_status=cleanup_result.status.value if cleanup_result else None,
            command_result=command_result,
            changed_file_report=changed_file_report,
            patch_diff=patch_diff,
            change_risk_report=change_risk_report,
            blocked_reason=blocked_reason,
            warnings=tuple(warnings),
            normalized_actions=normalized_actions
            or _safe_normalized_command_actions(config.command),
            approval_request=approval_request,
            containment_features=containment_features,
        )


def _submit_patch_approval_request(
    config: GuardedRunConfig,
    approval_request: ApprovalRequest,
) -> None:
    if config.approval_queue is None:
        return

    try:
        config.approval_queue.submit(approval_request)
    except ApprovalQueueError as exc:
        raise PatchApprovalError(
            f"Approval request could not be stored in shared approval queue: {exc}"
        ) from exc


def classify_and_decide_patch(patch_diff: PatchDiff) -> PatchRiskDecision:
    """Hard enforcement gate for guarded workspace patches.

    The deterministic patch classifier remains the first authority. The
    subjective-risk layer can only add report-level reasons; it never removes
    deterministic reasons or downgrades a risky deterministic decision.
    """

    report = classify_patch_risk(patch_diff)
    subjective_reasons = _collect_subjective_validation_reasons(patch_diff, report)

    if subjective_reasons:
        report = classify_patch_risk(
            patch_diff,
            validation_reasons=subjective_reasons,
        )

    risk_level = report.overall_risk_level

    if risk_level == RiskLevel.CRITICAL:
        return PatchRiskDecision(
            allowed=False,
            risk_level=risk_level,
            reason="Guarded patch blocked before completion: critical risk change detected.",
            report=report,
        )

    if risk_level == RiskLevel.HIGH:
        return PatchRiskDecision(
            allowed=False,
            risk_level=risk_level,
            reason="Guarded patch requires approval before completion: high risk change detected.",
            report=report,
        )

    return PatchRiskDecision(
        allowed=True,
        risk_level=risk_level,
        reason="Guarded patch accepted by deterministic patch-risk gate.",
        report=report,
    )


def _collect_subjective_validation_reasons(
    patch_diff: PatchDiff,
    report: ChangeRiskReport,
) -> tuple[ChangeRiskReason, ...]:
    """Collect subjective-risk report reasons for guarded patch classification."""

    system_risk_by_path = {
        file_risk.path: _system_risk_score_for_level(file_risk.risk_level)
        for file_risk in report.files
    }

    try:
        return collect_subjective_patch_reasons(
            workspace_path=patch_diff.workspace_path,
            baseline_commit_sha=patch_diff.baseline_commit_sha,
            files=patch_diff.files,
            system_risk_by_path=system_risk_by_path,
            file_risk_by_path={file_risk.path: file_risk for file_risk in report.files},
        )
    except SubjectiveRiskCollectionError as exc:
        return (
            ChangeRiskReason(
                code="subjective-risk-collection-failed",
                risk_level=RiskLevel.HIGH,
                reason=(
                    "Subjective human-context analysis could not complete; "
                    "guarded patch requires human approval."
                ),
                evidence=(("error", str(exc)),),
            ),
        )


def _system_risk_score_for_level(risk_level: RiskLevel) -> float:
    if risk_level == RiskLevel.CRITICAL:
        return 8.5
    if risk_level == RiskLevel.HIGH:
        return 6.5
    if risk_level == RiskLevel.MEDIUM:
        return 4.0
    return 2.0


def _audit_normalized_actions(
    config: GuardedRunConfig,
    *,
    trace_id: str,
    event_type: str,
    decision: Decision,
    allowed: bool,
    severity: Severity,
    reason: str,
    actions: tuple[NormalizedAction, ...],
    metadata: dict[str, object],
) -> None:
    _audit(
        config,
        trace_id=trace_id,
        event_type=event_type,
        decision=decision,
        allowed=allowed,
        severity=severity,
        reason=reason,
        metadata={
            **metadata,
            "normalized_actions": normalized_actions_audit_summary(actions),
        },
    )


def _audit_command_intent(
    config: GuardedRunConfig,
    *,
    trace_id: str,
    command: tuple[str, ...],
) -> ActionIntentReport:
    report = classify_command_intent(command)
    _audit(
        config,
        trace_id=trace_id,
        event_type="guarded_run.command_intent_classified",
        decision=Decision.ALLOW,
        allowed=True,
        severity=_severity_for_action_intent(report.max_severity),
        reason="Guarded command intent classified before execution.",
        metadata={
            "command": _command_audit_summary(command),
            **report.to_audit_metadata(),
        },
    )
    return report


def _severity_for_action_intent(severity: ActionIntentSeverity) -> Severity:
    if severity == ActionIntentSeverity.CRITICAL:
        return Severity.CRITICAL
    if severity == ActionIntentSeverity.HIGH:
        return Severity.HIGH
    if severity == ActionIntentSeverity.MEDIUM:
        return Severity.MEDIUM
    return Severity.LOW


def _select_backend(config: GuardedRunConfig) -> ExecutionBackendSelection:
    env = os.environ.copy()

    if config.unsafe_local_requested:
        env["RYGNAL_UNSAFE_LOCAL"] = "1"
    else:
        env.pop("RYGNAL_UNSAFE_LOCAL", None)

    capabilities = detect_host_backend_capabilities(env=env)
    return select_execution_backend(capabilities)


def _command_backend_for(backend_name: ExecutionBackendName) -> CommandBackend:
    if backend_name not in _IMPLEMENTED_COMMAND_BACKENDS:
        return UnsupportedCommandBackend(_unsupported_command_backend_reason(backend_name))

    if backend_name == ExecutionBackendName.LINUX_BUBBLEWRAP:
        return BubblewrapCommandBackend()

    if backend_name == ExecutionBackendName.UNSAFE_LOCAL:
        return UnsafeLocalCommandBackend()

    return UnsupportedCommandBackend(_unsupported_command_backend_reason(backend_name))


def _unsupported_command_backend_reason(backend_name: ExecutionBackendName) -> str:
    return (
        f"Backend {backend_name.value} was selected but command execution is not "
        "implemented for the guarded runner."
    )


def _validate_command(command: object) -> tuple[str, ...]:
    if isinstance(command, str):
        raise ValueError("Command must be argv-style, not a shell string.")

    try:
        command_tuple = tuple(command)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError("Command must be an argv-style iterable of strings.") from exc

    if not command_tuple:
        raise ValueError("Command must not be empty.")

    if any(not isinstance(item, str) for item in command_tuple):
        raise ValueError("Every command item must be a string.")

    if any(item == "" for item in command_tuple):
        raise ValueError("Command items must not be empty strings.")

    return command_tuple


def _validate_trusted_repo_path(trusted_repo_path: Path) -> Path:
    trusted_path = Path(trusted_repo_path).expanduser()

    if not trusted_path.exists():
        raise ValueError(f"Trusted repository path does not exist: {trusted_path}")

    if not trusted_path.is_dir():
        raise ValueError(f"Trusted repository path is not a directory: {trusted_path}")

    return trusted_path.resolve()


def _validate_timeout(timeout_seconds: int) -> None:
    if timeout_seconds <= 0:
        raise ValueError("Timeout must be a positive number of seconds.")


def _verify_trusted_repo_state(
    trusted_repo: Path,
    *,
    allow_dirty_override: bool,
    warnings: list[str],
) -> None:
    changes = get_uncommitted_changes(trusted_repo)
    tracked_dirty = bool(changes.staged or changes.unstaged)

    if not tracked_dirty:
        return

    if allow_dirty_override:
        warnings.append("Dirty trusted repository override was explicitly enabled.")
        return

    lines = ["Tracked uncommitted changes detected in trusted repository:"]
    if changes.staged:
        lines.append(f"  Staged: {len(changes.staged)} files")
    if changes.unstaged:
        lines.append(f"  Unstaged: {len(changes.unstaged)} files")
    lines.append("\nRygnal guarded execution blocked to prevent data loss.")
    lines.append("Commit or stash tracked changes, or pass allow_dirty_override=True.")

    raise DirtyRepositoryError("\n".join(lines))


def _run_subprocess(
    command: tuple[str, ...],
    *,
    cwd: Path,
    timeout_seconds: int,
) -> GuardedCommandResult:
    started = time.monotonic()
    cleanup_warnings: list[str] = []

    try:
        process = _start_guarded_process(command, cwd=cwd)

        with _temporary_process_signal_cleanup(process, cleanup_warnings):
            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
                duration_ms = int((time.monotonic() - started) * 1000)

                return GuardedCommandResult(
                    command=command,
                    exit_code=process.returncode,
                    stdout=stdout or "",
                    stderr=_append_cleanup_warnings(stderr or "", cleanup_warnings),
                    timed_out=False,
                    duration_ms=duration_ms,
                )
            except subprocess.TimeoutExpired as exc:
                cleanup_warnings.extend(_terminate_guarded_process_tree(process))
                stdout, stderr, drain_warning = _drain_guarded_process_output(process, exc)
                if drain_warning:
                    cleanup_warnings.append(drain_warning)

                duration_ms = int((time.monotonic() - started) * 1000)

                return GuardedCommandResult(
                    command=command,
                    exit_code=None,
                    stdout=stdout,
                    stderr=_append_cleanup_warnings(stderr, cleanup_warnings),
                    timed_out=True,
                    duration_ms=duration_ms,
                )
    except OSError as exc:
        raise GuardedCommandExecutionError(f"Failed to start guarded command: {exc}") from exc


def _start_guarded_process(command: tuple[str, ...], *, cwd: Path) -> subprocess.Popen[str]:
    kwargs: dict[str, object] = {}
    if _posix_process_group_supported():
        kwargs["start_new_session"] = True

    return subprocess.Popen(  # nosec B603 B607
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        **kwargs,
    )


def _posix_process_group_supported() -> bool:
    return os.name == "posix" and hasattr(os, "getpgid") and hasattr(os, "killpg")


def _terminate_guarded_process_tree(process: subprocess.Popen[str]) -> list[str]:
    warnings: list[str] = []
    process_group_id, group_warning = _guarded_process_group_id(process)
    if group_warning:
        warnings.append(group_warning)

    if process.poll() is None:
        warnings.extend(_terminate_guarded_process(process, process_group_id))

        try:
            process.wait(timeout=_PROCESS_GROUP_TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass

    # SIGTERM can kill the parent while same-group children keep running.
    # Always attempt one bounded force-kill pass against the original group id.
    warnings.extend(_force_kill_guarded_process(process, process_group_id))

    try:
        process.wait(timeout=_PROCESS_GROUP_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        warnings.append("Guarded command did not exit after forced cleanup; output may be partial.")

    return warnings


def _terminate_guarded_process(
    process: subprocess.Popen[str],
    process_group_id: int | None,
) -> list[str]:
    if process_group_id is not None:
        return _signal_guarded_process_group_id(
            process_group_id,
            signal.SIGTERM,
            action="terminate",
        )

    return _signal_direct_process(
        process,
        signal.SIGTERM,
        action="terminate",
        fallback_message="POSIX process groups unavailable; terminated direct process only.",
    )


def _force_kill_guarded_process(
    process: subprocess.Popen[str],
    process_group_id: int | None,
) -> list[str]:
    sigkill = getattr(signal, "SIGKILL", None)
    if process_group_id is not None and sigkill is not None:
        return _signal_guarded_process_group_id(
            process_group_id,
            sigkill,
            action="force-kill",
        )

    if process.poll() is not None:
        return []

    try:
        process.kill()
    except ProcessLookupError:
        return []
    except OSError as exc:
        return [f"Failed to force-kill guarded process: {exc}"]

    return ["POSIX process groups unavailable; force-killed direct process only."]


def _guarded_process_group_id(process: subprocess.Popen[str]) -> tuple[int | None, str | None]:
    if not _posix_process_group_supported():
        return None, None

    try:
        return os.getpgid(process.pid), None
    except ProcessLookupError:
        return None, None
    except OSError as exc:
        return None, f"Failed to inspect guarded process group: {exc}"


def _signal_guarded_process_group_id(
    process_group_id: int,
    signal_number: int,
    *,
    action: str,
) -> list[str]:
    try:
        os.killpg(process_group_id, signal_number)
    except ProcessLookupError:
        return []
    except OSError as exc:
        return [f"Failed to signal guarded process group during {action}: {exc}"]

    return []


def _signal_direct_process(
    process: subprocess.Popen[str],
    signal_number: int,
    *,
    action: str,
    fallback_message: str,
) -> list[str]:
    if process.poll() is not None:
        return []

    try:
        process.send_signal(signal_number)
    except ProcessLookupError:
        return []
    except OSError as exc:
        return [f"Failed to signal guarded process during {action}: {exc}"]

    return [fallback_message]


def _drain_guarded_process_output(
    process: subprocess.Popen[str],
    timeout_error: subprocess.TimeoutExpired,
) -> tuple[str, str, str | None]:
    try:
        stdout, stderr = process.communicate(timeout=_PROCESS_OUTPUT_DRAIN_GRACE_SECONDS)
        return stdout or "", stderr or "", None
    except subprocess.TimeoutExpired as drain_error:
        _close_process_pipes(process)
        stdout = _stream_to_text(drain_error.stdout) or _stream_to_text(timeout_error.stdout)
        stderr = _stream_to_text(drain_error.stderr) or _stream_to_text(timeout_error.stderr)
        return (
            stdout,
            stderr,
            (
                "Guarded command output pipes did not close after cleanup; "
                "stdout/stderr may be partial."
            ),
        )


def _close_process_pipes(process: subprocess.Popen[str]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except OSError:
            pass


def _append_cleanup_warnings(stderr: str, warnings: list[str]) -> str:
    if not warnings:
        return stderr

    warning_text = "\n".join(f"[rygnal cleanup] {warning}" for warning in warnings)
    if not stderr:
        return f"{warning_text}\n"

    return f"{stderr.rstrip()}\n{warning_text}\n"


@contextmanager
def _temporary_process_signal_cleanup(
    process: subprocess.Popen[str],
    cleanup_warnings: list[str],
):
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    previous_handlers: dict[int, object] = {}

    def restore_handlers() -> None:
        for signal_number, previous_handler in previous_handlers.items():
            signal.signal(signal_number, previous_handler)

    def cleanup_before_signal_exit(signum: int, frame: object) -> None:
        cleanup_warnings.extend(_terminate_guarded_process_tree(process))
        restore_handlers()

        previous_handler = previous_handlers.get(signum, signal.SIG_DFL)
        if callable(previous_handler):
            previous_handler(signum, frame)
            return

        if previous_handler == signal.SIG_IGN:
            return

        if signum == getattr(signal, "SIGINT", None):
            raise KeyboardInterrupt

        raise SystemExit(128 + signum)

    for signal_name in _SIGNAL_NAMES_FOR_PROCESS_CLEANUP:
        signal_number = getattr(signal, signal_name, None)
        if signal_number is None:
            continue

        try:
            previous_handlers[signal_number] = signal.getsignal(signal_number)
            signal.signal(signal_number, cleanup_before_signal_exit)
        except (OSError, RuntimeError, ValueError) as exc:
            previous_handlers.pop(signal_number, None)
            cleanup_warnings.append(
                f"Could not install guarded cleanup handler for {signal_name}: {exc}"
            )

    try:
        yield
    finally:
        restore_handlers()


def _build_bubblewrap_command(command: tuple[str, ...], workspace_path: Path) -> list[str]:
    bwrap_path = shutil.which("bwrap")
    if bwrap_path is None:
        raise GuardedCommandExecutionError("Bubblewrap backend selected but bwrap was not found.")

    workspace = workspace_path.resolve()
    passwd_file, group_file = _write_synthetic_identity_files(workspace)

    args = [
        bwrap_path,
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-net",
        "--die-with-parent",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        _SANDBOX_ETC.as_posix(),
        "--dir",
        "/var",
        "--tmpfs",
        _SANDBOX_TMP.as_posix(),
        "--tmpfs",
        _SANDBOX_VAR_TMP.as_posix(),
        "--dir",
        _SANDBOX_RUN.as_posix(),
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        _SANDBOX_TMP.as_posix(),
        "--setenv",
        "TMPDIR",
        _SANDBOX_TMP.as_posix(),
        "--setenv",
        "PWD",
        _SANDBOX_WORKSPACE.as_posix(),
        "--ro-bind",
        passwd_file.as_posix(),
        "/etc/passwd",
        "--ro-bind",
        group_file.as_posix(),
        "/etc/group",
    ]

    for runtime_path in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(runtime_path).exists():
            args.extend(["--ro-bind", runtime_path, runtime_path])

    for runtime_file in (
        "/etc/nsswitch.conf",
        "/etc/ld.so.cache",
    ):
        if Path(runtime_file).exists():
            args.extend(["--ro-bind", runtime_file, runtime_file])

    args.extend(_bubblewrap_workspace_mount_args(workspace))
    args.extend(
        [
            "--chdir",
            _SANDBOX_WORKSPACE.as_posix(),
            "--",
            *command,
        ]
    )

    return args


def _bubblewrap_workspace_mount_args(workspace: Path) -> list[str]:
    plan = WorkspaceMountPlan(
        mounts=(
            MountContract(
                sandbox_path=_SANDBOX_WORKSPACE.as_posix(),
                kind=MountKind.WRITABLE_BIND,
                host_source=workspace.as_posix(),
            ),
        )
    )

    args: list[str] = []
    for mount in plan.mounts:
        if mount.kind != MountKind.WRITABLE_BIND or mount.host_source is None:
            raise GuardedCommandExecutionError(
                "Workspace mount plan must contain only writable workspace bind mounts."
            )

        args.extend(["--bind", mount.host_source, mount.sandbox_path])

    return args


def _write_synthetic_identity_files(workspace: Path) -> tuple[Path, Path]:
    """Create minimal identity files outside the sandbox-visible workspace."""

    identity_dir = workspace.parent.joinpath(".rygnal-sandbox-identity")
    identity_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    uid = os.getuid() if hasattr(os, "getuid") else 65534
    gid = os.getgid() if hasattr(os, "getgid") else 65534

    passwd_file = identity_dir.joinpath("passwd")
    group_file = identity_dir.joinpath("group")

    passwd_file.write_text(
        "\\n".join(
            (
                "root:x:0:0:root:/root:/usr/sbin/nologin",
                f"rygnal:x:{uid}:{gid}:Rygnal Sandbox User:/tmp:/usr/sbin/nologin",
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
                "",
            )
        ),
        encoding="utf-8",
    )
    group_file.write_text(
        "\\n".join(
            (
                "root:x:0:",
                f"rygnal:x:{gid}:",
                "nogroup:x:65534:",
                "",
            )
        ),
        encoding="utf-8",
    )

    passwd_file.chmod(0o644)
    group_file.chmod(0o644)

    return passwd_file, group_file


def _blocked_result(
    *,
    config: GuardedRunConfig,
    trace_id: str,
    trusted_repo_path: str,
    reason: str,
    warnings: list[str],
    backend_name: str | None = None,
    backend_safe_by_default: bool = False,
    containment_verified: bool = False,
    containment_features: dict[str, bool] | None = None,
    normalized_actions: tuple[NormalizedAction, ...] | None = None,
    event_type: str = "guarded_run.blocked",
) -> GuardedRunResult:
    if not normalized_actions:
        normalized_actions = _safe_normalized_command_actions(config.command)

    _audit(
        config,
        trace_id=trace_id,
        event_type=event_type,
        decision=Decision.BLOCK,
        allowed=False,
        severity=Severity.HIGH,
        reason=reason,
        metadata={
            "backend_name": backend_name,
            "backend_safe_by_default": backend_safe_by_default,
            "containment_verified": containment_verified,
            "containment_features": containment_features or {},
            "blocked_reason": reason,
            "warnings": tuple(warnings),
            "command": _command_audit_summary(config.command),
            "normalized_actions": normalized_actions_audit_summary(normalized_actions),
        },
    )

    return GuardedRunResult(
        status=GuardedRunStatus.BLOCKED,
        run_id=None,
        trusted_repo_path=trusted_repo_path,
        workspace_path=None,
        baseline_commit_sha=None,
        backend_name=backend_name,
        backend_safe_by_default=backend_safe_by_default,
        containment_verified=containment_verified,
        cleanup_performed=False,
        cleanup_status=None,
        command_result=None,
        changed_file_report=None,
        patch_diff=None,
        change_risk_report=None,
        blocked_reason=reason,
        warnings=tuple(warnings),
        normalized_actions=normalized_actions,
        containment_features=containment_features or {},
    )


def _safe_normalized_command_actions(command: object) -> tuple[NormalizedAction, ...]:
    if isinstance(command, str):
        return ()

    try:
        command_tuple = tuple(command)  # type: ignore[arg-type]
    except TypeError:
        return ()

    if not command_tuple or any(not isinstance(item, str) for item in command_tuple):
        return ()

    try:
        return (normalize_command_action(command_tuple),)
    except (TypeError, ValueError):
        return ()


def _audit(
    config: GuardedRunConfig,
    *,
    trace_id: str,
    event_type: str,
    decision: Decision,
    allowed: bool,
    severity: Severity,
    reason: str,
    metadata: dict[str, object],
) -> None:
    if config.audit_logger is None:
        return

    request = ToolRequest(
        tool_name="guarded_runner",
        action=event_type,
        target=str(config.trusted_repo_path),
        input={"command": _command_audit_summary(config.command)},
        user_id=config.user_id,
        agent_id=config.agent_id,
        environment=config.environment,
        metadata={"trace_id": trace_id},
    )
    policy_decision = PolicyDecision(
        decision=decision,
        allowed=allowed,
        severity=severity,
        reason=reason,
        policy_id="guarded-runner",
    )

    config.audit_logger.log_decision(
        request,
        policy_decision,
        metadata={
            "event_type": event_type,
            "trace_id": trace_id,
            **metadata,
        },
    )


def _worktree_metadata(
    worktree: GuardedWorktree,
    backend_name: str | None,
    containment_verified: bool,
) -> dict[str, object]:
    return {
        "run_id": worktree.run_id,
        "trusted_repo_path": worktree.trusted_repo_path.as_posix(),
        "workspace_path": worktree.workspace_path.as_posix(),
        "baseline_commit_sha": worktree.baseline_commit_sha,
        "backend_name": backend_name,
        "containment_verified": containment_verified,
    }


def _command_metadata(result: GuardedCommandResult) -> dict[str, object]:
    return {
        "command": _command_audit_summary(result.command),
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "duration_ms": result.duration_ms,
        "stdout": _stream_metadata(result.stdout),
        "stderr": _stream_metadata(result.stderr),
    }


def _stream_metadata(value: str) -> dict[str, object]:
    encoded = value.encode("utf-8", errors="replace")
    return {
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _stream_to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return value


def _command_audit_summary(command: object) -> dict[str, object]:
    if isinstance(command, str):
        command_items = (command,)
    else:
        try:
            command_items = tuple(str(item) for item in command)  # type: ignore[arg-type]
        except TypeError:
            command_items = (repr(command),)

    encoded = "\0".join(command_items).encode("utf-8", errors="replace")
    executable = Path(command_items[0]).name if command_items else None

    return {
        "argc": len(command_items),
        "executable": executable,
        "argv_sha256": hashlib.sha256(encoded).hexdigest(),
    }


__all__ = [
    "BubblewrapCommandBackend",
    "CommandBackend",
    "GuardedCommandResult",
    "GuardedRunConfig",
    "GuardedRunResult",
    "GuardedRunStatus",
    "GuardedRunnerError",
    "UnsupportedCommandBackend",
    "UnsafeLocalCommandBackend",
    "run_guarded",
]
