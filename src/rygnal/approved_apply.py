"""Apply approved guarded workspace patches to a trusted repository."""

from __future__ import annotations

import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from threading import Lock
from typing import Any

from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import evaluate_guarded_change_gate
from rygnal.change_risk import ChangeRiskReport, classify_patch_risk
from rygnal.models import (
    ApprovalDecision,
    ApprovalRequest,
    Decision,
    PolicyDecision,
    Severity,
    ToolRequest,
)
from rygnal.patch_approval import (
    PatchApprovalError,
    assert_patch_approval_granted,
    evaluate_patch_approval_requirement,
)
from rygnal.patch_diff import PatchDiff
from rygnal.path_safety import (
    PathSafetyError,
    ensure_patch_paths_safe,
    write_path_safety_audit_event,
)


class ApprovedPatchApplyError(RuntimeError):
    """Raised when an approved patch cannot be safely applied."""


class ApprovedPatchApplyOutcome(StrEnum):
    APPLIED = "applied"


APPROVED_PATCH_APPLY_POLICY_ID = "guarded-workspace-approved-patch-apply"

_USED_PATCH_APPROVALS: set[tuple[str, str, str]] = set()
_USED_PATCH_APPROVALS_LOCK = Lock()


@dataclass(frozen=True)
class ApprovedPatchApplyResult:
    outcome: ApprovedPatchApplyOutcome
    target_repo_path: str
    patch_sha256: str
    baseline_commit_sha: str
    approval_id: str
    approved_by: str
    files: tuple[str, ...]
    risk_report: ChangeRiskReport

    @cached_property
    def applied(self) -> bool:
        return self.outcome == ApprovedPatchApplyOutcome.APPLIED

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "applied": self.applied,
            "target_repo_path": self.target_repo_path,
            "patch_sha256": self.patch_sha256,
            "baseline_commit_sha": self.baseline_commit_sha,
            "approval_id": self.approval_id,
            "approved_by": self.approved_by,
            "files": self.files,
            "overall_risk_level": self.risk_report.overall_risk_level.value,
            "risk_counts": self.risk_report.risk_counts,
            "risk_report": self.risk_report.audit_summary,
        }


def apply_approved_patch(
    patch_diff: PatchDiff,
    target_repo_path: str | Path,
    *,
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
    risk_report: ChangeRiskReport | None = None,
    logger: AuditLogger | None = None,
) -> ApprovedPatchApplyResult:
    target_repo = Path(target_repo_path).resolve()
    _ensure_git_repo_root(target_repo)

    try:
        ensure_patch_paths_safe(patch_diff, target_repo)
    except PathSafetyError as exc:
        if logger is not None:
            write_path_safety_audit_event(
                logger,
                exc.report,
                user_id=approval_request.requested_by,
                agent_id=approval_request.agent_id,
                environment=approval_request.environment,
                trace_id=approval_request.trace_id,
            )
        raise ApprovedPatchApplyError(str(exc)) from exc

    report = risk_report or classify_patch_risk(patch_diff)
    gate = evaluate_guarded_change_gate(patch_diff, risk_report=report)

    if gate.blocked:
        raise ApprovedPatchApplyError("Blocked patches cannot be applied.")

    requirement = evaluate_patch_approval_requirement(
        patch_diff,
        risk_report=report,
        gate_decision=gate,
    )
    forced_approval = bool(approval_request.metadata.get("forced_approval", False))

    if not requirement.required and not forced_approval:
        raise ApprovedPatchApplyError(
            "Patch does not require approval; use the safe auto-apply flow."
        )

    try:
        assert_patch_approval_granted(approval_request, approval_decision, patch_diff)
    except PatchApprovalError as exc:
        raise ApprovedPatchApplyError(str(exc)) from exc

    _validate_request_for_apply(approval_request)
    _ensure_clean_repo(target_repo)
    _ensure_target_at_baseline(target_repo, patch_diff.baseline_commit_sha)

    approval_use_key = _approval_use_key(approval_request, patch_diff)
    _ensure_approval_not_previously_applied(logger, approval_use_key)
    _reserve_approval_use(approval_use_key)
    try:
        _check_patch_applies(target_repo, patch_diff.patch)
        _apply_patch(target_repo, patch_diff.patch)
    except Exception:
        _release_approval_use(approval_use_key)
        raise

    result = ApprovedPatchApplyResult(
        outcome=ApprovedPatchApplyOutcome.APPLIED,
        target_repo_path=target_repo.as_posix(),
        patch_sha256=patch_diff.patch_sha256,
        baseline_commit_sha=patch_diff.baseline_commit_sha,
        approval_id=approval_request.approval_id,
        approved_by=approval_decision.decided_by,
        files=tuple(file.path for file in patch_diff.files),
        risk_report=report,
    )

    if logger is not None:
        write_approved_patch_apply_audit_event(
            logger,
            result,
            approval_request=approval_request,
        )

    return result


def write_approved_patch_apply_audit_event(
    logger: AuditLogger,
    result: ApprovedPatchApplyResult,
    *,
    approval_request: ApprovalRequest,
) -> Any:
    request = ToolRequest(
        tool_name="guarded_workspace",
        action="apply_approved_patch",
        target=result.patch_sha256,
        input=result.audit_summary,
        user_id=approval_request.requested_by,
        agent_id=approval_request.agent_id,
        environment=approval_request.environment,
        metadata={
            "trace_id": approval_request.trace_id,
            "event_type": "guarded_workspace.approved_patch_apply",
            "approval_id": result.approval_id,
            "patch_sha256": result.patch_sha256,
            "baseline_commit_sha": result.baseline_commit_sha,
        },
    )
    decision = PolicyDecision(
        decision=Decision.ALLOW,
        allowed=True,
        severity=_coerce_severity(approval_request.severity),
        reason="Approved guarded workspace patch applied to trusted repository.",
        policy_id=APPROVED_PATCH_APPLY_POLICY_ID,
    )

    return logger.log_decision(request, decision, metadata=result.audit_summary)


def _approval_use_key(
    approval_request: ApprovalRequest,
    patch_diff: PatchDiff,
) -> tuple[str, str, str]:
    return (
        approval_request.approval_id,
        patch_diff.patch_sha256,
        patch_diff.baseline_commit_sha,
    )


def _reserve_approval_use(key: tuple[str, str, str]) -> None:
    with _USED_PATCH_APPROVALS_LOCK:
        if key in _USED_PATCH_APPROVALS:
            raise ApprovedPatchApplyError("Approval has already been used for this guarded patch.")
        _USED_PATCH_APPROVALS.add(key)


def _release_approval_use(key: tuple[str, str, str]) -> None:
    with _USED_PATCH_APPROVALS_LOCK:
        _USED_PATCH_APPROVALS.discard(key)


def _ensure_approval_not_previously_applied(
    logger: AuditLogger | None,
    key: tuple[str, str, str],
) -> None:
    if logger is None:
        raise ApprovedPatchApplyError(
            "Approved patch apply requires an audit logger for durable replay protection."
        )

    for event in _read_approved_patch_apply_audit_events(logger):
        if _approved_patch_apply_event_matches_key(event, key):
            raise ApprovedPatchApplyError("Approval has already been used for this guarded patch.")


def _read_approved_patch_apply_audit_events(logger: AuditLogger) -> tuple[Any, ...]:
    storage_backend = getattr(logger, "storage_backend", None)

    if storage_backend is not None:
        try:
            return _read_approved_patch_apply_events_from_storage(storage_backend)
        except ApprovedPatchApplyError:
            raise
        except Exception as exc:
            raise ApprovedPatchApplyError(
                "Could not verify durable approval replay history."
            ) from exc

    return tuple(
        event for event in logger.read_events() if event.policy_id == APPROVED_PATCH_APPLY_POLICY_ID
    )


def _read_approved_patch_apply_events_from_storage(
    storage_backend: Any,
) -> tuple[Any, ...]:
    read_events = getattr(storage_backend, "read_events", None)
    if not callable(read_events):
        raise ApprovedPatchApplyError(
            "Audit storage backend cannot read durable approval replay history."
        )

    return tuple(
        event for event in read_events() if event.policy_id == APPROVED_PATCH_APPLY_POLICY_ID
    )


def _approved_patch_apply_event_matches_key(
    event: Any,
    key: tuple[str, str, str],
) -> bool:
    approval_id, patch_sha256, baseline_commit_sha = key
    metadata = getattr(event, "metadata", {}) or {}

    return (
        metadata.get("approval_id") == approval_id
        and metadata.get("patch_sha256") == patch_sha256
        and metadata.get("baseline_commit_sha") == baseline_commit_sha
    )


def _validate_request_for_apply(approval_request: ApprovalRequest) -> None:
    if approval_request.tool_name != "guarded_workspace":
        raise ApprovedPatchApplyError("Approval request tool mismatch.")

    if approval_request.action != "approve_patch_apply":
        raise ApprovedPatchApplyError("Approval request action mismatch.")

    supported_policy_ids = {
        "guarded-workspace-risky-patch-approval",
        "guarded-workspace-intent-approval",
        "guarded-workspace-non-auto-apply-approval",
        "guarded-workspace-explicit-approval",
    }

    if approval_request.policy_id not in supported_policy_ids:
        raise ApprovedPatchApplyError("Approval request policy mismatch.")


def _ensure_git_repo_root(path: Path) -> None:
    if not path.exists() or not path.is_dir():
        raise ApprovedPatchApplyError(f"Target repository does not exist: {path}")

    result = _run_git(path, "rev-parse", "--show-toplevel")
    root = Path(_decode(result.stdout).strip()).resolve()

    if root != path:
        raise ApprovedPatchApplyError(f"Target path is not the Git repository root: {path}")


def _ensure_clean_repo(path: Path) -> None:
    result = _run_git(path, "status", "--porcelain", "--untracked-files=all")

    if result.stdout.strip():
        raise ApprovedPatchApplyError("Target repository must be clean before apply.")


def _ensure_target_at_baseline(path: Path, baseline_commit_sha: str) -> None:
    result = _run_git(path, "rev-parse", "HEAD")
    head_sha = _decode(result.stdout).strip().lower()

    if head_sha != baseline_commit_sha.lower():
        raise ApprovedPatchApplyError(
            "Target repository HEAD does not match guarded patch baseline."
        )


def _check_patch_applies(path: Path, patch: str) -> None:
    _run_git(
        path,
        "apply",
        "--check",
        "--whitespace=error",
        "-",
        input_bytes=patch.encode("utf-8"),
    )


def _apply_patch(path: Path, patch: str) -> None:
    _run_git(
        path,
        "apply",
        "--whitespace=error",
        "-",
        input_bytes=patch.encode("utf-8"),
    )


def _run_git(
    cwd: Path,
    *args: str,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(  # nosec B603
        [_git_executable(), *args],
        cwd=cwd,
        input=input_bytes,
        check=False,
        capture_output=True,
    )

    if result.returncode != 0:
        stderr = _decode(result.stderr).strip()
        stdout = _decode(result.stdout).strip()
        detail = stderr or stdout or f"git {' '.join(args)} failed"
        raise ApprovedPatchApplyError(detail)

    return result


def _git_executable() -> str:
    git = shutil.which("git")
    if git is None:
        raise ApprovedPatchApplyError("git executable not found on PATH.")

    return git


def _decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _coerce_severity(value: Severity | str) -> Severity:
    if isinstance(value, Severity):
        return value

    return Severity(value)


__all__ = [
    "ApprovedPatchApplyError",
    "ApprovedPatchApplyOutcome",
    "ApprovedPatchApplyResult",
    "apply_approved_patch",
    "write_approved_patch_apply_audit_event",
]
