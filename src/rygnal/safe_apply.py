"""Auto-apply support for low-risk guarded workspace patches."""

from __future__ import annotations

import hashlib
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from typing import Any

from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import (
    GuardedChangeGateDecision,
    evaluate_guarded_change_gate,
)
from rygnal.change_risk import ChangeRiskReport, FileRiskClassification, classify_patch_risk
from rygnal.models import Decision, PolicyDecision, Severity, ToolRequest, new_trace_id
from rygnal.patch_diff import PatchDiff, generate_patch_diff
from rygnal.path_safety import (
    PathSafetyError,
    ensure_patch_paths_safe,
    write_path_safety_audit_event,
)
from rygnal.risk_engine import RiskLevel


class SafePatchApplyError(RuntimeError):
    """Raised when a safe patch cannot be applied reliably."""


class SafePatchApplyOutcome(StrEnum):
    APPLIED = "applied"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class SafePatchSkipReason:
    code: str
    reason: str
    path: str | None = None

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "code": self.code,
            "reason": self.reason,
            "path": self.path,
        }


@dataclass(frozen=True)
class SafePatchApplyResult:
    outcome: SafePatchApplyOutcome
    target_repo_path: str
    patch_sha256: str
    baseline_commit_sha: str
    files: tuple[str, ...]
    risk_report: ChangeRiskReport
    skip_reasons: tuple[SafePatchSkipReason, ...] = ()

    @cached_property
    def applied(self) -> bool:
        return self.outcome == SafePatchApplyOutcome.APPLIED

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "applied": self.applied,
            "target_repo_path": self.target_repo_path,
            "patch_sha256": self.patch_sha256,
            "baseline_commit_sha": self.baseline_commit_sha,
            "files": self.files,
            "overall_risk_level": self.risk_report.overall_risk_level.value,
            "risk_counts": self.risk_report.risk_counts,
            "skip_reasons": tuple(reason.audit_summary for reason in self.skip_reasons),
            "risk_report": self.risk_report.audit_summary,
        }


def auto_apply_safe_patch(
    patch_diff: PatchDiff,
    target_repo_path: str | Path,
    *,
    risk_report: ChangeRiskReport | None = None,
    gate_decision: GuardedChangeGateDecision | None = None,
    logger: AuditLogger | None = None,
    user_id: str = "demo_user",
    agent_id: str = "demo_agent",
    environment: str = "local",
    trace_id: str | None = None,
) -> SafePatchApplyResult:
    target_repo = Path(target_repo_path).resolve()

    _ensure_git_repo(target_repo)
    try:
        ensure_patch_paths_safe(patch_diff, target_repo)
    except PathSafetyError as exc:
        if logger is not None:
            write_path_safety_audit_event(
                logger,
                exc.report,
                user_id=user_id,
                agent_id=agent_id,
                environment=environment,
                trace_id=trace_id,
            )
        raise SafePatchApplyError(str(exc)) from exc

    _ensure_clean_repo(target_repo)
    _ensure_patch_integrity(patch_diff)
    _ensure_target_at_baseline(
        target_repo,
        patch_diff.baseline_commit_sha,
    )

    report = risk_report or classify_patch_risk(patch_diff)
    gate = gate_decision or evaluate_guarded_change_gate(patch_diff, risk_report=report)

    skip_reasons = _auto_apply_skip_reasons(patch_diff, report, gate)
    result = _result(
        SafePatchApplyOutcome.SKIPPED,
        target_repo,
        patch_diff,
        report,
        skip_reasons,
    )

    if skip_reasons:
        return result

    _check_patch_applies(target_repo, patch_diff.patch)
    _apply_patch(target_repo, patch_diff.patch)

    try:
        _verify_applied_patch(target_repo, patch_diff)
        result = _result(
            SafePatchApplyOutcome.APPLIED,
            target_repo,
            patch_diff,
            report,
            (),
        )

        if logger is not None:
            write_safe_patch_apply_audit_event(
                logger,
                result,
                user_id=user_id,
                agent_id=agent_id,
                environment=environment,
                trace_id=trace_id,
            )
    except Exception as exc:
        _rollback_after_failed_apply(
            target_repo,
            patch_diff,
            failure=exc,
        )

    return result


def write_safe_patch_apply_audit_event(
    logger: AuditLogger,
    result: SafePatchApplyResult,
    *,
    user_id: str = "demo_user",
    agent_id: str = "demo_agent",
    environment: str = "local",
    trace_id: str | None = None,
) -> Any:
    request = ToolRequest(
        tool_name="guarded_workspace",
        action="auto_apply_safe_patch",
        target=result.patch_sha256,
        input=result.audit_summary,
        user_id=user_id,
        agent_id=agent_id,
        environment=environment,
        metadata={
            "trace_id": trace_id or new_trace_id(),
            "event_type": "guarded_workspace.safe_patch_apply",
            "patch_sha256": result.patch_sha256,
            "baseline_commit_sha": result.baseline_commit_sha,
        },
    )
    decision = PolicyDecision(
        decision=Decision.ALLOW,
        allowed=True,
        severity=Severity.LOW,
        reason="Low-risk guarded workspace patch auto-applied.",
        policy_id="guarded-workspace-safe-patch-auto-apply",
    )

    return logger.log_decision(request, decision, metadata=result.audit_summary)


def _auto_apply_skip_reasons(
    patch_diff: PatchDiff,
    risk_report: ChangeRiskReport,
    gate_decision: GuardedChangeGateDecision,
) -> tuple[SafePatchSkipReason, ...]:
    reasons: list[SafePatchSkipReason] = []

    if gate_decision.blocked:
        reasons.append(
            SafePatchSkipReason(
                code="blocked-by-change-gate",
                reason="Patch was blocked by the dangerous-change gate.",
            )
        )

    if patch_diff.changed_file_count == 0:
        reasons.append(
            SafePatchSkipReason(
                code="empty-patch",
                reason="Patch has no changed files to apply.",
            )
        )

    if patch_diff.ignored_file_count:
        reasons.append(
            SafePatchSkipReason(
                code="ignored-workspace-changes",
                reason="Guarded workspace contains ignored changes outside the patch.",
            )
        )

    if risk_report.overall_risk_level != RiskLevel.LOW:
        reasons.append(
            SafePatchSkipReason(
                code="not-low-risk",
                reason="Only low-risk patches may be auto-applied.",
            )
        )

    for report_reason in risk_report.report_reasons:
        if report_reason.code.startswith(("large-diff-", "hard-diff-")):
            reasons.append(
                SafePatchSkipReason(
                    code=report_reason.code,
                    reason=report_reason.reason,
                )
            )

    for file_risk in risk_report.files:
        if not _is_docs_or_tests_only(file_risk):
            reasons.append(
                SafePatchSkipReason(
                    code="not-docs-or-tests-only",
                    reason="Only documentation and test-only patches may be auto-applied.",
                    path=file_risk.path,
                )
            )

        if file_risk.binary:
            reasons.append(
                SafePatchSkipReason(
                    code="binary-file-change",
                    reason="Binary changes are not eligible for auto-apply.",
                    path=file_risk.path,
                )
            )

        mode_skip_reason = _unsafe_mode_skip_reason(file_risk)
        if mode_skip_reason is not None:
            reasons.append(mode_skip_reason)

    return tuple(_dedupe_reasons(reasons))


def _is_docs_or_tests_only(file_risk: FileRiskClassification) -> bool:
    if file_risk.risk_level != RiskLevel.LOW:
        return False

    reason_codes = {reason.code for reason in file_risk.reasons}
    return bool(reason_codes) and reason_codes <= {"documentation-change", "test-change"}


def _unsafe_mode_skip_reason(
    file_risk: FileRiskClassification,
) -> SafePatchSkipReason | None:
    modes = {mode for mode in (file_risk.old_mode, file_risk.new_mode) if mode}

    if "120000" in modes:
        return SafePatchSkipReason(
            code="symlink-mode",
            reason="Symlink metadata is not eligible for auto-apply.",
            path=file_risk.path,
        )

    if "100755" in modes:
        return SafePatchSkipReason(
            code="executable-mode",
            reason="Executable file metadata is not eligible for auto-apply.",
            path=file_risk.path,
        )

    if file_risk.mode_changed:
        return SafePatchSkipReason(
            code="mode-change",
            reason="File mode changes are not eligible for auto-apply.",
            path=file_risk.path,
        )

    unsafe_modes = modes - {"100644"}
    if unsafe_modes:
        return SafePatchSkipReason(
            code="unsupported-file-mode",
            reason="Unsupported file mode is not eligible for auto-apply.",
            path=file_risk.path,
        )

    return None


def _dedupe_reasons(
    reasons: list[SafePatchSkipReason],
) -> tuple[SafePatchSkipReason, ...]:
    seen: set[tuple[str, str | None]] = set()
    deduped: list[SafePatchSkipReason] = []

    for reason in reasons:
        key = (reason.code, reason.path)
        if key in seen:
            continue

        seen.add(key)
        deduped.append(reason)

    return tuple(deduped)


def _result(
    outcome: SafePatchApplyOutcome,
    target_repo: Path,
    patch_diff: PatchDiff,
    risk_report: ChangeRiskReport,
    skip_reasons: tuple[SafePatchSkipReason, ...],
) -> SafePatchApplyResult:
    return SafePatchApplyResult(
        outcome=outcome,
        target_repo_path=target_repo.as_posix(),
        patch_sha256=patch_diff.patch_sha256,
        baseline_commit_sha=patch_diff.baseline_commit_sha,
        files=tuple(file.path for file in patch_diff.files),
        risk_report=risk_report,
        skip_reasons=skip_reasons,
    )


def _ensure_git_repo(path: Path) -> None:
    if not path.exists() or not path.is_dir():
        raise SafePatchApplyError(f"Target repository does not exist: {path}")

    result = _run_git(path, "rev-parse", "--show-toplevel")
    root = Path(result.stdout.decode("utf-8", errors="replace").strip()).resolve()

    if root != path:
        raise SafePatchApplyError(f"Target path is not the Git repository root: {path}")


def _ensure_clean_repo(path: Path) -> None:
    status = _run_git(path, "status", "--porcelain", "--untracked-files=all")

    if status.stdout.strip():
        raise SafePatchApplyError("Target repository must be clean before auto-apply.")


def _ensure_patch_integrity(
    patch_diff: PatchDiff,
) -> None:
    patch_bytes = patch_diff.patch.encode(
        "utf-8",
        errors="surrogateescape",
    )
    actual_sha256 = hashlib.sha256(patch_bytes).hexdigest()

    if actual_sha256 != patch_diff.patch_sha256:
        raise SafePatchApplyError("Patch content does not match its declared SHA-256.")

    if len(patch_bytes) != patch_diff.patch_size_bytes:
        raise SafePatchApplyError("Patch content does not match its declared byte length.")


def _ensure_target_at_baseline(
    path: Path,
    baseline_commit_sha: str,
) -> None:
    head = _run_git(
        path,
        "rev-parse",
        "HEAD",
    )
    actual_head = head.stdout.decode(
        "utf-8",
        errors="replace",
    ).strip()

    if actual_head != baseline_commit_sha:
        raise SafePatchApplyError("Target repository HEAD does not match the patch baseline.")


def _verify_applied_patch(
    path: Path,
    expected: PatchDiff,
) -> None:
    actual = generate_patch_diff(
        path,
        expected.baseline_commit_sha,
    )

    if actual.patch_sha256 != expected.patch_sha256:
        raise SafePatchApplyError(
            "Applied repository diff does not match the approved patch digest."
        )

    if actual.patch_size_bytes != expected.patch_size_bytes:
        raise SafePatchApplyError(
            "Applied repository diff does not match the approved patch length."
        )

    if actual.files != expected.files:
        raise SafePatchApplyError(
            "Applied repository file metadata does not match the approved patch."
        )

    if actual.ignored_files != expected.ignored_files:
        raise SafePatchApplyError("Applied repository contains ignored changes outside the patch.")


def _rollback_after_failed_apply(
    path: Path,
    patch_diff: PatchDiff,
    *,
    failure: Exception,
) -> None:
    try:
        _run_git(
            path,
            "apply",
            "--reverse",
            "--whitespace=error",
            "-",
            input_bytes=_patch_bytes(patch_diff.patch),
        )

        _ensure_target_at_baseline(
            path,
            patch_diff.baseline_commit_sha,
        )
        _ensure_clean_repo(path)

    except Exception as rollback_error:
        raise SafePatchApplyError(
            "Automatic apply failed and rollback "
            "could not restore the trusted repository: "
            f"{rollback_error}"
        ) from failure

    raise SafePatchApplyError(
        "Automatic apply failed after mutation; "
        "the trusted repository was rolled back "
        f"safely: {failure}"
    ) from failure


def _patch_bytes(patch: str) -> bytes:
    return patch.encode(
        "utf-8",
        errors="surrogateescape",
    )


def _check_patch_applies(path: Path, patch: str) -> None:
    _run_git(
        path,
        "apply",
        "--check",
        "--whitespace=error",
        "-",
        input_bytes=_patch_bytes(patch),
    )


def _apply_patch(path: Path, patch: str) -> None:
    _run_git(
        path,
        "apply",
        "--whitespace=error",
        "-",
        input_bytes=_patch_bytes(patch),
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
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        detail = stderr or stdout or f"git {' '.join(args)} failed"
        raise SafePatchApplyError(detail)

    return result


def _git_executable() -> str:
    git = shutil.which("git")
    if git is None:
        raise SafePatchApplyError("git executable not found on PATH.")

    return git


__all__ = [
    "SafePatchApplyError",
    "SafePatchApplyOutcome",
    "SafePatchApplyResult",
    "SafePatchSkipReason",
    "auto_apply_safe_patch",
    "write_safe_patch_apply_audit_event",
]
