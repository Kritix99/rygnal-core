"""Authoritative post-execution patch decision and mutation boundary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import (
    GuardedChangeGateDecision,
    evaluate_guarded_change_gate,
)
from rygnal.change_risk import ChangeRiskReport
from rygnal.intent_fallback_policy import IntentFallbackEvaluation
from rygnal.intent_receipt import IntentDecisionReceipt
from rygnal.models import ApprovalRequest, Severity
from rygnal.patch_approval import (
    PatchApprovalRequirement,
    create_patch_approval_request,
    evaluate_patch_approval_requirement,
)
from rygnal.patch_artifact import (
    PatchArtifact,
    PatchArtifactError,
    PatchArtifactStore,
    bind_artifact_to_approval,
)
from rygnal.patch_diff import PatchDiff
from rygnal.risk_engine import RiskLevel
from rygnal.safe_apply import (
    SafePatchApplyError,
    SafePatchApplyOutcome,
    SafePatchApplyResult,
    auto_apply_safe_patch,
)


class ApprovalQueueWriter(Protocol):
    """Minimal queue boundary required by guarded patch finalization."""

    def submit(
        self,
        approval_request: ApprovalRequest,
    ) -> ApprovalRequest:
        """Persist one pending approval request."""


class GuardedPatchApplyOutcome(StrEnum):
    """Trusted-repository mutation outcome for one guarded patch."""

    NOT_GENERATED = "not_generated"
    NOT_APPLIED = "not_applied"
    APPLIED = "applied"
    PENDING_APPROVAL = "pending_approval"
    APPLY_FAILED = "apply_failed"


class GuardedPatchFinalStatus(StrEnum):
    """Runner-compatible status produced by authoritative finalization."""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"
    APPROVAL_REQUIRED = "approval_required"


@dataclass(frozen=True)
class GuardedPatchFinalizationRequest:
    """Inputs required to decide whether a patch may mutate trust."""

    current_status: str

    run_id: str
    trace_id: str

    trusted_repo_path: str | Path
    run_root: str | Path

    user_id: str
    agent_id: str
    environment: str

    command_exit_code: int | None
    command_timed_out: bool

    patch_diff: PatchDiff | None
    risk_report: ChangeRiskReport | None

    intent_fallback_evaluation: IntentFallbackEvaluation | None = None
    intent_decision_receipt: IntentDecisionReceipt | None = None

    approval_queue: ApprovalQueueWriter | None = None
    audit_logger: AuditLogger | None = None


@dataclass(frozen=True)
class GuardedPatchFinalizationResult:
    """Complete outcome of the trusted mutation decision."""

    status: GuardedPatchFinalStatus
    apply_outcome: GuardedPatchApplyOutcome

    blocked_reason: str | None = None
    approval_request: ApprovalRequest | None = None
    artifact_id: str | None = None

    safe_apply_result: SafePatchApplyResult | None = None
    gate_decision: GuardedChangeGateDecision | None = None
    approval_requirement: PatchApprovalRequirement | None = None

    @property
    def applied(self) -> bool:
        return self.apply_outcome == GuardedPatchApplyOutcome.APPLIED

    @property
    def pending_approval(self) -> bool:
        return self.apply_outcome == GuardedPatchApplyOutcome.PENDING_APPROVAL

    @property
    def audit_summary(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "apply_outcome": self.apply_outcome.value,
            "applied": self.applied,
            "pending_approval": self.pending_approval,
            "blocked_reason": self.blocked_reason,
            "artifact_id": self.artifact_id,
            "approval_id": (
                self.approval_request.approval_id if self.approval_request is not None else None
            ),
            "safe_apply": (
                self.safe_apply_result.audit_summary if self.safe_apply_result is not None else None
            ),
            "gate": (self.gate_decision.audit_summary if self.gate_decision is not None else None),
            "approval_requirement": (
                self.approval_requirement.audit_summary
                if self.approval_requirement is not None
                else None
            ),
        }


def finalize_guarded_patch(
    request: GuardedPatchFinalizationRequest,
) -> GuardedPatchFinalizationResult:
    """Make one authoritative block, approval, or trusted-apply decision."""
    current_status = _normalize_current_status(request.current_status)

    if request.command_timed_out or current_status == GuardedPatchFinalStatus.TIMED_OUT:
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.TIMED_OUT,
            apply_outcome=(GuardedPatchApplyOutcome.NOT_APPLIED),
            blocked_reason=("Timed-out commands never apply generated changes."),
        )

    if (
        request.command_exit_code not in (None, 0)
        or current_status == GuardedPatchFinalStatus.FAILED
    ):
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.FAILED,
            apply_outcome=(GuardedPatchApplyOutcome.NOT_APPLIED),
            blocked_reason=("Failed commands never apply generated changes."),
        )

    if current_status == GuardedPatchFinalStatus.BLOCKED:
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.BLOCKED,
            apply_outcome=(GuardedPatchApplyOutcome.NOT_APPLIED),
            blocked_reason=("Blocked guarded runs never apply generated changes."),
        )

    intent = request.intent_fallback_evaluation

    if intent is not None and intent.should_block:
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.BLOCKED,
            apply_outcome=(GuardedPatchApplyOutcome.NOT_APPLIED),
            blocked_reason=(
                "Intent enforcement blocked the generated action: "
                f"match_state={intent.match_state.value}; "
                f"reasons={','.join(intent.reason_codes)}"
            ),
        )

    patch_diff = request.patch_diff

    if patch_diff is None or patch_diff.changed_file_count == 0:
        if intent is not None and intent.requires_approval:
            return GuardedPatchFinalizationResult(
                status=(GuardedPatchFinalStatus.APPROVAL_REQUIRED),
                apply_outcome=(GuardedPatchApplyOutcome.NOT_GENERATED),
                blocked_reason=(
                    "Intent enforcement requires human review: "
                    f"match_state={intent.match_state.value}; "
                    f"reasons={','.join(intent.reason_codes)}"
                ),
            )

        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.COMPLETED,
            apply_outcome=(GuardedPatchApplyOutcome.NOT_GENERATED),
        )

    risk_report = request.risk_report

    if risk_report is None:
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.FAILED,
            apply_outcome=(GuardedPatchApplyOutcome.APPLY_FAILED),
            blocked_reason=(
                "Generated patch had no verified risk report; trusted mutation failed closed."
            ),
        )

    try:
        gate = evaluate_guarded_change_gate(
            patch_diff,
            risk_report=risk_report,
        )
        requirement = evaluate_patch_approval_requirement(
            patch_diff,
            risk_report=risk_report,
            gate_decision=gate,
        )
    except Exception as exc:
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.FAILED,
            apply_outcome=(GuardedPatchApplyOutcome.APPLY_FAILED),
            blocked_reason=(f"Patch decision evaluation failed closed: {exc}"),
        )

    if gate.blocked or risk_report.overall_risk_level == RiskLevel.CRITICAL:
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.BLOCKED,
            apply_outcome=(GuardedPatchApplyOutcome.NOT_APPLIED),
            blocked_reason=(
                "Generated patch blocked before trusted mutation: "
                "critical risk or a dangerous change was detected."
            ),
            gate_decision=gate,
            approval_requirement=requirement,
        )

    intent_requires_approval = bool(intent is not None and intent.requires_approval)

    if requirement.required or intent_requires_approval:
        return _persist_pending_approval(
            request=request,
            patch_diff=patch_diff,
            risk_report=risk_report,
            gate_decision=gate,
            requirement=requirement,
            forced_reason=(
                "Intent enforcement requires approval before trusted apply."
                if (intent_requires_approval and not requirement.required)
                else None
            ),
            forced_policy_id=(
                "guarded-workspace-intent-approval"
                if (intent_requires_approval and not requirement.required)
                else None
            ),
        )

    try:
        safe_apply = auto_apply_safe_patch(
            patch_diff,
            request.trusted_repo_path,
            risk_report=risk_report,
            gate_decision=gate,
            logger=request.audit_logger,
            user_id=request.user_id,
            agent_id=request.agent_id,
            environment=request.environment,
            trace_id=request.trace_id,
        )
    except SafePatchApplyError as exc:
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.FAILED,
            apply_outcome=(GuardedPatchApplyOutcome.APPLY_FAILED),
            blocked_reason=(f"Automatic trusted apply failed closed: {exc}"),
            gate_decision=gate,
            approval_requirement=requirement,
        )
    except Exception as exc:
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.FAILED,
            apply_outcome=(GuardedPatchApplyOutcome.APPLY_FAILED),
            blocked_reason=(f"Unexpected automatic apply failure: {exc}"),
            gate_decision=gate,
            approval_requirement=requirement,
        )

    if safe_apply.outcome == SafePatchApplyOutcome.APPLIED:
        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.COMPLETED,
            apply_outcome=GuardedPatchApplyOutcome.APPLIED,
            safe_apply_result=safe_apply,
            gate_decision=gate,
            approval_requirement=requirement,
        )

    skip_codes = (
        ", ".join(reason.code for reason in safe_apply.skip_reasons)
        or "unspecified-safe-apply-skip"
    )

    return _persist_pending_approval(
        request=request,
        patch_diff=patch_diff,
        risk_report=risk_report,
        gate_decision=gate,
        requirement=requirement,
        forced_reason=(
            "Patch passed the final block decision but is "
            "not eligible for automatic apply "
            f"({skip_codes}); explicit approval is required."
        ),
        forced_policy_id=("guarded-workspace-non-auto-apply-approval"),
        safe_apply_result=safe_apply,
    )


def _persist_pending_approval(
    *,
    request: GuardedPatchFinalizationRequest,
    patch_diff: PatchDiff,
    risk_report: ChangeRiskReport,
    gate_decision: GuardedChangeGateDecision,
    requirement: PatchApprovalRequirement,
    forced_reason: str | None,
    forced_policy_id: str | None,
    safe_apply_result: SafePatchApplyResult | None = None,
) -> GuardedPatchFinalizationResult:
    artifact: PatchArtifact | None = None
    store: PatchArtifactStore | None = None

    try:
        store = PatchArtifactStore(Path(request.run_root).expanduser().resolve() / "artifacts")

        if requirement.required and forced_reason is None:
            approval_request = create_patch_approval_request(
                patch_diff,
                requested_by=request.user_id,
                agent_id=request.agent_id,
                environment=request.environment,
                risk_report=risk_report,
                gate_decision=gate_decision,
                trace_id=request.trace_id,
            )
        else:
            approval_request = _forced_approval_request(
                request=request,
                patch_diff=patch_diff,
                risk_report=risk_report,
                requirement=requirement,
                reason=(forced_reason or ("Explicit approval is required before trusted apply.")),
                policy_id=(forced_policy_id or ("guarded-workspace-explicit-approval")),
            )

        artifact = store.persist(
            patch_diff=patch_diff,
            run_id=request.run_id,
            trace_id=request.trace_id,
            approval_request=approval_request,
            trusted_repo_path=(request.trusted_repo_path),
            risk_report=risk_report,
            intent_summary=_intent_summary(request),
        )

        approval_request = bind_artifact_to_approval(
            approval_request,
            artifact,
        )

        if request.approval_queue is not None:
            request.approval_queue.submit(approval_request)

    except Exception as exc:
        if artifact is not None and store is not None:
            try:
                store.delete(artifact.artifact_id)
            except PatchArtifactError:
                pass

        return GuardedPatchFinalizationResult(
            status=GuardedPatchFinalStatus.FAILED,
            apply_outcome=(GuardedPatchApplyOutcome.APPLY_FAILED),
            blocked_reason=(f"Pending approval persistence failed closed: {exc}"),
            safe_apply_result=safe_apply_result,
            gate_decision=gate_decision,
            approval_requirement=requirement,
        )

    return GuardedPatchFinalizationResult(
        status=(GuardedPatchFinalStatus.APPROVAL_REQUIRED),
        apply_outcome=(GuardedPatchApplyOutcome.PENDING_APPROVAL),
        blocked_reason=approval_request.reason,
        approval_request=approval_request,
        artifact_id=artifact.artifact_id,
        safe_apply_result=safe_apply_result,
        gate_decision=gate_decision,
        approval_requirement=requirement,
    )


def _forced_approval_request(
    *,
    request: GuardedPatchFinalizationRequest,
    patch_diff: PatchDiff,
    risk_report: ChangeRiskReport,
    requirement: PatchApprovalRequirement,
    reason: str,
    policy_id: str,
) -> ApprovalRequest:
    return ApprovalRequest(
        requested_by=request.user_id,
        agent_id=request.agent_id,
        environment=request.environment,
        trace_id=request.trace_id,
        tool_name="guarded_workspace",
        action="approve_patch_apply",
        target=patch_diff.patch_sha256,
        policy_id=policy_id,
        reason=reason,
        severity=_severity_for_risk(risk_report.overall_risk_level),
        risk_assessment={
            "requirement": (requirement.audit_summary),
            "risk_report": (risk_report.audit_summary),
            "forced_approval": True,
        },
        metadata={
            "patch_sha256": patch_diff.patch_sha256,
            "baseline_commit_sha": (patch_diff.baseline_commit_sha),
            "patch_size_bytes": (patch_diff.patch_size_bytes),
            "changed_file_count": (patch_diff.changed_file_count),
            "files": tuple(file.path for file in patch_diff.files),
            "forced_approval": True,
        },
    )


def _intent_summary(
    request: GuardedPatchFinalizationRequest,
) -> dict[str, object]:
    summary: dict[str, object] = {}

    if request.intent_fallback_evaluation is not None:
        evaluation = request.intent_fallback_evaluation

        summary["match_state"] = evaluation.match_state.value
        summary["recommended_hint"] = evaluation.recommended_hint.value
        summary["effective_hint"] = evaluation.effective_hint.value
        summary["should_block"] = evaluation.should_block
        summary["requires_approval"] = evaluation.requires_approval
        summary["reason_codes"] = evaluation.reason_codes

    if request.intent_decision_receipt is not None:
        summary["receipt"] = request.intent_decision_receipt.audit_summary

    return summary


def _normalize_current_status(
    value: str,
) -> GuardedPatchFinalStatus:
    try:
        return GuardedPatchFinalStatus(str(value))
    except ValueError:
        return GuardedPatchFinalStatus.FAILED


def _severity_for_risk(
    risk_level: RiskLevel,
) -> Severity:
    if risk_level == RiskLevel.CRITICAL:
        return Severity.CRITICAL

    if risk_level == RiskLevel.HIGH:
        return Severity.HIGH

    if risk_level == RiskLevel.MEDIUM:
        return Severity.MEDIUM

    return Severity.LOW


__all__ = [
    "ApprovalQueueWriter",
    "GuardedPatchApplyOutcome",
    "GuardedPatchFinalStatus",
    "GuardedPatchFinalizationRequest",
    "GuardedPatchFinalizationResult",
    "finalize_guarded_patch",
]
