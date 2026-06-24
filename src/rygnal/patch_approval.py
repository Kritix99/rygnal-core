"""Approval boundary for risky guarded workspace patches."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cached_property
from typing import Any

from rygnal.approval_receipt import (
    ApprovalReceiptError,
    assert_approval_receipt_valid,
    attach_approval_receipt,
)
from rygnal.approval_state import ApprovalStateMachine
from rygnal.audit_logger import AuditLogger
from rygnal.change_gate import GuardedChangeGateDecision, evaluate_guarded_change_gate
from rygnal.change_risk import ChangeRiskReport, FileRiskClassification, classify_patch_risk
from rygnal.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    Decision,
    PolicyDecision,
    Severity,
    ToolRequest,
    new_trace_id,
    utc_now_iso,
)
from rygnal.patch_diff import PatchDiff
from rygnal.path_safety import PathSafetyError, ensure_patch_path_forms_safe
from rygnal.risk_engine import RiskLevel
from rygnal.security import redact_sensitive_value


class PatchApprovalError(RuntimeError):
    """Raised when patch approval state is invalid."""


DEFAULT_PATCH_APPROVAL_TTL_SECONDS = 60 * 60


@dataclass(frozen=True)
class PatchApprovalReason:
    code: str
    reason: str
    path: str | None = None
    risk_level: RiskLevel | None = None

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "code": self.code,
            "reason": self.reason,
            "path": self.path,
            "risk_level": self.risk_level.value if self.risk_level else None,
        }


@dataclass(frozen=True)
class PatchApprovalRequirement:
    required: bool
    reasons: tuple[PatchApprovalReason, ...]
    risk_report: ChangeRiskReport
    gate_decision: GuardedChangeGateDecision

    @cached_property
    def audit_summary(self) -> dict[str, object]:
        return {
            "required": self.required,
            "reasons": tuple(reason.audit_summary for reason in self.reasons),
            "blocked": self.gate_decision.blocked,
            "overall_risk_level": self.risk_report.overall_risk_level.value,
            "risk_counts": self.risk_report.risk_counts,
        }


def evaluate_patch_approval_requirement(
    patch_diff: PatchDiff,
    *,
    risk_report: ChangeRiskReport | None = None,
    gate_decision: GuardedChangeGateDecision | None = None,
) -> PatchApprovalRequirement:
    report = risk_report or classify_patch_risk(patch_diff)
    gate = gate_decision or evaluate_guarded_change_gate(patch_diff, risk_report=report)

    if gate.blocked:
        return PatchApprovalRequirement(
            required=False,
            reasons=(),
            risk_report=report,
            gate_decision=gate,
        )

    reasons = _approval_reasons(patch_diff, report)

    return PatchApprovalRequirement(
        required=bool(reasons),
        reasons=reasons,
        risk_report=report,
        gate_decision=gate,
    )


def requires_patch_approval(
    patch_diff: PatchDiff,
    *,
    risk_report: ChangeRiskReport | None = None,
    gate_decision: GuardedChangeGateDecision | None = None,
) -> bool:
    return evaluate_patch_approval_requirement(
        patch_diff,
        risk_report=risk_report,
        gate_decision=gate_decision,
    ).required


def create_patch_approval_request(
    patch_diff: PatchDiff,
    *,
    requested_by: str,
    agent_id: str = "demo_agent",
    environment: str = "local",
    risk_report: ChangeRiskReport | None = None,
    gate_decision: GuardedChangeGateDecision | None = None,
    trace_id: str | None = None,
) -> ApprovalRequest:
    try:
        ensure_patch_path_forms_safe(patch_diff)
    except PathSafetyError as exc:
        raise PatchApprovalError(str(exc)) from exc

    requirement = evaluate_patch_approval_requirement(
        patch_diff,
        risk_report=risk_report,
        gate_decision=gate_decision,
    )

    if requirement.gate_decision.blocked:
        raise PatchApprovalError("Blocked patches cannot be approved.")

    if not requirement.required:
        raise PatchApprovalError("Patch does not require approval.")

    return ApprovalRequest(
        requested_by=requested_by,
        agent_id=agent_id,
        environment=environment,
        trace_id=trace_id or new_trace_id(),
        tool_name="guarded_workspace",
        action="approve_patch_apply",
        target=patch_diff.patch_sha256,
        policy_id="guarded-workspace-risky-patch-approval",
        reason="Risky guarded workspace patch requires approval before apply.",
        severity=_severity_from_risk_level(requirement.risk_report.overall_risk_level),
        risk_assessment={
            "requirement": requirement.audit_summary,
            "risk_report": requirement.risk_report.audit_summary,
        },
        metadata={
            "patch_sha256": patch_diff.patch_sha256,
            "baseline_commit_sha": patch_diff.baseline_commit_sha,
            "patch_size_bytes": patch_diff.patch_size_bytes,
            "changed_file_count": patch_diff.changed_file_count,
            "files": tuple(file.path for file in patch_diff.files),
        },
    )


def approve_patch_request(
    approval_request: ApprovalRequest,
    *,
    decided_by: str,
    reason: str = "Approved risky guarded workspace patch.",
    patch_sha256: str | None = None,
) -> ApprovalDecision:
    _validate_decision_context(approval_request, patch_sha256=patch_sha256)

    decision = ApprovalDecision(
        approval_id=approval_request.approval_id,
        status=ApprovalStatus.APPROVED,
        approved=True,
        decided_by=decided_by,
        decided_at=utc_now_iso(),
        reason=str(redact_sensitive_value(reason)),
        metadata=_decision_binding_metadata(approval_request),
    )

    return attach_approval_receipt(approval_request, decision)


def reject_patch_request(
    approval_request: ApprovalRequest,
    *,
    decided_by: str,
    reason: str = "Rejected risky guarded workspace patch.",
    patch_sha256: str | None = None,
) -> ApprovalDecision:
    _validate_decision_context(approval_request, patch_sha256=patch_sha256)

    return ApprovalDecision(
        approval_id=approval_request.approval_id,
        status=ApprovalStatus.REJECTED,
        approved=False,
        decided_by=decided_by,
        decided_at=utc_now_iso(),
        reason=str(redact_sensitive_value(reason)),
        metadata=_decision_binding_metadata(approval_request),
    )


def assert_patch_approval_granted(
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
    patch_diff: PatchDiff,
    *,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_PATCH_APPROVAL_TTL_SECONDS,
) -> None:
    transition = ApprovalStateMachine.validate_transition(
        current_status=ApprovalStatus.PENDING,
        next_status=approval_decision.status,
    )
    if not transition.allowed:
        raise PatchApprovalError(transition.reason)

    if approval_request.approval_id != approval_decision.approval_id:
        raise PatchApprovalError("Approval decision does not match request.")

    if approval_request.target != patch_diff.patch_sha256:
        raise PatchApprovalError("Approval request is not bound to this patch digest.")

    if approval_decision.metadata.get("patch_sha256") != patch_diff.patch_sha256:
        raise PatchApprovalError("Approval decision is not bound to this patch digest.")

    request_baseline = approval_request.metadata.get("baseline_commit_sha")
    if request_baseline != patch_diff.baseline_commit_sha:
        raise PatchApprovalError("Approval request baseline does not match guarded patch.")

    decision_baseline = approval_decision.metadata.get("baseline_commit_sha")
    if decision_baseline != patch_diff.baseline_commit_sha:
        raise PatchApprovalError("Approval decision baseline does not match guarded patch.")

    _ensure_patch_approval_not_expired(
        approval_request,
        approval_decision,
        now=now,
        ttl_seconds=ttl_seconds,
    )

    if approval_decision.status != ApprovalStatus.APPROVED or not approval_decision.approved:
        raise PatchApprovalError("Patch approval was not granted.")

    try:
        assert_approval_receipt_valid(approval_request, approval_decision)
    except ApprovalReceiptError as exc:
        raise PatchApprovalError(str(exc)) from exc


def write_patch_approval_request_audit_event(
    logger: AuditLogger,
    approval_request: ApprovalRequest,
) -> Any:
    request = _tool_request_from_approval_request(
        approval_request,
        action="approval_requested",
        input_payload=approval_request.model_dump(mode="json"),
    )
    decision = PolicyDecision(
        decision=Decision.REQUIRE_APPROVAL,
        allowed=False,
        severity=approval_request.severity,
        reason=approval_request.reason,
        policy_id=approval_request.policy_id,
    )

    return logger.log_decision(
        request,
        decision,
        metadata={"approval_request": approval_request.model_dump(mode="json")},
    )


def write_patch_approval_decision_audit_event(
    logger: AuditLogger,
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
) -> Any:
    request = _tool_request_from_approval_request(
        approval_request,
        action="approval_decided",
        input_payload={
            "approval_request": approval_request.model_dump(mode="json"),
            "approval_decision": approval_decision.model_dump(mode="json"),
        },
    )
    decision = PolicyDecision(
        decision=Decision.ALLOW if approval_decision.approved else Decision.BLOCK,
        allowed=approval_decision.approved,
        severity=approval_request.severity,
        reason=approval_decision.reason,
        policy_id=approval_request.policy_id,
    )

    return logger.log_decision(
        request,
        decision,
        metadata={
            "approval_request": approval_request.model_dump(mode="json"),
            "approval_decision": approval_decision.model_dump(mode="json"),
        },
    )


def _approval_reasons(
    patch_diff: PatchDiff,
    risk_report: ChangeRiskReport,
) -> tuple[PatchApprovalReason, ...]:
    reasons: list[PatchApprovalReason] = []

    if patch_diff.ignored_file_count:
        reasons.append(
            PatchApprovalReason(
                code="ignored-workspace-changes",
                reason="Workspace contains ignored changes outside the reviewable patch.",
            )
        )

    if risk_report.overall_risk_level != RiskLevel.LOW:
        reasons.append(
            PatchApprovalReason(
                code="overall-risk",
                reason="Patch risk is above the safe auto-apply threshold.",
                risk_level=risk_report.overall_risk_level,
            )
        )

    for report_reason in risk_report.report_reasons:
        if report_reason.risk_level in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}:
            reasons.append(
                PatchApprovalReason(
                    code=report_reason.code,
                    reason=report_reason.reason,
                    risk_level=report_reason.risk_level,
                )
            )

    for file_risk in risk_report.files:
        reasons.extend(_file_approval_reasons(file_risk))

    return _dedupe_reasons(reasons)


def _file_approval_reasons(
    file_risk: FileRiskClassification,
) -> tuple[PatchApprovalReason, ...]:
    reasons: list[PatchApprovalReason] = []

    if not _is_low_risk_docs_or_tests(file_risk):
        reasons.append(
            PatchApprovalReason(
                code="not-safe-auto-apply-file",
                reason="Changed file is not eligible for safe auto-apply.",
                path=file_risk.path,
                risk_level=file_risk.risk_level,
            )
        )

    for risk_reason in file_risk.reasons:
        if risk_reason.risk_level in {RiskLevel.MEDIUM, RiskLevel.HIGH}:
            reasons.append(
                PatchApprovalReason(
                    code=risk_reason.code,
                    reason=risk_reason.reason,
                    path=file_risk.path,
                    risk_level=risk_reason.risk_level,
                )
            )

    return tuple(reasons)


def _is_low_risk_docs_or_tests(file_risk: FileRiskClassification) -> bool:
    if file_risk.risk_level != RiskLevel.LOW:
        return False

    reason_codes = {reason.code for reason in file_risk.reasons}
    return bool(reason_codes) and reason_codes <= {"documentation-change", "test-change"}


def _decision_binding_metadata(approval_request: ApprovalRequest) -> dict[str, Any]:
    metadata: dict[str, Any] = {"patch_sha256": approval_request.target}

    baseline_commit_sha = approval_request.metadata.get("baseline_commit_sha")
    if isinstance(baseline_commit_sha, str) and baseline_commit_sha.strip():
        metadata["baseline_commit_sha"] = baseline_commit_sha

    return metadata


def _ensure_patch_approval_not_expired(
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
    *,
    now: datetime | None,
    ttl_seconds: int,
) -> None:
    if ttl_seconds <= 0:
        raise PatchApprovalError("Patch approval TTL must be positive.")

    created_at = _parse_approval_timestamp(
        approval_request.created_at,
        field_name="approval request creation time",
    )

    if approval_decision.decided_at is None:
        raise PatchApprovalError("Approval decision time is required.")

    decided_at = _parse_approval_timestamp(
        approval_decision.decided_at,
        field_name="approval decision time",
    )
    current_time = (now or datetime.now(UTC)).astimezone(UTC)

    if decided_at < created_at:
        raise PatchApprovalError("Approval decision predates approval request.")

    if created_at > current_time:
        raise PatchApprovalError("Approval request creation time is in the future.")

    if decided_at > current_time:
        raise PatchApprovalError("Approval decision time is in the future.")

    if (current_time - created_at).total_seconds() > ttl_seconds:
        raise PatchApprovalError("Patch approval is stale or expired.")


def _parse_approval_timestamp(value: str, *, field_name: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise PatchApprovalError(f"Invalid {field_name}.") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def _validate_decision_context(
    approval_request: ApprovalRequest,
    *,
    patch_sha256: str | None,
) -> None:
    if patch_sha256 is not None and approval_request.target != patch_sha256:
        raise PatchApprovalError("Approval request patch digest mismatch.")


def _tool_request_from_approval_request(
    approval_request: ApprovalRequest,
    *,
    action: str,
    input_payload: dict[str, Any],
) -> ToolRequest:
    return ToolRequest(
        tool_name=approval_request.tool_name,
        action=action,
        target=str(approval_request.target),
        input=input_payload,
        user_id=approval_request.requested_by,
        agent_id=approval_request.agent_id,
        environment=approval_request.environment,
        metadata={
            "trace_id": approval_request.trace_id,
            "event_type": f"guarded_workspace.{action}",
            "approval_id": approval_request.approval_id,
            "patch_sha256": approval_request.target,
        },
    )


def _severity_from_risk_level(risk_level: RiskLevel) -> Severity:
    if risk_level == RiskLevel.CRITICAL:
        return Severity.CRITICAL
    if risk_level == RiskLevel.HIGH:
        return Severity.HIGH
    if risk_level == RiskLevel.MEDIUM:
        return Severity.MEDIUM

    return Severity.LOW


def _dedupe_reasons(
    reasons: list[PatchApprovalReason],
) -> tuple[PatchApprovalReason, ...]:
    seen: set[tuple[str, str | None]] = set()
    deduped: list[PatchApprovalReason] = []

    for reason in reasons:
        key = (reason.code, reason.path)
        if key in seen:
            continue

        seen.add(key)
        deduped.append(reason)

    return tuple(deduped)


__all__ = [
    "PatchApprovalError",
    "PatchApprovalReason",
    "PatchApprovalRequirement",
    "approve_patch_request",
    "assert_patch_approval_granted",
    "create_patch_approval_request",
    "evaluate_patch_approval_requirement",
    "reject_patch_request",
    "requires_patch_approval",
    "write_patch_approval_decision_audit_event",
    "write_patch_approval_request_audit_event",
]
