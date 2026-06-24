"""Approval workflow for Rygnal.

Approval Workflow v1 handles actions that require human approval before execution.
"""

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from rygnal.approval_authorization import (
    ApprovalAuthorizationEngine,
    ApprovalAuthorizationResult,
    ApprovalReviewerPermission,
)
from rygnal.approval_receipt import attach_approval_receipt
from rygnal.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    PolicyDecision,
    RolePermission,
    ToolRequest,
    new_trace_id,
    utc_now_iso,
)
from rygnal.roles import load_roles_file
from rygnal.security import redact_sensitive_value

ApprovalResolver = Callable[[ApprovalRequest], ApprovalDecision]

DENIED_APPROVER_ROLES = frozenset({"viewer"})


class ApprovalWorkflow:
    """Create approval requests and resolve approve/reject decisions."""

    def __init__(
        self,
        resolver: ApprovalResolver | None = None,
        reviewer_roles: Mapping[str, str] | None = None,
        reviewer_permissions: Mapping[str, ApprovalReviewerPermission] | None = None,
        role_permissions: Mapping[str, RolePermission] | None = None,
        authorization_engine: ApprovalAuthorizationEngine | None = None,
    ) -> None:
        self.resolver = resolver or reject_by_default
        self.authorization_engine = authorization_engine or ApprovalAuthorizationEngine(
            reviewer_permissions=_build_reviewer_permissions(
                reviewer_roles=reviewer_roles,
                reviewer_permissions=reviewer_permissions,
            ),
            role_permissions=role_permissions,
        )

    @classmethod
    def from_roles_file(
        cls,
        *,
        roles_path: str | Path,
        resolver: ApprovalResolver | None = None,
    ) -> "ApprovalWorkflow":
        """Build an approval workflow backed by operator-managed roles.yaml."""
        return cls(
            resolver=resolver,
            role_permissions=load_roles_file(roles_path),
        )

    def request_approval(
        self,
        request: ToolRequest,
        policy_decision: PolicyDecision,
        risk_assessment: dict[str, Any] | None = None,
    ) -> tuple[ApprovalRequest, ApprovalDecision]:
        """Create an approval request and return the authorized approval decision."""
        approval_request = ApprovalRequest(
            trace_id=str(request.metadata.get("trace_id") or new_trace_id()),
            requested_by=request.user_id,
            agent_id=request.agent_id,
            environment=request.environment,
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            policy_id=policy_decision.policy_id,
            reason=policy_decision.reason,
            severity=policy_decision.severity,
            risk_assessment=_redacted_mapping(risk_assessment),
            metadata=_redacted_mapping(request.metadata),
        )

        approval_decision = self.resolver(approval_request)

        if approval_decision.approval_id != approval_request.approval_id:
            raise ValueError("Approval decision ID does not match approval request ID.")

        authorization_result = self.authorization_engine.authorize(
            approval_request=approval_request,
            approval_decision=approval_decision,
        )

        authorized_decision = _apply_authorization_result(
            approval_decision=approval_decision,
            authorization_result=authorization_result,
        )

        return approval_request, attach_approval_receipt(
            approval_request,
            authorized_decision,
        )


def reject_by_default(approval_request: ApprovalRequest) -> ApprovalDecision:
    """Safe default resolver when no human approval system is configured."""
    return ApprovalDecision(
        approval_id=approval_request.approval_id,
        status=ApprovalStatus.REJECTED,
        approved=False,
        decided_by="system",
        decided_at=utc_now_iso(),
        reason="Approval workflow is not configured. Request rejected by default.",
    )


def approve_for_testing(
    approval_request: ApprovalRequest,
    decided_by: str = "test_reviewer",
    reason: str = "Approved for controlled test execution.",
) -> ApprovalDecision:
    """Approve an action for deterministic tests or controlled local workflows."""
    return ApprovalDecision(
        approval_id=approval_request.approval_id,
        status=ApprovalStatus.APPROVED,
        approved=True,
        decided_by=decided_by,
        decided_at=utc_now_iso(),
        reason=reason,
    )


def reject_for_testing(
    approval_request: ApprovalRequest,
    decided_by: str = "test_reviewer",
    reason: str = "Rejected for controlled test execution.",
) -> ApprovalDecision:
    """Reject an action for deterministic tests or controlled local workflows."""
    return ApprovalDecision(
        approval_id=approval_request.approval_id,
        status=ApprovalStatus.REJECTED,
        approved=False,
        decided_by=decided_by,
        decided_at=utc_now_iso(),
        reason=reason,
    )


def _apply_authorization_result(
    *,
    approval_decision: ApprovalDecision,
    authorization_result: ApprovalAuthorizationResult,
) -> ApprovalDecision:
    """Apply authorization result to an approval decision without mutating it."""
    metadata = {
        **approval_decision.metadata,
        **authorization_result.metadata,
    }

    if authorization_result.allowed:
        return approval_decision.model_copy(update={"metadata": metadata})

    return ApprovalDecision(
        approval_id=approval_decision.approval_id,
        status=ApprovalStatus.REJECTED,
        approved=False,
        decided_by="system",
        decided_at=utc_now_iso(),
        reason=authorization_result.reason,
        metadata=metadata,
    )


def _build_reviewer_permissions(
    *,
    reviewer_roles: Mapping[str, str] | None,
    reviewer_permissions: Mapping[str, ApprovalReviewerPermission] | None,
) -> dict[str, ApprovalReviewerPermission]:
    """Build reviewer permissions from explicit permissions and legacy role mapping."""
    permissions = dict(reviewer_permissions or {})

    for reviewer, role in dict(reviewer_roles or {}).items():
        normalized_role = role.strip().lower()
        permissions[reviewer] = ApprovalReviewerPermission(
            role=role,
            can_approve=normalized_role not in DENIED_APPROVER_ROLES,
        )

    return permissions


def _redacted_mapping(value: dict[str, Any] | None) -> dict[str, Any]:
    """Return a safely redacted metadata mapping for approval context."""
    redacted_value = redact_sensitive_value(value or {})

    if not isinstance(redacted_value, dict):
        return {}

    return redacted_value
