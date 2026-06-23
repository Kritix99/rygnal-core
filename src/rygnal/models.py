"""Shared data models for Rygnal."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from rygnal.version import package_version


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def new_event_id() -> str:
    """Return a unique audit event ID."""
    return f"evt_{uuid4().hex}"


def new_trace_id() -> str:
    """Return a unique trace ID."""
    return f"trace_{uuid4().hex}"


def new_approval_id() -> str:
    """Return a unique approval request ID."""
    return f"apr_{uuid4().hex}"


class Decision(StrEnum):
    """Possible policy decisions."""

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    SIMULATE = "simulate"


class Severity(StrEnum):
    """Risk severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStatus(StrEnum):
    """Tool execution status."""

    EXECUTED = "executed"
    SKIPPED = "skipped"
    FAILED = "failed"
    SIMULATED = "simulated"


class ApprovalStatus(StrEnum):
    """Approval lifecycle status."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class RuntimeMode(StrEnum):
    """Rygnal execution runtime modes."""

    OBSERVE = "observe"
    SIMULATE = "simulate"
    ENFORCE = "enforce"
    PRODUCTION_SAFE = "production_safe"


class RolePermission(BaseModel):
    """Operator-configured approval permissions for a reviewer role."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str = Field(min_length=1)
    allowed_severities: list[Severity] = Field(min_length=1)
    allowed_actions: list[str] | None = None
    environments: list[str] | None = None

    @field_validator("role")
    @classmethod
    def _reject_blank_role(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Role must not be blank.")

        return value

    @field_validator("allowed_actions", "environments")
    @classmethod
    def _reject_empty_or_blank_string_lists(
        cls,
        value: list[str] | None,
    ) -> list[str] | None:
        if value is None:
            return value

        if not value:
            raise ValueError("Role permission lists must not be empty.")

        if any(not item.strip() for item in value):
            raise ValueError("Role permission list values must not be blank.")

        return value


class ToolRequest(BaseModel):
    """A tool action requested by an AI agent."""

    tool_name: str
    action: str | None = None
    target: str | None = None
    input: Any | None = None
    user_id: str = "demo_user"
    agent_id: str = "demo_agent"
    environment: str = "local"
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyRule(BaseModel):
    """A single policy rule."""

    model_config = ConfigDict(extra="forbid")

    id: str
    decision: Decision
    severity: Severity = Severity.LOW
    reason: str
    priority: int = Field(default=100, ge=0, le=1000)

    tool_name: str | None = None
    action: str | None = None
    environment: str | None = None
    target_equals: str | None = None
    target_contains: str | None = None
    target_matches: str | None = None
    target_not_matches: str | None = None
    input_equals: Any | None = None
    input_contains: str | None = None
    metadata_equals: dict[str, Any] = Field(default_factory=dict)
    metadata_contains: dict[str, str] = Field(default_factory=dict)
    risk_level: str | None = None
    risk_score_min: float | None = None


class PolicySchema(BaseModel):
    """Validated policy file schema.

    Policy files must declare fallback behavior explicitly so Rygnal does not
    rely on hidden policy defaults during rule no-match cases.
    """

    model_config = ConfigDict(extra="forbid")

    policy_version: str = "policy.v1"
    default_decision: Decision
    rules: list[PolicyRule] = Field(default_factory=list)


class PolicyExplanation(BaseModel):
    """Explain why a policy decision was produced."""

    policy_version: str
    matched: bool
    matched_rule_id: str | None = None
    matched_rule_priority: int | None = None
    matched_conditions: list[str] = Field(default_factory=list)
    evaluated_rule_ids: list[str] = Field(default_factory=list)
    default_decision: bool = False


class PolicyDecision(BaseModel):
    """Policy evaluation result."""

    decision: Decision
    allowed: bool
    severity: Severity
    reason: str
    policy_id: str | None = None
    explanation: PolicyExplanation | None = None


class ApprovalRequest(BaseModel):
    """Approval request created for human-reviewed actions."""

    model_config = ConfigDict(frozen=True)

    approval_id: str = Field(default_factory=new_approval_id, min_length=1)
    created_at: str = Field(default_factory=utc_now_iso, min_length=1)
    trace_id: str = Field(default_factory=new_trace_id, min_length=1)

    requested_by: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)

    tool_name: str = Field(min_length=1)
    action: str | None = None
    target: Any | None = None
    policy_id: str | None = None
    reason: str = Field(min_length=1)
    severity: Severity = Severity.LOW
    risk_assessment: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "approval_id",
        "created_at",
        "trace_id",
        "requested_by",
        "agent_id",
        "environment",
        "tool_name",
        "reason",
    )
    @classmethod
    def _reject_blank_context(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Approval request context fields must not be blank.")

        return value


class ApprovalDecision(BaseModel):
    """Human approval result."""

    approval_id: str
    status: ApprovalStatus
    approved: bool
    decided_by: str | None = None
    decided_at: str | None = None
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    """Tamper-evident audit event for an AI-agent tool decision."""

    schema_version: str = "audit.v1"
    rygnal_engine_version: str = Field(default_factory=package_version, min_length=1)
    event_id: str = Field(default_factory=new_event_id)
    timestamp: str = Field(default_factory=utc_now_iso)
    trace_id: str = Field(default_factory=new_trace_id)

    user_id: str
    agent_id: str
    environment: str

    tool_name: str
    action: str | None = None
    target: Any | None = None
    input: Any | None = None

    decision: Decision
    allowed: bool
    severity: Severity
    policy_id: str | None = None
    reason: str

    metadata: dict[str, Any] = Field(default_factory=dict)
    prev_event_hash: str | None = None
    event_hash: str | None = None


class ToolExecutionResult(BaseModel):
    """Result of a tool execution attempt."""

    status: ExecutionStatus
    executed: bool
    output: Any | None = None
    error: str | None = None


class InterceptorResult(BaseModel):
    """Final result returned by the Rygnal interceptor."""

    request: ToolRequest
    risk_assessment: dict[str, Any]
    policy_decision: PolicyDecision
    audit_event: AuditEvent
    execution: ToolExecutionResult
    approval_decision: ApprovalDecision | None = None
