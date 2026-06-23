"""Rygnal interceptor.

The interceptor is the runtime control point between AI agents and tools.
"""

from typing import Any

from rygnal.approval import ApprovalWorkflow
from rygnal.audit_logger import AuditLogger
from rygnal.models import (
    ApprovalDecision,
    AuditEvent,
    Decision,
    ExecutionStatus,
    InterceptorResult,
    PolicyDecision,
    PolicyExplanation,
    RuntimeMode,
    Severity,
    ToolExecutionResult,
    ToolRequest,
)
from rygnal.policy_engine import PolicyEngine
from rygnal.risk_engine import RiskEngine
from rygnal.security import redact_sensitive_value
from rygnal.tool_executor import ToolExecutor

GLOBAL_FAIL_CLOSED_POLICY_ID = "global-fail-closed"
GLOBAL_FAIL_CLOSED_POLICY_VERSION = "global-fail-closed.v1"
FAIL_CLOSED_RUNTIME_ERRORS = (RuntimeError, ValueError, OSError, LookupError)


class RygnalInterceptor:
    """Intercept AI-agent tool requests before execution."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        tool_executor: ToolExecutor,
        risk_engine: RiskEngine | None = None,
        approval_workflow: ApprovalWorkflow | None = None,
        runtime_mode: RuntimeMode | None = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.tool_executor = tool_executor
        self.risk_engine = risk_engine or RiskEngine()
        self.approval_workflow = approval_workflow
        self.runtime_mode = runtime_mode or RuntimeMode.ENFORCE

    def intercept(self, request: ToolRequest) -> InterceptorResult:
        """Assess risk, evaluate policy, audit, and optionally execute a tool request."""
        try:
            risk_assessment = self.risk_engine.assess(request)
        except FAIL_CLOSED_RUNTIME_ERRORS as exc:
            return self._fail_closed_result(
                request=request,
                reason_code="risk_assessment_failed",
                exc=exc,
            )

        risk_metadata = self._risk_metadata(risk_assessment)

        try:
            policy_decision = self.policy_engine.evaluate(
                request,
                risk_assessment=risk_assessment,
            )
        except FAIL_CLOSED_RUNTIME_ERRORS as exc:
            return self._fail_closed_result(
                request=request,
                reason_code="policy_evaluation_failed",
                exc=exc,
                risk_metadata=risk_metadata,
            )
        approval_decision: ApprovalDecision | None = None

        # Flatten risk metadata to top level for backward compatibility
        audit_metadata: dict[str, Any] = risk_metadata.copy()
        audit_metadata["runtime_mode"] = self.runtime_mode.value

        policy_explanation = self._policy_explanation_metadata(policy_decision)
        if policy_explanation:
            audit_metadata["policy_explanation"] = policy_explanation

        if policy_decision.decision == Decision.REQUIRE_APPROVAL:
            approval_workflow = self.approval_workflow or ApprovalWorkflow()
            try:
                approval_request, approval_decision = approval_workflow.request_approval(
                    request=request,
                    policy_decision=policy_decision,
                    risk_assessment=risk_metadata,
                )
            except FAIL_CLOSED_RUNTIME_ERRORS as exc:
                return self._fail_closed_result(
                    request=request,
                    reason_code="approval_workflow_failed",
                    exc=exc,
                    risk_metadata=risk_metadata,
                    extra_metadata={
                        "unconfirmed_pre_approval_decision": policy_decision.model_dump(
                            mode="json"
                        ),
                    },
                )
            audit_metadata["approval"] = {
                "approval_id": approval_request.approval_id,
                "status": approval_decision.status,
                "approved": approval_decision.approved,
                "decided_by": approval_decision.decided_by,
                "decided_at": approval_decision.decided_at,
                "reason": approval_decision.reason,
                "metadata": approval_decision.metadata,
            }

        audit_event = self.audit_logger.log_decision(
            request=request,
            policy_decision=policy_decision,
            metadata=audit_metadata,
        )

        execution = self._execute_with_decision(
            request=request,
            policy_decision=policy_decision,
            approval_decision=approval_decision,
        )

        return InterceptorResult(
            request=request,
            risk_assessment=risk_metadata,
            policy_decision=policy_decision,
            audit_event=audit_event,
            execution=execution,
            approval_decision=approval_decision,
        )

    def handle(self, request: ToolRequest) -> InterceptorResult:
        """Alias for intercept."""
        return self.intercept(request)

    def _fail_closed_result(
        self,
        *,
        request: ToolRequest,
        reason_code: str,
        exc: Exception,
        risk_metadata: dict[str, Any] | None = None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> InterceptorResult:
        error_type = type(exc).__name__
        reason = f"global_fail_closed:{reason_code}:{error_type}"
        safe_risk_metadata = dict(risk_metadata or {})

        policy_decision = PolicyDecision(
            decision=Decision.BLOCK,
            allowed=False,
            severity=Severity.HIGH,
            reason=reason,
            policy_id=GLOBAL_FAIL_CLOSED_POLICY_ID,
            explanation=PolicyExplanation(
                policy_version=GLOBAL_FAIL_CLOSED_POLICY_VERSION,
                matched=False,
                matched_rule_id=None,
                matched_rule_priority=None,
                matched_conditions=[reason_code],
                evaluated_rule_ids=[],
                default_decision=False,
            ),
        )

        audit_metadata: dict[str, Any] = {
            **safe_risk_metadata,
            "runtime_mode": self.runtime_mode.value,
            "fail_closed": True,
            "fail_closed_reason_code": reason_code,
            "error_type": error_type,
            "error_summary": f"{error_type} during {reason_code}",
            "policy_explanation": policy_decision.explanation.model_dump(mode="json")
            if policy_decision.explanation is not None
            else None,
        }

        if extra_metadata:
            audit_metadata.update(extra_metadata)

        audit_event = self._log_or_synthesize_fail_closed_audit_event(
            request=request,
            policy_decision=policy_decision,
            metadata=audit_metadata,
        )

        return InterceptorResult(
            request=request,
            risk_assessment=safe_risk_metadata,
            policy_decision=policy_decision,
            audit_event=audit_event,
            execution=ToolExecutionResult(
                status=ExecutionStatus.SKIPPED,
                executed=False,
                error=reason,
            ),
            approval_decision=None,
        )

    def _log_or_synthesize_fail_closed_audit_event(
        self,
        *,
        request: ToolRequest,
        policy_decision: PolicyDecision,
        metadata: dict[str, Any],
    ) -> AuditEvent:
        try:
            return self.audit_logger.log_decision(
                request=request,
                policy_decision=policy_decision,
                metadata=metadata,
            )
        except FAIL_CLOSED_RUNTIME_ERRORS as audit_exc:
            audit_error_type = type(audit_exc).__name__
            fallback_metadata = {
                **metadata,
                "audit_write_failed": True,
                "audit_error_type": audit_error_type,
                "audit_error_summary": f"{audit_error_type} while writing fail-closed audit event",
            }

            return AuditEvent(
                trace_id=str(request.metadata.get("trace_id") or ""),
                user_id=request.user_id,
                agent_id=request.agent_id,
                environment=request.environment,
                tool_name=request.tool_name,
                action=request.action,
                target=redact_sensitive_value(request.target),
                input=redact_sensitive_value(request.input),
                decision=policy_decision.decision,
                allowed=policy_decision.allowed,
                severity=policy_decision.severity,
                policy_id=policy_decision.policy_id,
                reason=policy_decision.reason,
                metadata=redact_sensitive_value(fallback_metadata),
            )

    def _execute_with_decision(
        self,
        request: ToolRequest,
        policy_decision: Any,
        approval_decision: ApprovalDecision | None,
    ) -> ToolExecutionResult:
        # In OBSERVE mode, never execute - just skip
        if self.runtime_mode == RuntimeMode.OBSERVE:
            return ToolExecutionResult(
                status=ExecutionStatus.SKIPPED,
                executed=False,
                error="Tool execution skipped: Rygnal is in observe mode.",
            )

        # In SIMULATE mode, never execute actual tools - simulate or skip
        if self.runtime_mode == RuntimeMode.SIMULATE:
            if policy_decision.decision == Decision.ALLOW:
                return ToolExecutionResult(
                    status=ExecutionStatus.SIMULATED,
                    executed=False,
                    output="Simulated tool execution (simulate mode).",
                )
            return ToolExecutionResult(
                status=ExecutionStatus.SKIPPED,
                executed=False,
                error=f"Tool execution skipped (simulate mode): {policy_decision.decision}",
            )

        # In ENFORCE mode, respect policy decisions
        if self.runtime_mode in {RuntimeMode.ENFORCE, RuntimeMode.PRODUCTION_SAFE}:
            if policy_decision.decision == Decision.ALLOW:
                return self.tool_executor.execute(request)

            if policy_decision.decision == Decision.SIMULATE:
                return ToolExecutionResult(
                    status=ExecutionStatus.SIMULATED,
                    executed=False,
                    output="Simulated decision. Tool was not executed.",
                )

            if policy_decision.decision == Decision.REQUIRE_APPROVAL:
                if approval_decision and approval_decision.approved:
                    return self.tool_executor.execute(request)

                return ToolExecutionResult(
                    status=ExecutionStatus.SKIPPED,
                    executed=False,
                    error="Tool execution skipped because approval was not granted.",
                )

            return ToolExecutionResult(
                status=ExecutionStatus.SKIPPED,
                executed=False,
                error=f"Tool execution skipped because decision is: {policy_decision.decision}",
            )

        # Fallback
        return ToolExecutionResult(
            status=ExecutionStatus.SKIPPED,
            executed=False,
            error=f"Tool execution skipped: unknown runtime mode {self.runtime_mode}",
        )

    @staticmethod
    def _policy_explanation_metadata(policy_decision: Any) -> dict[str, Any]:
        explanation = getattr(policy_decision, "explanation", None)

        if explanation is None:
            return {}

        if hasattr(explanation, "model_dump"):
            return explanation.model_dump(mode="json")

        if isinstance(explanation, dict):
            return explanation

        return {}

    @staticmethod
    def _risk_metadata(risk_assessment: Any) -> dict[str, Any]:
        if hasattr(risk_assessment, "model_dump"):
            return risk_assessment.model_dump(mode="json")

        if isinstance(risk_assessment, dict):
            return risk_assessment

        return {}
