from typing import Any

import pytest

from rygnal.approval import ApprovalWorkflow, approve_for_testing, reject_for_testing
from rygnal.audit_logger import AuditLogger
from rygnal.interceptor import RygnalInterceptor
from rygnal.models import (
    ApprovalStatus,
    Decision,
    ExecutionStatus,
    PolicyDecision,
    RuntimeMode,
    Severity,
    ToolRequest,
)
from rygnal.tool_executor import ToolExecutor


class StaticPolicyEngine:
    def __init__(self, policy_decision: PolicyDecision) -> None:
        self.policy_decision = policy_decision
        self.calls: list[dict[str, Any]] = []

    def evaluate(
        self,
        request: ToolRequest,
        risk_assessment: Any | None = None,
    ) -> PolicyDecision:
        self.calls.append(
            {
                "request": request,
                "risk_assessment": risk_assessment,
            }
        )
        return self.policy_decision


class StaticRiskEngine:
    def assess(self, _request: ToolRequest) -> dict[str, Any]:
        return {
            "risk_score": 42,
            "risk_level": "medium",
            "signals": ["branch-complete-test"],
        }


class FailingRiskEngine:
    def assess(self, _request: ToolRequest) -> dict[str, Any]:
        raise RuntimeError("risk engine failed")


class FailingPolicyEngine:
    def evaluate(
        self,
        _request: ToolRequest,
        risk_assessment: Any | None = None,
    ) -> PolicyDecision:
        raise RuntimeError("policy engine failed")


class FailingApprovalWorkflow:
    def request_approval(
        self,
        *,
        request: ToolRequest,
        policy_decision: PolicyDecision,
        risk_assessment: dict[str, Any],
    ):
        raise RuntimeError("approval workflow failed")


class SpyTool:
    def __init__(self) -> None:
        self.calls: list[ToolRequest] = []

    def __call__(self, request: ToolRequest) -> dict[str, str]:
        self.calls.append(request)
        return {"executed": "true", "target": request.target or ""}


def make_policy_decision(
    decision: Decision,
    *,
    allowed: bool | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        allowed=decision == Decision.ALLOW if allowed is None else allowed,
        severity=Severity.LOW,
        policy_id=f"test-{decision.value}",
        reason=f"Deterministic {decision.value} decision for interceptor branch test.",
    )


def build_interceptor(
    tmp_path,
    policy_decision: PolicyDecision,
    *,
    runtime_mode: RuntimeMode = RuntimeMode.ENFORCE,
    approval_workflow: ApprovalWorkflow | None = None,
) -> tuple[RygnalInterceptor, StaticPolicyEngine, SpyTool]:
    spy_tool = SpyTool()
    executor = ToolExecutor()
    executor.register("branch_test_tool", spy_tool)

    policy_engine = StaticPolicyEngine(policy_decision)

    interceptor = RygnalInterceptor(
        policy_engine=policy_engine,  # type: ignore[arg-type]
        audit_logger=AuditLogger(tmp_path / "audit_log.jsonl"),
        tool_executor=executor,
        risk_engine=StaticRiskEngine(),  # type: ignore[arg-type]
        approval_workflow=approval_workflow,
        runtime_mode=runtime_mode,
    )

    return interceptor, policy_engine, spy_tool


def make_request() -> ToolRequest:
    return ToolRequest(
        tool_name="branch_test_tool",
        action="execute",
        target="safe-target.txt",
    )


def assert_audit_is_written(interceptor: RygnalInterceptor, result) -> None:
    events = interceptor.audit_logger.read_events()

    assert len(events) == 1
    assert events[0].event_id == result.audit_event.event_id
    assert events[0].metadata["risk_score"] == 42
    assert events[0].metadata["risk_level"] == "medium"
    assert interceptor.audit_logger.verify_integrity() is True


def test_risk_assessment_failure_fails_closed_before_policy_or_execution(tmp_path):
    spy_tool = SpyTool()
    executor = ToolExecutor()
    executor.register("branch_test_tool", spy_tool)
    policy_engine = StaticPolicyEngine(make_policy_decision(Decision.ALLOW))

    interceptor = RygnalInterceptor(
        policy_engine=policy_engine,  # type: ignore[arg-type]
        audit_logger=AuditLogger(tmp_path / "audit_log.jsonl"),
        tool_executor=executor,
        risk_engine=FailingRiskEngine(),  # type: ignore[arg-type]
    )

    result = interceptor.intercept(make_request())

    assert policy_engine.calls == []
    assert spy_tool.calls == []
    assert result.policy_decision.decision == Decision.BLOCK
    assert result.policy_decision.allowed is False
    assert result.policy_decision.severity == Severity.CRITICAL
    assert result.policy_decision.policy_id == "global-fail-closed"
    assert "risk_assessment_failed" in result.policy_decision.reason
    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert result.audit_event.metadata["fail_closed"] is True
    assert result.audit_event.metadata["fail_closed_reason_code"] == "risk_assessment_failed"
    events = interceptor.audit_logger.read_events()
    assert len(events) == 1
    assert events[0].event_id == result.audit_event.event_id
    assert events[0].metadata["fail_closed_reason_code"] == "risk_assessment_failed"


def test_policy_evaluation_failure_fails_closed_before_execution(tmp_path):
    spy_tool = SpyTool()
    executor = ToolExecutor()
    executor.register("branch_test_tool", spy_tool)

    interceptor = RygnalInterceptor(
        policy_engine=FailingPolicyEngine(),  # type: ignore[arg-type]
        audit_logger=AuditLogger(tmp_path / "audit_log.jsonl"),
        tool_executor=executor,
        risk_engine=StaticRiskEngine(),  # type: ignore[arg-type]
    )

    result = interceptor.intercept(make_request())

    assert spy_tool.calls == []
    assert result.risk_assessment["risk_score"] == 42
    assert result.policy_decision.decision == Decision.BLOCK
    assert result.policy_decision.allowed is False
    assert result.policy_decision.severity == Severity.CRITICAL
    assert result.policy_decision.policy_id == "global-fail-closed"
    assert "policy_evaluation_failed" in result.policy_decision.reason
    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert result.audit_event.metadata["fail_closed"] is True
    assert result.audit_event.metadata["fail_closed_reason_code"] == "policy_evaluation_failed"
    assert_audit_is_written(interceptor, result)


def test_approval_workflow_failure_fails_closed_before_execution(tmp_path):
    spy_tool = SpyTool()
    executor = ToolExecutor()
    executor.register("branch_test_tool", spy_tool)
    policy_decision = make_policy_decision(Decision.REQUIRE_APPROVAL, allowed=False)

    interceptor = RygnalInterceptor(
        policy_engine=StaticPolicyEngine(policy_decision),  # type: ignore[arg-type]
        audit_logger=AuditLogger(tmp_path / "audit_log.jsonl"),
        tool_executor=executor,
        risk_engine=StaticRiskEngine(),  # type: ignore[arg-type]
        approval_workflow=FailingApprovalWorkflow(),  # type: ignore[arg-type]
    )

    result = interceptor.intercept(make_request())

    assert spy_tool.calls == []
    assert result.risk_assessment["risk_score"] == 42
    assert result.policy_decision.decision == Decision.BLOCK
    assert result.policy_decision.allowed is False
    assert result.policy_decision.severity == Severity.CRITICAL
    assert result.policy_decision.policy_id == "global-fail-closed"
    assert "approval_workflow_failed" in result.policy_decision.reason
    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert result.audit_event.metadata["fail_closed"] is True
    assert result.audit_event.metadata["fail_closed_reason_code"] == "approval_workflow_failed"
    assert result.audit_event.metadata["original_policy_decision"]["decision"] == "require_approval"
    assert_audit_is_written(interceptor, result)


def test_enforce_allow_branch_executes_registered_tool(tmp_path):
    interceptor, policy_engine, spy_tool = build_interceptor(
        tmp_path,
        make_policy_decision(Decision.ALLOW),
    )

    result = interceptor.intercept(make_request())

    assert policy_engine.calls
    assert result.policy_decision.decision == Decision.ALLOW
    assert result.execution.status == ExecutionStatus.EXECUTED
    assert result.execution.executed is True
    assert result.execution.output == {
        "executed": "true",
        "target": "safe-target.txt",
    }
    assert len(spy_tool.calls) == 1
    assert result.approval_decision is None
    assert_audit_is_written(interceptor, result)


def test_enforce_block_branch_skips_execution(tmp_path):
    interceptor, _policy_engine, spy_tool = build_interceptor(
        tmp_path,
        make_policy_decision(Decision.BLOCK, allowed=False),
    )

    result = interceptor.intercept(make_request())

    assert result.policy_decision.decision == Decision.BLOCK
    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert spy_tool.calls == []
    assert result.approval_decision is None
    assert_audit_is_written(interceptor, result)


def test_enforce_simulate_decision_branch_does_not_execute_tool(tmp_path):
    interceptor, _policy_engine, spy_tool = build_interceptor(
        tmp_path,
        make_policy_decision(Decision.SIMULATE, allowed=True),
    )

    result = interceptor.intercept(make_request())

    assert result.policy_decision.decision == Decision.SIMULATE
    assert result.execution.status == ExecutionStatus.SIMULATED
    assert result.execution.executed is False
    assert spy_tool.calls == []
    assert result.approval_decision is None
    assert_audit_is_written(interceptor, result)


def test_enforce_approved_approval_branch_executes_tool(tmp_path):
    interceptor, _policy_engine, spy_tool = build_interceptor(
        tmp_path,
        make_policy_decision(Decision.REQUIRE_APPROVAL, allowed=False),
        approval_workflow=ApprovalWorkflow(resolver=approve_for_testing),
    )

    result = interceptor.intercept(make_request())

    assert result.policy_decision.decision == Decision.REQUIRE_APPROVAL
    assert result.approval_decision is not None
    assert result.approval_decision.status == ApprovalStatus.APPROVED
    assert result.execution.status == ExecutionStatus.EXECUTED
    assert result.execution.executed is True
    assert len(spy_tool.calls) == 1
    assert result.audit_event.metadata["approval"]["approved"] is True
    assert_audit_is_written(interceptor, result)


def test_enforce_rejected_approval_branch_skips_execution(tmp_path):
    interceptor, _policy_engine, spy_tool = build_interceptor(
        tmp_path,
        make_policy_decision(Decision.REQUIRE_APPROVAL, allowed=False),
        approval_workflow=ApprovalWorkflow(resolver=reject_for_testing),
    )

    result = interceptor.intercept(make_request())

    assert result.policy_decision.decision == Decision.REQUIRE_APPROVAL
    assert result.approval_decision is not None
    assert result.approval_decision.status == ApprovalStatus.REJECTED
    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert spy_tool.calls == []
    assert result.audit_event.metadata["approval"]["approved"] is False
    assert_audit_is_written(interceptor, result)


def test_observe_mode_never_executes_even_when_policy_allows(tmp_path):
    interceptor, _policy_engine, spy_tool = build_interceptor(
        tmp_path,
        make_policy_decision(Decision.ALLOW),
        runtime_mode=RuntimeMode.OBSERVE,
    )

    result = interceptor.intercept(make_request())

    assert result.policy_decision.decision == Decision.ALLOW
    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert "observe mode" in (result.execution.error or "")
    assert spy_tool.calls == []
    assert result.audit_event.metadata["runtime_mode"] == "observe"
    assert_audit_is_written(interceptor, result)


@pytest.mark.parametrize(
    ("policy_decision", "expected_status"),
    [
        (make_policy_decision(Decision.ALLOW), ExecutionStatus.SIMULATED),
        (make_policy_decision(Decision.BLOCK, allowed=False), ExecutionStatus.SKIPPED),
        (
            make_policy_decision(Decision.REQUIRE_APPROVAL, allowed=False),
            ExecutionStatus.SKIPPED,
        ),
    ],
)
def test_simulate_mode_never_executes_tools(
    tmp_path,
    policy_decision: PolicyDecision,
    expected_status: ExecutionStatus,
):
    interceptor, _policy_engine, spy_tool = build_interceptor(
        tmp_path,
        policy_decision,
        runtime_mode=RuntimeMode.SIMULATE,
    )

    result = interceptor.intercept(make_request())

    assert result.execution.status == expected_status
    assert result.execution.executed is False
    assert spy_tool.calls == []
    assert result.audit_event.metadata["runtime_mode"] == "simulate"
    assert_audit_is_written(interceptor, result)
