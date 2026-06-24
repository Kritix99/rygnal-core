import pytest

from rygnal.approval import (
    ApprovalWorkflow,
    approve_for_testing,
    reject_for_testing,
)
from rygnal.approval_receipt import (
    APPROVAL_RECEIPT_HASH_KEY,
    APPROVAL_RECEIPT_SCHEMA_VERSION_KEY,
    ApprovalReceiptConflictError,
    ApprovalReceiptPayloadError,
    ReceiptStatus,
    attach_approval_receipt,
    calculate_approval_receipt_hash,
    verify_approval_receipt,
)
from rygnal.audit_logger import AuditLogger
from rygnal.interceptor import RygnalInterceptor
from rygnal.models import ApprovalStatus, Decision, ExecutionStatus, ToolRequest
from rygnal.policy_engine import load_default_policy_engine
from rygnal.risk_engine import RiskEngine
from rygnal.tool_executor import ToolExecutor


def build_interceptor(tmp_path, approval_workflow=None):
    executor = ToolExecutor()
    logger = AuditLogger(tmp_path / "audit_log.jsonl")

    return RygnalInterceptor(
        policy_engine=load_default_policy_engine(),
        audit_logger=logger,
        tool_executor=executor,
        risk_engine=RiskEngine(),
        approval_workflow=approval_workflow,
    )


def test_default_approval_workflow_rejects_safely():
    workflow = ApprovalWorkflow()

    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
    )
    policy_decision = load_default_policy_engine().evaluate(request)

    approval_request, approval_decision = workflow.request_approval(request, policy_decision)

    assert approval_request.approval_id == approval_decision.approval_id
    assert approval_decision.status == ApprovalStatus.REJECTED
    assert approval_decision.approved is False


def test_rejected_approval_required_action_never_executes(tmp_path):
    interceptor = build_interceptor(
        tmp_path,
        approval_workflow=ApprovalWorkflow(resolver=reject_for_testing),
    )

    called = {"value": False}

    def delete_file(request: ToolRequest) -> dict[str, str]:
        called["value"] = True
        return {"deleted": request.target or ""}

    interceptor.tool_executor.register("file_delete", delete_file)

    result = interceptor.intercept(
        ToolRequest(
            tool_name="file_delete",
            action="delete_file",
            target="customer_data.csv",
        )
    )

    assert result.policy_decision.decision == Decision.REQUIRE_APPROVAL
    assert result.approval_decision is not None
    assert result.approval_decision.status == ApprovalStatus.REJECTED
    assert result.execution.status == ExecutionStatus.SKIPPED
    assert result.execution.executed is False
    assert called["value"] is False


def test_approved_action_executes_after_approval(tmp_path):
    interceptor = build_interceptor(
        tmp_path,
        approval_workflow=ApprovalWorkflow(resolver=approve_for_testing),
    )

    called = {"value": False}

    def delete_file(request: ToolRequest) -> dict[str, str]:
        called["value"] = True
        return {"deleted": request.target or ""}

    interceptor.tool_executor.register("file_delete", delete_file)

    result = interceptor.intercept(
        ToolRequest(
            tool_name="file_delete",
            action="delete_file",
            target="customer_data.csv",
        )
    )

    assert result.policy_decision.decision == Decision.REQUIRE_APPROVAL
    assert result.approval_decision is not None
    assert result.approval_decision.status == ApprovalStatus.APPROVED
    assert result.execution.status == ExecutionStatus.EXECUTED
    assert result.execution.executed is True
    assert called["value"] is True


def test_approval_decision_is_stored_in_audit_metadata(tmp_path):
    interceptor = build_interceptor(
        tmp_path,
        approval_workflow=ApprovalWorkflow(resolver=approve_for_testing),
    )

    interceptor.tool_executor.register(
        "file_delete",
        lambda request: {"deleted": request.target or ""},
    )

    result = interceptor.intercept(
        ToolRequest(
            tool_name="file_delete",
            action="delete_file",
            target="customer_data.csv",
        )
    )

    events = interceptor.audit_logger.read_events()

    assert len(events) == 1
    assert events[0].event_id == result.audit_event.event_id
    assert events[0].metadata["approval"]["status"] == "approved"
    assert events[0].metadata["approval"]["approved"] is True
    assert events[0].metadata["risk_score"] >= 60
    assert interceptor.audit_logger.verify_integrity() is True


def test_allowed_action_does_not_create_approval_decision(tmp_path):
    interceptor = build_interceptor(tmp_path)

    interceptor.tool_executor.register(
        "file_read",
        lambda request: {"target": request.target, "content": "safe"},
    )

    result = interceptor.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.policy_decision.decision == Decision.ALLOW
    assert result.approval_decision is None
    assert result.execution.status == ExecutionStatus.EXECUTED


def test_approved_approval_decision_gets_receipt_hash():
    workflow = ApprovalWorkflow(resolver=approve_for_testing)

    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
    )
    policy_decision = load_default_policy_engine().evaluate(request)
    approval_request, approval_decision = workflow.request_approval(request, policy_decision)

    assert approval_decision.status == ApprovalStatus.APPROVED
    assert approval_decision.metadata[APPROVAL_RECEIPT_HASH_KEY]
    assert verify_approval_receipt(approval_request, approval_decision) == ReceiptStatus.VALID


def test_rejected_approval_decision_does_not_get_receipt_hash():
    workflow = ApprovalWorkflow(resolver=reject_for_testing)

    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
    )
    policy_decision = load_default_policy_engine().evaluate(request)
    _approval_request, approval_decision = workflow.request_approval(request, policy_decision)

    assert approval_decision.status == ApprovalStatus.REJECTED
    assert APPROVAL_RECEIPT_HASH_KEY not in approval_decision.metadata


def test_approval_receipt_hash_is_deterministic_for_same_payload():
    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
    )
    policy_decision = load_default_policy_engine().evaluate(request)
    approval_request, approval_decision = ApprovalWorkflow(
        resolver=approve_for_testing
    ).request_approval(request, policy_decision)

    unsigned_decision = approval_decision.model_copy(
        update={
            "metadata": {
                key: value
                for key, value in approval_decision.metadata.items()
                if key != APPROVAL_RECEIPT_HASH_KEY
            }
        }
    )

    first_hash = calculate_approval_receipt_hash(
        approval_request=approval_request,
        approval_decision=unsigned_decision,
    )
    second_hash = calculate_approval_receipt_hash(
        approval_request=approval_request,
        approval_decision=unsigned_decision,
    )

    assert first_hash == second_hash


def test_approval_receipt_verification_fails_after_decision_tampering():
    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
    )
    policy_decision = load_default_policy_engine().evaluate(request)
    approval_request, approval_decision = ApprovalWorkflow(
        resolver=approve_for_testing
    ).request_approval(request, policy_decision)

    tampered_decision = approval_decision.model_copy(update={"reason": "Tampered reason."})

    assert verify_approval_receipt(approval_request, approval_decision) == ReceiptStatus.VALID
    assert verify_approval_receipt(approval_request, tampered_decision) == ReceiptStatus.TAMPERED


def test_approved_approval_decision_without_receipt_is_missing():
    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
    )
    policy_decision = load_default_policy_engine().evaluate(request)
    approval_request, approval_decision = ApprovalWorkflow(
        resolver=approve_for_testing
    ).request_approval(request, policy_decision)

    legacy_metadata = {
        key: value
        for key, value in approval_decision.metadata.items()
        if key
        not in {
            APPROVAL_RECEIPT_HASH_KEY,
            APPROVAL_RECEIPT_SCHEMA_VERSION_KEY,
        }
    }
    legacy_decision = approval_decision.model_copy(update={"metadata": legacy_metadata})

    assert legacy_decision.approved is True
    assert verify_approval_receipt(approval_request, legacy_decision) == ReceiptStatus.MISSING


def test_approval_receipt_hash_is_stable_for_equivalent_metadata_order():
    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
        metadata={"b": "second", "a": "first"},
    )
    policy_decision = load_default_policy_engine().evaluate(request)
    approval_request, approval_decision = ApprovalWorkflow(
        resolver=approve_for_testing
    ).request_approval(request, policy_decision)

    first_decision = approval_decision.model_copy(
        update={"metadata": {"z": "last", "a": "first", "nested": {"b": 2, "a": 1}}}
    )
    second_decision = approval_decision.model_copy(
        update={"metadata": {"nested": {"a": 1, "b": 2}, "a": "first", "z": "last"}}
    )

    assert calculate_approval_receipt_hash(
        approval_request=approval_request,
        approval_decision=first_decision,
    ) == calculate_approval_receipt_hash(
        approval_request=approval_request,
        approval_decision=second_decision,
    )


def test_attach_approval_receipt_is_idempotent_and_detects_conflict():
    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
    )
    policy_decision = load_default_policy_engine().evaluate(request)
    approval_request, approval_decision = ApprovalWorkflow(
        resolver=approve_for_testing
    ).request_approval(request, policy_decision)

    reattached = attach_approval_receipt(approval_request, approval_decision)
    tampered_decision = approval_decision.model_copy(update={"reason": "Tampered reason."})

    assert (
        reattached.metadata[APPROVAL_RECEIPT_HASH_KEY]
        == approval_decision.metadata[APPROVAL_RECEIPT_HASH_KEY]
    )

    with pytest.raises(ApprovalReceiptConflictError):
        attach_approval_receipt(approval_request, tampered_decision)


def test_approval_receipt_rejects_non_canonical_metadata_type():
    request = ToolRequest(
        tool_name="file_delete",
        action="delete_file",
        target="customer_data.csv",
    )
    policy_decision = load_default_policy_engine().evaluate(request)
    approval_request, approval_decision = ApprovalWorkflow(
        resolver=approve_for_testing
    ).request_approval(request, policy_decision)

    non_canonical = approval_decision.model_copy(update={"metadata": {"bad": {"set-value"}}})

    with pytest.raises(ApprovalReceiptPayloadError, match="non-canonical type"):
        calculate_approval_receipt_hash(
            approval_request=approval_request,
            approval_decision=non_canonical,
        )
