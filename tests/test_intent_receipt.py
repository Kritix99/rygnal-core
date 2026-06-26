from rygnal.intent_contract import (
    IntentContract,
    IntentContractSource,
    IntentDecisionHint,
    IntentEnforcementMode,
    IntentMatchResult,
    IntentMatchState,
    IntentOperation,
    NormalizedAction,
    NormalizedActionSource,
    ResourceKind,
    ResourceScope,
    ResourceScopeType,
)
from rygnal.intent_fallback_policy import IntentFallbackEvaluation
from rygnal.intent_receipt import (
    INTENT_DECISION_RECEIPT_SCHEMA_VERSION,
    build_intent_decision_receipt,
    calculate_intent_decision_receipt_hash,
    intent_decision_receipt_payload,
)


def _contract() -> IntentContract:
    return IntentContract(
        contract_id="intent_contract_1",
        session_id="intent_session_1",
        source=IntentContractSource.YAML,
        task_objective="Receipt test",
        allowed_actions=(IntentOperation.CREATE,),
        target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="docs/**"),),
        enforcement_mode=IntentEnforcementMode.ENFORCE,
    )


def _match_result() -> IntentMatchResult:
    return IntentMatchResult(
        match_state=IntentMatchState.UNKNOWN,
        contract_id="intent_contract_1",
        action_id="action_1",
        reason_codes=("scope-unknown:no-affected-paths",),
        decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
    )


def _fallback() -> IntentFallbackEvaluation:
    return IntentFallbackEvaluation(
        contract_id="intent_contract_1",
        enforcement_mode=IntentEnforcementMode.ENFORCE,
        match_state=IntentMatchState.UNKNOWN,
        recommended_hint=IntentDecisionHint.REQUIRE_APPROVAL,
        effective_hint=IntentDecisionHint.REQUIRE_APPROVAL,
        reason_codes=("fallback:unknown-resource-or-operation",),
        result_count=1,
        metadata={"unknown_action_ids": ("action_1",)},
    )


def _action() -> NormalizedAction:
    return NormalizedAction(
        action_id="action_1",
        source=NormalizedActionSource.FILESYSTEM,
        operation=IntentOperation.CREATE,
        affected_paths=(".env",),
        resource_kind=ResourceKind.SENSITIVE,
    )


def test_intent_decision_receipt_is_deterministic() -> None:
    first = build_intent_decision_receipt(
        contract=_contract(),
        match_results=(_match_result(),),
        fallback_evaluation=_fallback(),
        trace_id="trace_receipt",
        normalized_actions=(_action(),),
    )
    second = build_intent_decision_receipt(
        contract=_contract(),
        match_results=(_match_result(),),
        fallback_evaluation=_fallback(),
        trace_id="trace_receipt",
        normalized_actions=(_action(),),
    )

    assert first.receipt_hash == second.receipt_hash
    assert first.schema_version == INTENT_DECISION_RECEIPT_SCHEMA_VERSION
    assert first.effective_hint == "require_approval"


def test_intent_receipt_hash_changes_when_decision_changes() -> None:
    receipt = build_intent_decision_receipt(
        contract=_contract(),
        match_results=(_match_result(),),
        fallback_evaluation=_fallback(),
        trace_id="trace_receipt",
        normalized_actions=(_action(),),
    )
    changed_fallback = IntentFallbackEvaluation(
        contract_id="intent_contract_1",
        enforcement_mode=IntentEnforcementMode.ENFORCE,
        match_state=IntentMatchState.HARD_SENSITIVE,
        recommended_hint=IntentDecisionHint.BLOCK,
        effective_hint=IntentDecisionHint.BLOCK,
        reason_codes=("fallback:hard-sensitive-boundary",),
        result_count=1,
        metadata={"hard_sensitive_action_ids": ("action_1",)},
    )
    changed_receipt = build_intent_decision_receipt(
        contract=_contract(),
        match_results=(
            IntentMatchResult(
                match_state=IntentMatchState.HARD_SENSITIVE,
                contract_id="intent_contract_1",
                action_id="action_1",
                reason_codes=("hard-sensitive-resource",),
                decision_hint=IntentDecisionHint.BLOCK,
            ),
        ),
        fallback_evaluation=changed_fallback,
        trace_id="trace_receipt",
        normalized_actions=(_action(),),
    )

    assert receipt.receipt_hash != changed_receipt.receipt_hash


def test_intent_receipt_payload_uses_hashes_not_raw_paths() -> None:
    payload = intent_decision_receipt_payload(
        contract=_contract(),
        match_results=(_match_result(),),
        fallback_evaluation=_fallback(),
        trace_id="trace_receipt",
        normalized_actions=(_action(),),
    )
    receipt = build_intent_decision_receipt(
        contract=_contract(),
        match_results=(_match_result(),),
        fallback_evaluation=_fallback(),
        trace_id="trace_receipt",
        normalized_actions=(_action(),),
    )

    assert ".env" not in str(payload)
    assert ".env" not in str(receipt.audit_summary)
    assert receipt.action_path_hashes
    assert calculate_intent_decision_receipt_hash(payload) == receipt.receipt_hash


def test_intent_receipt_correlates_prompt_plan_and_action_without_raw_text() -> None:
    contract = IntentContract(
        contract_id="intent_contract_1",
        session_id="intent_session_1",
        source=IntentContractSource.YAML,
        task_objective="Receipt evidence test",
        human_prompt="Please create docs. token=secret-value",
        ai_plan="I will create docs/readme.md only.",
        evidence_source="chat",
        allowed_actions=(IntentOperation.CREATE,),
        target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="docs/**"),),
        enforcement_mode=IntentEnforcementMode.ENFORCE,
    )

    receipt = build_intent_decision_receipt(
        contract=contract,
        match_results=(_match_result(),),
        fallback_evaluation=_fallback(),
        trace_id="trace_receipt",
        normalized_actions=(_action(),),
    )
    payload = intent_decision_receipt_payload(
        contract=contract,
        match_results=(_match_result(),),
        fallback_evaluation=_fallback(),
        trace_id="trace_receipt",
        normalized_actions=(_action(),),
    )

    assert receipt.evidence_hash
    assert payload["contract"]["intent_evidence"]["human_prompt_present"] is True
    assert payload["contract"]["intent_evidence"]["ai_plan_present"] is True
    assert "secret-value" not in str(payload)
    assert "Please create docs" not in str(payload)
    assert "I will create" not in str(payload)
