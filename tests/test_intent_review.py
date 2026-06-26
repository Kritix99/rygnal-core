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
from rygnal.intent_review import (
    INTENT_REVIEW_SCHEMA_VERSION,
    IntentReviewDecisionType,
    IntentReviewNextAction,
    build_intent_review_decision,
)


def _contract(
    *,
    enforcement_mode: IntentEnforcementMode = IntentEnforcementMode.ENFORCE,
) -> IntentContract:
    return IntentContract(
        contract_id="intent_review_test",
        session_id="intent_session_review_test",
        source=IntentContractSource.YAML,
        task_objective="Modify only approved docs",
        allowed_actions=(IntentOperation.CREATE, IntentOperation.MODIFY),
        target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="docs/allowed/**"),),
        enforcement_mode=enforcement_mode,
    )


def _action(
    *,
    action_id: str = "action_1",
    operation: IntentOperation = IntentOperation.CREATE,
    path: str = "docs/outside.md",
    resource_kind: ResourceKind = ResourceKind.FILE,
) -> NormalizedAction:
    return NormalizedAction(
        action_id=action_id,
        source=NormalizedActionSource.FILESYSTEM,
        operation=operation,
        affected_paths=(path,),
        resource_kind=resource_kind,
    )


def _fallback(
    *,
    enforcement_mode: IntentEnforcementMode = IntentEnforcementMode.ENFORCE,
    match_state: IntentMatchState = IntentMatchState.DRIFT,
    recommended_hint: IntentDecisionHint = IntentDecisionHint.REQUIRE_APPROVAL,
    effective_hint: IntentDecisionHint = IntentDecisionHint.REQUIRE_APPROVAL,
    result_count: int = 1,
) -> IntentFallbackEvaluation:
    return IntentFallbackEvaluation(
        contract_id="intent_review_test",
        enforcement_mode=enforcement_mode,
        match_state=match_state,
        recommended_hint=recommended_hint,
        effective_hint=effective_hint,
        reason_codes=(f"fallback:{match_state.value}",),
        result_count=result_count,
        metadata={},
    )


def test_scope_expansion_suggested_for_scope_drift_without_auto_expanding_contract() -> None:
    contract = _contract()
    action = _action(path="docs/outside.md")
    result = IntentMatchResult(
        match_state=IntentMatchState.DRIFT,
        contract_id=contract.contract_id,
        action_id=action.action_id,
        unmatched_scopes=contract.target_scopes,
        reason_codes=("target-scope-drift",),
        decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
    )

    review = build_intent_review_decision(
        contract=contract,
        match_results=(result,),
        fallback_evaluation=_fallback(match_state=IntentMatchState.DRIFT),
        normalized_actions=(action,),
        true_risk_level="high",
    )

    assert review.schema_version == INTENT_REVIEW_SCHEMA_VERSION
    assert review.decision == IntentReviewDecisionType.SCOPE_EXPANSION_SUGGESTED
    assert review.recommended_next_action == (
        IntentReviewNextAction.REQUEST_SCOPE_EXPANSION_APPROVAL
    )
    assert review.current_intent_contract_id == contract.contract_id
    assert review.true_risk_level == "high"
    assert review.proposed_additional_scope == (
        {
            "type": "exact_path",
            "value": "docs/outside.md",
            "value_sha256": review.proposed_additional_scope[0]["value_sha256"],
            "resource_kind": "file",
            "source_action_id": "action_1",
            "source_match_state": "drift",
            "requires_human_approval": True,
            "auto_apply": False,
        },
    )
    assert contract.target_scopes[0].value == "docs/allowed/**"
    assert review.metadata["scope_auto_expanded"] is False
    assert review.metadata["approval_submitted"] is False


def test_policy_deny_for_hard_sensitive_boundary() -> None:
    contract = _contract()
    action = _action(path=".env", resource_kind=ResourceKind.SECRET)
    result = IntentMatchResult(
        match_state=IntentMatchState.HARD_SENSITIVE,
        contract_id=contract.contract_id,
        action_id=action.action_id,
        reason_codes=("hard-sensitive-resource", "resource_kind:secret"),
        decision_hint=IntentDecisionHint.BLOCK,
    )

    review = build_intent_review_decision(
        contract=contract,
        match_results=(result,),
        fallback_evaluation=_fallback(
            match_state=IntentMatchState.HARD_SENSITIVE,
            recommended_hint=IntentDecisionHint.BLOCK,
            effective_hint=IntentDecisionHint.BLOCK,
        ),
        normalized_actions=(action,),
    )

    assert review.decision == IntentReviewDecisionType.POLICY_DENY
    assert review.recommended_next_action == IntentReviewNextAction.DENY
    assert review.true_risk_level == "critical"
    assert "hard-sensitive-resource" in review.reason_codes


def test_shadow_mode_emits_shadow_only_trace_without_approval_submission() -> None:
    contract = _contract(enforcement_mode=IntentEnforcementMode.SHADOW)
    action = _action(path=".env", resource_kind=ResourceKind.SECRET)
    result = IntentMatchResult(
        match_state=IntentMatchState.HARD_SENSITIVE,
        contract_id=contract.contract_id,
        action_id=action.action_id,
        reason_codes=("hard-sensitive-resource",),
        decision_hint=IntentDecisionHint.BLOCK,
    )

    review = build_intent_review_decision(
        contract=contract,
        match_results=(result,),
        fallback_evaluation=_fallback(
            enforcement_mode=IntentEnforcementMode.SHADOW,
            match_state=IntentMatchState.HARD_SENSITIVE,
            recommended_hint=IntentDecisionHint.BLOCK,
            effective_hint=IntentDecisionHint.AUDIT,
        ),
        normalized_actions=(action,),
    )

    assert review.decision == IntentReviewDecisionType.SHADOW_ONLY_TRACE
    assert review.recommended_next_action == IntentReviewNextAction.INSPECT_SHADOW_TRACE
    assert review.metadata["shadowed_recommended_hint"] == "block"
    assert review.metadata["approval_submitted"] is False


def test_grouped_review_suggested_for_multiple_conflicting_actions() -> None:
    contract = _contract()
    actions = (
        _action(action_id="action_1", operation=IntentOperation.DELETE_FILE),
        _action(action_id="action_2", operation=IntentOperation.DELETE_FILE),
    )
    results = tuple(
        IntentMatchResult(
            match_state=IntentMatchState.CONFLICT,
            contract_id=contract.contract_id,
            action_id=action.action_id,
            reason_codes=("operation-not-allowed:delete_file",),
            decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
        )
        for action in actions
    )

    review = build_intent_review_decision(
        contract=contract,
        match_results=results,
        fallback_evaluation=_fallback(
            match_state=IntentMatchState.CONFLICT,
            result_count=2,
        ),
        normalized_actions=actions,
    )

    assert review.decision == IntentReviewDecisionType.GROUPED_REVIEW_SUGGESTED
    assert review.recommended_next_action == IntentReviewNextAction.GROUP_REVIEW
    assert review.action_summary["action_count"] == 2
    assert review.action_summary["action_ids"] == ("action_1", "action_2")


def test_silent_permit_for_exact_allowed_intent() -> None:
    contract = _contract()
    action = _action(path="docs/allowed/readme.md")
    result = IntentMatchResult(
        match_state=IntentMatchState.EXACT_MATCH,
        contract_id=contract.contract_id,
        action_id=action.action_id,
        matched_scopes=contract.target_scopes,
        decision_hint=IntentDecisionHint.ALLOW,
    )

    review = build_intent_review_decision(
        contract=contract,
        match_results=(result,),
        fallback_evaluation=_fallback(
            match_state=IntentMatchState.EXACT_MATCH,
            recommended_hint=IntentDecisionHint.ALLOW,
            effective_hint=IntentDecisionHint.ALLOW,
        ),
        normalized_actions=(action,),
    )

    assert review.decision == IntentReviewDecisionType.SILENT_PERMIT
    assert review.recommended_next_action == IntentReviewNextAction.PERMIT
    assert review.matched_scopes[0]["type"] == "path_glob"
