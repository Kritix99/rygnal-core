from rygnal.intent_contract import (
    IntentContract,
    IntentContractSource,
    IntentDecisionHint,
    IntentEnforcementMode,
    IntentMatchResult,
    IntentMatchState,
    IntentOperation,
)
from rygnal.intent_fallback_policy import (
    evaluate_intent_fallback,
    intent_fallback_evaluations_audit_summary,
)


def contract(
    *,
    enforcement_mode: IntentEnforcementMode = IntentEnforcementMode.ENFORCE,
) -> IntentContract:
    return IntentContract(
        source=IntentContractSource.YAML,
        task_objective="Fallback policy test",
        allowed_actions=(IntentOperation.TEST,),
        enforcement_mode=enforcement_mode,
    )


def match_result(
    match_state: IntentMatchState,
    *,
    action_id: str = "action_1",
    decision_hint: IntentDecisionHint = IntentDecisionHint.REQUIRE_APPROVAL,
    reason_codes: tuple[str, ...] = ("test-reason",),
) -> IntentMatchResult:
    kwargs = {
        "match_state": match_state,
        "contract_id": "intent_1",
        "action_id": action_id,
        "decision_hint": decision_hint,
    }

    if match_state != IntentMatchState.EXACT_MATCH:
        kwargs["reason_codes"] = reason_codes

    return IntentMatchResult(**kwargs)


def test_exact_matches_allow_in_enforce_mode() -> None:
    evaluation = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.EXACT_MATCH,
                decision_hint=IntentDecisionHint.ALLOW,
            ),
        ),
        contract(),
    )

    assert evaluation.match_state == IntentMatchState.EXACT_MATCH
    assert evaluation.recommended_hint == IntentDecisionHint.ALLOW
    assert evaluation.effective_hint == IntentDecisionHint.ALLOW
    assert not evaluation.requires_approval
    assert not evaluation.should_block


def test_unknown_match_requires_approval_in_enforce_mode() -> None:
    evaluation = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.UNKNOWN,
                reason_codes=("scope-unknown:no-affected-paths",),
            ),
        ),
        contract(),
    )

    assert evaluation.match_state == IntentMatchState.UNKNOWN
    assert evaluation.recommended_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert evaluation.effective_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert evaluation.requires_approval
    assert "fallback:unknown-resource-or-operation" in evaluation.reason_codes


def test_drift_requires_approval_in_enforce_mode() -> None:
    evaluation = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.DRIFT,
                reason_codes=("target-scope-drift",),
            ),
        ),
        contract(),
    )

    assert evaluation.match_state == IntentMatchState.DRIFT
    assert evaluation.effective_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert evaluation.metadata["drift_action_ids"] == ("action_1",)


def test_conflict_requires_approval_in_enforce_mode() -> None:
    evaluation = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.CONFLICT,
                reason_codes=("operation-not-allowed",),
            ),
        ),
        contract(),
    )

    assert evaluation.match_state == IntentMatchState.CONFLICT
    assert evaluation.effective_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert evaluation.metadata["conflict_action_ids"] == ("action_1",)


def test_hard_sensitive_boundary_blocks_in_enforce_mode() -> None:
    evaluation = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.HARD_SENSITIVE,
                reason_codes=("hard-sensitive-resource",),
                decision_hint=IntentDecisionHint.BLOCK,
            ),
        ),
        contract(),
    )

    assert evaluation.match_state == IntentMatchState.HARD_SENSITIVE
    assert evaluation.recommended_hint == IntentDecisionHint.BLOCK
    assert evaluation.effective_hint == IntentDecisionHint.BLOCK
    assert evaluation.should_block
    assert evaluation.metadata["hard_sensitive_action_ids"] == ("action_1",)


def test_partial_match_audits_in_enforce_mode() -> None:
    evaluation = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.PARTIAL_MATCH,
                decision_hint=IntentDecisionHint.AUDIT,
                reason_codes=("operation-semantic-match:config_change",),
            ),
        ),
        contract(),
    )

    assert evaluation.match_state == IntentMatchState.PARTIAL_MATCH
    assert evaluation.effective_hint == IntentDecisionHint.AUDIT
    assert evaluation.should_audit


def test_shadow_mode_downgrades_block_to_audit_effectively() -> None:
    evaluation = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.HARD_SENSITIVE,
                decision_hint=IntentDecisionHint.BLOCK,
                reason_codes=("hard-sensitive-resource",),
            ),
        ),
        contract(enforcement_mode=IntentEnforcementMode.SHADOW),
    )

    assert evaluation.recommended_hint == IntentDecisionHint.BLOCK
    assert evaluation.effective_hint == IntentDecisionHint.AUDIT
    assert evaluation.should_audit
    assert not evaluation.should_block


def test_disabled_mode_records_recommendation_but_has_no_effective_hint() -> None:
    evaluation = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.UNKNOWN,
                reason_codes=("scope-unknown:no-affected-paths",),
            ),
        ),
        contract(enforcement_mode=IntentEnforcementMode.DISABLED),
    )

    assert evaluation.recommended_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert evaluation.effective_hint == IntentDecisionHint.NONE
    assert not evaluation.requires_approval
    assert not evaluation.should_block


def test_empty_match_results_fail_closed_to_approval_recommendation() -> None:
    evaluation = evaluate_intent_fallback((), contract())

    assert evaluation.match_state == IntentMatchState.UNKNOWN
    assert evaluation.effective_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert "fallback:no-match-results" in evaluation.reason_codes


def test_fallback_evaluations_audit_summary_is_queryable() -> None:
    first = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.EXACT_MATCH,
                decision_hint=IntentDecisionHint.ALLOW,
            ),
        ),
        contract(),
    )
    second = evaluate_intent_fallback(
        (
            match_result(
                IntentMatchState.UNKNOWN,
                reason_codes=("scope-unknown:no-affected-paths",),
            ),
        ),
        contract(enforcement_mode=IntentEnforcementMode.SHADOW),
    )

    summary = intent_fallback_evaluations_audit_summary((first, second))

    assert summary["evaluation_count"] == 2
    assert summary["recommended_hint_counts"] == {"allow": 1, "require_approval": 1}
    assert summary["effective_hint_counts"] == {"allow": 1, "audit": 1}
    assert summary["match_state_counts"] == {"exact_match": 1, "unknown": 1}
