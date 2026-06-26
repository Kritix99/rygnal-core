"""Fallback policy for unknown intent matches and sensitive boundaries.

This module converts capability match results into mode-aware fallback hints.
It does not mutate guarded-run state, submit approvals, or block execution.
Runtime integration happens in a later issue.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from rygnal.intent_contract import (
    IntentContract,
    IntentDecisionHint,
    IntentEnforcementMode,
    IntentMatchResult,
    IntentMatchState,
)


@dataclass(frozen=True)
class IntentFallbackEvaluation:
    contract_id: str | None
    enforcement_mode: IntentEnforcementMode
    match_state: IntentMatchState
    recommended_hint: IntentDecisionHint
    effective_hint: IntentDecisionHint
    reason_codes: tuple[str, ...]
    result_count: int
    metadata: dict[str, Any]

    @property
    def should_block(self) -> bool:
        return self.effective_hint == IntentDecisionHint.BLOCK

    @property
    def requires_approval(self) -> bool:
        return self.effective_hint == IntentDecisionHint.REQUIRE_APPROVAL

    @property
    def should_audit(self) -> bool:
        return self.effective_hint == IntentDecisionHint.AUDIT

    @property
    def audit_summary(self) -> dict[str, object]:
        return {
            "contract_id": self.contract_id,
            "enforcement_mode": self.enforcement_mode.value,
            "match_state": self.match_state.value,
            "recommended_hint": self.recommended_hint.value,
            "effective_hint": self.effective_hint.value,
            "reason_codes": self.reason_codes,
            "result_count": self.result_count,
            "should_block": self.should_block,
            "requires_approval": self.requires_approval,
            "should_audit": self.should_audit,
            "metadata": self.metadata,
        }


def evaluate_intent_fallback(
    results: Iterable[IntentMatchResult],
    contract: IntentContract,
) -> IntentFallbackEvaluation:
    """Evaluate match results under the contract enforcement mode."""
    result_tuple = tuple(results)
    match_state, recommended_hint, fallback_reasons = _recommended_fallback(result_tuple)
    effective_hint = _effective_hint(
        recommended_hint,
        enforcement_mode=contract.enforcement_mode,
    )

    return IntentFallbackEvaluation(
        contract_id=contract.contract_id,
        enforcement_mode=contract.enforcement_mode,
        match_state=match_state,
        recommended_hint=recommended_hint,
        effective_hint=effective_hint,
        reason_codes=_reason_codes(result_tuple, fallback_reasons),
        result_count=len(result_tuple),
        metadata={
            "match_state_counts": _state_counts(result_tuple),
            "decision_hint_counts": _hint_counts(result_tuple),
            "hard_sensitive_action_ids": _action_ids_for_state(
                result_tuple,
                IntentMatchState.HARD_SENSITIVE,
            ),
            "unknown_action_ids": _action_ids_for_state(
                result_tuple,
                IntentMatchState.UNKNOWN,
            ),
            "drift_action_ids": _action_ids_for_state(
                result_tuple,
                IntentMatchState.DRIFT,
            ),
            "conflict_action_ids": _action_ids_for_state(
                result_tuple,
                IntentMatchState.CONFLICT,
            ),
        },
    )


def intent_fallback_evaluations_audit_summary(
    evaluations: Iterable[IntentFallbackEvaluation],
) -> dict[str, object]:
    """Return a queryable, audit-safe summary for fallback evaluations."""
    evaluation_tuple = tuple(evaluations)
    recommended_counts: Counter[str] = Counter()
    effective_counts: Counter[str] = Counter()
    state_counts: Counter[str] = Counter()

    for evaluation in evaluation_tuple:
        recommended_counts[evaluation.recommended_hint.value] += 1
        effective_counts[evaluation.effective_hint.value] += 1
        state_counts[evaluation.match_state.value] += 1

    return {
        "evaluation_count": len(evaluation_tuple),
        "recommended_hint_counts": dict(recommended_counts),
        "effective_hint_counts": dict(effective_counts),
        "match_state_counts": dict(state_counts),
        "evaluations": tuple(evaluation.audit_summary for evaluation in evaluation_tuple),
    }


def _recommended_fallback(
    results: tuple[IntentMatchResult, ...],
) -> tuple[IntentMatchState, IntentDecisionHint, tuple[str, ...]]:
    if not results:
        return (
            IntentMatchState.UNKNOWN,
            IntentDecisionHint.REQUIRE_APPROVAL,
            ("fallback:no-match-results",),
        )

    if _has_state(results, IntentMatchState.HARD_SENSITIVE):
        return (
            IntentMatchState.HARD_SENSITIVE,
            IntentDecisionHint.BLOCK,
            ("fallback:hard-sensitive-boundary",),
        )

    if _has_state(results, IntentMatchState.UNKNOWN):
        return (
            IntentMatchState.UNKNOWN,
            IntentDecisionHint.REQUIRE_APPROVAL,
            ("fallback:unknown-resource-or-operation",),
        )

    if _has_state(results, IntentMatchState.CONFLICT):
        return (
            IntentMatchState.CONFLICT,
            IntentDecisionHint.REQUIRE_APPROVAL,
            ("fallback:capability-conflict",),
        )

    if _has_state(results, IntentMatchState.DRIFT):
        return (
            IntentMatchState.DRIFT,
            IntentDecisionHint.REQUIRE_APPROVAL,
            ("fallback:scope-drift",),
        )

    if _has_state(results, IntentMatchState.PARTIAL_MATCH):
        return (
            IntentMatchState.PARTIAL_MATCH,
            IntentDecisionHint.AUDIT,
            ("fallback:partial-semantic-match",),
        )

    if all(result.match_state == IntentMatchState.EXACT_MATCH for result in results):
        return (
            IntentMatchState.EXACT_MATCH,
            IntentDecisionHint.ALLOW,
            ("fallback:exact-match",),
        )

    return (
        IntentMatchState.UNKNOWN,
        IntentDecisionHint.REQUIRE_APPROVAL,
        ("fallback:unhandled-match-state",),
    )


def _effective_hint(
    recommended_hint: IntentDecisionHint,
    *,
    enforcement_mode: IntentEnforcementMode,
) -> IntentDecisionHint:
    if enforcement_mode == IntentEnforcementMode.DISABLED:
        return IntentDecisionHint.NONE

    if enforcement_mode == IntentEnforcementMode.SHADOW:
        if recommended_hint in {
            IntentDecisionHint.BLOCK,
            IntentDecisionHint.REQUIRE_APPROVAL,
        }:
            return IntentDecisionHint.AUDIT

        return recommended_hint

    return recommended_hint


def _reason_codes(
    results: tuple[IntentMatchResult, ...],
    fallback_reasons: tuple[str, ...],
) -> tuple[str, ...]:
    codes: list[str] = list(fallback_reasons)

    for result in results:
        codes.extend(result.reason_codes)

    return tuple(dict.fromkeys(codes))


def _has_state(
    results: tuple[IntentMatchResult, ...],
    state: IntentMatchState,
) -> bool:
    return any(result.match_state == state for result in results)


def _state_counts(results: tuple[IntentMatchResult, ...]) -> dict[str, int]:
    return dict(Counter(result.match_state.value for result in results))


def _hint_counts(results: tuple[IntentMatchResult, ...]) -> dict[str, int]:
    return dict(Counter(result.decision_hint.value for result in results))


def _action_ids_for_state(
    results: tuple[IntentMatchResult, ...],
    state: IntentMatchState,
) -> tuple[str, ...]:
    return tuple(
        result.action_id
        for result in results
        if result.match_state == state and result.action_id is not None
    )
