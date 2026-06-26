"""Structured review and scope-expansion hooks for intent decisions.

This module turns already-computed intent match/fallback facts into one
audit-safe decision object for CLI/API/future UI rendering. It does not mutate
intent scope, submit approvals, or change enforcement behavior.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from rygnal.intent_contract import (
    IntentContract,
    IntentDecisionHint,
    IntentEnforcementMode,
    IntentMatchResult,
    IntentMatchState,
    NormalizedAction,
    ResourceScope,
)
from rygnal.intent_fallback_policy import IntentFallbackEvaluation
from rygnal.security import redact_sensitive_value

INTENT_REVIEW_SCHEMA_VERSION = "intent-review.v1"


class IntentReviewDecisionType(StrEnum):
    REVIEW_NEEDED = "review_needed"
    GROUPED_REVIEW_SUGGESTED = "grouped_review_suggested"
    SCOPE_EXPANSION_SUGGESTED = "scope_expansion_suggested"
    POLICY_DENY = "policy_deny"
    SILENT_PERMIT = "silent_permit"
    SHADOW_ONLY_TRACE = "shadow_only_trace"


class IntentReviewNextAction(StrEnum):
    NONE = "none"
    PERMIT = "permit"
    REVIEW = "review"
    GROUP_REVIEW = "group_review"
    REQUEST_SCOPE_EXPANSION_APPROVAL = "request_scope_expansion_approval"
    DENY = "deny"
    INSPECT_SHADOW_TRACE = "inspect_shadow_trace"


@dataclass(frozen=True)
class IntentReviewDecision:
    schema_version: str
    decision: IntentReviewDecisionType
    action_summary: dict[str, Any]
    affected_resources: tuple[dict[str, Any], ...]
    current_intent_contract_id: str | None
    proposed_additional_scope: tuple[dict[str, Any], ...] = ()
    reason_codes: tuple[str, ...] = ()
    true_risk_level: str = "unknown"
    matched_scopes: tuple[dict[str, Any], ...] = ()
    unmatched_scopes: tuple[dict[str, Any], ...] = ()
    recommended_next_action: IntentReviewNextAction = IntentReviewNextAction.REVIEW
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def audit_summary(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "decision": self.decision.value,
            "action_summary": self.action_summary,
            "affected_resources": self.affected_resources,
            "current_intent_contract_id": self.current_intent_contract_id,
            "proposed_additional_scope": self.proposed_additional_scope,
            "reason_codes": self.reason_codes,
            "true_risk_level": self.true_risk_level,
            "matched_scopes": self.matched_scopes,
            "unmatched_scopes": self.unmatched_scopes,
            "recommended_next_action": self.recommended_next_action.value,
            "metadata": self.metadata,
        }


_SCOPE_EXPANSION_STATES = frozenset(
    {
        IntentMatchState.DRIFT,
        IntentMatchState.UNKNOWN,
    }
)


def build_intent_review_decision(
    *,
    contract: IntentContract,
    match_results: tuple[IntentMatchResult, ...],
    fallback_evaluation: IntentFallbackEvaluation,
    normalized_actions: tuple[NormalizedAction, ...],
    true_risk_level: str | None = None,
) -> IntentReviewDecision:
    """Build one grouped review decision from existing intent policy facts.

    The returned object is intentionally descriptive only. It can suggest future
    scope expansion approval, but it never expands contract scope by itself.
    """
    decision, next_action = _decision_type_and_next_action(
        match_results=match_results,
        fallback_evaluation=fallback_evaluation,
    )

    return IntentReviewDecision(
        schema_version=INTENT_REVIEW_SCHEMA_VERSION,
        decision=decision,
        action_summary=_action_summary(normalized_actions, match_results),
        affected_resources=_affected_resources(normalized_actions),
        current_intent_contract_id=contract.contract_id,
        proposed_additional_scope=_proposed_additional_scope(
            match_results=match_results,
            normalized_actions=normalized_actions,
        ),
        reason_codes=_reason_codes(match_results, fallback_evaluation),
        true_risk_level=true_risk_level or _fallback_risk_level(fallback_evaluation),
        matched_scopes=_scope_summaries(
            scope for result in match_results for scope in result.matched_scopes
        ),
        unmatched_scopes=_scope_summaries(
            scope for result in match_results for scope in result.unmatched_scopes
        ),
        recommended_next_action=next_action,
        metadata={
            "enforcement_mode": fallback_evaluation.enforcement_mode.value,
            "match_state": fallback_evaluation.match_state.value,
            "recommended_hint": fallback_evaluation.recommended_hint.value,
            "effective_hint": fallback_evaluation.effective_hint.value,
            "result_count": fallback_evaluation.result_count,
            "shadowed_recommended_hint": (
                fallback_evaluation.recommended_hint.value
                if fallback_evaluation.enforcement_mode == IntentEnforcementMode.SHADOW
                else None
            ),
            "scope_auto_expanded": False,
            "approval_submitted": False,
        },
    )


def _decision_type_and_next_action(
    *,
    match_results: tuple[IntentMatchResult, ...],
    fallback_evaluation: IntentFallbackEvaluation,
) -> tuple[IntentReviewDecisionType, IntentReviewNextAction]:
    if fallback_evaluation.enforcement_mode == IntentEnforcementMode.SHADOW:
        return (
            IntentReviewDecisionType.SHADOW_ONLY_TRACE,
            IntentReviewNextAction.INSPECT_SHADOW_TRACE,
        )

    if fallback_evaluation.effective_hint in {
        IntentDecisionHint.NONE,
        IntentDecisionHint.ALLOW,
    }:
        return IntentReviewDecisionType.SILENT_PERMIT, IntentReviewNextAction.PERMIT

    if fallback_evaluation.effective_hint == IntentDecisionHint.BLOCK:
        return IntentReviewDecisionType.POLICY_DENY, IntentReviewNextAction.DENY

    if fallback_evaluation.effective_hint == IntentDecisionHint.REQUIRE_APPROVAL:
        if _has_scope_expansion_candidate(match_results):
            return (
                IntentReviewDecisionType.SCOPE_EXPANSION_SUGGESTED,
                IntentReviewNextAction.REQUEST_SCOPE_EXPANSION_APPROVAL,
            )

        if _review_action_count(match_results) > 1:
            return (
                IntentReviewDecisionType.GROUPED_REVIEW_SUGGESTED,
                IntentReviewNextAction.GROUP_REVIEW,
            )

        return IntentReviewDecisionType.REVIEW_NEEDED, IntentReviewNextAction.REVIEW

    if fallback_evaluation.effective_hint == IntentDecisionHint.AUDIT:
        if _review_action_count(match_results) > 1:
            return (
                IntentReviewDecisionType.GROUPED_REVIEW_SUGGESTED,
                IntentReviewNextAction.GROUP_REVIEW,
            )

        if fallback_evaluation.match_state == IntentMatchState.PARTIAL_MATCH:
            return IntentReviewDecisionType.REVIEW_NEEDED, IntentReviewNextAction.REVIEW

    return IntentReviewDecisionType.SILENT_PERMIT, IntentReviewNextAction.PERMIT


def _action_summary(
    actions: tuple[NormalizedAction, ...],
    match_results: tuple[IntentMatchResult, ...],
) -> dict[str, object]:
    operation_counts = Counter(action.operation.value for action in actions)
    source_counts = Counter(action.source.value for action in actions)
    resource_kind_counts = Counter(action.resource_kind.value for action in actions)
    match_state_counts = Counter(result.match_state.value for result in match_results)

    path_count = 0
    for action in actions:
        path_count += len(action.affected_paths)
        path_count += 1 if action.old_path else 0
        path_count += 1 if action.new_path else 0

    return {
        "action_count": len(actions),
        "path_count": path_count,
        "operation_counts": dict(operation_counts),
        "source_counts": dict(source_counts),
        "resource_kind_counts": dict(resource_kind_counts),
        "match_state_counts": dict(match_state_counts),
        "action_ids": tuple(action.action_id for action in actions),
    }


def _affected_resources(
    actions: tuple[NormalizedAction, ...],
) -> tuple[dict[str, Any], ...]:
    resources: list[dict[str, Any]] = []

    for action in actions:
        for path in action.affected_paths:
            resources.append(_resource_summary(action=action, path=path, role="affected_path"))

        if action.old_path:
            resources.append(
                _resource_summary(action=action, path=action.old_path, role="old_path")
            )

        if action.new_path:
            resources.append(
                _resource_summary(action=action, path=action.new_path, role="new_path")
            )

        if not action.affected_paths and not action.old_path and not action.new_path:
            resources.append(
                {
                    "action_id": action.action_id,
                    "operation": action.operation.value,
                    "resource_kind": action.resource_kind.value,
                    "path": None,
                    "path_sha256": None,
                    "role": "pathless_action",
                }
            )

    return tuple(resources)


def _resource_summary(
    *,
    action: NormalizedAction,
    path: str,
    role: str,
) -> dict[str, Any]:
    redacted_path = str(redact_sensitive_value(path))
    return {
        "action_id": action.action_id,
        "operation": action.operation.value,
        "resource_kind": action.resource_kind.value,
        "path": redacted_path,
        "path_sha256": _sha256(path),
        "role": role,
    }


def _proposed_additional_scope(
    *,
    match_results: tuple[IntentMatchResult, ...],
    normalized_actions: tuple[NormalizedAction, ...],
) -> tuple[dict[str, Any], ...]:
    actions_by_id = {action.action_id: action for action in normalized_actions}
    proposed: list[dict[str, Any]] = []

    for result in match_results:
        if result.match_state not in _SCOPE_EXPANSION_STATES:
            continue

        action = actions_by_id.get(result.action_id or "")
        if action is None:
            for raw_path in tuple(result.metadata.get("affected_paths", ())):
                proposed.append(_scope_expansion_summary(raw_path, result=result))
            continue

        candidate_paths = tuple(action.affected_paths)
        if action.old_path:
            candidate_paths += (action.old_path,)
        if action.new_path:
            candidate_paths += (action.new_path,)

        for path in candidate_paths:
            proposed.append(
                _scope_expansion_summary(
                    path,
                    result=result,
                    resource_kind=action.resource_kind.value,
                )
            )

    return _unique_dicts(proposed)


def _scope_expansion_summary(
    path: str,
    *,
    result: IntentMatchResult,
    resource_kind: str | None = None,
) -> dict[str, Any]:
    redacted_path = str(redact_sensitive_value(path))
    return {
        "type": "exact_path",
        "value": redacted_path,
        "value_sha256": _sha256(path),
        "resource_kind": resource_kind,
        "source_action_id": result.action_id,
        "source_match_state": result.match_state.value,
        "requires_human_approval": True,
        "auto_apply": False,
    }


def _scope_summaries(scopes: Any) -> tuple[dict[str, Any], ...]:
    return _unique_dicts(_scope_summary(scope) for scope in scopes)


def _scope_summary(scope: ResourceScope) -> dict[str, Any]:
    redacted_value = str(redact_sensitive_value(scope.value))
    return {
        "type": scope.type.value,
        "value": redacted_value,
        "value_sha256": _sha256(scope.value),
        "resource_kind": scope.resource_kind.value if scope.resource_kind else None,
        "metadata_keys": tuple(sorted(str(key) for key in scope.metadata)),
    }


def _reason_codes(
    match_results: tuple[IntentMatchResult, ...],
    fallback_evaluation: IntentFallbackEvaluation,
) -> tuple[str, ...]:
    codes: list[str] = list(fallback_evaluation.reason_codes)

    for result in match_results:
        codes.extend(result.reason_codes)

    return tuple(dict.fromkeys(codes))


def _has_scope_expansion_candidate(match_results: tuple[IntentMatchResult, ...]) -> bool:
    return any(result.match_state in _SCOPE_EXPANSION_STATES for result in match_results)


def _review_action_count(match_results: tuple[IntentMatchResult, ...]) -> int:
    action_ids = {
        result.action_id
        for result in match_results
        if result.action_id and result.match_state != IntentMatchState.EXACT_MATCH
    }
    return len(action_ids)


def _fallback_risk_level(fallback_evaluation: IntentFallbackEvaluation) -> str:
    if fallback_evaluation.effective_hint == IntentDecisionHint.BLOCK:
        return "critical"

    if fallback_evaluation.effective_hint == IntentDecisionHint.REQUIRE_APPROVAL:
        return "high"

    if fallback_evaluation.effective_hint == IntentDecisionHint.AUDIT:
        return "medium"

    return "low"


def _unique_dicts(values: Any) -> tuple[dict[str, Any], ...]:
    seen: set[tuple[tuple[str, str], ...]] = set()
    unique: list[dict[str, Any]] = []

    for value in values:
        marker = tuple(sorted((str(key), str(value[key])) for key in value))
        if marker in seen:
            continue

        seen.add(marker)
        unique.append(value)

    return tuple(unique)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
