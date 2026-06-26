"""Deterministic receipts for intent decision tracing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from rygnal.intent_contract import IntentContract, IntentMatchResult, NormalizedAction
from rygnal.intent_evidence import intent_evidence_audit_summary
from rygnal.intent_fallback_policy import IntentFallbackEvaluation
from rygnal.security import redact_sensitive_value

INTENT_DECISION_RECEIPT_SCHEMA_VERSION = "intent-decision-receipt.v1"


@dataclass(frozen=True)
class IntentDecisionReceipt:
    schema_version: str
    receipt_hash: str
    trace_id: str
    contract_id: str
    session_id: str
    enforcement_mode: str
    match_state: str
    recommended_hint: str
    effective_hint: str
    result_count: int
    action_ids: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    action_path_hashes: tuple[str, ...] = ()
    evidence_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def audit_summary(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "receipt_hash": self.receipt_hash,
            "trace_id": self.trace_id,
            "contract_id": self.contract_id,
            "session_id": self.session_id,
            "enforcement_mode": self.enforcement_mode,
            "match_state": self.match_state,
            "recommended_hint": self.recommended_hint,
            "effective_hint": self.effective_hint,
            "result_count": self.result_count,
            "action_ids": self.action_ids,
            "reason_codes": self.reason_codes,
            "action_path_hashes": self.action_path_hashes,
            "evidence_hash": self.evidence_hash,
            "metadata": self.metadata,
        }


def build_intent_decision_receipt(
    *,
    contract: IntentContract,
    match_results: tuple[IntentMatchResult, ...],
    fallback_evaluation: IntentFallbackEvaluation,
    trace_id: str,
    normalized_actions: tuple[NormalizedAction, ...] = (),
) -> IntentDecisionReceipt:
    evidence_summary = intent_evidence_audit_summary(contract)
    payload = intent_decision_receipt_payload(
        contract=contract,
        match_results=match_results,
        fallback_evaluation=fallback_evaluation,
        trace_id=trace_id,
        normalized_actions=normalized_actions,
    )
    receipt_hash = calculate_intent_decision_receipt_hash(payload)

    return IntentDecisionReceipt(
        schema_version=INTENT_DECISION_RECEIPT_SCHEMA_VERSION,
        receipt_hash=receipt_hash,
        trace_id=trace_id,
        contract_id=contract.contract_id,
        session_id=contract.session_id,
        enforcement_mode=contract.enforcement_mode.value,
        match_state=fallback_evaluation.match_state.value,
        recommended_hint=fallback_evaluation.recommended_hint.value,
        effective_hint=fallback_evaluation.effective_hint.value,
        result_count=len(match_results),
        action_ids=_action_ids(match_results, normalized_actions),
        reason_codes=_receipt_reason_codes(match_results, fallback_evaluation),
        action_path_hashes=_action_path_hashes(normalized_actions),
        evidence_hash=evidence_summary.get("combined_evidence_hash"),
        metadata={
            "payload_sha256": receipt_hash,
            "target_scope_count": len(contract.target_scopes),
            "excluded_scope_count": len(contract.excluded_scopes),
        },
    )


def calculate_intent_decision_receipt_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def intent_decision_receipt_payload(
    *,
    contract: IntentContract,
    match_results: tuple[IntentMatchResult, ...],
    fallback_evaluation: IntentFallbackEvaluation,
    trace_id: str,
    normalized_actions: tuple[NormalizedAction, ...] = (),
) -> dict[str, Any]:
    return _stable_json_value(
        {
            "schema_version": INTENT_DECISION_RECEIPT_SCHEMA_VERSION,
            "trace_id": trace_id,
            "contract": {
                "contract_id": contract.contract_id,
                "session_id": contract.session_id,
                "source": contract.source.value,
                "enforcement_mode": contract.enforcement_mode.value,
                "allowed_actions": tuple(action.value for action in contract.allowed_actions),
                "target_scope_count": len(contract.target_scopes),
                "excluded_scope_count": len(contract.excluded_scopes),
                "risk_ceiling": contract.risk_ceiling,
                "intent_evidence": intent_evidence_audit_summary(contract),
            },
            "decision": {
                "match_state": fallback_evaluation.match_state.value,
                "recommended_hint": fallback_evaluation.recommended_hint.value,
                "effective_hint": fallback_evaluation.effective_hint.value,
                "result_count": len(match_results),
                "reason_codes": _receipt_reason_codes(match_results, fallback_evaluation),
            },
            "matches": tuple(
                {
                    "match_state": result.match_state.value,
                    "decision_hint": result.decision_hint.value,
                    "action_id": result.action_id,
                    "contract_id": result.contract_id,
                    "reason_codes": result.reason_codes,
                    "matched_scope_count": len(result.matched_scopes),
                    "unmatched_scope_count": len(result.unmatched_scopes),
                }
                for result in match_results
            ),
            "actions": tuple(
                {
                    "action_id": action.action_id,
                    "source": action.source.value,
                    "operation": action.operation.value,
                    "resource_kind": action.resource_kind.value,
                    "affected_path_count": len(action.affected_paths),
                    "affected_path_hashes": _path_hashes(action.affected_paths),
                    "old_path_hash": _path_hash(action.old_path) if action.old_path else None,
                    "new_path_hash": _path_hash(action.new_path) if action.new_path else None,
                }
                for action in normalized_actions
            ),
        }
    )


def _receipt_reason_codes(
    match_results: tuple[IntentMatchResult, ...],
    fallback_evaluation: IntentFallbackEvaluation,
) -> tuple[str, ...]:
    codes: list[str] = list(fallback_evaluation.reason_codes)
    for result in match_results:
        codes.extend(result.reason_codes)

    return tuple(dict.fromkeys(codes))


def _action_ids(
    match_results: tuple[IntentMatchResult, ...],
    normalized_actions: tuple[NormalizedAction, ...],
) -> tuple[str, ...]:
    ids: list[str] = []

    for result in match_results:
        if result.action_id:
            ids.append(result.action_id)

    for action in normalized_actions:
        ids.append(action.action_id)

    return tuple(dict.fromkeys(ids))


def _action_path_hashes(actions: tuple[NormalizedAction, ...]) -> tuple[str, ...]:
    hashes: list[str] = []
    for action in actions:
        hashes.extend(_path_hashes(action.affected_paths))
        if action.old_path:
            hashes.append(_path_hash(action.old_path))
        if action.new_path:
            hashes.append(_path_hash(action.new_path))

    return tuple(dict.fromkeys(hashes))


def _path_hashes(paths: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(_path_hash(path) for path in paths)


def _path_hash(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()


def _stable_json_value(value: Any) -> Any:
    redacted = redact_sensitive_value(value)
    return json.loads(json.dumps(redacted, sort_keys=True, default=str))


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        _stable_json_value(value),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
