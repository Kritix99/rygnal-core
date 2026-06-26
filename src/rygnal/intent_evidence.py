"""Audit-safe evidence summaries for intent contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from rygnal.intent_contract import IntentContract
from rygnal.security import redact_sensitive_value

INTENT_EVIDENCE_SCHEMA_VERSION = "intent-evidence.v1"


def intent_evidence_audit_summary(contract: IntentContract) -> dict[str, object]:
    """Return a queryable, audit-safe summary of human/AI intent evidence.

    Raw prompts and plans can contain sensitive task context. The summary records
    presence, size, source, metadata keys, and deterministic redacted hashes
    without exposing the raw prompt or plan.
    """
    human_prompt_hash = _safe_text_hash(contract.human_prompt)
    ai_plan_hash = _safe_text_hash(contract.ai_plan)

    summary: dict[str, object] = {
        "schema_version": INTENT_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": contract.evidence_source,
        "human_prompt_present": contract.human_prompt is not None,
        "ai_plan_present": contract.ai_plan is not None,
        "human_prompt_sha256": human_prompt_hash,
        "ai_plan_sha256": ai_plan_hash,
        "human_prompt_byte_length": _byte_length(contract.human_prompt),
        "ai_plan_byte_length": _byte_length(contract.ai_plan),
        "evidence_metadata_keys": tuple(sorted(str(key) for key in contract.evidence_metadata)),
    }

    summary["combined_evidence_hash"] = _summary_hash(summary)
    return summary


def _safe_text_hash(value: str | None) -> str | None:
    if value is None:
        return None

    redacted = str(redact_sensitive_value(value))
    return hashlib.sha256(redacted.encode("utf-8")).hexdigest()


def _byte_length(value: str | None) -> int:
    if value is None:
        return 0

    return len(value.encode("utf-8", errors="replace"))


def _summary_hash(summary: dict[str, object]) -> str:
    payload = {key: value for key, value in summary.items() if key != "combined_evidence_hash"}
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        redact_sensitive_value(value),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
