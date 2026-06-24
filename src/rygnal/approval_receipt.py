"""Deterministic approval receipt hashing for Rygnal."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from rygnal.models import ApprovalDecision, ApprovalRequest, ApprovalStatus
from rygnal.security import redact_sensitive_value

APPROVAL_RECEIPT_SCHEMA_VERSION = "approval-receipt.v1"
APPROVAL_RECEIPT_SCHEMA_VERSION_KEY = "approval_receipt_schema_version"
APPROVAL_RECEIPT_HASH_KEY = "approval_receipt_hash"

_RECEIPT_METADATA_KEYS = frozenset(
    {
        APPROVAL_RECEIPT_SCHEMA_VERSION_KEY,
        APPROVAL_RECEIPT_HASH_KEY,
    }
)


class ReceiptStatus(StrEnum):
    """Approval receipt verification status."""

    VALID = "valid"
    MISSING = "missing"
    TAMPERED = "tampered"


class ApprovalReceiptError(ValueError):
    """Base error for approval receipt failures."""


class ApprovalReceiptMissingError(ApprovalReceiptError):
    """Raised when an approved decision has no receipt hash."""

    def __init__(self, approval_id: str) -> None:
        super().__init__(f"Approval receipt hash is missing for approval '{approval_id}'.")


class ApprovalReceiptTamperedError(ApprovalReceiptError):
    """Raised when an approval receipt hash does not match its payload."""

    def __init__(self, approval_id: str) -> None:
        super().__init__(f"Approval receipt hash is invalid for approval '{approval_id}'.")


class ApprovalReceiptConflictError(ApprovalReceiptError):
    """Raised when an existing receipt conflicts with the current payload."""

    def __init__(self, approval_id: str) -> None:
        super().__init__(f"Approval receipt hash conflict for approval '{approval_id}'.")


class ApprovalReceiptPayloadError(ApprovalReceiptError):
    """Raised when receipt payload construction cannot be canonicalized."""

    def __init__(
        self,
        approval_id: str,
        *,
        missing_fields: tuple[str, ...] = (),
        reason: str | None = None,
    ) -> None:
        detail = reason or f"missing required fields: {', '.join(missing_fields)}"
        super().__init__(
            f"Invalid approval receipt payload for approval '{approval_id}': {detail}."
        )


def attach_approval_receipt(
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
) -> ApprovalDecision:
    """Attach a deterministic receipt hash to approved decisions.

    Rejected decisions intentionally remain unsigned in this PR. Rejection
    integrity is covered by the audit hash chain; this receipt is scoped to
    approval-grant integrity.
    """
    if approval_decision.status != ApprovalStatus.APPROVED or not approval_decision.approved:
        return approval_decision

    existing_hash = approval_decision.metadata.get(APPROVAL_RECEIPT_HASH_KEY)
    unsigned_decision = _without_receipt_metadata(approval_decision)
    receipt_hash = calculate_approval_receipt_hash(
        approval_request=approval_request,
        approval_decision=unsigned_decision,
    )

    if isinstance(existing_hash, str) and existing_hash and existing_hash != receipt_hash:
        raise ApprovalReceiptConflictError(approval_decision.approval_id)

    return unsigned_decision.model_copy(
        update={
            "metadata": {
                **unsigned_decision.metadata,
                APPROVAL_RECEIPT_SCHEMA_VERSION_KEY: APPROVAL_RECEIPT_SCHEMA_VERSION,
                APPROVAL_RECEIPT_HASH_KEY: receipt_hash,
            }
        }
    )


def verify_approval_receipt(
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
) -> ReceiptStatus:
    """Return the explicit receipt verification status."""
    expected_hash = approval_decision.metadata.get(APPROVAL_RECEIPT_HASH_KEY)
    if not isinstance(expected_hash, str) or not expected_hash:
        return ReceiptStatus.MISSING

    unsigned_decision = _without_receipt_metadata(approval_decision)
    try:
        actual_hash = calculate_approval_receipt_hash(
            approval_request=approval_request,
            approval_decision=unsigned_decision,
        )
    except ApprovalReceiptPayloadError:
        return ReceiptStatus.TAMPERED

    if actual_hash != expected_hash:
        return ReceiptStatus.TAMPERED

    return ReceiptStatus.VALID


def assert_approval_receipt_valid(
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
) -> None:
    """Raise if an approved decision receipt is missing or invalid."""
    status = verify_approval_receipt(approval_request, approval_decision)

    if status == ReceiptStatus.VALID:
        return

    if status == ReceiptStatus.MISSING:
        raise ApprovalReceiptMissingError(approval_decision.approval_id)

    raise ApprovalReceiptTamperedError(approval_decision.approval_id)


def calculate_approval_receipt_hash(
    *,
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
) -> str:
    """Calculate the deterministic approval receipt hash."""
    payload = approval_receipt_payload(
        approval_request=approval_request,
        approval_decision=approval_decision,
    )
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def approval_receipt_payload(
    *,
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
) -> dict[str, Any]:
    """Build the stable approval receipt payload."""
    approval_id = getattr(approval_request, "approval_id", "unknown")
    _validate_receipt_shape(
        approval_id=approval_id,
        approval_request=approval_request,
        approval_decision=approval_decision,
    )

    decision_metadata = _receipt_free_metadata(approval_decision.metadata)

    return _stable_json_value(
        {
            "schema_version": APPROVAL_RECEIPT_SCHEMA_VERSION,
            "request": {
                "approval_id": approval_request.approval_id,
                "created_at": approval_request.created_at,
                "trace_id": approval_request.trace_id,
                "requested_by": approval_request.requested_by,
                "agent_id": approval_request.agent_id,
                "environment": approval_request.environment,
                "tool_name": approval_request.tool_name,
                "action": approval_request.action,
                "target": approval_request.target,
                "policy_id": approval_request.policy_id,
                "reason": approval_request.reason,
                "severity": approval_request.severity.value,
                "metadata": approval_request.metadata,
            },
            "decision": {
                "approval_id": approval_decision.approval_id,
                "status": approval_decision.status.value,
                "approved": approval_decision.approved,
                "decided_by": approval_decision.decided_by,
                "decided_at": approval_decision.decided_at,
                "reason": approval_decision.reason,
                "metadata": decision_metadata,
            },
        }
    )


def _validate_receipt_shape(
    *,
    approval_id: str,
    approval_request: ApprovalRequest,
    approval_decision: ApprovalDecision,
) -> None:
    required_request_fields = (
        "approval_id",
        "created_at",
        "trace_id",
        "requested_by",
        "agent_id",
        "environment",
        "tool_name",
        "action",
        "policy_id",
        "reason",
        "severity",
        "metadata",
    )
    required_decision_fields = (
        "approval_id",
        "status",
        "approved",
        "decided_by",
        "decided_at",
        "reason",
        "metadata",
    )

    missing = tuple(
        f"request.{field}"
        for field in required_request_fields
        if not hasattr(approval_request, field)
    ) + tuple(
        f"decision.{field}"
        for field in required_decision_fields
        if not hasattr(approval_decision, field)
    )

    if missing:
        raise ApprovalReceiptPayloadError(approval_id, missing_fields=missing)


def _without_receipt_metadata(approval_decision: ApprovalDecision) -> ApprovalDecision:
    return approval_decision.model_copy(
        update={"metadata": _receipt_free_metadata(approval_decision.metadata)}
    )


def _receipt_free_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in metadata.items() if key not in _RECEIPT_METADATA_KEYS}


def _canonical_json(payload: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=_reject_non_canonical_type,
        ).encode("utf-8")
    except TypeError as exc:
        raise ApprovalReceiptPayloadError(
            str(payload.get("approval_id", "unknown")),
            reason=str(exc),
        ) from exc


def _reject_non_canonical_type(value: Any) -> None:
    raise TypeError(f"non-canonical type in receipt payload: {type(value).__name__}")


def _stable_json_value(value: Any) -> Any:
    redacted = redact_sensitive_value(value)

    if isinstance(redacted, Mapping):
        return {
            str(key): _stable_json_value(redacted[key]) for key in sorted(redacted.keys(), key=str)
        }

    if isinstance(redacted, tuple | list):
        return [_stable_json_value(item) for item in redacted]

    if isinstance(redacted, str | int | bool) or redacted is None:
        return redacted

    raise ApprovalReceiptPayloadError(
        "unknown",
        reason=f"non-canonical type in receipt payload: {type(redacted).__name__}",
    )


__all__ = [
    "APPROVAL_RECEIPT_HASH_KEY",
    "APPROVAL_RECEIPT_SCHEMA_VERSION",
    "APPROVAL_RECEIPT_SCHEMA_VERSION_KEY",
    "ApprovalReceiptConflictError",
    "ApprovalReceiptError",
    "ApprovalReceiptMissingError",
    "ApprovalReceiptPayloadError",
    "ApprovalReceiptTamperedError",
    "ReceiptStatus",
    "approval_receipt_payload",
    "assert_approval_receipt_valid",
    "attach_approval_receipt",
    "calculate_approval_receipt_hash",
    "verify_approval_receipt",
]
