"""In-memory approval queue for local Rygnal approval APIs."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rygnal.approval_authorization import ApprovalAuthorizationEngine
from rygnal.approval_state import ApprovalStateMachine
from rygnal.models import ApprovalDecision, ApprovalRequest, ApprovalStatus, utc_now_iso
from rygnal.security import redact_sensitive_value


class ApprovalQueueError(RuntimeError):
    """Base class for approval queue errors."""


class ApprovalNotFoundError(ApprovalQueueError):
    """Raised when an approval request does not exist."""


class ApprovalDeniedError(ApprovalQueueError):
    """Raised when an approval decision is not authorized."""


class ApprovalStateConflictError(ApprovalQueueError):
    """Raised when an approval request is no longer pending."""


@dataclass(frozen=True)
class QueuedApproval:
    """Approval request plus queue lifecycle state."""

    request: ApprovalRequest
    status: ApprovalStatus = ApprovalStatus.PENDING
    decision: ApprovalDecision | None = None

    @property
    def approval_id(self) -> str:
        return self.request.approval_id

    def to_dict(self) -> dict[str, Any]:
        """Return API-safe queued approval data."""
        payload = {
            "approval_id": self.request.approval_id,
            "status": self.status.value,
            "request": self.request.model_dump(mode="json"),
            "approval_decision": (
                self.decision.model_dump(mode="json") if self.decision is not None else None
            ),
        }
        redacted = redact_sensitive_value(payload)

        if not isinstance(redacted, dict):
            raise ApprovalQueueError("Approval queue redaction returned invalid data.")

        return redacted


class InMemoryApprovalQueue:
    """Process-local approval queue with authorization and state checks."""

    def __init__(
        self,
        *,
        authorization_engine: ApprovalAuthorizationEngine | None = None,
    ) -> None:
        self.authorization_engine = authorization_engine or ApprovalAuthorizationEngine()
        self._items: dict[str, QueuedApproval] = {}

    def submit(self, approval_request: ApprovalRequest) -> ApprovalRequest:
        """Add an approval request to the queue."""
        self._store_item(QueuedApproval(request=approval_request))
        return approval_request

    def list(self, *, status: ApprovalStatus | None = None) -> tuple[QueuedApproval, ...]:
        """Return queued approvals in insertion order."""
        items = tuple(self._items.values())

        if status is None:
            return items

        return tuple(item for item in items if item.status == status)

    def get(self, approval_id: str) -> QueuedApproval:
        """Return one queued approval."""
        try:
            return self._items[approval_id]
        except KeyError as exc:
            raise ApprovalNotFoundError(f"Approval request '{approval_id}' was not found.") from exc

    def approve(self, approval_id: str, *, decided_by: str, reason: str) -> QueuedApproval:
        """Approve a pending approval request."""
        return self._decide(
            approval_id,
            status=ApprovalStatus.APPROVED,
            approved=True,
            decided_by=decided_by,
            reason=reason,
        )

    def reject(self, approval_id: str, *, decided_by: str, reason: str) -> QueuedApproval:
        """Reject a pending approval request."""
        return self._decide(
            approval_id,
            status=ApprovalStatus.REJECTED,
            approved=False,
            decided_by=decided_by,
            reason=reason,
        )

    def _decide(
        self,
        approval_id: str,
        *,
        status: ApprovalStatus,
        approved: bool,
        decided_by: str,
        reason: str,
    ) -> QueuedApproval:
        item = self.get(approval_id)

        transition = ApprovalStateMachine.validate_transition(
            current_status=item.status,
            next_status=status,
        )
        if not transition.allowed:
            raise ApprovalStateConflictError(transition.reason)

        decision = ApprovalDecision(
            approval_id=approval_id,
            status=status,
            approved=approved,
            decided_by=decided_by,
            decided_at=utc_now_iso(),
            reason=str(redact_sensitive_value(reason)),
        )

        authorization = self.authorization_engine.authorize(
            approval_request=item.request,
            approval_decision=decision,
            current_status=item.status,
        )
        if not authorization.allowed:
            raise ApprovalDeniedError(authorization.reason)

        updated = QueuedApproval(request=item.request, status=status, decision=decision)
        self._store_item(updated)
        return updated

    def _store_item(self, item: QueuedApproval) -> None:
        self._items[item.approval_id] = item


class SQLiteApprovalQueue(InMemoryApprovalQueue):
    """SQLite-backed approval queue with the same API as the in-memory queue."""

    def __init__(
        self,
        db_path: str | Path = "logs/approval_queue.db",
        *,
        authorization_engine: ApprovalAuthorizationEngine | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(authorization_engine=authorization_engine)
        self._initialize()
        self._load_items()

    def _store_item(self, item: QueuedApproval) -> None:
        self._persist_item(item)
        self._items[item.approval_id] = item

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    approval_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    decision_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_queue_status ON approval_queue(status)"
            )

    def _load_items(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT status, request_json, decision_json
                FROM approval_queue
                ORDER BY id ASC
                """
            ).fetchall()

        self._items = {}
        for row in rows:
            request = ApprovalRequest(**json.loads(row["request_json"]))
            decision_json = row["decision_json"]
            decision = (
                ApprovalDecision(**json.loads(decision_json)) if decision_json is not None else None
            )
            item = QueuedApproval(
                request=request,
                status=ApprovalStatus(row["status"]),
                decision=decision,
            )
            self._items[item.approval_id] = item

    def _persist_item(self, item: QueuedApproval) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO approval_queue (
                    approval_id,
                    status,
                    request_json,
                    decision_json,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(approval_id) DO UPDATE SET
                    status = excluded.status,
                    request_json = excluded.request_json,
                    decision_json = excluded.decision_json,
                    updated_at = excluded.updated_at
                """,
                (
                    item.approval_id,
                    item.status.value,
                    _redacted_model_json(item.request),
                    _redacted_model_json(item.decision) if item.decision is not None else None,
                    item.request.created_at,
                    utc_now_iso(),
                ),
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection


def _redacted_model_json(model: ApprovalRequest | ApprovalDecision) -> str:
    payload = redact_sensitive_value(model.model_dump(mode="json"))
    if not isinstance(payload, dict):
        raise ApprovalQueueError("Approval queue persistence redaction returned invalid data.")

    return json.dumps(payload, sort_keys=True)


__all__ = [
    "ApprovalDeniedError",
    "ApprovalNotFoundError",
    "ApprovalQueueError",
    "ApprovalStateConflictError",
    "InMemoryApprovalQueue",
    "QueuedApproval",
    "SQLiteApprovalQueue",
]
