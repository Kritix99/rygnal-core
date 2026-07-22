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
from rygnal.sqlite_runtime import (
    connect_sqlite,
    initialize_sqlite_database,
)

APPROVAL_QUEUE_DB_PATH_ENV = "RYGNAL_APPROVAL_QUEUE_DB_PATH"


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

    def record_decision(
        self,
        approval_id: str,
        *,
        approval_decision: ApprovalDecision,
    ) -> QueuedApproval:
        """Validate and persist an externally constructed decision."""
        item = self.get(approval_id)

        if approval_decision.approval_id != approval_id:
            raise ApprovalQueueError("Approval decision ID does not match the queued request.")

        transition = ApprovalStateMachine.validate_transition(
            current_status=item.status,
            next_status=approval_decision.status,
        )

        if not transition.allowed:
            raise ApprovalStateConflictError(transition.reason)

        authorization = self.authorization_engine.authorize(
            approval_request=item.request,
            approval_decision=approval_decision,
            current_status=item.status,
        )

        if not authorization.allowed:
            raise ApprovalDeniedError(authorization.reason)

        updated = QueuedApproval(
            request=item.request,
            status=approval_decision.status,
            decision=approval_decision,
        )
        self._store_item(updated)
        return updated

    def _decide(
        self,
        approval_id: str,
        *,
        status: ApprovalStatus,
        approved: bool,
        decided_by: str,
        reason: str,
    ) -> QueuedApproval:
        decision = ApprovalDecision(
            approval_id=approval_id,
            status=status,
            approved=approved,
            decided_by=decided_by,
            decided_at=utc_now_iso(),
            reason=str(redact_sensitive_value(reason)),
        )

        return self.record_decision(
            approval_id,
            approval_decision=decision,
        )

    def _store_item(self, item: QueuedApproval) -> None:
        self._items[item.approval_id] = item


class SQLiteApprovalQueue(InMemoryApprovalQueue):
    """Transactional durable approval queue."""

    def __init__(
        self,
        db_path: str | Path = "logs/approval_queue.db",
        *,
        authorization_engine: (ApprovalAuthorizationEngine | None) = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        initialize_sqlite_database(self.db_path)
        super().__init__(authorization_engine=authorization_engine)
        self._initialize()
        self._load_items()

    def submit(
        self,
        approval_request: ApprovalRequest,
    ) -> ApprovalRequest:
        """Insert once; identical resubmission is idempotent."""
        request_json = _redacted_model_json(approval_request)
        now = utc_now_iso()
        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT request_json
                FROM approval_queue
                WHERE approval_id = ?
                """,
                (approval_request.approval_id,),
            ).fetchone()

            if row is not None:
                if str(row["request_json"]) != request_json:
                    connection.rollback()
                    raise ApprovalQueueError("Approval ID is already bound to a different request.")

                connection.commit()
                self._load_items()
                return approval_request

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
                VALUES (?, ?, ?, NULL, ?, ?)
                """,
                (
                    approval_request.approval_id,
                    ApprovalStatus.PENDING.value,
                    request_json,
                    approval_request.created_at,
                    now,
                ),
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

        self._load_items()
        return approval_request

    def list(
        self,
        *,
        status: ApprovalStatus | None = None,
    ) -> tuple[QueuedApproval, ...]:
        self._load_items()
        return super().list(status=status)

    def get(
        self,
        approval_id: str,
    ) -> QueuedApproval:
        self._load_items()
        return super().get(approval_id)

    def approve(
        self,
        approval_id: str,
        *,
        decided_by: str,
        reason: str,
    ) -> QueuedApproval:
        return super().approve(
            approval_id,
            decided_by=decided_by,
            reason=reason,
        )

    def reject(
        self,
        approval_id: str,
        *,
        decided_by: str,
        reason: str,
    ) -> QueuedApproval:
        return super().reject(
            approval_id,
            decided_by=decided_by,
            reason=reason,
        )

    def record_decision(
        self,
        approval_id: str,
        *,
        approval_decision: ApprovalDecision,
    ) -> QueuedApproval:
        """Atomically commit exactly one terminal decision."""
        if approval_decision.approval_id != approval_id:
            raise ApprovalQueueError("Approval decision ID does not match the queued request.")

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT status, request_json, decision_json
                FROM approval_queue
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()

            if row is None:
                connection.rollback()
                raise ApprovalNotFoundError(f"Approval request '{approval_id}' was not found.")

            request = ApprovalRequest(**json.loads(row["request_json"]))
            current_status = ApprovalStatus(row["status"])
            decision_json = row["decision_json"]
            current_decision = (
                ApprovalDecision(**json.loads(decision_json)) if decision_json is not None else None
            )

            if current_status != ApprovalStatus.PENDING:
                if current_decision is not None and _same_terminal_decision(
                    current_decision,
                    approval_decision,
                ):
                    connection.commit()
                    updated = QueuedApproval(
                        request=request,
                        status=current_status,
                        decision=current_decision,
                    )
                    self._items[approval_id] = updated
                    return updated

                connection.rollback()
                raise ApprovalStateConflictError(
                    "Approval already has a different terminal decision."
                )

            transition = ApprovalStateMachine.validate_transition(
                current_status=current_status,
                next_status=approval_decision.status,
            )

            if not transition.allowed:
                connection.rollback()
                raise ApprovalStateConflictError(transition.reason)

            authorization = self.authorization_engine.authorize(
                approval_request=request,
                approval_decision=(approval_decision),
                current_status=current_status,
            )

            if not authorization.allowed:
                connection.rollback()
                raise ApprovalDeniedError(authorization.reason)

            cursor = connection.execute(
                """
                UPDATE approval_queue
                SET status = ?,
                    decision_json = ?,
                    updated_at = ?
                WHERE approval_id = ?
                  AND status = ?
                """,
                (
                    approval_decision.status.value,
                    _redacted_model_json(approval_decision),
                    utc_now_iso(),
                    approval_id,
                    ApprovalStatus.PENDING.value,
                ),
            )

            if cursor.rowcount != 1:
                connection.rollback()
                raise ApprovalStateConflictError("Approval state changed concurrently.")

            connection.commit()
            updated = QueuedApproval(
                request=request,
                status=approval_decision.status,
                decision=approval_decision,
            )
            self._items[approval_id] = updated
            return updated
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def pragma_snapshot(self) -> dict[str, Any]:
        with self._connect() as connection:
            names = (
                "journal_mode",
                "synchronous",
                "busy_timeout",
                "foreign_keys",
            )
            return {name: connection.execute(f"PRAGMA {name}").fetchone()[0] for name in names}

    def _store_item(
        self,
        item: QueuedApproval,
    ) -> None:
        if item.status == ApprovalStatus.PENDING:
            self.submit(item.request)
            return

        if item.decision is None:
            raise ApprovalQueueError("Terminal approval is missing a decision.")

        self.record_decision(
            item.approval_id,
            approval_decision=item.decision,
        )

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
                    updated_at TEXT NOT NULL,
                    CHECK (
                        (status = 'pending'
                         AND decision_json IS NULL)
                        OR
                        (status IN ('approved', 'rejected')
                         AND decision_json IS NOT NULL)
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_approval_queue_status
                ON approval_queue(status)
                """
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

        loaded: dict[str, QueuedApproval] = {}

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
            loaded[item.approval_id] = item

        self._items = loaded

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.db_path)


def _same_terminal_decision(
    left: ApprovalDecision,
    right: ApprovalDecision,
) -> bool:
    """Compare semantic idempotency, excluding timestamps."""
    return (
        left.approval_id == right.approval_id
        and left.status == right.status
        and left.approved == right.approved
        and left.decided_by == right.decided_by
        and left.reason == right.reason
        and left.metadata == right.metadata
    )


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
