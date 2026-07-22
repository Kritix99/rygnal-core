"""Concurrent SQLite audit storage backend for Rygnal."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rygnal.models import AuditEvent
from rygnal.sqlite_runtime import (
    connect_sqlite,
    initialize_sqlite_database,
)


class SQLiteAuditStore:
    """Store a single transactional audit hash chain."""

    def __init__(
        self,
        db_path: str | Path = "logs/audit_log.db",
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        initialize_sqlite_database(self.db_path)
        self._initialize()

    def append_chained_event(
        self,
        event: AuditEvent,
        hash_event: Callable[[AuditEvent], str],
    ) -> AuditEvent:
        """Atomically bind and insert one hash-chain event."""
        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT event_hash
                FROM audit_events
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

            event.prev_event_hash = (
                str(row["event_hash"])
                if row is not None and row["event_hash"] is not None
                else None
            )
            event.event_hash = hash_event(event)

            self._insert_event(connection, event)
            connection.commit()
            return event
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def write_event(self, event: AuditEvent) -> None:
        """Persist an already finalized event."""
        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            self._insert_event(connection, event)
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def read_events(
        self,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        query = "SELECT payload_json FROM audit_events ORDER BY id ASC"
        params: list[Any] = []

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        with self._connect() as connection:
            rows = connection.execute(
                query,
                params,
            ).fetchall()

        return [self._event_from_payload(row["payload_json"]) for row in rows]

    def count_events(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()

        return int(row["count"])

    def get_event(
        self,
        event_id: str,
    ) -> AuditEvent | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload_json
                FROM audit_events
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()

        return self._event_from_payload(row["payload_json"]) if row is not None else None

    def last_event_hash(self) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT event_hash
                FROM audit_events
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

        if row is None:
            return None

        value = row["event_hash"]
        return str(value) if value is not None else None

    def find_events(
        self,
        *,
        decision: str | None = None,
        policy_id: str | None = None,
        tool_name: str | None = None,
        allowed: bool | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        where: list[str] = []
        params: list[Any] = []

        if decision is not None:
            where.append("decision = ?")
            params.append(decision)

        if policy_id is not None:
            where.append("policy_id = ?")
            params.append(policy_id)

        if tool_name is not None:
            where.append("tool_name = ?")
            params.append(tool_name)

        if allowed is not None:
            where.append("allowed = ?")
            params.append(int(allowed))

        if severity is not None:
            where.append("severity = ?")
            params.append(severity)

        query = "SELECT payload_json FROM audit_events"

        if where:
            query += " WHERE " + " AND ".join(where)

        query += " ORDER BY id ASC LIMIT ?"
        params.append(limit)

        with self._connect() as connection:
            rows = connection.execute(
                query,
                params,
            ).fetchall()

        return [self._event_from_payload(row["payload_json"]) for row in rows]

    def pragma_snapshot(self) -> dict[str, Any]:
        with self._connect() as connection:
            names = (
                "journal_mode",
                "synchronous",
                "busy_timeout",
                "foreign_keys",
            )
            return {name: connection.execute(f"PRAGMA {name}").fetchone()[0] for name in names}

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    action TEXT,
                    decision TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    policy_id TEXT,
                    reason TEXT NOT NULL,
                    prev_event_hash TEXT,
                    event_hash TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL
                )
                """
            )

            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(audit_events)").fetchall()
            }

            if "prev_event_hash" not in columns:
                connection.execute(
                    """
                    ALTER TABLE audit_events
                    ADD COLUMN prev_event_hash TEXT
                    """
                )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_audit_events_trace_id
                ON audit_events(trace_id)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_audit_events_policy_id
                ON audit_events(policy_id)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_audit_events_tool_name
                ON audit_events(tool_name)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_audit_events_decision
                ON audit_events(decision)
                """
            )

    def _insert_event(
        self,
        connection: sqlite3.Connection,
        event: AuditEvent,
    ) -> None:
        if not event.event_hash:
            raise ValueError("Audit event must have an integrity hash.")

        payload = event.model_dump(mode="json")

        connection.execute(
            """
            INSERT INTO audit_events (
                event_id,
                timestamp,
                trace_id,
                user_id,
                agent_id,
                environment,
                tool_name,
                action,
                decision,
                allowed,
                severity,
                policy_id,
                reason,
                prev_event_hash,
                event_hash,
                payload_json
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                event.event_id,
                event.timestamp,
                event.trace_id,
                event.user_id,
                event.agent_id,
                event.environment,
                event.tool_name,
                event.action,
                event.decision.value,
                int(event.allowed),
                event.severity.value,
                event.policy_id,
                event.reason,
                event.prev_event_hash,
                event.event_hash,
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.db_path)

    @staticmethod
    def _event_from_payload(
        payload_json: str,
    ) -> AuditEvent:
        return AuditEvent(**json.loads(payload_json))


__all__ = ["SQLiteAuditStore"]
