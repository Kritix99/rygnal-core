"""Append-only concurrent audit logger for Rygnal."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from rygnal.models import (
    AuditEvent,
    PolicyDecision,
    ToolRequest,
    new_trace_id,
)
from rygnal.security import redact_sensitive_value


class AuditLogger:
    """Write hash-chained audit events safely."""

    def __init__(
        self,
        log_path: str | Path = "logs/audit_log.jsonl",
        storage_backend: Any | None = None,
    ) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.storage_backend = storage_backend

    def log_decision(
        self,
        request: ToolRequest,
        policy_decision: PolicyDecision,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        trace_value = request.metadata.get("trace_id")
        trace_id = (
            str(redact_sensitive_value(trace_value)) if trace_value is not None else new_trace_id()
        )

        event = AuditEvent(
            trace_id=trace_id,
            user_id=request.user_id,
            agent_id=request.agent_id,
            environment=request.environment,
            tool_name=request.tool_name,
            action=request.action,
            target=redact_sensitive_value(request.target),
            input=redact_sensitive_value(request.input),
            decision=policy_decision.decision,
            allowed=policy_decision.allowed,
            severity=policy_decision.severity,
            policy_id=policy_decision.policy_id,
            reason=policy_decision.reason,
            metadata=redact_sensitive_value(metadata or {}),
        )

        self.write_event(event)
        return event

    def write_event(
        self,
        event: AuditEvent,
    ) -> None:
        append_chained = getattr(
            self.storage_backend,
            "append_chained_event",
            None,
        )

        if callable(append_chained):
            append_chained(
                event,
                self._calculate_event_hash,
            )
            self._append_jsonl_mirror(event)
            return

        with self._locked_jsonl() as log_file:
            event.prev_event_hash = self._last_hash_from_handle(log_file)
            event.event_hash = self._calculate_event_hash(event)
            log_file.seek(0, os.SEEK_END)
            log_file.write(
                json.dumps(
                    event.model_dump(mode="json"),
                    sort_keys=True,
                )
                + "\n"
            )
            log_file.flush()
            os.fsync(log_file.fileno())

        if self.storage_backend is not None:
            self.storage_backend.write_event(event)

    def read_events(self) -> list[AuditEvent]:
        storage_read = getattr(
            self.storage_backend,
            "read_events",
            None,
        )

        if callable(storage_read):
            return list(storage_read())

        if not self.log_path.exists():
            return []

        with self._locked_jsonl(create=False) as log_file:
            log_file.seek(0)
            return [AuditEvent(**json.loads(line)) for line in log_file if line.strip()]

    def verify_integrity(self) -> bool:
        events = self.read_events()
        previous_hash: str | None = None

        for event in events:
            expected_hash = event.event_hash

            if event.prev_event_hash != previous_hash:
                return False

            event.event_hash = None
            actual_hash = self._calculate_event_hash(event)

            if actual_hash != expected_hash:
                return False

            previous_hash = expected_hash

        return True

    def _last_event_hash(self) -> str | None:
        storage_last = getattr(
            self.storage_backend,
            "last_event_hash",
            None,
        )

        if callable(storage_last):
            return storage_last()

        if not self.log_path.exists():
            return None

        with self._locked_jsonl(create=False) as log_file:
            return self._last_hash_from_handle(log_file)

    def _append_jsonl_mirror(
        self,
        event: AuditEvent,
    ) -> None:
        """Append a non-authoritative local mirror."""
        with self._locked_jsonl() as log_file:
            log_file.seek(0, os.SEEK_END)
            log_file.write(
                json.dumps(
                    event.model_dump(mode="json"),
                    sort_keys=True,
                )
                + "\n"
            )
            log_file.flush()
            os.fsync(log_file.fileno())

    @contextmanager
    def _locked_jsonl(
        self,
        *,
        create: bool = True,
    ) -> Iterator[Any]:
        if not create and not self.log_path.exists():
            raise FileNotFoundError(self.log_path)

        mode = "a+" if create else "r"
        handle = self.log_path.open(
            mode,
            encoding="utf-8",
        )

        try:
            _lock_file(handle)
            yield handle
        finally:
            _unlock_file(handle)
            handle.close()

    @staticmethod
    def _last_hash_from_handle(
        handle: Any,
    ) -> str | None:
        handle.seek(0)
        last_hash: str | None = None

        for line in handle:
            if line.strip():
                payload = json.loads(line)
                value = payload.get("event_hash")
                last_hash = str(value) if value is not None else None

        return last_hash

    @staticmethod
    def _calculate_event_hash(
        event: AuditEvent,
    ) -> str:
        data = event.model_dump(mode="json")
        data["event_hash"] = None

        if data.get("schema_version") == "audit.v1":
            data.pop(
                "rygnal_package_version",
                None,
            )

        payload = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _lock_file(handle: Any) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(
            handle.fileno(),
            msvcrt.LK_LOCK,
            1,
        )
        return

    import fcntl

    fcntl.flock(
        handle.fileno(),
        fcntl.LOCK_EX,
    )


def _unlock_file(handle: Any) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        try:
            msvcrt.locking(
                handle.fileno(),
                msvcrt.LK_UNLCK,
                1,
            )
        except OSError:
            pass
        return

    import fcntl

    fcntl.flock(
        handle.fileno(),
        fcntl.LOCK_UN,
    )


__all__ = ["AuditLogger"]
