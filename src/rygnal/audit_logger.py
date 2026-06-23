"""Append-only audit logger for Rygnal.

The logger stores structured JSONL audit events and adds a simple hash chain
so future tampering can be detected.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from rygnal.models import AuditEvent, PolicyDecision, ToolRequest, new_trace_id
from rygnal.security import redact_sensitive_value

SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "credential",
)

REDACTED = "[REDACTED]"


class AuditLogger:
    """Write Rygnal audit events to an append-only JSONL file."""

    def __init__(
        self,
        log_path: str | Path = "logs/audit_log.jsonl",
        storage_backend: Any | None = None,
    ) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_backend = storage_backend

    def log_decision(
        self,
        request: ToolRequest,
        policy_decision: PolicyDecision,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Create and persist an audit event for a policy decision."""
        trace_id_value = request.metadata.get("trace_id")
        trace_id = (
            str(redact_sensitive_value(trace_id_value))
            if trace_id_value is not None
            else new_trace_id()
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

    def write_event(self, event: AuditEvent) -> None:
        """Append one audit event to the JSONL log file."""
        event.prev_event_hash = self._last_event_hash()
        event.event_hash = self._calculate_event_hash(event)

        with self.log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(event.model_dump(mode="json"), sort_keys=True) + "\n")

        if self.storage_backend is not None:
            self.storage_backend.write_event(event)

    def read_events(self) -> list[AuditEvent]:
        """Read all audit events from the log file."""
        if not self.log_path.exists():
            return []

        events: list[AuditEvent] = []
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(AuditEvent(**json.loads(line)))

        return events

    def verify_integrity(self) -> bool:
        """Verify the audit log hash chain."""
        events = self.read_events()
        previous_hash: str | None = None

        for event in events:
            expected_hash = event.event_hash
            stored_previous_hash = event.prev_event_hash

            if stored_previous_hash != previous_hash:
                return False

            event.event_hash = None
            actual_hash = self._calculate_event_hash(event)

            if actual_hash != expected_hash:
                return False

            previous_hash = expected_hash

        return True

    def _last_event_hash(self) -> str | None:
        if not self.log_path.exists():
            return None

        lines = [line for line in self.log_path.read_text(encoding="utf-8").splitlines() if line]
        if not lines:
            return None

        last_event = json.loads(lines[-1])
        return last_event.get("event_hash")

    @staticmethod
    def _calculate_event_hash(event: AuditEvent) -> str:
        data = event.model_dump(mode="json")
        data["event_hash"] = None

        # audit.v1 existed before package-version stamping. Keep v1 verification
        # compatible by hashing only the fields that existed in that schema.
        if data.get("schema_version") == "audit.v1":
            data.pop("rygnal_package_version", None)

        payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
