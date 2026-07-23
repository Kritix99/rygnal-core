"""Read-only local audit-log CLI."""

from __future__ import annotations

import json
from pathlib import Path

from rygnal.audit_logger import AuditLogger
from rygnal.audit_query import AuditQuery, query_audit_events
from rygnal.local_paths import resolve_local_paths


def run_audit_cli(args: object) -> int:
    """Query the persistent local JSONL audit log."""
    paths = resolve_local_paths(
        data_dir=getattr(args, "data_dir", None),
        create=False,
    )

    verify_integrity = bool(getattr(args, "verify_integrity", False))

    source: str | Path | object = paths.audit_jsonl

    if verify_integrity and paths.audit_jsonl.exists():
        source = AuditLogger(paths.audit_jsonl)

    query = AuditQuery(
        event_id=getattr(args, "event_id", None),
        trace_id=getattr(args, "trace_id", None),
        decision=getattr(args, "decision", None),
        tool_name=getattr(args, "tool_name", None),
        action=getattr(args, "action", None),
        severity=getattr(args, "severity", None),
        policy_id=getattr(args, "policy_id", None),
        since=getattr(args, "since", None),
        until=getattr(args, "until", None),
        limit=getattr(args, "limit", 50),
        offset=getattr(args, "offset", 0),
        newest_first=bool(getattr(args, "newest_first", False)),
    )

    result = query_audit_events(
        source,
        query,
        verify_integrity=verify_integrity,
    )

    if bool(getattr(args, "json", False)):
        print(
            json.dumps(
                result.to_dict(),
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    print(f"Audit log: {paths.audit_jsonl}")

    if not result.events:
        print("No audit events found.")
    else:
        print()
        print(f"{'Timestamp':19}  {'Decision':17}  {'Severity':9}  {'Tool':20}  {'Policy'}")
        print("-" * 96)

        for event in result.events:
            timestamp = event.timestamp.replace("T", " ")[:19]
            decision = event.decision.value
            severity = event.severity.value
            policy_id = event.policy_id or "-"

            print(
                f"{timestamp:19}  "
                f"{decision:17.17}  "
                f"{severity:9.9}  "
                f"{event.tool_name:20.20}  "
                f"{policy_id}"
            )

    print()
    print(f"Returned {result.returned_count} of {result.total_matching} matching event(s).")

    if result.integrity_verified is not None:
        print("Integrity: " + ("valid" if result.integrity_verified else "invalid"))

    for warning in result.warnings:
        print(f"Warning: {warning}")

    return 0


__all__ = ["run_audit_cli"]
