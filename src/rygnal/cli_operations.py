"""Plain operational CLI commands for durable approvals and artifacts."""

from __future__ import annotations

import argparse
import json
from typing import Any

from rygnal.local_runtime import create_local_runtime_dependencies
from rygnal.models import ApprovalStatus


def run_approval_list_cli(
    args: argparse.Namespace,
) -> int:
    """List durable patch approvals."""
    dependencies = create_local_runtime_dependencies(
        data_dir=args.data_dir,
    )
    status = ApprovalStatus(args.status) if args.status is not None else None
    views = dependencies.approval_service.list(status=status)
    payload = {
        "approvals": tuple(view.to_dict() for view in views),
        "returned_count": len(views),
    }

    if args.json:
        _print_json(payload)
        return 0

    if not views:
        print("No durable patch approvals found.")
        return 0

    for view in views:
        print(
            " ".join(
                (
                    view.approval_id,
                    f"status={view.approval_status}",
                    f"artifact={view.artifact_id}",
                    f"risk={view.severity}",
                    f"expired={str(view.artifact_expired).lower()}",
                )
            )
        )

    return 0


def run_approval_show_cli(
    args: argparse.Namespace,
) -> int:
    """Inspect one durable patch approval."""
    dependencies = create_local_runtime_dependencies(
        data_dir=args.data_dir,
    )
    view = dependencies.approval_service.inspect_approval(args.approval_id)
    _print_view(
        view.to_dict(),
        json_output=args.json,
    )
    return 0


def run_approval_approve_cli(
    args: argparse.Namespace,
) -> int:
    """Approve one durable patch request."""
    dependencies = create_local_runtime_dependencies(
        data_dir=args.data_dir,
    )
    view = dependencies.approval_service.approve(
        args.approval_id,
        decided_by=args.decided_by,
        reason=args.reason,
    )
    _print_view(
        view.to_dict(),
        json_output=args.json,
    )
    return 0


def run_approval_reject_cli(
    args: argparse.Namespace,
) -> int:
    """Reject one durable patch request."""
    dependencies = create_local_runtime_dependencies(
        data_dir=args.data_dir,
    )
    view = dependencies.approval_service.reject(
        args.approval_id,
        decided_by=args.decided_by,
        reason=args.reason,
    )
    _print_view(
        view.to_dict(),
        json_output=args.json,
    )
    return 0


def run_artifact_show_cli(
    args: argparse.Namespace,
) -> int:
    """Inspect one durable patch artifact."""
    dependencies = create_local_runtime_dependencies(
        data_dir=args.data_dir,
    )
    view = dependencies.approval_service.inspect_artifact(args.artifact_id)
    _print_view(
        view.to_dict(),
        json_output=args.json,
    )
    return 0


def run_artifact_apply_cli(
    args: argparse.Namespace,
) -> int:
    """Apply one approved durable patch artifact."""
    dependencies = create_local_runtime_dependencies(
        data_dir=args.data_dir,
    )
    result = dependencies.approval_service.apply_artifact(
        args.artifact_id,
        args.repo,
    )
    payload = _result_summary(result)

    if args.json:
        _print_json(payload)
        return 0

    print(f"Artifact ID: {args.artifact_id}")
    print("Applied: " + str(bool(payload.get("applied"))).lower())

    outcome = payload.get("outcome")

    if outcome is not None:
        print(f"Outcome: {outcome}")

    patch_sha = payload.get("patch_sha256")

    if patch_sha is not None:
        print(f"Patch SHA-256: {patch_sha}")

    print(f"Trusted repository: {args.repo}")
    return 0


def _print_view(
    payload: dict[str, Any],
    *,
    json_output: bool,
) -> None:
    if json_output:
        _print_json(payload)
        return

    approval = payload["approval"]
    artifact = payload["artifact"]
    decision = approval["decision"]

    print(f"Approval ID: {approval['approval_id']}")
    print(f"Approval status: {approval['status']}")
    print(f"Requested by: {approval['requested_by']}")
    print(f"Severity: {approval['severity']}")
    print(f"Reason: {approval['reason']}")
    print(f"Artifact ID: {artifact['artifact_id']}")
    print(f"Artifact state: {artifact['state']}")
    print("Artifact expired: " + str(bool(artifact["expired"])).lower())
    print("Patch SHA-256: " + str(artifact["patch_sha256"]))
    print("Changed files: " + str(artifact["changed_file_count"]))
    print("Baseline commit: " + str(artifact["baseline_commit_sha"]))

    if decision["status"] is not None:
        print(f"Decision: {decision['status']}")
        print(f"Decided by: {decision['decided_by']}")
        print(f"Decision reason: {decision['reason']}")


def _result_summary(result: Any) -> dict[str, Any]:
    summary = getattr(result, "audit_summary", None)

    if callable(summary):
        summary = summary()

    if not isinstance(summary, dict):
        summary = {
            "applied": bool(getattr(result, "applied", False)),
            "outcome": _enum_value(getattr(result, "outcome", None)),
        }

    return summary


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _print_json(payload: Any) -> None:
    print(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


__all__ = [
    "run_approval_approve_cli",
    "run_approval_list_cli",
    "run_approval_reject_cli",
    "run_approval_show_cli",
    "run_artifact_apply_cli",
    "run_artifact_show_cli",
]
