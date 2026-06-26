"""CLI support for running commands through the guarded runner."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from rygnal.audit_logger import AuditLogger
from rygnal.guarded_runner import (
    GuardedRunConfig,
    GuardedRunResult,
    GuardedRunStatus,
    run_guarded,
)
from rygnal.intent_loader import IntentLoadError, load_intent_contract_from_yaml_file

EXIT_COMPLETED = 0
EXIT_COMMAND_FAILED = 1
EXIT_BLOCKED = 2
EXIT_APPROVAL_REQUIRED = 3
EXIT_TIMED_OUT = 4
EXIT_CLEANUP_FAILED = 5
EXIT_USAGE_ERROR = 64


def default_guarded_run_root() -> Path:
    """Return the default directory used for guarded run workspaces."""
    return Path(tempfile.gettempdir()) / "rygnal-runs"


def run_guarded_cli(args: argparse.Namespace) -> int:
    """Run an agent command through Rygnal's guarded runner."""
    try:
        agent_command = normalize_agent_command(args.agent_command)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    audit_logger = AuditLogger(args.audit_log) if args.audit_log else None

    intent_contract = None
    intent_path = getattr(args, "intent", None)
    if intent_path is not None:
        try:
            intent_contract = load_intent_contract_from_yaml_file(intent_path)
        except IntentLoadError as exc:
            print(f"Intent file invalid: {intent_path}", file=sys.stderr)
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE_ERROR

    config = GuardedRunConfig(
        trusted_repo_path=args.repo,
        command=agent_command,
        timeout_seconds=args.timeout,
        rygnal_run_root=args.run_root,
        preserve_workspace=args.preserve_workspace,
        unsafe_local_requested=args.unsafe_local,
        allow_dirty_override=args.allow_dirty,
        audit_logger=audit_logger,
        environment="cli",
        user_id="cli_user",
        agent_id="cli_agent",
        intent_contract=intent_contract,
    )

    result = run_guarded(config)

    if args.json:
        print(json.dumps(to_safe_json_summary(result), sort_keys=True))
    else:
        print(render_guarded_run_summary(result))

    if args.show_stdout and result.command_result and result.command_result.stdout:
        print()
        print("Stdout:")
        print(
            result.command_result.stdout,
            end="" if result.command_result.stdout.endswith("\n") else "\n",
        )

    if args.show_stderr and result.command_result and result.command_result.stderr:
        print()
        print("Stderr:", file=sys.stderr)
        print(
            result.command_result.stderr,
            end="" if result.command_result.stderr.endswith("\n") else "\n",
            file=sys.stderr,
        )

    return exit_code_for_result(result)


def normalize_agent_command(raw: list[str]) -> tuple[str, ...]:
    """Normalize argv captured after `rygnal run --`."""
    command = list(raw)

    if command and command[0] == "--":
        command = command[1:]

    if not command:
        raise ValueError("Missing agent command. Usage: rygnal run -- <command>")

    return tuple(command)


def exit_code_for_result(result: GuardedRunResult) -> int:
    """Map guarded-run status to stable Rygnal CLI exit codes."""
    status = result.status

    if status == GuardedRunStatus.COMPLETED:
        return EXIT_COMPLETED
    if status == GuardedRunStatus.FAILED:
        return EXIT_COMMAND_FAILED
    if status == GuardedRunStatus.APPROVAL_REQUIRED:
        return EXIT_APPROVAL_REQUIRED
    if status == GuardedRunStatus.BLOCKED:
        return EXIT_BLOCKED
    if status == GuardedRunStatus.TIMED_OUT:
        return EXIT_TIMED_OUT
    if status == GuardedRunStatus.CLEANUP_FAILED:
        return EXIT_CLEANUP_FAILED

    return EXIT_COMMAND_FAILED


def render_guarded_run_summary(result: GuardedRunResult) -> str:
    """Render a deterministic, audit-safe human summary."""
    command = result.command_result
    changed_report = result.changed_file_report
    patch = result.patch_diff

    changed_paths = _changed_paths(result)
    workspace_display = _workspace_display(result)
    blocked_reason = _cli_blocked_reason(result.blocked_reason)

    lines = [
        "Rygnal guarded run",
        "",
        f"Status: {_value(result.status)}",
        f"Backend: {result.backend_name or 'none'}",
        f"Backend safe by default: {_yes_no(result.backend_safe_by_default)}",
        f"Containment verified: {_yes_no(result.containment_verified)}",
        f"Trusted repo: {result.trusted_repo_path or 'unknown'}",
        f"Workspace: {workspace_display}",
        f"Cleanup status: {result.cleanup_status or 'not_performed'}",
        f"Baseline: {_short_sha(result.baseline_commit_sha)}",
    ]

    if blocked_reason:
        lines.append(f"Reason: {blocked_reason}")

    approval_request = getattr(result, "approval_request", None)
    if approval_request is not None:
        lines.append(f"Approval ID: {approval_request.approval_id}")

    lines.extend(
        [
            "",
            "Command:",
            f"  Exit code: {command.exit_code if command else 'n/a'}",
            f"  Timed out: {_yes_no(command.timed_out if command else False)}",
            f"  Duration: {_duration_ms(command)}ms",
            "",
            "Changes:",
            f"  Changed files: {changed_report.changed_file_count if changed_report else 0}",
            f"  Ignored files: {changed_report.ignored_file_count if changed_report else 0}",
            f"  Patch generated: {_yes_no(patch is not None)}",
            f"  Patch SHA-256: {patch.patch_sha256 if patch else 'none'}",
            f"  Patch size: {patch.patch_size_bytes if patch else 0} bytes",
        ]
    )

    warnings = _unique_warnings(result.warnings)
    if warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in warnings:
            lines.append(f"  - {warning}")

    if changed_paths:
        lines.append("")
        lines.append("Changed paths:")
        for path in changed_paths:
            lines.append(f"  {path}")

    lines.append("")
    lines.append("Next:")
    if result.status == GuardedRunStatus.APPROVAL_REQUIRED:
        lines.append("  Review and approve the guarded patch before applying it.")
        lines.append("  Do not apply changes directly from the disposable workspace.")
    elif result.status == GuardedRunStatus.BLOCKED:
        lines.append("  Fix the blocked reason and rerun the command.")
        lines.append(
            "  For dirty tracked repos, commit/stash changes or rerun with `--allow-dirty`."
        )
    else:
        lines.append(
            "  Review the generated patch metadata. Patch application is not "
            "performed by `rygnal run`."
        )

    return "\n".join(lines)


def to_safe_json_summary(result: GuardedRunResult) -> dict[str, Any]:
    """Return a machine-readable summary without raw patch/stdout/stderr content."""
    command = result.command_result
    changed_report = result.changed_file_report
    patch = result.patch_diff

    return {
        "status": _value(result.status),
        "backend_name": result.backend_name,
        "backend_safe_by_default": result.backend_safe_by_default,
        "containment_verified": result.containment_verified,
        "containment_features": dict(getattr(result, "containment_features", {})),
        "trusted_repo_path": result.trusted_repo_path,
        "workspace_path": _visible_workspace_path(result),
        "baseline_commit_sha": result.baseline_commit_sha,
        "cleanup_performed": result.cleanup_performed,
        "cleanup_status": result.cleanup_status,
        "blocked_reason": result.blocked_reason,
        "command": {
            "exit_code": command.exit_code if command else None,
            "timed_out": command.timed_out if command else False,
            "duration_ms": _duration_ms(command),
        },
        "changes": {
            "changed_file_count": changed_report.changed_file_count if changed_report else 0,
            "ignored_file_count": changed_report.ignored_file_count if changed_report else 0,
            "changed_paths": _changed_paths(result),
        },
        "patch": {
            "generated": patch is not None,
            "sha256": patch.patch_sha256 if patch else None,
            "size_bytes": patch.patch_size_bytes if patch else 0,
        },
        "warnings": _unique_warnings(result.warnings),
    }


def _approval_json_summary(result: GuardedRunResult) -> dict[str, Any]:
    approval_request = getattr(result, "approval_request", None)

    if approval_request is None:
        return {"required": False}

    return {
        "required": True,
        "approval_id": approval_request.approval_id,
        "target": approval_request.target,
        "severity": approval_request.severity.value,
        "reason": approval_request.reason,
    }


def _cli_blocked_reason(reason: str | None) -> str | None:
    if reason is None:
        return None

    return reason.replace("allow_dirty_override=True", "`--allow-dirty`")


def _unique_warnings(warnings: tuple[str, ...] | list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []

    for warning in warnings:
        normalized = warning.strip()
        if not normalized or normalized in seen:
            continue

        seen.add(normalized)
        unique.append(normalized)

    return unique


def _changed_paths(result: GuardedRunResult) -> list[str]:
    report = result.changed_file_report
    if not report:
        return []

    return [changed_file.path for changed_file in report.files]


def _workspace_display(result: GuardedRunResult) -> str:
    visible_path = _visible_workspace_path(result)

    if visible_path:
        return f"preserved: {visible_path}"

    if result.workspace_path is None:
        return "not_created"

    if result.cleanup_performed:
        return "cleaned"

    return "not_cleaned"


def _visible_workspace_path(result: GuardedRunResult) -> str | None:
    if result.status == GuardedRunStatus.CLEANUP_FAILED:
        return result.workspace_path

    if result.cleanup_performed:
        return None

    return result.workspace_path


def _duration_ms(command: object | None) -> int:
    if command is None:
        return 0

    duration_ms = getattr(command, "duration_ms", None)
    if duration_ms is not None:
        return int(duration_ms)

    duration_seconds = getattr(command, "duration_seconds", None)
    if duration_seconds is not None:
        return int(round(float(duration_seconds) * 1000))

    return 0


def _short_sha(value: str | None) -> str:
    if not value:
        return "none"

    return value[:12]


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _value(value: object) -> str:
    return getattr(value, "value", str(value))
