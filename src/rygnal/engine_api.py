from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from rygnal.action_normalizer import normalized_actions_audit_summary
from rygnal.approval_queue import APPROVAL_QUEUE_DB_PATH_ENV, SQLiteApprovalQueue
from rygnal.audit_logger import AuditLogger
from rygnal.guarded_runner import GuardedRunConfig, GuardedRunResult, GuardedRunStatus, run_guarded
from rygnal.schemas import (
    EngineAction,
    EngineError,
    EngineEvent,
    EngineEventName,
    EngineRequest,
    EngineStatus,
    make_event,
    new_request_id,
)
from rygnal.untracked_files import UntrackedFilePolicy

LOGGER = logging.getLogger("rygnal.engine_api")


def main() -> int:
    _configure_logging()

    line = sys.stdin.readline()
    fallback_request_id = _extract_request_id_best_effort(line) or new_request_id()

    _emit(
        make_event(
            request_id=fallback_request_id,
            event=EngineEventName.ENGINE_STARTED,
            status=EngineStatus.STARTING,
            data={
                "transport": "stdio",
                "encoding": "ndjson",
                "raw_stdout": False,
            },
        )
    )

    if not line.strip():
        _emit_error(
            request_id=fallback_request_id,
            status=EngineStatus.INVALID_JSON,
            code="invalid_json",
            message="Expected one JSON request line on stdin.",
        )
        return 1

    try:
        raw_request = json.loads(line)
    except json.JSONDecodeError as exc:
        _emit_error(
            request_id=fallback_request_id,
            status=EngineStatus.INVALID_JSON,
            code="invalid_json",
            message="Request body is not valid JSON.",
            details={"line": exc.lineno, "column": exc.colno},
        )
        return 1

    if isinstance(raw_request, dict) and "request_id" not in raw_request:
        raw_request["request_id"] = fallback_request_id

    try:
        request = EngineRequest.model_validate(raw_request)
    except ValidationError as exc:
        _emit_error(
            request_id=fallback_request_id,
            status=EngineStatus.INVALID_REQUEST,
            code="invalid_request",
            message="Request failed engine contract validation.",
            details={"validation_errors": _validation_error_details(exc)},
        )
        return 1

    _emit(
        make_event(
            request_id=request.request_id,
            event=EngineEventName.REQUEST_ACCEPTED,
            status=EngineStatus.ACCEPTED,
            data={
                "action": request.action.value,
                "trusted_repo": _safe_path_identity(request.trusted_repo_path),
                "command": _command_summary(request.command),
            },
        )
    )

    if request.action != EngineAction.GUARDED_RUN_START:
        _emit_error(
            request_id=request.request_id,
            status=EngineStatus.UNKNOWN_ACTION,
            code="unknown_action",
            message=f"Unsupported engine action: {request.action.value}",
        )
        return 1

    try:
        _run_guarded_request(request)
    except Exception as exc:  # pragma: no cover - last-resort protocol safety
        LOGGER.exception("Unhandled engine_api failure")
        _emit_error(
            request_id=request.request_id,
            status=EngineStatus.INTERNAL_ERROR,
            code="internal_error",
            message="Engine failed before producing a guarded run result.",
            details={"error_type": type(exc).__name__},
            event=EngineEventName.RUN_FAILED,
        )
        return 2

    return 0


def _run_guarded_request(request: EngineRequest) -> None:
    _emit(
        make_event(
            request_id=request.request_id,
            event=EngineEventName.RUN_STARTED,
            status=EngineStatus.RUNNING,
            data={
                "trusted_repo": _safe_path_identity(request.trusted_repo_path),
                "timeout_seconds": request.timeout_seconds,
                "unsafe_local_requested": request.unsafe_local_requested,
                "preserve_workspace": request.preserve_workspace,
            },
        )
    )

    _emit(
        make_event(
            request_id=request.request_id,
            event=EngineEventName.COMMAND_STARTED,
            status=EngineStatus.COMMAND_STARTED,
            data={
                "command": _command_summary(request.command),
                "raw_stdout": False,
                "raw_stderr": False,
            },
        )
    )

    result = run_guarded(_build_guarded_config(request))

    if result.run_id is not None:
        _emit(
            make_event(
                request_id=request.request_id,
                event=EngineEventName.WORKSPACE_CREATED,
                status=EngineStatus.WORKSPACE_CREATED,
                data={
                    "run_id": result.run_id,
                    "baseline_commit_sha": result.baseline_commit_sha,
                    "workspace_path_returned": False,
                },
            )
        )

    if result.command_result is not None:
        _emit(
            make_event(
                request_id=request.request_id,
                event=EngineEventName.COMMAND_FINISHED,
                status=EngineStatus.COMMAND_FINISHED,
                data=_command_result_summary(result, request),
            )
        )

    _emit(
        make_event(
            request_id=request.request_id,
            event=EngineEventName.WORKSPACE_CLEANED,
            status=EngineStatus.WORKSPACE_CLEANED,
            data={
                "cleanup_performed": result.cleanup_performed,
                "cleanup_status": result.cleanup_status,
                "workspace_path_returned": False,
            },
        )
    )

    final_status = _engine_status_for_guarded_result(result)
    final_summary = _guarded_result_summary(result, request)

    if final_status == EngineStatus.APPROVAL_REQUIRED:
        _emit(
            make_event(
                request_id=request.request_id,
                event=EngineEventName.APPROVAL_REQUIRED,
                status=EngineStatus.APPROVAL_REQUIRED,
                data=final_summary,
            )
        )

    _emit(
        make_event(
            request_id=request.request_id,
            event=EngineEventName.RUN_COMPLETED,
            status=final_status,
            data=final_summary,
        )
    )


def _approval_queue_from_environment() -> SQLiteApprovalQueue | None:
    db_path = os.environ.get(APPROVAL_QUEUE_DB_PATH_ENV)
    if not db_path:
        return None

    return SQLiteApprovalQueue(Path(db_path))


def _build_guarded_config(request: EngineRequest) -> GuardedRunConfig:
    audit_logger = (
        AuditLogger(request.audit_log_path) if request.audit_log_path is not None else None
    )
    run_root = request.run_root or Path(tempfile.gettempdir()).joinpath("rygnal-runs")

    return GuardedRunConfig(
        trusted_repo_path=request.trusted_repo_path,
        command=request.command,
        timeout_seconds=request.timeout_seconds,
        rygnal_run_root=run_root,
        allow_dirty_override=request.allow_dirty_override,
        untracked_policy=UntrackedFilePolicy(request.untracked_file_policy),
        preserve_workspace=request.preserve_workspace,
        unsafe_local_requested=request.unsafe_local_requested,
        environment=request.environment,
        user_id=request.user_id,
        agent_id=request.agent_id,
        trace_id=request.request_id,
        intent_contract=request.intent_contract,
        audit_logger=audit_logger,
        approval_queue=_approval_queue_from_environment(),
    )


def _engine_status_for_guarded_result(result: GuardedRunResult) -> EngineStatus:
    if result.command_result is not None and result.command_result.timed_out:
        return EngineStatus.TIMED_OUT

    # Approval-required patches must not be hidden by a non-zero agent exit.
    if result.status == GuardedRunStatus.APPROVAL_REQUIRED:
        return EngineStatus.APPROVAL_REQUIRED

    if result.command_result is not None and result.command_result.exit_code not in (None, 0):
        return EngineStatus.COMMAND_FAILED

    if result.status == GuardedRunStatus.COMPLETED:
        return EngineStatus.COMPLETED

    if result.status == GuardedRunStatus.TIMED_OUT:
        return EngineStatus.TIMED_OUT

    if result.status == GuardedRunStatus.BLOCKED:
        return EngineStatus.BLOCKED

    if result.status == GuardedRunStatus.CLEANUP_FAILED:
        return EngineStatus.CLEANUP_FAILED

    return EngineStatus.BLOCKED if result.blocked_reason else EngineStatus.COMMAND_FAILED


def _approval_summary(result: GuardedRunResult) -> dict[str, Any]:
    approval_request = getattr(result, "approval_request", None)

    if approval_request is None:
        return {"required": False}

    return {
        "required": True,
        "approval_id": approval_request.approval_id,
        "target": approval_request.target,
        "policy_id": approval_request.policy_id,
        "severity": approval_request.severity.value,
        "reason": approval_request.reason,
    }


def _guarded_result_summary(result: GuardedRunResult, request: EngineRequest) -> dict[str, Any]:
    changed_files = ()
    ignored_file_count = 0

    if result.changed_file_report is not None:
        changed_files = result.changed_file_report.files
        ignored_file_count = len(result.changed_file_report.ignored_files)

    return {
        "status": _engine_status_for_guarded_result(result).value,
        "run_id": result.run_id,
        "trusted_repo": _safe_path_identity(Path(result.trusted_repo_path)),
        "workspace_path_returned": False,
        "baseline_commit_sha": result.baseline_commit_sha,
        "backend": {
            "name": result.backend_name,
            "safe_by_default": result.backend_safe_by_default,
            "containment_verified": result.containment_verified,
            "containment_features": dict(getattr(result, "containment_features", {})),
        },
        "cleanup": {
            "performed": result.cleanup_performed,
            "status": result.cleanup_status,
        },
        "command": (
            _command_result_summary(result, request)
            if result.command_result is not None
            else {"present": False}
        ),
        "changes": {
            "changed_file_count": len(changed_files),
            "ignored_file_count": ignored_file_count,
            "files": tuple(
                {
                    "path": file.path,
                    "kind": file.kind.value,
                    "old_path": file.old_path,
                    "mode_changed": file.mode_changed,
                }
                for file in changed_files
            ),
        },
        "patch": _patch_summary(result, request),
        "risk": _risk_summary(result),
        "blocked_reason": result.blocked_reason,
        "approval": _approval_summary(result),
        "normalized_actions": normalized_actions_audit_summary(
            tuple(getattr(result, "normalized_actions", ()))
        ),
        "warnings": tuple(dict.fromkeys(result.warnings)),
    }


def _risk_summary(result: GuardedRunResult) -> dict[str, Any]:
    risk_report = result.change_risk_report

    if risk_report is None:
        return {
            "present": False,
            "level": "low",
            "reasons": (),
            "counts": {},
        }

    reason_codes: list[str] = []

    for report_reason in risk_report.report_reasons:
        reason_codes.append(report_reason.code)

    for file_risk in risk_report.files:
        for reason in file_risk.reasons:
            reason_codes.append(reason.code)

    return {
        "present": True,
        "level": risk_report.overall_risk_level.value,
        "reasons": tuple(dict.fromkeys(reason_codes)),
        "counts": risk_report.risk_counts,
    }


def _command_result_summary(result: GuardedRunResult, request: EngineRequest) -> dict[str, Any]:
    command_result = result.command_result
    if command_result is None:
        return {"present": False}

    stdout_bytes = command_result.stdout.encode("utf-8", errors="replace")
    stderr_bytes = command_result.stderr.encode("utf-8", errors="replace")

    summary: dict[str, Any] = {
        "present": True,
        "exit_code": command_result.exit_code,
        "timed_out": command_result.timed_out,
        "duration_ms": command_result.duration_ms,
        "stdout": _bytes_metadata(stdout_bytes),
        "stderr": _bytes_metadata(stderr_bytes),
    }

    if request.debug.include_stdout:
        summary["stdout"]["raw"] = command_result.stdout

    if request.debug.include_stderr:
        summary["stderr"]["raw"] = command_result.stderr

    return summary


def _patch_summary(result: GuardedRunResult, request: EngineRequest) -> dict[str, Any]:
    patch_diff = result.patch_diff
    if patch_diff is None:
        return {
            "generated": False,
            "sha256": None,
            "size_bytes": 0,
            "changed_file_count": 0,
            "ignored_file_count": 0,
            "total_additions": 0,
            "total_deletions": 0,
            "binary_file_count": 0,
            "files": (),
        }

    summary: dict[str, Any] = {
        "generated": True,
        "sha256": patch_diff.patch_sha256,
        "size_bytes": patch_diff.patch_size_bytes,
        "changed_file_count": patch_diff.changed_file_count,
        "ignored_file_count": patch_diff.ignored_file_count,
        "total_additions": patch_diff.total_additions,
        "total_deletions": patch_diff.total_deletions,
        "binary_file_count": patch_diff.binary_file_count,
        "files": tuple(file.audit_summary for file in patch_diff.files),
    }

    if request.debug.include_raw_patch:
        summary["raw"] = patch_diff.patch

    return summary


def _validation_error_details(exc: ValidationError) -> tuple[dict[str, Any], ...]:
    safe_errors: list[dict[str, Any]] = []

    for error in exc.errors(include_input=False):
        safe_error = dict(error)
        ctx = safe_error.get("ctx")
        if isinstance(ctx, dict):
            safe_error["ctx"] = {key: str(value) for key, value in ctx.items()}
        safe_errors.append(safe_error)

    return tuple(safe_errors)


def _emit_error(
    *,
    request_id: str,
    status: EngineStatus,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    event: EngineEventName = EngineEventName.ENGINE_ERROR,
) -> None:
    _emit(
        make_event(
            request_id=request_id,
            event=event,
            status=status,
            ok=False,
            data={},
            error=EngineError(
                code=code,
                message=message,
                details=details or {},
            ),
        )
    )


def _emit(event: EngineEvent) -> None:
    sys.stdout.write(event.model_dump_json() + "\n")
    sys.stdout.flush()


def _bytes_metadata(payload: bytes) -> dict[str, Any]:
    return {
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _command_summary(command: Iterable[str]) -> dict[str, Any]:
    items = tuple(command)
    executable = items[0] if items else None
    joined = "\0".join(items).encode("utf-8", errors="replace")
    return {
        "argc": len(items),
        "executable": executable,
        "argv_sha256": hashlib.sha256(joined).hexdigest(),
    }


def _safe_path_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    return {
        "name": resolved.name,
        "sha256": hashlib.sha256(resolved.as_posix().encode("utf-8")).hexdigest(),
        "absolute_path_returned": False,
    }


def _extract_request_id_best_effort(line: str) -> str | None:
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(raw, dict):
        return None

    request_id = raw.get("request_id")
    return request_id if isinstance(request_id, str) and request_id else None


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(levelname)s:%(name)s:%(message)s",
        force=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
