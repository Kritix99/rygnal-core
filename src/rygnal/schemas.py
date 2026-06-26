from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from rygnal.intent_contract import IntentContract

PROTOCOL_VERSION = "rygnal.engine.v1"


class EngineAction(StrEnum):
    GUARDED_RUN_START = "guarded_run.start"


class EngineEventName(StrEnum):
    ENGINE_STARTED = "engine.started"
    REQUEST_ACCEPTED = "request.accepted"
    RUN_STARTED = "run.started"
    WORKSPACE_CREATED = "workspace.created"
    COMMAND_STARTED = "command.started"
    COMMAND_FINISHED = "command.finished"
    WORKSPACE_CLEANED = "workspace.cleaned"
    APPROVAL_REQUIRED = "approval.required"
    RUN_COMPLETED = "run.completed"
    RUN_FAILED = "run.failed"
    ENGINE_ERROR = "engine.error"


class EngineStatus(StrEnum):
    STARTING = "starting"
    ACCEPTED = "accepted"
    RUNNING = "running"
    WORKSPACE_CREATED = "workspace_created"
    COMMAND_STARTED = "command_started"
    COMMAND_FINISHED = "command_finished"
    WORKSPACE_CLEANED = "workspace_cleaned"
    APPROVAL_REQUIRED = "approval_required"
    COMPLETED = "completed"
    COMMAND_FAILED = "command_failed"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"
    CLEANUP_FAILED = "cleanup_failed"
    INVALID_JSON = "invalid_json"
    INVALID_REQUEST = "invalid_request"
    UNKNOWN_ACTION = "unknown_action"
    INTERNAL_ERROR = "internal_error"


class EngineDebugOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    include_raw_patch: bool = False
    include_stdout: bool = False
    include_stderr: bool = False


class EngineRequest(BaseModel):
    """Strict machine-facing request from Go CLI/TUI into Python engine."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    protocol_version: Literal["rygnal.engine.v1"] = PROTOCOL_VERSION
    action: EngineAction
    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex, min_length=1, max_length=128)

    trusted_repo_path: Path
    command: tuple[str, ...] = Field(min_length=1)

    timeout_seconds: int = Field(default=300, ge=1, le=86_400)
    run_root: Path | None = None
    audit_log_path: Path | None = None

    preserve_workspace: bool = False
    unsafe_local_requested: bool
    allow_dirty_override: bool = False
    untracked_file_policy: Literal["block", "preserve_and_warn"] = "block"

    environment: str = Field(default="local", min_length=1, max_length=128)
    user_id: str = Field(default="local_user", min_length=1, max_length=256)
    agent_id: str = Field(default="local_agent", min_length=1, max_length=256)

    intent_contract: IntentContract | None = None

    debug: EngineDebugOptions = Field(default_factory=EngineDebugOptions)

    @field_validator("trusted_repo_path")
    @classmethod
    def trusted_repo_path_must_be_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("trusted_repo_path must be absolute")
        return value

    @field_validator("run_root", "audit_log_path")
    @classmethod
    def optional_paths_must_be_absolute(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("optional engine paths must be absolute")
        return value

    @field_validator("command", mode="before")
    @classmethod
    def command_must_be_argv_list(cls, value: object) -> object:
        if isinstance(value, str):
            raise ValueError("command must be an argv list, not a shell string")
        if not isinstance(value, (list, tuple)):
            raise ValueError("command must be an argv list")
        if not value:
            raise ValueError("command must not be empty")
        if any(not isinstance(item, str) or item == "" for item in value):
            raise ValueError("command items must be non-empty strings")
        return value


class EngineError(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    details: dict[str, Any] = Field(default_factory=dict)


class EngineEvent(BaseModel):
    """Uniform NDJSON envelope emitted on stdout, one JSON object per line."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    protocol_version: Literal["rygnal.engine.v1"] = PROTOCOL_VERSION
    request_id: str = Field(min_length=1)
    timestamp: str
    event: EngineEventName
    ok: bool
    status: EngineStatus
    data: dict[str, Any] = Field(default_factory=dict)
    error: EngineError | None = None


def new_request_id() -> str:
    return uuid.uuid4().hex


def utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_event(
    *,
    request_id: str,
    event: EngineEventName,
    status: EngineStatus,
    ok: bool = True,
    data: dict[str, Any] | None = None,
    error: EngineError | None = None,
) -> EngineEvent:
    return EngineEvent(
        request_id=request_id,
        timestamp=utc_timestamp(),
        event=event,
        ok=ok,
        status=status,
        data=data or {},
        error=error,
    )
