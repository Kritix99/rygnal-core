"""Data contracts for Rygnal intent governance."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

INTENT_PROTOCOL_VERSION = "rygnal.intent.v1"

_MODEL_CONFIG = ConfigDict(extra="forbid", frozen=True, validate_default=True)


def new_intent_contract_id() -> str:
    return f"intent_{uuid4().hex}"


def new_intent_session_id() -> str:
    return f"intent_session_{uuid4().hex}"


class IntentContractSource(StrEnum):
    YAML = "yaml"
    CLI = "cli"
    JSON = "json"
    PROMPT_DRAFT = "prompt_draft"
    JIT_EXPANSION = "jit_expansion"


class IntentEnforcementMode(StrEnum):
    DISABLED = "disabled"
    SHADOW = "shadow"
    ENFORCE = "enforce"


class IntentOperation(StrEnum):
    READ = "read"
    CREATE = "create"
    MODIFY = "modify"
    DELETE_FILE = "delete_file"
    DELETE_FOLDER = "delete_folder"
    RENAME = "rename"
    MOVE = "move"
    COMMAND = "command"
    DEPENDENCY_CHANGE = "dependency_change"
    CONFIG_CHANGE = "config_change"
    TEST = "test"
    BUILD = "build"
    UNKNOWN = "unknown"


class ResourceScopeType(StrEnum):
    EXACT_PATH = "exact_path"
    PATH_GLOB = "path_glob"
    FILE_TYPE = "file_type"
    RESOURCE_KIND = "resource_kind"
    SYMBOL = "symbol"


class ResourceKind(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"
    PYTHON_MODULE = "python_module"
    PYTHON_SYMBOL = "python_symbol"
    RUST_MODULE = "rust_module"
    RUST_SYMBOL = "rust_symbol"
    CONFIG = "config"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    LOCKFILE = "lockfile"
    CI_WORKFLOW = "ci_workflow"
    SECRET = "secret"
    TEST = "test"
    GENERATED = "generated"
    DATABASE_MIGRATION = "database_migration"
    POLICY = "policy"
    DOCUMENTATION = "documentation"
    UNKNOWN = "unknown"


class NormalizedActionSource(StrEnum):
    TOOL_CALL = "tool_call"
    PATCH = "patch"
    DIFF = "diff"
    COMMAND = "command"
    FILESYSTEM = "filesystem"
    RUST_KERNEL = "rust_kernel"
    UNKNOWN = "unknown"


class IntentMatchState(StrEnum):
    EXACT_MATCH = "exact_match"
    PARTIAL_MATCH = "partial_match"
    DRIFT = "drift"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"
    HARD_SENSITIVE = "hard_sensitive"


class IntentDecisionHint(StrEnum):
    NONE = "none"
    ALLOW = "allow"
    AUDIT = "audit"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


class ResourceScope(BaseModel):
    model_config = _MODEL_CONFIG

    type: ResourceScopeType
    value: str = Field(min_length=1, max_length=4096)
    resource_kind: ResourceKind | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def _reject_blank_value(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Resource scope value must not be blank.")
        return normalized


class IntentContract(BaseModel):
    model_config = _MODEL_CONFIG

    protocol_version: Literal["rygnal.intent.v1"] = INTENT_PROTOCOL_VERSION
    contract_id: str = Field(default_factory=new_intent_contract_id, min_length=1, max_length=128)
    session_id: str = Field(default_factory=new_intent_session_id, min_length=1, max_length=128)

    source: IntentContractSource
    task_objective: str = Field(min_length=1, max_length=4096)
    human_prompt: str | None = Field(default=None, min_length=1, max_length=16384)
    ai_plan: str | None = Field(default=None, min_length=1, max_length=16384)
    evidence_source: str | None = Field(default=None, min_length=1, max_length=256)
    evidence_metadata: dict[str, Any] = Field(default_factory=dict)
    allowed_actions: tuple[IntentOperation, ...] = Field(min_length=1)
    target_scopes: tuple[ResourceScope, ...] = Field(default_factory=tuple)
    excluded_scopes: tuple[ResourceScope, ...] = Field(default_factory=tuple)

    risk_ceiling: int = Field(default=100, ge=0, le=100)
    expires_at: str | None = Field(default=None, min_length=1, max_length=128)
    enforcement_mode: IntentEnforcementMode = IntentEnforcementMode.SHADOW
    approved_by: str | None = Field(default=None, min_length=1, max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "contract_id",
        "session_id",
        "task_objective",
        "human_prompt",
        "ai_plan",
        "evidence_source",
        "expires_at",
        "approved_by",
    )
    @classmethod
    def _reject_blank_context(cls, value: str | None) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        if not normalized:
            raise ValueError("Intent contract string fields must not be blank.")
        return normalized

    @model_validator(mode="after")
    def _require_scope_for_mutating_actions(self) -> Self:
        mutating_actions = {
            IntentOperation.CREATE,
            IntentOperation.MODIFY,
            IntentOperation.DELETE_FILE,
            IntentOperation.DELETE_FOLDER,
            IntentOperation.RENAME,
            IntentOperation.MOVE,
            IntentOperation.DEPENDENCY_CHANGE,
            IntentOperation.CONFIG_CHANGE,
        }

        if (
            any(action in mutating_actions for action in self.allowed_actions)
            and not self.target_scopes
        ):
            raise ValueError("Mutating intent contracts must include at least one target scope.")

        return self


class NormalizedAction(BaseModel):
    model_config = _MODEL_CONFIG

    action_id: str = Field(default_factory=lambda: f"action_{uuid4().hex}", min_length=1)
    source: NormalizedActionSource
    operation: IntentOperation

    affected_paths: tuple[str, ...] = Field(default_factory=tuple)
    old_path: str | None = Field(default=None, min_length=1, max_length=4096)
    new_path: str | None = Field(default=None, min_length=1, max_length=4096)
    resource_kind: ResourceKind = ResourceKind.UNKNOWN

    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    diff_metadata: dict[str, Any] = Field(default_factory=dict)
    reason_codes: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("action_id", "old_path", "new_path")
    @classmethod
    def _reject_blank_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        if not normalized:
            raise ValueError("Normalized action string fields must not be blank.")
        return normalized

    @field_validator("affected_paths", "reason_codes")
    @classmethod
    def _reject_blank_tuple_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized_values = tuple(value.strip() for value in values)

        if any(not value for value in normalized_values):
            raise ValueError("Normalized action tuple fields must not contain blank values.")

        return normalized_values

    @model_validator(mode="after")
    def _require_rename_boundaries(self) -> Self:
        if self.operation == IntentOperation.RENAME and not (self.old_path and self.new_path):
            raise ValueError("Rename actions must include old_path and new_path.")

        return self


class IntentMatchResult(BaseModel):
    model_config = _MODEL_CONFIG

    match_state: IntentMatchState
    contract_id: str | None = Field(default=None, min_length=1, max_length=128)
    action_id: str | None = Field(default=None, min_length=1, max_length=128)

    matched_scopes: tuple[ResourceScope, ...] = Field(default_factory=tuple)
    unmatched_scopes: tuple[ResourceScope, ...] = Field(default_factory=tuple)
    reason_codes: tuple[str, ...] = Field(default_factory=tuple)
    decision_hint: IntentDecisionHint = IntentDecisionHint.NONE
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("contract_id", "action_id")
    @classmethod
    def _reject_blank_ids(cls, value: str | None) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        if not normalized:
            raise ValueError("Intent match identifiers must not be blank.")
        return normalized

    @field_validator("reason_codes")
    @classmethod
    def _reject_blank_reason_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized_values = tuple(value.strip() for value in values)

        if any(not value for value in normalized_values):
            raise ValueError("Intent match reason codes must not contain blank values.")

        return normalized_values

    @model_validator(mode="after")
    def _require_reasoning_for_non_exact_matches(self) -> Self:
        if self.match_state != IntentMatchState.EXACT_MATCH and not self.reason_codes:
            raise ValueError("Non-exact intent match results must include reason codes.")

        if self.match_state == IntentMatchState.EXACT_MATCH and self.unmatched_scopes:
            raise ValueError("Exact intent match results must not include unmatched scopes.")

        return self
