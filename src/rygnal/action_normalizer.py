"""Normalize guarded-run commands and file effects into audit-safe actions."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

from rygnal.changed_files import ChangedFile, ChangedFileKind, ChangedFileReport
from rygnal.intent_contract import (
    IntentOperation,
    NormalizedAction,
    NormalizedActionSource,
    ResourceKind,
)
from rygnal.patch_diff import PatchDiff, PatchFileDiff

_SECRET_ARG_KEYS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)
_INLINE_CODE_OPTIONS = {"-c", "--command", "-e", "--eval"}

_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9._-]{8,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
)
_DEPENDENCY_MANIFESTS = {
    "Cargo.toml",
    "Gemfile",
    "go.mod",
    "package.json",
    "pnpm-workspace.yaml",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "uv.toml",
}
_LOCKFILE_NAMES = {
    "Cargo.lock",
    "Gemfile.lock",
    "go.sum",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}


def normalize_command_action(command: tuple[str, ...]) -> NormalizedAction:
    """Normalize a command before execution."""
    executable = _command_name(command)
    operation = _operation_from_command(command)
    affected_paths = _extract_repo_paths(command)
    resource_kind = _dominant_resource_kind(affected_paths)

    raw_evidence = {
        "kind": "argv",
        "executable": executable,
        "argc": len(command),
        "argv_redacted": _redacted_command(command),
    }

    reason_codes = (
        "source:command",
        f"operation:{operation.value}",
        f"executable:{executable or 'unknown'}",
        f"resource_kind:{resource_kind.value}",
    )

    return NormalizedAction(
        action_id=_stable_action_id(
            source=NormalizedActionSource.COMMAND,
            operation=operation,
            affected_paths=affected_paths,
            old_path=None,
            new_path=None,
            metadata=raw_evidence,
        ),
        source=NormalizedActionSource.COMMAND,
        operation=operation,
        affected_paths=affected_paths,
        resource_kind=resource_kind,
        raw_evidence=raw_evidence,
        reason_codes=reason_codes,
    )


def normalize_changed_file_action(
    changed_file: ChangedFile,
    *,
    patch_file: PatchFileDiff | None = None,
    patch_diff: PatchDiff | None = None,
) -> NormalizedAction:
    """Normalize one post-execution changed file."""
    operation = _operation_from_changed_file(changed_file)
    affected_paths = _affected_paths_for_changed_file(changed_file)
    resource_kind = _dominant_resource_kind(affected_paths)
    diff_metadata = _diff_metadata(patch_file=patch_file, patch_diff=patch_diff)

    old_path = changed_file.old_path if changed_file.kind == ChangedFileKind.RENAMED else None
    new_path = changed_file.path if changed_file.kind == ChangedFileKind.RENAMED else None

    raw_evidence = {
        "kind": "changed_file",
        "changed_file_kind": changed_file.kind.value,
        "path": changed_file.path,
        "old_path": changed_file.old_path,
        "mode_changed": changed_file.mode_changed,
        "old_mode": changed_file.old_mode,
        "new_mode": changed_file.new_mode,
    }

    reason_codes = (
        "source:filesystem",
        f"changed_file_kind:{changed_file.kind.value}",
        f"operation:{operation.value}",
        f"resource_kind:{resource_kind.value}",
    )

    if patch_file is not None:
        reason_codes = (*reason_codes, "patch_metadata:present")
    else:
        reason_codes = (*reason_codes, "patch_metadata:absent")

    return NormalizedAction(
        action_id=_stable_action_id(
            source=NormalizedActionSource.FILESYSTEM,
            operation=operation,
            affected_paths=affected_paths,
            old_path=old_path,
            new_path=new_path,
            metadata={
                "changed_file_kind": changed_file.kind.value,
                "patch_sha256": patch_diff.patch_sha256 if patch_diff is not None else None,
            },
        ),
        source=NormalizedActionSource.FILESYSTEM,
        operation=operation,
        affected_paths=affected_paths,
        old_path=old_path,
        new_path=new_path,
        resource_kind=resource_kind,
        raw_evidence=raw_evidence,
        diff_metadata=diff_metadata,
        reason_codes=reason_codes,
    )


def normalize_changed_file_actions(
    changed_file_report: ChangedFileReport,
    *,
    patch_diff: PatchDiff | None = None,
) -> tuple[NormalizedAction, ...]:
    """Normalize all changed files in deterministic order."""
    patch_files_by_key = _patch_files_by_key(patch_diff)

    return tuple(
        normalize_changed_file_action(
            changed_file,
            patch_file=patch_files_by_key.get(_patch_lookup_key(changed_file)),
            patch_diff=patch_diff,
        )
        for changed_file in changed_file_report.files
    )


def normalize_guarded_actions(
    command: tuple[str, ...],
    *,
    changed_file_report: ChangedFileReport | None = None,
    patch_diff: PatchDiff | None = None,
) -> tuple[NormalizedAction, ...]:
    """Normalize guarded-run command intent and actual file effects."""
    command_action = normalize_command_action(command)

    if changed_file_report is None:
        return (command_action,)

    return (
        command_action,
        *normalize_changed_file_actions(changed_file_report, patch_diff=patch_diff),
    )


def normalized_actions_audit_summary(
    actions: tuple[NormalizedAction, ...],
) -> dict[str, object]:
    """Return a compact, audit-safe summary for normalized actions."""
    operation_counts: dict[str, int] = {}
    resource_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}

    for action in actions:
        operation_counts[action.operation.value] = (
            operation_counts.get(action.operation.value, 0) + 1
        )
        resource_counts[action.resource_kind.value] = (
            resource_counts.get(action.resource_kind.value, 0) + 1
        )
        source_counts[action.source.value] = source_counts.get(action.source.value, 0) + 1

    return {
        "action_count": len(actions),
        "operation_counts": operation_counts,
        "resource_kind_counts": resource_counts,
        "source_counts": source_counts,
        "actions": tuple(action.model_dump(mode="json") for action in actions),
    }


def _operation_from_command(command: tuple[str, ...]) -> IntentOperation:
    executable = _command_name(command)
    args = tuple(arg.lower() for arg in command[1:])

    if executable in {"rm", "rmdir", "unlink"}:
        return (
            IntentOperation.DELETE_FOLDER
            if any(arg in {"-r", "-rf", "-fr", "--recursive"} for arg in args)
            else IntentOperation.DELETE_FILE
        )

    if executable == "git" and args:
        if args[0] == "rm":
            return IntentOperation.DELETE_FILE
        if args[0] == "mv":
            return IntentOperation.MOVE

    if executable in {"mv", "rename"}:
        return IntentOperation.MOVE

    if executable in {"cp", "mkdir", "touch"}:
        return IntentOperation.CREATE

    if executable in {"pytest", "tox"}:
        return IntentOperation.TEST

    if executable in {"ruff"}:
        return IntentOperation.TEST

    if executable in {"python", "python3"} and any("pytest" in arg for arg in args):
        return IntentOperation.TEST

    if executable in {"cargo", "make", "mvn", "gradle"}:
        if "test" in args:
            return IntentOperation.TEST
        if "build" in args:
            return IntentOperation.BUILD

    if executable in {"npm", "pnpm", "yarn"}:
        if "test" in args:
            return IntentOperation.TEST
        if "build" in args:
            return IntentOperation.BUILD
        if any(arg in {"install", "add", "remove", "update"} for arg in args):
            return IntentOperation.DEPENDENCY_CHANGE

    if executable in {"pip", "pip3", "poetry", "uv"}:
        if any(arg in {"install", "add", "remove", "update", "sync"} for arg in args):
            return IntentOperation.DEPENDENCY_CHANGE

    return IntentOperation.COMMAND


def _operation_from_changed_file(changed_file: ChangedFile) -> IntentOperation:
    if changed_file.kind in {ChangedFileKind.ADDED, ChangedFileKind.UNTRACKED}:
        return IntentOperation.CREATE
    if changed_file.kind in {ChangedFileKind.MODIFIED, ChangedFileKind.MODE_CHANGED}:
        return IntentOperation.MODIFY
    if changed_file.kind == ChangedFileKind.DELETED:
        return IntentOperation.DELETE_FILE
    if changed_file.kind == ChangedFileKind.RENAMED:
        return IntentOperation.RENAME

    return IntentOperation.UNKNOWN


def _affected_paths_for_changed_file(changed_file: ChangedFile) -> tuple[str, ...]:
    if changed_file.kind == ChangedFileKind.RENAMED and changed_file.old_path is not None:
        return (changed_file.old_path, changed_file.path)

    return (changed_file.path,)


def _diff_metadata(
    *,
    patch_file: PatchFileDiff | None,
    patch_diff: PatchDiff | None,
) -> dict[str, Any]:
    if patch_file is None:
        return {
            "patch_present": patch_diff is not None,
            "file_patch_present": False,
        }

    return {
        "patch_present": patch_diff is not None,
        "file_patch_present": True,
        "patch_sha256": patch_diff.patch_sha256 if patch_diff is not None else None,
        "patch_size_bytes": patch_diff.patch_size_bytes if patch_diff is not None else None,
        "additions": patch_file.additions,
        "deletions": patch_file.deletions,
        "binary": patch_file.binary,
        "old_mode": patch_file.old_mode,
        "new_mode": patch_file.new_mode,
        "mode_changed": patch_file.mode_changed,
    }


def _patch_files_by_key(
    patch_diff: PatchDiff | None,
) -> dict[tuple[str | None, str], PatchFileDiff]:
    if patch_diff is None:
        return {}

    return {
        (patch_file.old_path, patch_file.path): patch_file for patch_file in patch_diff.files
    } | {(None, patch_file.path): patch_file for patch_file in patch_diff.files}


def _patch_lookup_key(changed_file: ChangedFile) -> tuple[str | None, str]:
    return (changed_file.old_path, changed_file.path)


def _command_name(command: tuple[str, ...]) -> str:
    if not command:
        return "unknown"

    return PurePosixPath(command[0]).name.lower() or "unknown"


def _extract_repo_paths(command: tuple[str, ...]) -> tuple[str, ...]:
    paths: list[str] = []
    skip_inline_payload = False

    for arg in command[1:]:
        if skip_inline_payload:
            skip_inline_payload = False
            continue

        if arg in _INLINE_CODE_OPTIONS:
            skip_inline_payload = True
            continue

        if not _looks_like_repo_path(arg):
            continue

        normalized = _normalize_candidate_path(arg)
        if normalized is None:
            continue

        paths.append(normalized)

    return tuple(dict.fromkeys(paths))


def _looks_like_repo_path(value: str) -> bool:
    if not value or value.startswith("-"):
        return False

    if "://" in value or "\n" in value or "\r" in value:
        return False

    if any(char in value for char in (" ", "\t", ";", "'", '"', "(", ")", "{", "}")):
        return False

    if "=" in value:
        return False

    if value in {".", ".."}:
        return False

    path = PurePosixPath(value)
    if path.is_absolute():
        return False

    name = path.name
    if value.startswith("./") or "/" in value:
        return True
    if name.startswith(".") and len(name) > 1:
        return True
    if "." in name:
        return True
    if name in _DEPENDENCY_MANIFESTS or name in _LOCKFILE_NAMES:
        return True

    return False


def _normalize_candidate_path(value: str) -> str | None:
    path = PurePosixPath(value)

    if any(part == ".." for part in path.parts):
        return None

    clean_parts = tuple(part for part in path.parts if part not in {"", "."})
    if not clean_parts:
        return None

    return PurePosixPath(*clean_parts).as_posix()


def _dominant_resource_kind(paths: tuple[str, ...]) -> ResourceKind:
    if not paths:
        return ResourceKind.UNKNOWN

    kinds = tuple(_resource_kind_for_path(path) for path in paths)

    for preferred in (
        ResourceKind.SENSITIVE,
        ResourceKind.POLICY,
        ResourceKind.CI_WORKFLOW,
        ResourceKind.DEPENDENCY_MANIFEST,
        ResourceKind.LOCKFILE,
        ResourceKind.CONFIG,
        ResourceKind.PYTHON_MODULE,
        ResourceKind.RUST_MODULE,
        ResourceKind.TEST,
    ):
        if preferred in kinds:
            return preferred

    return kinds[0]


def _resource_kind_for_path(path: str) -> ResourceKind:
    normalized = path.replace("\\", "/").strip()
    lowered = normalized.lower()
    name = PurePosixPath(normalized).name

    if _is_secret_path(lowered):
        return ResourceKind.SENSITIVE
    if normalized.startswith(".github/workflows/"):
        return ResourceKind.CI_WORKFLOW
    if name in _LOCKFILE_NAMES:
        return ResourceKind.LOCKFILE
    if name in _DEPENDENCY_MANIFESTS:
        return ResourceKind.DEPENDENCY_MANIFEST
    if _is_policy_path(lowered):
        return ResourceKind.POLICY
    if _is_test_path(lowered):
        return ResourceKind.TEST
    if lowered.endswith(".py"):
        return ResourceKind.PYTHON_MODULE
    if lowered.endswith(".rs"):
        return ResourceKind.RUST_MODULE
    if lowered.endswith((".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".conf")):
        return ResourceKind.CONFIG
    if lowered.endswith((".md", ".rst", ".txt")):
        return ResourceKind.DOCUMENTATION
    if "." not in name:
        return ResourceKind.DIRECTORY

    return ResourceKind.FILE


def _is_secret_path(lowered_path: str) -> bool:
    secret_tokens = (
        ".env",
        "credential",
        "credentials",
        "id_rsa",
        "private_key",
        "secret",
        "secrets",
        "token",
    )
    return any(token in lowered_path for token in secret_tokens)


def _is_policy_path(lowered_path: str) -> bool:
    return (
        lowered_path.startswith(".rygnal/")
        or "/policy" in lowered_path
        or lowered_path.startswith("policies/")
        or lowered_path.endswith("policy.yaml")
        or lowered_path.endswith("policy.yml")
    )


def _is_test_path(lowered_path: str) -> bool:
    path = PurePosixPath(lowered_path)
    return (
        lowered_path.startswith("tests/")
        or lowered_path.startswith("test/")
        or path.name.startswith("test_")
        or path.name.endswith("_test.py")
        or path.name.endswith("_test.rs")
    )


def _redacted_command(command: tuple[str, ...]) -> tuple[str, ...]:
    redacted: list[str] = []
    skip_inline_payload = False

    for arg in command:
        if skip_inline_payload:
            redacted.append("[REDACTED_INLINE_CODE]")
            skip_inline_payload = False
            continue

        redacted.append(_redact_command_arg(arg))

        if arg in _INLINE_CODE_OPTIONS:
            skip_inline_payload = True

    return tuple(redacted)


def _redact_command_arg(arg: str) -> str:
    lowered = arg.lower()

    if any(pattern.search(arg) for pattern in _SECRET_VALUE_PATTERNS):
        return "[REDACTED]"

    if any(key in lowered for key in _SECRET_ARG_KEYS):
        if "=" in arg:
            key, _value = arg.split("=", 1)
            return f"{key}=[REDACTED]"
        return "[REDACTED]"

    return arg


def _stable_action_id(
    *,
    source: NormalizedActionSource,
    operation: IntentOperation,
    affected_paths: tuple[str, ...],
    old_path: str | None,
    new_path: str | None,
    metadata: dict[str, Any],
) -> str:
    payload = {
        "source": source.value,
        "operation": operation.value,
        "affected_paths": affected_paths,
        "old_path": old_path,
        "new_path": new_path,
        "metadata": metadata,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    return f"normalized_action_{hashlib.sha256(encoded).hexdigest()[:24]}"
