"""Intent contract loading for CLI, API, and engine integrations."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from yaml import YAMLError

from rygnal.intent_contract import IntentContract

DEFAULT_INTENT_MAX_BYTES = 256 * 1024


class IntentLoadError(ValueError):
    """Raised when an intent contract cannot be loaded safely."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.details = dict(details or {})
        super().__init__(f"{code}: {message}")


def load_intent_contract_from_mapping(data: Mapping[str, Any]) -> IntentContract:
    """Validate an intent contract from a mapping object."""
    try:
        return IntentContract.model_validate(dict(data))
    except ValidationError as exc:
        raise IntentLoadError(
            "invalid_intent_contract",
            "Intent contract failed validation.",
            details={"errors": exc.errors(include_url=False, include_input=False)},
        ) from exc


def load_intent_contract_from_json_text(text: str) -> IntentContract:
    """Load an intent contract from a JSON document string."""
    _ensure_text_within_limit(text)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IntentLoadError(
            "invalid_intent_json",
            "Intent JSON is not valid.",
            details={"line": exc.lineno, "column": exc.colno, "position": exc.pos},
        ) from exc

    return _load_intent_contract_from_document(data)


def load_intent_contract_from_yaml_text(text: str) -> IntentContract:
    """Load an intent contract from a YAML document string."""
    _ensure_text_within_limit(text)

    try:
        data = yaml.safe_load(text)
    except YAMLError as exc:
        raise IntentLoadError(
            "invalid_intent_yaml",
            "Intent YAML is not valid.",
            details={"error_type": type(exc).__name__},
        ) from exc

    return _load_intent_contract_from_document(data)


def load_intent_contract_from_yaml_file(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_INTENT_MAX_BYTES,
) -> IntentContract:
    """Load an intent contract from a YAML file path."""
    intent_path = Path(path)

    if not intent_path.exists():
        raise IntentLoadError(
            "intent_file_not_found",
            "Intent file does not exist.",
            details={"path": str(intent_path)},
        )

    if not intent_path.is_file():
        raise IntentLoadError(
            "intent_path_not_file",
            "Intent path must point to a file.",
            details={"path": str(intent_path)},
        )

    size_bytes = intent_path.stat().st_size
    if size_bytes > max_bytes:
        raise IntentLoadError(
            "intent_file_too_large",
            "Intent file exceeds the configured size limit.",
            details={
                "path": str(intent_path),
                "size_bytes": size_bytes,
                "max_bytes": max_bytes,
            },
        )

    try:
        text = intent_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise IntentLoadError(
            "intent_file_read_error",
            "Intent file could not be read.",
            details={"path": str(intent_path), "error_type": type(exc).__name__},
        ) from exc

    return load_intent_contract_from_yaml_text(text)


def _load_intent_contract_from_document(data: object) -> IntentContract:
    if data is None:
        raise IntentLoadError(
            "empty_intent_contract",
            "Intent document must not be empty.",
        )

    if not isinstance(data, Mapping):
        raise IntentLoadError(
            "invalid_intent_document_shape",
            "Intent document must be a mapping/object.",
            details={"document_type": type(data).__name__},
        )

    return load_intent_contract_from_mapping(data)


def _ensure_text_within_limit(
    text: str,
    *,
    max_bytes: int = DEFAULT_INTENT_MAX_BYTES,
) -> None:
    size_bytes = len(text.encode("utf-8"))

    if size_bytes > max_bytes:
        raise IntentLoadError(
            "intent_text_too_large",
            "Intent document exceeds the configured size limit.",
            details={"size_bytes": size_bytes, "max_bytes": max_bytes},
        )
