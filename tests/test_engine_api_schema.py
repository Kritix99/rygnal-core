from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from rygnal.intent_contract import IntentOperation
from rygnal.schemas import EngineRequest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_engine_schema_files_exist_and_lock_protocol_version() -> None:
    request_schema = json.loads(
        (PROJECT_ROOT / "schemas/engine_request.schema.json").read_text(encoding="utf-8")
    )
    event_schema = json.loads(
        (PROJECT_ROOT / "schemas/engine_event.schema.json").read_text(encoding="utf-8")
    )

    assert request_schema["properties"]["protocol_version"]["const"] == "rygnal.engine.v1"
    assert event_schema["properties"]["protocol_version"]["const"] == "rygnal.engine.v1"


def test_engine_request_model_accepts_strict_valid_request(tmp_path: Path) -> None:
    request = EngineRequest.model_validate(
        {
            "protocol_version": "rygnal.engine.v1",
            "action": "guarded_run.start",
            "request_id": "schema-valid-test",
            "trusted_repo_path": tmp_path.resolve().as_posix(),
            "command": [sys.executable, "-c", "print('hello')"],
            "unsafe_local_requested": True,
        }
    )

    assert request.request_id == "schema-valid-test"
    assert request.command[0] == sys.executable
    assert request.unsafe_local_requested is True
    assert request.debug.include_raw_patch is False
    assert request.debug.include_stdout is False
    assert request.debug.include_stderr is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command", "python -c 'print(1)'"),
        ("trusted_repo_path", "."),
        ("run_root", "relative-runs"),
        ("audit_log_path", "relative-audit.jsonl"),
    ],
)
def test_engine_request_model_rejects_unsafe_shapes(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    payload = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "schema-invalid-test",
        "trusted_repo_path": tmp_path.resolve().as_posix(),
        "command": [sys.executable, "-c", "print('hello')"],
        "unsafe_local_requested": True,
    }
    payload[field] = value

    with pytest.raises(ValidationError):
        EngineRequest.model_validate(payload)


def test_engine_request_model_forbids_shell_true(tmp_path: Path) -> None:
    payload = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "schema-shell-test",
        "trusted_repo_path": tmp_path.resolve().as_posix(),
        "command": [sys.executable, "-c", "print('hello')"],
        "unsafe_local_requested": True,
        "shell": True,
    }

    with pytest.raises(ValidationError):
        EngineRequest.model_validate(payload)


def test_engine_request_model_accepts_intent_contract_json(tmp_path: Path) -> None:
    request = EngineRequest.model_validate(
        {
            "protocol_version": "rygnal.engine.v1",
            "action": "guarded_run.start",
            "request_id": "schema-intent-test",
            "trusted_repo_path": tmp_path.resolve().as_posix(),
            "command": [sys.executable, "-c", "print('hello')"],
            "unsafe_local_requested": True,
            "intent_contract": {
                "source": "json",
                "task_objective": "Refactor authentication middleware",
                "allowed_actions": ["modify"],
                "target_scopes": [
                    {
                        "type": "path_glob",
                        "value": "src/auth/**",
                    }
                ],
                "enforcement_mode": "shadow",
            },
        }
    )

    assert request.intent_contract is not None
    assert request.intent_contract.source == "json"
    assert request.intent_contract.allowed_actions == (IntentOperation.MODIFY,)
    assert request.intent_contract.target_scopes[0].value == "src/auth/**"


def test_engine_request_model_rejects_invalid_intent_contract(tmp_path: Path) -> None:
    payload = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "schema-invalid-intent-test",
        "trusted_repo_path": tmp_path.resolve().as_posix(),
        "command": [sys.executable, "-c", "print('hello')"],
        "unsafe_local_requested": True,
        "intent_contract": {
            "source": "json",
            "task_objective": "Modify source without target scope",
            "allowed_actions": ["modify"],
        },
    }

    with pytest.raises(ValidationError):
        EngineRequest.model_validate(payload)


def test_engine_request_schema_exposes_intent_contract() -> None:
    request_schema = json.loads(
        (PROJECT_ROOT / "schemas/engine_request.schema.json").read_text(encoding="utf-8")
    )

    intent_schema = request_schema["properties"]["intent_contract"]

    assert intent_schema["anyOf"][0]["$ref"] == "#/$defs/IntentContract"
    assert "IntentContract" in request_schema["$defs"]
    assert "ResourceScope" in request_schema["$defs"]
