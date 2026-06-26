import json
from pathlib import Path

import pytest

from rygnal.intent_contract import IntentContract, IntentEnforcementMode, IntentOperation
from rygnal.intent_loader import (
    DEFAULT_INTENT_MAX_BYTES,
    IntentLoadError,
    load_intent_contract_from_json_text,
    load_intent_contract_from_mapping,
    load_intent_contract_from_yaml_file,
    load_intent_contract_from_yaml_text,
)

VALID_INTENT_MAPPING = {
    "source": "yaml",
    "task_objective": "Refactor authentication middleware",
    "allowed_actions": ["modify", "rename"],
    "target_scopes": [
        {"type": "path_glob", "value": "src/auth/**"},
        {"type": "path_glob", "value": "tests/auth/**"},
    ],
    "excluded_scopes": [{"type": "exact_path", "value": "src/auth/secrets.py"}],
    "risk_ceiling": 70,
    "enforcement_mode": "enforce",
}


def test_load_intent_contract_from_mapping() -> None:
    contract = load_intent_contract_from_mapping(VALID_INTENT_MAPPING)

    assert isinstance(contract, IntentContract)
    assert contract.task_objective == "Refactor authentication middleware"
    assert contract.allowed_actions == (IntentOperation.MODIFY, IntentOperation.RENAME)
    assert contract.enforcement_mode == IntentEnforcementMode.ENFORCE
    assert contract.target_scopes[0].value == "src/auth/**"


def test_load_intent_contract_from_json_text() -> None:
    contract = load_intent_contract_from_json_text(json.dumps(VALID_INTENT_MAPPING))

    assert contract.source == "yaml"
    assert contract.risk_ceiling == 70


def test_load_intent_contract_from_yaml_text() -> None:
    contract = load_intent_contract_from_yaml_text(
        """
source: yaml
task_objective: Refactor authentication middleware
allowed_actions:
  - modify
target_scopes:
  - type: path_glob
    value: src/auth/**
risk_ceiling: 60
enforcement_mode: shadow
"""
    )

    assert contract.allowed_actions == (IntentOperation.MODIFY,)
    assert contract.target_scopes[0].value == "src/auth/**"


def test_load_intent_contract_from_yaml_file(tmp_path: Path) -> None:
    intent_file = tmp_path / "intent.yaml"
    intent_file.write_text(
        """
source: yaml
task_objective: Run auth tests
allowed_actions:
  - test
enforcement_mode: shadow
""",
        encoding="utf-8",
    )

    contract = load_intent_contract_from_yaml_file(intent_file)

    assert contract.task_objective == "Run auth tests"
    assert contract.allowed_actions == (IntentOperation.TEST,)


@pytest.mark.parametrize(
    ("text", "expected_code"),
    [
        ("", "empty_intent_contract"),
        ("[]", "invalid_intent_document_shape"),
        ("source: [", "invalid_intent_yaml"),
    ],
)
def test_yaml_loader_returns_stable_error_codes(text: str, expected_code: str) -> None:
    with pytest.raises(IntentLoadError) as exc_info:
        load_intent_contract_from_yaml_text(text)

    assert exc_info.value.code == expected_code
    assert expected_code in str(exc_info.value)


def test_json_loader_rejects_invalid_json_with_location() -> None:
    with pytest.raises(IntentLoadError) as exc_info:
        load_intent_contract_from_json_text('{"source":')

    assert exc_info.value.code == "invalid_intent_json"
    assert exc_info.value.details["line"] == 1
    assert exc_info.value.details["column"]


def test_loader_wraps_pydantic_validation_errors() -> None:
    with pytest.raises(IntentLoadError) as exc_info:
        load_intent_contract_from_mapping(
            {
                "source": "json",
                "task_objective": "Modify source without a target scope",
                "allowed_actions": ["modify"],
            }
        )

    assert exc_info.value.code == "invalid_intent_contract"
    assert exc_info.value.details["errors"]


def test_yaml_file_loader_rejects_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yaml"

    with pytest.raises(IntentLoadError) as exc_info:
        load_intent_contract_from_yaml_file(missing)

    assert exc_info.value.code == "intent_file_not_found"
    assert exc_info.value.details["path"] == str(missing)


def test_yaml_file_loader_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(IntentLoadError) as exc_info:
        load_intent_contract_from_yaml_file(tmp_path)

    assert exc_info.value.code == "intent_path_not_file"


def test_yaml_file_loader_rejects_large_file(tmp_path: Path) -> None:
    intent_file = tmp_path / "large-intent.yaml"
    intent_file.write_text("x" * (DEFAULT_INTENT_MAX_BYTES + 1), encoding="utf-8")

    with pytest.raises(IntentLoadError) as exc_info:
        load_intent_contract_from_yaml_file(intent_file)

    assert exc_info.value.code == "intent_file_too_large"
    assert exc_info.value.details["size_bytes"] == DEFAULT_INTENT_MAX_BYTES + 1


def test_text_loader_rejects_large_document() -> None:
    with pytest.raises(IntentLoadError) as exc_info:
        load_intent_contract_from_json_text("x" * (DEFAULT_INTENT_MAX_BYTES + 1))

    assert exc_info.value.code == "intent_text_too_large"


def test_loader_accepts_prompt_plan_evidence_fields() -> None:
    contract = load_intent_contract_from_mapping(
        {
            "source": "yaml",
            "task_objective": "Update docs",
            "human_prompt": "Please update docs.",
            "ai_plan": "Edit docs only.",
            "evidence_source": "chat",
            "evidence_metadata": {"conversation_id": "conv_1"},
            "allowed_actions": ["modify"],
            "target_scopes": [{"type": "path_glob", "value": "docs/**"}],
        }
    )

    assert contract.human_prompt == "Please update docs."
    assert contract.ai_plan == "Edit docs only."
    assert contract.evidence_source == "chat"
    assert contract.evidence_metadata["conversation_id"] == "conv_1"
