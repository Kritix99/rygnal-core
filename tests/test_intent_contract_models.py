import pytest
from pydantic import ValidationError

from rygnal.intent_contract import (
    IntentContract,
    IntentContractSource,
    IntentDecisionHint,
    IntentEnforcementMode,
    IntentMatchResult,
    IntentMatchState,
    IntentOperation,
    NormalizedAction,
    NormalizedActionSource,
    ResourceKind,
    ResourceScope,
    ResourceScopeType,
)


def test_intent_contract_serializes_stable_json_shape() -> None:
    contract = IntentContract(
        source=IntentContractSource.YAML,
        task_objective="Refactor authentication middleware",
        allowed_actions=(IntentOperation.MODIFY, IntentOperation.RENAME),
        target_scopes=(
            ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/auth/**"),
            ResourceScope(type=ResourceScopeType.PATH_GLOB, value="tests/auth/**"),
        ),
        excluded_scopes=(
            ResourceScope(type=ResourceScopeType.EXACT_PATH, value="src/auth/secrets.py"),
        ),
        risk_ceiling=70,
        enforcement_mode=IntentEnforcementMode.ENFORCE,
        approved_by="local-user",
        metadata={"ticket": "#336"},
    )

    payload = contract.model_dump(mode="json")

    assert payload["protocol_version"] == "rygnal.intent.v1"
    assert payload["source"] == "yaml"
    assert payload["allowed_actions"] == ["modify", "rename"]
    assert payload["target_scopes"][0]["type"] == "path_glob"
    assert payload["excluded_scopes"][0]["value"] == "src/auth/secrets.py"
    assert payload["risk_ceiling"] == 70
    assert payload["enforcement_mode"] == "enforce"

    assert IntentContract.model_validate(payload) == contract


def test_intent_contract_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        IntentContract.model_validate(
            {
                "source": "json",
                "task_objective": "Update tests",
                "allowed_actions": ["test"],
                "unexpected": True,
            }
        )


def test_mutating_intent_requires_target_scope() -> None:
    with pytest.raises(ValidationError, match="target scope"):
        IntentContract(
            source=IntentContractSource.CLI,
            task_objective="Modify source code",
            allowed_actions=(IntentOperation.MODIFY,),
        )


def test_non_mutating_intent_can_omit_target_scope() -> None:
    contract = IntentContract(
        source=IntentContractSource.CLI,
        task_objective="Run test suite",
        allowed_actions=(IntentOperation.TEST,),
    )

    assert contract.target_scopes == ()
    assert contract.enforcement_mode == IntentEnforcementMode.SHADOW


def test_resource_scope_rejects_blank_value() -> None:
    with pytest.raises(ValidationError, match="blank"):
        ResourceScope(type=ResourceScopeType.PATH_GLOB, value="   ")


def test_normalized_action_serializes_rename_boundaries() -> None:
    action = NormalizedAction(
        source=NormalizedActionSource.PATCH,
        operation=IntentOperation.RENAME,
        affected_paths=("src/auth/old.py", "src/auth/new.py"),
        old_path="src/auth/old.py",
        new_path="src/auth/new.py",
        resource_kind=ResourceKind.PYTHON_MODULE,
        raw_evidence={"patch_id": "patch-1"},
        reason_codes=("rename-decomposed",),
    )

    payload = action.model_dump(mode="json")

    assert payload["source"] == "patch"
    assert payload["operation"] == "rename"
    assert payload["old_path"] == "src/auth/old.py"
    assert payload["new_path"] == "src/auth/new.py"
    assert payload["resource_kind"] == "python_module"

    assert NormalizedAction.model_validate(payload) == action


def test_normalized_action_requires_rename_old_and_new_paths() -> None:
    with pytest.raises(ValidationError, match="old_path and new_path"):
        NormalizedAction(
            source=NormalizedActionSource.TOOL_CALL,
            operation=IntentOperation.RENAME,
            old_path="src/auth/old.py",
        )


def test_normalized_action_rejects_blank_path_entries() -> None:
    with pytest.raises(ValidationError, match="blank"):
        NormalizedAction(
            source=NormalizedActionSource.DIFF,
            operation=IntentOperation.MODIFY,
            affected_paths=("src/auth/app.py", " "),
            resource_kind=ResourceKind.PYTHON_MODULE,
        )


def test_intent_match_result_serializes_exact_match() -> None:
    scope = ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/auth/**")
    result = IntentMatchResult(
        match_state=IntentMatchState.EXACT_MATCH,
        contract_id="intent_contract_1",
        action_id="action_1",
        matched_scopes=(scope,),
        decision_hint=IntentDecisionHint.ALLOW,
    )

    payload = result.model_dump(mode="json")

    assert payload["match_state"] == "exact_match"
    assert payload["decision_hint"] == "allow"
    assert payload["matched_scopes"][0]["value"] == "src/auth/**"

    assert IntentMatchResult.model_validate(payload) == result


def test_intent_match_result_requires_reason_codes_for_non_exact_state() -> None:
    with pytest.raises(ValidationError, match="reason codes"):
        IntentMatchResult(match_state=IntentMatchState.DRIFT)


def test_exact_match_cannot_have_unmatched_scopes() -> None:
    with pytest.raises(ValidationError, match="unmatched scopes"):
        IntentMatchResult(
            match_state=IntentMatchState.EXACT_MATCH,
            unmatched_scopes=(
                ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/payments/**"),
            ),
        )


def test_non_exact_match_keeps_reason_codes_and_hint() -> None:
    result = IntentMatchResult(
        match_state=IntentMatchState.PARTIAL_MATCH,
        unmatched_scopes=(
            ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/payments/**"),
        ),
        reason_codes=("scope-drift", "partial-resource-match"),
        decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
    )

    assert result.match_state == IntentMatchState.PARTIAL_MATCH
    assert result.reason_codes == ("scope-drift", "partial-resource-match")
    assert result.decision_hint == IntentDecisionHint.REQUIRE_APPROVAL


def test_intent_contract_accepts_human_prompt_and_ai_plan_evidence() -> None:
    contract = IntentContract(
        source=IntentContractSource.YAML,
        task_objective="Update docs",
        human_prompt="Human asked to update docs.",
        ai_plan="AI plans to edit docs only.",
        evidence_source="chat",
        evidence_metadata={"message_id": "msg_1"},
        allowed_actions=(IntentOperation.MODIFY,),
        target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="docs/**"),),
    )

    assert contract.human_prompt == "Human asked to update docs."
    assert contract.ai_plan == "AI plans to edit docs only."
    assert contract.evidence_source == "chat"
    assert contract.evidence_metadata["message_id"] == "msg_1"


def test_intent_contract_rejects_blank_human_prompt() -> None:
    with pytest.raises(ValidationError):
        IntentContract(
            source=IntentContractSource.YAML,
            task_objective="Update docs",
            human_prompt="   ",
            allowed_actions=(IntentOperation.TEST,),
        )
