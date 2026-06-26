from rygnal.intent_contract import (
    IntentContract,
    IntentContractSource,
    IntentOperation,
    ResourceScope,
    ResourceScopeType,
)
from rygnal.intent_evidence import (
    INTENT_EVIDENCE_SCHEMA_VERSION,
    intent_evidence_audit_summary,
)


def test_intent_evidence_summary_is_queryable_and_safe() -> None:
    contract = IntentContract(
        source=IntentContractSource.YAML,
        task_objective="Update docs",
        human_prompt="Please update docs. token=secret-value",
        ai_plan="I will only edit docs/readme.md.",
        evidence_source="chat",
        evidence_metadata={"conversation_id": "conv_1"},
        allowed_actions=(IntentOperation.MODIFY,),
        target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="docs/**"),),
    )

    summary = intent_evidence_audit_summary(contract)

    assert summary["schema_version"] == INTENT_EVIDENCE_SCHEMA_VERSION
    assert summary["human_prompt_present"] is True
    assert summary["ai_plan_present"] is True
    assert summary["evidence_source"] == "chat"
    assert summary["human_prompt_sha256"]
    assert summary["ai_plan_sha256"]
    assert summary["combined_evidence_hash"]
    assert summary["evidence_metadata_keys"] == ("conversation_id",)
    assert "secret-value" not in str(summary)
    assert "Please update docs" not in str(summary)
    assert "I will only edit" not in str(summary)
