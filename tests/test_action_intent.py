from rygnal.action_intent import (
    ActionIntentCode,
    ActionIntentRecommendation,
    ActionIntentSeverity,
    classify_action_intent,
    classify_command_intent,
    classify_diff_intent,
    classify_path_intent,
)


def test_test_command_is_low_risk_test_build_intent() -> None:
    report = classify_command_intent(("python", "-m", "pytest", "-q"))

    assert ActionIntentCode.TEST_OR_BUILD.value in report.intent_codes
    assert report.max_severity == ActionIntentSeverity.LOW
    assert report.recommended_action == ActionIntentRecommendation.ALLOW


def test_dependency_command_requires_approval() -> None:
    report = classify_command_intent(("pip", "install", "requests"))

    assert ActionIntentCode.DEPENDENCY_CHANGE.value in report.intent_codes
    assert ActionIntentCode.EXTERNAL_DOWNLOAD.value in report.intent_codes
    assert report.recommended_action == ActionIntentRecommendation.REQUIRE_APPROVAL


def test_recursive_force_delete_blocks_as_destructive_intent() -> None:
    report = classify_command_intent(("rm", "-rf", "dist"))

    assert ActionIntentCode.FILESYSTEM_DESTRUCTIVE.value in report.intent_codes
    assert report.max_severity == ActionIntentSeverity.CRITICAL
    assert report.recommended_action == ActionIntentRecommendation.BLOCK


def test_secret_path_blocks_as_credential_access() -> None:
    report = classify_path_intent((".env", "src/app.py"))

    assert ActionIntentCode.SECRET_OR_CREDENTIAL_ACCESS.value in report.intent_codes
    assert report.recommended_action == ActionIntentRecommendation.BLOCK


def test_ci_and_container_paths_require_approval() -> None:
    report = classify_path_intent((".github/workflows/ci.yml", "docker-compose.yml"))

    assert ActionIntentCode.DEPLOYMENT_OR_CI_CHANGE.value in report.intent_codes
    assert ActionIntentCode.CONTAINER_OR_INFRA_CHANGE.value in report.intent_codes
    assert report.recommended_action == ActionIntentRecommendation.REQUIRE_APPROVAL


def test_audit_approval_path_is_governance_sensitive() -> None:
    report = classify_path_intent(("src/rygnal/approval_queue.py",))

    assert ActionIntentCode.AUDIT_OR_APPROVAL_CHANGE.value in report.intent_codes
    assert report.recommended_action == ActionIntentRecommendation.REQUIRE_APPROVAL


def test_added_secret_like_content_is_detected() -> None:
    report = classify_diff_intent({"settings.py": ("API_KEY = 'sk-live-super-secret-token'",)})

    assert ActionIntentCode.SECRET_OR_CREDENTIAL_ACCESS.value in report.intent_codes
    assert report.recommended_action == ActionIntentRecommendation.BLOCK


def test_added_network_endpoint_is_detected() -> None:
    report = classify_diff_intent({"src/client.py": ("BASE_URL = 'https://example.com/api'",)})

    assert ActionIntentCode.NETWORK_ACCESS.value in report.intent_codes
    assert report.recommended_action == ActionIntentRecommendation.REQUIRE_APPROVAL


def test_approval_bypass_content_blocks() -> None:
    report = classify_diff_intent(
        {"src/rygnal/approval.py": ("# TODO: skip approval for agent changes",)}
    )

    assert ActionIntentCode.APPROVAL_BYPASS_ATTEMPT.value in report.intent_codes
    assert report.max_severity == ActionIntentSeverity.CRITICAL
    assert report.recommended_action == ActionIntentRecommendation.BLOCK


def test_mixed_intent_keeps_multiple_labels_and_highest_recommendation() -> None:
    report = classify_action_intent(
        command=("python", "-m", "pytest", "-q"),
        changed_paths=("requirements.txt", ".github/workflows/ci.yml"),
        added_lines_by_path={
            "src/client.py": ("url = 'https://example.com/download'",),
        },
    )

    assert ActionIntentCode.TEST_OR_BUILD.value in report.intent_codes
    assert ActionIntentCode.DEPENDENCY_CHANGE.value in report.intent_codes
    assert ActionIntentCode.DEPLOYMENT_OR_CI_CHANGE.value in report.intent_codes
    assert ActionIntentCode.NETWORK_ACCESS.value in report.intent_codes
    assert report.recommended_action == ActionIntentRecommendation.REQUIRE_APPROVAL


def test_unknown_inline_execution_is_ambiguous() -> None:
    report = classify_command_intent(("bash", "-c", "echo ok"))

    assert report.unknown_signals == ("bash:inline-execution",)
    assert ActionIntentCode.UNKNOWN_OR_AMBIGUOUS.value in report.intent_codes
    assert report.recommended_action == ActionIntentRecommendation.REQUIRE_APPROVAL


def test_audit_metadata_is_serializable_and_evidence_backed() -> None:
    report = classify_command_intent(("rm", "-rf", "tmp"))
    metadata = report.to_audit_metadata()

    assert metadata["max_severity"] == "critical"
    assert metadata["recommended_action"] == "block"
    assert metadata["intents"]
    assert metadata["intents"][0]["evidence"]


def test_privilege_escalation_command_blocks() -> None:
    report = classify_command_intent(("sudo", "chmod", "+s", "/usr/bin/python"))

    assert ActionIntentCode.PRIVILEGE_ESCALATION.value in report.intent_codes
    assert report.max_severity == ActionIntentSeverity.CRITICAL
    assert report.recommended_action == ActionIntentRecommendation.BLOCK


def test_inline_destructive_command_keeps_ambiguous_signal_and_blocks() -> None:
    report = classify_command_intent(("bash", "-c", "rm -rf tmp"))

    assert ActionIntentCode.FILESYSTEM_DESTRUCTIVE.value in report.intent_codes
    assert ActionIntentCode.UNKNOWN_OR_AMBIGUOUS.value in report.intent_codes
    assert report.unknown_signals == ("bash:inline-execution",)
    assert report.recommended_action == ActionIntentRecommendation.BLOCK


def test_encoded_dynamic_execution_is_bypass_and_ambiguous() -> None:
    report = classify_command_intent(("bash", "-c", "echo cm0gLXJmIHRtcA== | base64 -d | sh"))

    assert ActionIntentCode.APPROVAL_BYPASS_ATTEMPT.value in report.intent_codes
    assert ActionIntentCode.UNKNOWN_OR_AMBIGUOUS.value in report.intent_codes
    assert "bash:encoded-dynamic-execution" in report.unknown_signals
    assert "bash:inline-execution" in report.unknown_signals
    assert report.max_severity == ActionIntentSeverity.CRITICAL
    assert report.recommended_action == ActionIntentRecommendation.BLOCK


def test_dynamic_execution_content_is_ambiguous_even_without_direct_destructive_signal() -> None:
    report = classify_command_intent(("python", "-c", "import os; os.system(cmd)"))

    assert ActionIntentCode.UNKNOWN_OR_AMBIGUOUS.value in report.intent_codes
    assert "python:dynamic-execution" in report.unknown_signals
    assert "python:inline-execution" in report.unknown_signals
    assert report.recommended_action == ActionIntentRecommendation.REQUIRE_APPROVAL
