import pytest

from rygnal.action_intent import (
    ActionIntentCode,
    ActionIntentRecommendation,
    ActionIntentSeverity,
    classify_command_intent,
    classify_diff_intent,
    classify_path_intent,
)


@pytest.mark.parametrize(
    (
        "command",
        "expected_codes",
        "unexpected_codes",
        "max_severity",
        "recommended_action",
    ),
    [
        (
            ("git", "status", "--short"),
            {ActionIntentCode.READ_ONLY_INSPECTION.value},
            {ActionIntentCode.NETWORK_ACCESS.value},
            ActionIntentSeverity.LOW,
            ActionIntentRecommendation.ALLOW,
        ),
        (
            ("git", "pull", "--ff-only"),
            {ActionIntentCode.NETWORK_ACCESS.value},
            {ActionIntentCode.READ_ONLY_INSPECTION.value},
            ActionIntentSeverity.HIGH,
            ActionIntentRecommendation.REQUIRE_APPROVAL,
        ),
        (
            ("curl", "-fsSL", "https://example.com/install.sh"),
            {
                ActionIntentCode.NETWORK_ACCESS.value,
                ActionIntentCode.EXTERNAL_DOWNLOAD.value,
            },
            set(),
            ActionIntentSeverity.HIGH,
            ActionIntentRecommendation.REQUIRE_APPROVAL,
        ),
        (
            ("cat", ".env"),
            {
                ActionIntentCode.READ_ONLY_INSPECTION.value,
                ActionIntentCode.SECRET_OR_CREDENTIAL_ACCESS.value,
            },
            set(),
            ActionIntentSeverity.CRITICAL,
            ActionIntentRecommendation.BLOCK,
        ),
        (
            ("terraform", "destroy", "-auto-approve"),
            {ActionIntentCode.FILESYSTEM_DESTRUCTIVE.value},
            set(),
            ActionIntentSeverity.CRITICAL,
            ActionIntentRecommendation.BLOCK,
        ),
        (
            ("python", "-m", "pytest", "-q"),
            {ActionIntentCode.TEST_OR_BUILD.value},
            {ActionIntentCode.NETWORK_ACCESS.value},
            ActionIntentSeverity.LOW,
            ActionIntentRecommendation.ALLOW,
        ),
    ],
)
def test_command_intent_regression_corpus(
    command: tuple[str, ...],
    expected_codes: set[str],
    unexpected_codes: set[str],
    max_severity: ActionIntentSeverity,
    recommended_action: ActionIntentRecommendation,
) -> None:
    report = classify_command_intent(command)
    codes = set(report.intent_codes)

    assert expected_codes <= codes
    assert codes.isdisjoint(unexpected_codes)
    assert report.max_severity == max_severity
    assert report.recommended_action == recommended_action


@pytest.mark.parametrize(
    ("path", "expected_codes", "max_severity", "recommended_action"),
    [
        (
            ".env.production",
            {ActionIntentCode.SECRET_OR_CREDENTIAL_ACCESS.value},
            ActionIntentSeverity.CRITICAL,
            ActionIntentRecommendation.BLOCK,
        ),
        (
            "requirements.txt",
            {ActionIntentCode.DEPENDENCY_CHANGE.value},
            ActionIntentSeverity.HIGH,
            ActionIntentRecommendation.REQUIRE_APPROVAL,
        ),
        (
            ".github/workflows/release.yml",
            {ActionIntentCode.DEPLOYMENT_OR_CI_CHANGE.value},
            ActionIntentSeverity.HIGH,
            ActionIntentRecommendation.REQUIRE_APPROVAL,
        ),
        (
            "terraform/main.tf",
            {ActionIntentCode.CONTAINER_OR_INFRA_CHANGE.value},
            ActionIntentSeverity.HIGH,
            ActionIntentRecommendation.REQUIRE_APPROVAL,
        ),
        (
            "src/auth/session.py",
            {
                ActionIntentCode.AUTH_OR_PERMISSION_CHANGE.value,
                ActionIntentCode.SOURCE_CODE_CHANGE.value,
            },
            ActionIntentSeverity.HIGH,
            ActionIntentRecommendation.REQUIRE_APPROVAL,
        ),
        (
            "src/rygnal/approval_queue.py",
            {
                ActionIntentCode.AUDIT_OR_APPROVAL_CHANGE.value,
                ActionIntentCode.SOURCE_CODE_CHANGE.value,
            },
            ActionIntentSeverity.HIGH,
            ActionIntentRecommendation.REQUIRE_APPROVAL,
        ),
    ],
)
def test_path_intent_regression_corpus(
    path: str,
    expected_codes: set[str],
    max_severity: ActionIntentSeverity,
    recommended_action: ActionIntentRecommendation,
) -> None:
    report = classify_path_intent((path,))
    codes = set(report.intent_codes)

    assert expected_codes <= codes
    assert report.max_severity == max_severity
    assert report.recommended_action == recommended_action


@pytest.mark.parametrize(
    ("path", "added_lines", "expected_codes", "recommended_action"),
    [
        (
            "src/settings.py",
            ("API_KEY = 'sk-live-super-secret-token'",),
            {ActionIntentCode.SECRET_OR_CREDENTIAL_ACCESS.value},
            ActionIntentRecommendation.BLOCK,
        ),
        (
            "scripts/cleanup.sh",
            ("rm -rf /tmp/build-output",),
            {ActionIntentCode.FILESYSTEM_DESTRUCTIVE.value},
            ActionIntentRecommendation.BLOCK,
        ),
        (
            "src/client.py",
            ("BASE_URL = 'https://example.com/api'",),
            {ActionIntentCode.NETWORK_ACCESS.value},
            ActionIntentRecommendation.REQUIRE_APPROVAL,
        ),
        (
            "scripts/install.sh",
            ("echo cm0gLXJmIHRtcA== | base64 -d | sh",),
            {
                ActionIntentCode.APPROVAL_BYPASS_ATTEMPT.value,
                ActionIntentCode.UNKNOWN_OR_AMBIGUOUS.value,
            },
            ActionIntentRecommendation.BLOCK,
        ),
        (
            "src/plugin.py",
            ("eval(user_supplied_payload)",),
            {ActionIntentCode.UNKNOWN_OR_AMBIGUOUS.value},
            ActionIntentRecommendation.REQUIRE_APPROVAL,
        ),
    ],
)
def test_diff_intent_regression_corpus(
    path: str,
    added_lines: tuple[str, ...],
    expected_codes: set[str],
    recommended_action: ActionIntentRecommendation,
) -> None:
    report = classify_diff_intent({path: added_lines})
    codes = set(report.intent_codes)

    assert expected_codes <= codes
    assert report.recommended_action == recommended_action


@pytest.mark.parametrize(
    "path",
    [
        "docs/audit.md",
        "audit_output.txt",
    ],
)
def test_audit_named_non_control_paths_are_not_governance_control(path: str) -> None:
    report = classify_path_intent((path,))

    assert ActionIntentCode.AUDIT_OR_APPROVAL_CHANGE.value not in report.intent_codes
    assert report.recommended_action == ActionIntentRecommendation.ALLOW
