import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from rygnal.audit_logger import AuditLogger
from rygnal.guarded_runner import GuardedRunConfig, GuardedRunResult, GuardedRunStatus, run_guarded
from rygnal.intent_contract import (
    IntentContract,
    IntentContractSource,
    IntentDecisionHint,
    IntentEnforcementMode,
    IntentMatchState,
    IntentOperation,
    NormalizedActionSource,
    ResourceScope,
    ResourceScopeType,
)
from rygnal.intent_review import IntentReviewDecisionType
from rygnal.risk_engine import RiskLevel


def _run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _create_repo(path: Path) -> Path:
    path.mkdir()

    _run_git(path, "init")
    _run_git(path, "config", "user.email", "test@example.com")
    _run_git(path, "config", "user.name", "Test User")

    (path / "README.md").write_text("# Intent Scenario Repo\n", encoding="utf-8")
    (path / "docs" / "allowed").mkdir(parents=True)
    (path / "docs" / "allowed" / "existing.md").write_text("existing\n", encoding="utf-8")
    (path / "src").mkdir()
    (path / "src" / "app.py").write_text("print('baseline')\n", encoding="utf-8")

    _run_git(path, "add", ".")
    _run_git(path, "commit", "-m", "baseline")

    return path


def _commit_file(repo: Path, path: str, content: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", f"add {path}")


def _path_scope(value: str) -> ResourceScope:
    return ResourceScope(type=ResourceScopeType.PATH_GLOB, value=value)


def _contract(
    *,
    target: str = "docs/allowed/**",
    mode: IntentEnforcementMode = IntentEnforcementMode.ENFORCE,
    allowed_actions: tuple[IntentOperation, ...] = (
        IntentOperation.COMMAND,
        IntentOperation.CREATE,
        IntentOperation.MODIFY,
        IntentOperation.RENAME,
    ),
    excluded_scopes: tuple[ResourceScope, ...] = (),
) -> IntentContract:
    return IntentContract(
        source=IntentContractSource.YAML,
        task_objective="End-to-end intent enforcement scenario",
        allowed_actions=allowed_actions,
        target_scopes=(_path_scope(target),),
        excluded_scopes=excluded_scopes,
        enforcement_mode=mode,
    )


def _write_paths_command(*paths: str, content: str = "scenario\n") -> tuple[str, ...]:
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "for raw_path in sys.argv[1:]:\n"
        "    path = Path(raw_path)\n"
        "    path.parent.mkdir(parents=True, exist_ok=True)\n"
        f"    path.write_text({content!r}, encoding='utf-8')\n"
    )
    return (sys.executable, "-c", code, *paths)


def _rename_command(old_path: str, new_path: str) -> tuple[str, ...]:
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "old_path = Path(sys.argv[1])\n"
        "new_path = Path(sys.argv[2])\n"
        "new_path.parent.mkdir(parents=True, exist_ok=True)\n"
        "old_path.rename(new_path)\n"
    )
    return (sys.executable, "-c", code, old_path, new_path)


def _pathless_command() -> tuple[str, ...]:
    return (sys.executable, "-c", "print('pathless intent scenario')")


def _run_intent_scenario(
    *,
    tmp_path: Path,
    repo: Path,
    command: tuple[str, ...],
    contract: IntentContract,
) -> tuple[GuardedRunResult, AuditLogger]:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    result = run_guarded(
        GuardedRunConfig(
            trusted_repo_path=repo,
            command=command,
            timeout_seconds=5,
            rygnal_run_root=tmp_path / "rygnal-runs",
            unsafe_local_requested=True,
            trace_id="trace_intent_scenario",
            intent_contract=contract,
            audit_logger=audit,
        )
    )
    return result, audit


def _intent_event(audit: AuditLogger) -> Any:
    events = [
        event for event in audit.read_events() if event.action == "guarded_run.intent_evaluated"
    ]
    assert events
    return events[-1]


def _actions_by_id(result: GuardedRunResult) -> dict[str, Any]:
    return {action.action_id: action for action in result.normalized_actions}


def _match_states(result: GuardedRunResult) -> tuple[IntentMatchState, ...]:
    return tuple(match.match_state for match in result.intent_match_results)


def _filesystem_match_states(result: GuardedRunResult) -> tuple[IntentMatchState, ...]:
    actions_by_id = _actions_by_id(result)
    return tuple(
        match.match_state
        for match in result.intent_match_results
        if match.action_id is not None
        and actions_by_id[match.action_id].source == NormalizedActionSource.FILESYSTEM
    )


def _reason_codes(result: GuardedRunResult) -> tuple[str, ...]:
    codes: list[str] = []
    if result.intent_fallback_evaluation is not None:
        codes.extend(result.intent_fallback_evaluation.reason_codes)

    for match in result.intent_match_results:
        codes.extend(match.reason_codes)

    return tuple(dict.fromkeys(codes))


def _affected_resource_paths(result: GuardedRunResult) -> tuple[str | None, ...]:
    assert result.intent_review_decision is not None
    return tuple(
        resource["path"]
        for resource in result.intent_review_decision.affected_resources
        if "path" in resource
    )


def _assert_intent_trace(result: GuardedRunResult, audit: AuditLogger) -> None:
    assert result.intent_match_results
    assert result.intent_fallback_evaluation is not None
    assert result.intent_decision_receipt is not None
    assert result.intent_review_decision is not None

    event = _intent_event(audit)
    assert event.metadata["intent_matches"]["result_count"] == len(result.intent_match_results)
    assert event.metadata["intent_fallback"]["effective_hint"] == (
        result.intent_fallback_evaluation.effective_hint.value
    )
    assert event.metadata["intent_receipt"]["receipt_hash"] == (
        result.intent_decision_receipt.receipt_hash
    )
    assert (
        event.metadata["intent_review"]["decision"] == result.intent_review_decision.decision.value
    )


def test_matched_intent_inside_scope_permits_and_records_true_risk(
    tmp_path: Path,
) -> None:
    repo = _create_repo(tmp_path / "repo")

    result, audit = _run_intent_scenario(
        tmp_path=tmp_path,
        repo=repo,
        command=_write_paths_command("docs/allowed/new.md"),
        contract=_contract(),
    )

    assert result.status == GuardedRunStatus.COMPLETED
    assert result.intent_fallback_evaluation is not None
    assert result.intent_fallback_evaluation.match_state == IntentMatchState.EXACT_MATCH
    assert result.intent_fallback_evaluation.effective_hint == IntentDecisionHint.ALLOW
    assert set(_filesystem_match_states(result)) == {IntentMatchState.EXACT_MATCH}
    assert result.change_risk_report is not None
    assert result.change_risk_report.overall_risk_level == RiskLevel.LOW
    assert result.intent_review_decision is not None
    assert result.intent_review_decision.true_risk_level == "low"
    assert result.intent_review_decision.decision == IntentReviewDecisionType.SILENT_PERMIT
    assert "docs/allowed/new.md" in _affected_resource_paths(result)
    assert not (repo / "docs" / "allowed" / "new.md").exists()

    _assert_intent_trace(result, audit)


@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_hint", "expected_review"),
    (
        (
            IntentEnforcementMode.DISABLED,
            GuardedRunStatus.COMPLETED,
            IntentDecisionHint.NONE,
            IntentReviewDecisionType.SILENT_PERMIT,
        ),
        (
            IntentEnforcementMode.SHADOW,
            GuardedRunStatus.COMPLETED,
            IntentDecisionHint.AUDIT,
            IntentReviewDecisionType.SHADOW_ONLY_TRACE,
        ),
        (
            IntentEnforcementMode.ENFORCE,
            GuardedRunStatus.APPROVAL_REQUIRED,
            IntentDecisionHint.REQUIRE_APPROVAL,
            IntentReviewDecisionType.SCOPE_EXPANSION_SUGGESTED,
        ),
    ),
)
def test_scope_drift_respects_disabled_shadow_and_enforce_modes(
    tmp_path: Path,
    mode: IntentEnforcementMode,
    expected_status: GuardedRunStatus,
    expected_hint: IntentDecisionHint,
    expected_review: IntentReviewDecisionType,
) -> None:
    repo = _create_repo(tmp_path / "repo")

    result, audit = _run_intent_scenario(
        tmp_path=tmp_path,
        repo=repo,
        command=_write_paths_command("docs/outside.md"),
        contract=_contract(mode=mode),
    )

    assert result.status == expected_status
    assert result.intent_fallback_evaluation is not None
    assert result.intent_fallback_evaluation.match_state == IntentMatchState.DRIFT
    assert result.intent_fallback_evaluation.effective_hint == expected_hint
    assert result.intent_review_decision is not None
    assert result.intent_review_decision.decision == expected_review
    assert "target-scope-drift" in _reason_codes(result)
    assert "docs/outside.md" in _affected_resource_paths(result)
    assert not (repo / "docs" / "outside.md").exists()

    _assert_intent_trace(result, audit)


def test_partial_compound_action_preserves_mixed_scope_result(
    tmp_path: Path,
) -> None:
    repo = _create_repo(tmp_path / "repo")

    result, audit = _run_intent_scenario(
        tmp_path=tmp_path,
        repo=repo,
        command=_write_paths_command("docs/allowed/inside.md", "docs/outside.md"),
        contract=_contract(),
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert IntentMatchState.PARTIAL_MATCH in _match_states(result)
    assert IntentMatchState.DRIFT in _match_states(result)
    assert "target-scope-partial" in _reason_codes(result)
    assert "docs/allowed/inside.md" in _affected_resource_paths(result)
    assert "docs/outside.md" in _affected_resource_paths(result)

    _assert_intent_trace(result, audit)


def test_excluded_scope_wins_over_broad_allowed_scope(
    tmp_path: Path,
) -> None:
    repo = _create_repo(tmp_path / "repo")
    excluded = ResourceScope(type=ResourceScopeType.PATH_GLOB, value="docs/private/**")

    result, audit = _run_intent_scenario(
        tmp_path=tmp_path,
        repo=repo,
        command=_write_paths_command("docs/private/internal.md"),
        contract=_contract(target="docs/**", excluded_scopes=(excluded,)),
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert IntentMatchState.CONFLICT in _match_states(result)
    assert result.intent_fallback_evaluation is not None
    assert result.intent_fallback_evaluation.effective_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert "excluded-scope-match" in _reason_codes(result)
    assert "docs/private/internal.md" in _affected_resource_paths(result)

    _assert_intent_trace(result, audit)


def test_sensitive_boundary_denies_representative_secret_resource(
    tmp_path: Path,
) -> None:
    repo = _create_repo(tmp_path / "repo")

    result, audit = _run_intent_scenario(
        tmp_path=tmp_path,
        repo=repo,
        command=_write_paths_command(".env", content="TOKEN=super-secret\n"),
        contract=_contract(),
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert IntentMatchState.HARD_SENSITIVE in _match_states(result)
    assert result.intent_fallback_evaluation is not None
    assert result.intent_fallback_evaluation.effective_hint == IntentDecisionHint.BLOCK
    assert result.intent_review_decision is not None
    assert result.intent_review_decision.decision == IntentReviewDecisionType.POLICY_DENY
    assert result.intent_review_decision.true_risk_level == "critical"
    assert "hard-sensitive-resource" in _reason_codes(result)

    _assert_intent_trace(result, audit)


def test_unknown_pathless_action_requires_review_in_enforce_mode(
    tmp_path: Path,
) -> None:
    repo = _create_repo(tmp_path / "repo")

    result, audit = _run_intent_scenario(
        tmp_path=tmp_path,
        repo=repo,
        command=_pathless_command(),
        contract=_contract(
            allowed_actions=(IntentOperation.COMMAND,),
            mode=IntentEnforcementMode.ENFORCE,
        ),
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.changed_file_report is not None
    assert result.changed_file_report.changed_file_count == 0
    assert result.intent_fallback_evaluation is not None
    assert result.intent_fallback_evaluation.match_state == IntentMatchState.UNKNOWN
    assert result.intent_fallback_evaluation.effective_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert result.intent_review_decision is not None
    assert result.intent_review_decision.true_risk_level == "high"
    assert "scope-unknown:no-affected-paths" in _reason_codes(result)

    _assert_intent_trace(result, audit)


def test_move_into_sensitive_boundary_is_not_missed(
    tmp_path: Path,
) -> None:
    repo = _create_repo(tmp_path / "repo")

    result, audit = _run_intent_scenario(
        tmp_path=tmp_path,
        repo=repo,
        command=_rename_command("src/app.py", ".env"),
        contract=_contract(
            target="src/**",
            allowed_actions=(
                IntentOperation.COMMAND,
                IntentOperation.RENAME,
                IntentOperation.DELETE_FILE,
                IntentOperation.CREATE,
            ),
        ),
    )

    assert result.status == GuardedRunStatus.BLOCKED
    assert IntentMatchState.HARD_SENSITIVE in _match_states(result)
    assert result.intent_fallback_evaluation is not None
    assert result.intent_fallback_evaluation.effective_hint == IntentDecisionHint.BLOCK
    assert result.intent_review_decision is not None
    assert result.intent_review_decision.decision == IntentReviewDecisionType.POLICY_DENY
    assert ".env" in _affected_resource_paths(result)
    assert (repo / "src" / "app.py").exists()
    assert not (repo / ".env").exists()

    _assert_intent_trace(result, audit)


def test_rust_criticality_and_intent_reasoning_are_both_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = _create_repo(tmp_path / "repo")
    captured: dict[str, Any] = {}

    def fake_evaluate(criticality_input: Any) -> RustCriticalityAssessment:
        captured["input"] = criticality_input
        return RustCriticalityAssessment(
            criticality_index=10.0,
            risk_level="critical",
            reasons=("scenario-rust-criticality",),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=0,
                new_node_count=1,
                old_token_count=0,
                new_token_count=3,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="source",
            path_severity="medium",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    result, audit = _run_intent_scenario(
        tmp_path=tmp_path,
        repo=repo,
        command=_write_paths_command("docs/allowed/rust_shadow.py", content="print('x')\n"),
        contract=_contract(),
    )

    assert result.status == GuardedRunStatus.APPROVAL_REQUIRED
    assert result.change_risk_report is not None
    assert result.change_risk_report.overall_risk_level == RiskLevel.HIGH
    assert result.intent_fallback_evaluation is not None
    assert result.intent_fallback_evaluation.match_state == IntentMatchState.EXACT_MATCH
    assert result.intent_fallback_evaluation.effective_hint == IntentDecisionHint.ALLOW
    assert result.intent_review_decision is not None
    assert result.intent_review_decision.true_risk_level == "high"
    assert result.intent_review_decision.decision == IntentReviewDecisionType.SILENT_PERMIT

    file_risk = next(
        file
        for file in result.change_risk_report.files
        if file.path == "docs/allowed/rust_shadow.py"
    )
    assert file_risk.audit_summary["rust_criticality"]["available"] is True
    assert file_risk.audit_summary["rust_criticality"]["risk_level"] == "critical"
    assert captured["input"].file_path == "docs/allowed/rust_shadow.py"

    _assert_intent_trace(result, audit)
