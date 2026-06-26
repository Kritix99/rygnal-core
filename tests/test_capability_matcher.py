from rygnal.capability_matcher import (
    intent_match_results_audit_summary,
    match_action_to_contract,
    match_actions_to_contract,
)
from rygnal.intent_contract import (
    IntentContract,
    IntentContractSource,
    IntentDecisionHint,
    IntentMatchState,
    IntentOperation,
    NormalizedAction,
    NormalizedActionSource,
    ResourceKind,
    ResourceScope,
    ResourceScopeType,
)


def contract(
    *,
    allowed_actions: tuple[IntentOperation, ...],
    target_scopes: tuple[ResourceScope, ...] = (),
    excluded_scopes: tuple[ResourceScope, ...] = (),
) -> IntentContract:
    return IntentContract(
        source=IntentContractSource.YAML,
        task_objective="Test contract",
        allowed_actions=allowed_actions,
        target_scopes=target_scopes,
        excluded_scopes=excluded_scopes,
    )


def action(
    *,
    operation: IntentOperation,
    affected_paths: tuple[str, ...] = (),
    resource_kind: ResourceKind = ResourceKind.UNKNOWN,
) -> NormalizedAction:
    return NormalizedAction(
        action_id="action_test",
        source=NormalizedActionSource.FILESYSTEM,
        operation=operation,
        affected_paths=affected_paths,
        resource_kind=resource_kind,
    )


def test_exact_path_and_operation_match_allows_action() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.MODIFY,
            affected_paths=("src/auth/app.py",),
            resource_kind=ResourceKind.PYTHON_MODULE,
        ),
        contract(
            allowed_actions=(IntentOperation.MODIFY,),
            target_scopes=(
                ResourceScope(type=ResourceScopeType.EXACT_PATH, value="src/auth/app.py"),
            ),
        ),
    )

    assert result.match_state == IntentMatchState.EXACT_MATCH
    assert result.decision_hint == IntentDecisionHint.ALLOW
    assert result.matched_scopes[0].value == "src/auth/app.py"


def test_path_glob_match_allows_action_inside_scope() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.MODIFY,
            affected_paths=("src/auth/service.py",),
            resource_kind=ResourceKind.PYTHON_MODULE,
        ),
        contract(
            allowed_actions=(IntentOperation.MODIFY,),
            target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/auth/**"),),
        ),
    )

    assert result.match_state == IntentMatchState.EXACT_MATCH


def test_file_type_scope_matches_suffix() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.MODIFY,
            affected_paths=("src/auth/service.py",),
            resource_kind=ResourceKind.PYTHON_MODULE,
        ),
        contract(
            allowed_actions=(IntentOperation.MODIFY,),
            target_scopes=(ResourceScope(type=ResourceScopeType.FILE_TYPE, value="py"),),
        ),
    )

    assert result.match_state == IntentMatchState.EXACT_MATCH


def test_resource_kind_scope_matches_without_path() -> None:
    result = match_action_to_contract(
        action(operation=IntentOperation.TEST, resource_kind=ResourceKind.TEST),
        contract(
            allowed_actions=(IntentOperation.TEST,),
            target_scopes=(ResourceScope(type=ResourceScopeType.RESOURCE_KIND, value="test"),),
        ),
    )

    assert result.match_state == IntentMatchState.EXACT_MATCH


def test_symbol_scope_uses_resource_graph_module_name() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.MODIFY,
            affected_paths=("src/rygnal/resource_graph.py",),
            resource_kind=ResourceKind.PYTHON_MODULE,
        ),
        contract(
            allowed_actions=(IntentOperation.MODIFY,),
            target_scopes=(
                ResourceScope(
                    type=ResourceScopeType.SYMBOL,
                    value="rygnal.resource_graph",
                ),
            ),
        ),
    )

    assert result.match_state == IntentMatchState.EXACT_MATCH


def test_semantic_config_change_partially_matches_config_file_mutation() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.MODIFY,
            affected_paths=(".github/workflows/ci.yml",),
            resource_kind=ResourceKind.CI_WORKFLOW,
        ),
        contract(
            allowed_actions=(IntentOperation.CONFIG_CHANGE,),
            target_scopes=(ResourceScope(type=ResourceScopeType.RESOURCE_KIND, value="config"),),
        ),
    )

    assert result.match_state == IntentMatchState.PARTIAL_MATCH
    assert result.decision_hint == IntentDecisionHint.AUDIT
    assert "operation-semantic-match:config_change" in result.reason_codes


def test_semantic_dependency_change_partially_matches_lockfile_mutation() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.MODIFY,
            affected_paths=("uv.lock",),
            resource_kind=ResourceKind.LOCKFILE,
        ),
        contract(
            allowed_actions=(IntentOperation.DEPENDENCY_CHANGE,),
            target_scopes=(
                ResourceScope(type=ResourceScopeType.RESOURCE_KIND, value="dependency_manifest"),
            ),
        ),
    )

    assert result.match_state == IntentMatchState.PARTIAL_MATCH
    assert "operation-semantic-match:dependency_change" in result.reason_codes


def test_excluded_scope_conflicts_before_allowing_target_match() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.MODIFY,
            affected_paths=("src/auth/secrets.py",),
            resource_kind=ResourceKind.PYTHON_MODULE,
        ),
        contract(
            allowed_actions=(IntentOperation.MODIFY,),
            target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/auth/**"),),
            excluded_scopes=(
                ResourceScope(type=ResourceScopeType.EXACT_PATH, value="src/auth/secrets.py"),
            ),
        ),
    )

    assert result.match_state == IntentMatchState.CONFLICT
    assert result.decision_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert "excluded-scope-match" in result.reason_codes


def test_operation_not_allowed_conflicts() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.DELETE_FILE,
            affected_paths=("src/auth/app.py",),
            resource_kind=ResourceKind.PYTHON_MODULE,
        ),
        contract(
            allowed_actions=(IntentOperation.MODIFY,),
            target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/auth/**"),),
        ),
    )

    assert result.match_state == IntentMatchState.CONFLICT
    assert result.decision_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert "operation-not-allowed" in result.reason_codes


def test_target_scope_drift_requires_approval_hint() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.MODIFY,
            affected_paths=("src/payments/app.py",),
            resource_kind=ResourceKind.PYTHON_MODULE,
        ),
        contract(
            allowed_actions=(IntentOperation.MODIFY,),
            target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/auth/**"),),
        ),
    )

    assert result.match_state == IntentMatchState.DRIFT
    assert result.decision_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert result.unmatched_scopes[0].value == "src/auth/**"


def test_pathless_action_with_path_scope_is_unknown() -> None:
    result = match_action_to_contract(
        action(operation=IntentOperation.COMMAND),
        contract(
            allowed_actions=(IntentOperation.COMMAND,),
            target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/**"),),
        ),
    )

    assert result.match_state == IntentMatchState.UNKNOWN
    assert result.decision_hint == IntentDecisionHint.REQUIRE_APPROVAL
    assert "scope-unknown:no-affected-paths" in result.reason_codes


def test_secret_action_is_hard_sensitive_even_if_scope_matches() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.MODIFY,
            affected_paths=(".env",),
            resource_kind=ResourceKind.SECRET,
        ),
        contract(
            allowed_actions=(IntentOperation.MODIFY,),
            target_scopes=(ResourceScope(type=ResourceScopeType.EXACT_PATH, value=".env"),),
        ),
    )

    assert result.match_state == IntentMatchState.HARD_SENSITIVE
    assert result.decision_hint == IntentDecisionHint.BLOCK


def test_match_many_and_audit_summary_are_queryable() -> None:
    test_contract = contract(
        allowed_actions=(IntentOperation.MODIFY,),
        target_scopes=(ResourceScope(type=ResourceScopeType.PATH_GLOB, value="src/**"),),
    )
    results = match_actions_to_contract(
        (
            action(
                operation=IntentOperation.MODIFY,
                affected_paths=("src/app.py",),
                resource_kind=ResourceKind.PYTHON_MODULE,
            ),
            action(
                operation=IntentOperation.DELETE_FILE,
                affected_paths=("src/app.py",),
                resource_kind=ResourceKind.PYTHON_MODULE,
            ),
        ),
        test_contract,
    )

    summary = intent_match_results_audit_summary(results)

    assert summary["result_count"] == 2
    assert summary["match_state_counts"] == {"exact_match": 1, "conflict": 1}
    assert summary["decision_hint_counts"] == {"allow": 1, "require_approval": 1}


def test_multi_path_action_is_partial_when_only_some_paths_match_target_scope() -> None:
    result = match_action_to_contract(
        action(
            operation=IntentOperation.COMMAND,
            affected_paths=("docs/allowed/inside.md", "docs/outside.md"),
            resource_kind=ResourceKind.DOCUMENTATION,
        ),
        contract(
            allowed_actions=(IntentOperation.COMMAND,),
            target_scopes=(
                ResourceScope(type=ResourceScopeType.PATH_GLOB, value="docs/allowed/**"),
            ),
        ),
    )

    assert result.match_state == IntentMatchState.PARTIAL_MATCH
    assert result.decision_hint == IntentDecisionHint.AUDIT
    assert "target-scope-partial" in result.reason_codes
    assert result.metadata["out_of_scope_paths"] == ("docs/outside.md",)
