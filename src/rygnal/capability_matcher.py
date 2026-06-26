"""Semantic capability matching for intent-governed actions.

This module compares normalized actions against an intent contract and returns
structured match results. It does not enforce policy or block execution.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

from rygnal.changed_files import normalize_repo_relative_path
from rygnal.intent_contract import (
    IntentContract,
    IntentDecisionHint,
    IntentMatchResult,
    IntentMatchState,
    IntentOperation,
    NormalizedAction,
    ResourceKind,
    ResourceScope,
    ResourceScopeType,
)
from rygnal.resource_graph import ResourceGraph, build_resource_graph_from_paths

_SENSITIVE_RESOURCE_KINDS = frozenset(
    {
        ResourceKind.SECRET,
    }
)

_CONFIG_RESOURCE_KINDS = frozenset(
    {
        ResourceKind.CONFIG,
        ResourceKind.CI_WORKFLOW,
        ResourceKind.POLICY,
    }
)

_DEPENDENCY_RESOURCE_KINDS = frozenset(
    {
        ResourceKind.DEPENDENCY_MANIFEST,
        ResourceKind.LOCKFILE,
    }
)

_MUTATING_OPERATIONS = frozenset(
    {
        IntentOperation.CREATE,
        IntentOperation.MODIFY,
        IntentOperation.DELETE_FILE,
        IntentOperation.DELETE_FOLDER,
        IntentOperation.RENAME,
        IntentOperation.MOVE,
    }
)


@dataclass(frozen=True)
class _OperationMatch:
    allowed: bool
    exact: bool
    reason_codes: tuple[str, ...]


def match_actions_to_contract(
    actions: Iterable[NormalizedAction],
    contract: IntentContract,
) -> tuple[IntentMatchResult, ...]:
    """Match many normalized actions against one intent contract."""
    return tuple(match_action_to_contract(action, contract) for action in actions)


def match_action_to_contract(
    action: NormalizedAction,
    contract: IntentContract,
) -> IntentMatchResult:
    """Return a structured semantic match result for one action."""
    action_paths, path_reason_codes = _normalized_action_paths(action)
    graph = _safe_graph_for_paths(action_paths)

    metadata = {
        "action_operation": action.operation.value,
        "action_resource_kind": action.resource_kind.value,
        "affected_paths": action_paths,
        "target_scope_count": len(contract.target_scopes),
        "excluded_scope_count": len(contract.excluded_scopes),
    }

    if action.resource_kind in _SENSITIVE_RESOURCE_KINDS:
        return IntentMatchResult(
            match_state=IntentMatchState.HARD_SENSITIVE,
            contract_id=contract.contract_id,
            action_id=action.action_id,
            reason_codes=(
                "hard-sensitive-resource",
                f"resource_kind:{action.resource_kind.value}",
            ),
            decision_hint=IntentDecisionHint.BLOCK,
            metadata=metadata,
        )

    if path_reason_codes:
        return IntentMatchResult(
            match_state=IntentMatchState.UNKNOWN,
            contract_id=contract.contract_id,
            action_id=action.action_id,
            reason_codes=path_reason_codes,
            decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
            metadata=metadata,
        )

    excluded_matches = _matching_scopes(
        contract.excluded_scopes,
        action=action,
        action_paths=action_paths,
        graph=graph,
    )
    if excluded_matches:
        return IntentMatchResult(
            match_state=IntentMatchState.CONFLICT,
            contract_id=contract.contract_id,
            action_id=action.action_id,
            matched_scopes=excluded_matches,
            reason_codes=("excluded-scope-match",),
            decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
            metadata={
                **metadata,
                "matched_excluded_scope_count": len(excluded_matches),
            },
        )

    operation_match = _operation_allowed(action, contract)
    if not operation_match.allowed:
        match_state = (
            IntentMatchState.UNKNOWN
            if action.operation == IntentOperation.UNKNOWN
            else IntentMatchState.CONFLICT
        )
        return IntentMatchResult(
            match_state=match_state,
            contract_id=contract.contract_id,
            action_id=action.action_id,
            reason_codes=operation_match.reason_codes,
            decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
            metadata=metadata,
        )

    if not contract.target_scopes:
        if operation_match.exact:
            return IntentMatchResult(
                match_state=IntentMatchState.EXACT_MATCH,
                contract_id=contract.contract_id,
                action_id=action.action_id,
                decision_hint=IntentDecisionHint.ALLOW,
                metadata=metadata,
            )

        return IntentMatchResult(
            match_state=IntentMatchState.PARTIAL_MATCH,
            contract_id=contract.contract_id,
            action_id=action.action_id,
            reason_codes=operation_match.reason_codes,
            decision_hint=IntentDecisionHint.AUDIT,
            metadata=metadata,
        )

    if not action_paths and _requires_path_or_graph_scope(contract.target_scopes):
        return IntentMatchResult(
            match_state=IntentMatchState.UNKNOWN,
            contract_id=contract.contract_id,
            action_id=action.action_id,
            unmatched_scopes=contract.target_scopes,
            reason_codes=("scope-unknown:no-affected-paths",),
            decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
            metadata=metadata,
        )

    matched_scopes = _matching_scopes(
        contract.target_scopes,
        action=action,
        action_paths=action_paths,
        graph=graph,
    )

    if not matched_scopes:
        return IntentMatchResult(
            match_state=IntentMatchState.DRIFT,
            contract_id=contract.contract_id,
            action_id=action.action_id,
            unmatched_scopes=contract.target_scopes,
            reason_codes=("target-scope-drift",),
            decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
            metadata=metadata,
        )

    if operation_match.exact:
        return IntentMatchResult(
            match_state=IntentMatchState.EXACT_MATCH,
            contract_id=contract.contract_id,
            action_id=action.action_id,
            matched_scopes=matched_scopes,
            decision_hint=IntentDecisionHint.ALLOW,
            metadata={
                **metadata,
                "matched_target_scope_count": len(matched_scopes),
            },
        )

    return IntentMatchResult(
        match_state=IntentMatchState.PARTIAL_MATCH,
        contract_id=contract.contract_id,
        action_id=action.action_id,
        matched_scopes=matched_scopes,
        reason_codes=operation_match.reason_codes,
        decision_hint=IntentDecisionHint.AUDIT,
        metadata={
            **metadata,
            "matched_target_scope_count": len(matched_scopes),
        },
    )


def intent_match_results_audit_summary(
    results: Iterable[IntentMatchResult],
) -> dict[str, object]:
    """Return a queryable, audit-safe summary for match results."""
    result_tuple = tuple(results)
    state_counts: dict[str, int] = {}
    hint_counts: dict[str, int] = {}

    for result in result_tuple:
        state_counts[result.match_state.value] = state_counts.get(result.match_state.value, 0) + 1
        hint_counts[result.decision_hint.value] = hint_counts.get(result.decision_hint.value, 0) + 1

    return {
        "result_count": len(result_tuple),
        "match_state_counts": state_counts,
        "decision_hint_counts": hint_counts,
        "results": tuple(result.model_dump(mode="json") for result in result_tuple),
    }


def _operation_allowed(action: NormalizedAction, contract: IntentContract) -> _OperationMatch:
    if action.operation in contract.allowed_actions:
        return _OperationMatch(
            allowed=True,
            exact=True,
            reason_codes=(f"operation-exact:{action.operation.value}",),
        )

    semantic_reason = _semantic_operation_reason(action, contract)
    if semantic_reason is not None:
        return _OperationMatch(
            allowed=True,
            exact=False,
            reason_codes=(semantic_reason,),
        )

    return _OperationMatch(
        allowed=False,
        exact=False,
        reason_codes=(
            "operation-not-allowed",
            f"action_operation:{action.operation.value}",
            "allowed_actions:" + ",".join(action.value for action in contract.allowed_actions),
        ),
    )


def _semantic_operation_reason(
    action: NormalizedAction,
    contract: IntentContract,
) -> str | None:
    if (
        IntentOperation.CONFIG_CHANGE in contract.allowed_actions
        and action.operation in _MUTATING_OPERATIONS
        and action.resource_kind in _CONFIG_RESOURCE_KINDS
    ):
        return "operation-semantic-match:config_change"

    if (
        IntentOperation.DEPENDENCY_CHANGE in contract.allowed_actions
        and action.operation in _MUTATING_OPERATIONS
        and action.resource_kind in _DEPENDENCY_RESOURCE_KINDS
    ):
        return "operation-semantic-match:dependency_change"

    return None


def _matching_scopes(
    scopes: tuple[ResourceScope, ...],
    *,
    action: NormalizedAction,
    action_paths: tuple[str, ...],
    graph: ResourceGraph,
) -> tuple[ResourceScope, ...]:
    return tuple(
        scope
        for scope in scopes
        if _scope_matches(scope, action=action, action_paths=action_paths, graph=graph)
    )


def _scope_matches(
    scope: ResourceScope,
    *,
    action: NormalizedAction,
    action_paths: tuple[str, ...],
    graph: ResourceGraph,
) -> bool:
    if scope.resource_kind is not None and not _resource_kind_matches(scope.resource_kind, action):
        return False

    if scope.type == ResourceScopeType.EXACT_PATH:
        return _matches_exact_path(scope.value, action_paths)

    if scope.type == ResourceScopeType.PATH_GLOB:
        return _matches_path_glob(scope.value, action_paths)

    if scope.type == ResourceScopeType.FILE_TYPE:
        return _matches_file_type(scope.value, action_paths)

    if scope.type == ResourceScopeType.RESOURCE_KIND:
        return _matches_resource_kind_scope(scope, action)

    if scope.type == ResourceScopeType.SYMBOL:
        return _matches_symbol(scope.value, graph)

    return False


def _matches_exact_path(scope_value: str, action_paths: tuple[str, ...]) -> bool:
    try:
        expected = normalize_repo_relative_path(scope_value)
    except Exception:
        return False

    return expected in action_paths


def _matches_path_glob(scope_value: str, action_paths: tuple[str, ...]) -> bool:
    pattern = scope_value.strip().replace("\\", "/").lstrip("/")
    return any(fnmatchcase(path, pattern) for path in action_paths)


def _matches_file_type(scope_value: str, action_paths: tuple[str, ...]) -> bool:
    suffix = scope_value.strip().lower()
    if not suffix:
        return False
    if not suffix.startswith("."):
        suffix = f".{suffix}"

    return any(PurePosixPath(path).name.lower().endswith(suffix) for path in action_paths)


def _matches_resource_kind_scope(scope: ResourceScope, action: NormalizedAction) -> bool:
    expected = scope.resource_kind

    if expected is None:
        try:
            expected = ResourceKind(scope.value.strip().lower())
        except ValueError:
            return False

    return _resource_kind_matches(expected, action)


def _resource_kind_matches(expected: ResourceKind, action: NormalizedAction) -> bool:
    if action.resource_kind == expected:
        return True

    if expected == ResourceKind.CONFIG and action.resource_kind in _CONFIG_RESOURCE_KINDS:
        return True

    if (
        expected == ResourceKind.DEPENDENCY_MANIFEST
        and action.resource_kind in _DEPENDENCY_RESOURCE_KINDS
    ):
        return True

    return False


def _matches_symbol(scope_value: str, graph: ResourceGraph) -> bool:
    expected = scope_value.strip()
    if not expected:
        return False

    return any(
        node.name == expected or node.node_id == expected
        for node in graph.nodes
        if node.kind
        in {
            ResourceKind.PYTHON_MODULE,
            ResourceKind.PYTHON_SYMBOL,
            ResourceKind.RUST_MODULE,
            ResourceKind.RUST_SYMBOL,
        }
    )


def _normalized_action_paths(action: NormalizedAction) -> tuple[tuple[str, ...], tuple[str, ...]]:
    raw_paths: list[str] = []
    raw_paths.extend(action.affected_paths)
    if action.old_path is not None:
        raw_paths.append(action.old_path)
    if action.new_path is not None:
        raw_paths.append(action.new_path)

    normalized_paths: list[str] = []
    reason_codes: list[str] = []

    for raw_path in raw_paths:
        try:
            normalized = normalize_repo_relative_path(raw_path)
        except Exception:
            reason_codes.append("invalid-action-path")
            continue

        if normalized not in normalized_paths:
            normalized_paths.append(normalized)

    return tuple(normalized_paths), tuple(dict.fromkeys(reason_codes))


def _safe_graph_for_paths(paths: tuple[str, ...]) -> ResourceGraph:
    if not paths:
        return ResourceGraph()

    return build_resource_graph_from_paths(paths)


def _requires_path_or_graph_scope(scopes: tuple[ResourceScope, ...]) -> bool:
    path_or_graph_scope_types = {
        ResourceScopeType.EXACT_PATH,
        ResourceScopeType.PATH_GLOB,
        ResourceScopeType.FILE_TYPE,
        ResourceScopeType.SYMBOL,
    }
    return any(scope.type in path_or_graph_scope_types for scope in scopes)
