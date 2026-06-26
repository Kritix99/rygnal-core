import pytest

from rygnal.changed_files import ChangedFile, ChangedFileKind, ChangedFileReport
from rygnal.intent_contract import ResourceKind
from rygnal.resource_graph import (
    ResourceGraphEdgeKind,
    build_resource_graph_from_changed_file_report,
    build_resource_graph_from_paths,
    classify_resource_path,
    python_module_name_for_path,
    rust_module_name_for_path,
)

BASELINE_SHA = "a" * 40


def test_classifies_python_rust_and_config_resources() -> None:
    assert classify_resource_path("src/rygnal/resource_graph.py") == ResourceKind.PYTHON_MODULE
    assert classify_resource_path("src/rust_kernel/lib.rs") == ResourceKind.RUST_MODULE
    assert classify_resource_path("pyproject.toml") == ResourceKind.DEPENDENCY_MANIFEST
    assert classify_resource_path(".github/workflows/ci.yml") == ResourceKind.CI_WORKFLOW
    assert classify_resource_path(".env") == ResourceKind.SENSITIVE
    assert classify_resource_path("docs/usage.md") == ResourceKind.DOCUMENTATION


def test_python_module_names_are_stable() -> None:
    assert python_module_name_for_path("src/rygnal/resource_graph.py") == "rygnal.resource_graph"
    assert python_module_name_for_path("src/rygnal/__init__.py") == "rygnal"
    assert python_module_name_for_path("tests/test_resource_graph.py") == "test_resource_graph"
    assert python_module_name_for_path("README.md") is None


def test_rust_module_names_follow_rust_file_layout() -> None:
    assert rust_module_name_for_path("src/lib.rs") == "crate"
    assert rust_module_name_for_path("src/main.rs") == "crate::main"
    assert rust_module_name_for_path("src/policy/mod.rs") == "policy"
    assert rust_module_name_for_path("src/policy/risk.rs") == "policy::risk"
    assert rust_module_name_for_path("README.md") is None


def test_build_resource_graph_creates_file_and_language_nodes() -> None:
    graph = build_resource_graph_from_paths(
        (
            "src/rygnal/resource_graph.py",
            "src/policy/risk.rs",
        )
    )

    node_ids = {node.node_id for node in graph.nodes}
    edge_kinds = {edge.kind for edge in graph.edges}

    assert "resource:file:src/rygnal/resource_graph.py" in node_ids
    assert "resource:python_module:rygnal.resource_graph" in node_ids
    assert "resource:file:src/policy/risk.rs" in node_ids
    assert "resource:rust_module:policy::risk" in node_ids
    assert ResourceGraphEdgeKind.DECLARES in edge_kinds


def test_config_files_get_configures_edges() -> None:
    graph = build_resource_graph_from_paths(
        (
            "pyproject.toml",
            ".github/workflows/ci.yml",
            ".rygnal/policy.yaml",
        )
    )

    config_edges = [edge for edge in graph.edges if edge.kind == ResourceGraphEdgeKind.CONFIGURES]

    assert len(config_edges) == 3
    assert any("resource_kind:dependency_manifest" in edge.reason_codes for edge in config_edges)
    assert any("resource_kind:ci_workflow" in edge.reason_codes for edge in config_edges)
    assert any("resource_kind:policy" in edge.reason_codes for edge in config_edges)


def test_graph_build_is_deterministic_and_deduplicates_paths() -> None:
    first = build_resource_graph_from_paths(
        (
            "src/rygnal/resource_graph.py",
            "./src/rygnal/resource_graph.py",
        )
    )
    second = build_resource_graph_from_paths(("src/rygnal/resource_graph.py",))

    assert first == second
    assert first.node_count == 2
    assert first.edge_count == 1


def test_rejects_unsafe_paths() -> None:
    with pytest.raises(Exception, match="traverse"):
        build_resource_graph_from_paths(("../secret.txt",))


def test_build_resource_graph_from_changed_file_report() -> None:
    report = ChangedFileReport(
        workspace_path="/tmp/workspace",
        baseline_commit_sha=BASELINE_SHA,
        files=(
            ChangedFile(path="src/rygnal/resource_graph.py", kind=ChangedFileKind.MODIFIED),
            ChangedFile(path="pyproject.toml", kind=ChangedFileKind.MODIFIED),
        ),
    )

    graph = build_resource_graph_from_changed_file_report(report)

    assert graph.node_by_id("resource:python_module:rygnal.resource_graph") is not None
    assert graph.node_by_id("resource:file:pyproject.toml").kind == ResourceKind.DEPENDENCY_MANIFEST
    assert graph.audit_summary["node_count"] == graph.node_count
