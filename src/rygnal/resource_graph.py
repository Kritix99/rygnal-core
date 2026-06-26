"""Deterministic resource graph primitives for intent governance.

This module builds stable, audit-safe graph facts from repository-relative
paths. It does not parse file contents, enforce policy, or decide risk.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from rygnal.changed_files import ChangedFileReport, normalize_repo_relative_path
from rygnal.intent_contract import ResourceKind

_PYTHON_SOURCE_ROOTS = ("src", "lib", "tests", "test")
_CONFIG_SUFFIXES = (".cfg", ".conf", ".ini", ".json", ".toml", ".yaml", ".yml")
_DOC_SUFFIXES = (".md", ".rst", ".txt")
_SECRET_TOKENS = (
    ".env",
    "credential",
    "credentials",
    "id_rsa",
    "private_key",
    "secret",
    "secrets",
    "token",
)
_DEPENDENCY_MANIFESTS = {
    "Cargo.toml",
    "Gemfile",
    "go.mod",
    "package.json",
    "pnpm-workspace.yaml",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "uv.toml",
}
_LOCKFILE_NAMES = {
    "Cargo.lock",
    "Gemfile.lock",
    "go.sum",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}


class ResourceGraphEdgeKind(StrEnum):
    CONTAINS = "contains"
    DECLARES = "declares"
    CONFIGURES = "configures"
    TRACKS = "tracks"


@dataclass(frozen=True)
class ResourceGraphNode:
    node_id: str
    kind: ResourceKind
    path: str | None = None
    name: str | None = None
    language: str | None = None
    metadata: dict[str, Any] | None = None

    @property
    def audit_summary(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "path": self.path,
            "name": self.name,
            "language": self.language,
            "metadata": self.metadata or {},
        }


@dataclass(frozen=True)
class ResourceGraphEdge:
    edge_id: str
    kind: ResourceGraphEdgeKind
    source_id: str
    target_id: str
    reason_codes: tuple[str, ...] = ()
    metadata: dict[str, Any] | None = None

    @property
    def audit_summary(self) -> dict[str, object]:
        return {
            "edge_id": self.edge_id,
            "kind": self.kind.value,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "reason_codes": self.reason_codes,
            "metadata": self.metadata or {},
        }


@dataclass(frozen=True)
class ResourceGraph:
    nodes: tuple[ResourceGraphNode, ...] = ()
    edges: tuple[ResourceGraphEdge, ...] = ()

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def audit_summary(self) -> dict[str, object]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes": tuple(node.audit_summary for node in self.nodes),
            "edges": tuple(edge.audit_summary for edge in self.edges),
        }

    def node_by_id(self, node_id: str) -> ResourceGraphNode | None:
        return next((node for node in self.nodes if node.node_id == node_id), None)


def build_resource_graph_from_changed_file_report(report: ChangedFileReport) -> ResourceGraph:
    """Build graph facts for changed files."""
    return build_resource_graph_from_paths(file.path for file in report.files)


def build_resource_graph_from_paths(paths: Iterable[str]) -> ResourceGraph:
    """Build a deterministic graph from repository-relative paths."""
    nodes_by_id: dict[str, ResourceGraphNode] = {}
    edges_by_id: dict[str, ResourceGraphEdge] = {}

    for raw_path in paths:
        path = normalize_repo_relative_path(raw_path)
        for node in _nodes_for_path(path):
            nodes_by_id.setdefault(node.node_id, node)

        file_node = _file_node(path)
        for edge in _edges_for_path(path, file_node.node_id):
            edges_by_id.setdefault(edge.edge_id, edge)

    return ResourceGraph(
        nodes=tuple(sorted(nodes_by_id.values(), key=lambda node: node.node_id)),
        edges=tuple(sorted(edges_by_id.values(), key=lambda edge: edge.edge_id)),
    )


def classify_resource_path(path: str) -> ResourceKind:
    """Classify one repository-relative path into a governance resource kind."""
    normalized = normalize_repo_relative_path(path)
    lowered = normalized.lower()
    name = PurePosixPath(normalized).name

    if _is_secret_path(lowered):
        return ResourceKind.SECRET
    if normalized.startswith(".github/workflows/"):
        return ResourceKind.CI_WORKFLOW
    if name in _LOCKFILE_NAMES:
        return ResourceKind.LOCKFILE
    if name in _DEPENDENCY_MANIFESTS:
        return ResourceKind.DEPENDENCY_MANIFEST
    if _is_policy_path(lowered):
        return ResourceKind.POLICY
    if _is_test_path(lowered):
        return ResourceKind.TEST
    if lowered.endswith(".py"):
        return ResourceKind.PYTHON_MODULE
    if lowered.endswith(".rs"):
        return ResourceKind.RUST_MODULE
    if lowered.endswith(_CONFIG_SUFFIXES):
        return ResourceKind.CONFIG
    if lowered.endswith(_DOC_SUFFIXES):
        return ResourceKind.DOCUMENTATION
    if "." not in name:
        return ResourceKind.DIRECTORY

    return ResourceKind.FILE


def python_module_name_for_path(path: str) -> str | None:
    normalized = normalize_repo_relative_path(path)
    if not normalized.endswith(".py"):
        return None

    without_suffix = normalized.removesuffix(".py")
    parts = list(PurePosixPath(without_suffix).parts)

    if parts and parts[0] in _PYTHON_SOURCE_ROOTS:
        parts = parts[1:]

    if parts and parts[-1] == "__init__":
        parts = parts[:-1]

    if not parts:
        return None

    return ".".join(parts)


def rust_module_name_for_path(path: str) -> str | None:
    normalized = normalize_repo_relative_path(path)
    if not normalized.endswith(".rs"):
        return None

    without_suffix = normalized.removesuffix(".rs")
    parts = list(PurePosixPath(without_suffix).parts)

    if parts and parts[0] == "src":
        parts = parts[1:]

    if not parts:
        return None

    if parts == ["lib"]:
        return "crate"
    if parts == ["main"]:
        return "crate::main"
    if parts[-1] == "mod":
        parts = parts[:-1]

    if not parts:
        return "crate"

    return "::".join(parts)


def _nodes_for_path(path: str) -> tuple[ResourceGraphNode, ...]:
    file_node = _file_node(path)
    nodes = [file_node]

    python_module = python_module_name_for_path(path)
    if python_module:
        nodes.append(
            ResourceGraphNode(
                node_id=_node_id("python_module", python_module),
                kind=ResourceKind.PYTHON_MODULE,
                path=path,
                name=python_module,
                language="python",
                metadata={"identifier_kind": "module"},
            )
        )

    rust_module = rust_module_name_for_path(path)
    if rust_module:
        nodes.append(
            ResourceGraphNode(
                node_id=_node_id("rust_module", rust_module),
                kind=ResourceKind.RUST_MODULE,
                path=path,
                name=rust_module,
                language="rust",
                metadata={"identifier_kind": "module"},
            )
        )

    return tuple(nodes)


def _edges_for_path(path: str, file_node_id: str) -> tuple[ResourceGraphEdge, ...]:
    edges: list[ResourceGraphEdge] = []

    python_module = python_module_name_for_path(path)
    if python_module:
        edges.append(
            _edge(
                kind=ResourceGraphEdgeKind.DECLARES,
                source_id=file_node_id,
                target_id=_node_id("python_module", python_module),
                reason_codes=("language:python", "declares:module"),
            )
        )

    rust_module = rust_module_name_for_path(path)
    if rust_module:
        edges.append(
            _edge(
                kind=ResourceGraphEdgeKind.DECLARES,
                source_id=file_node_id,
                target_id=_node_id("rust_module", rust_module),
                reason_codes=("language:rust", "declares:module"),
            )
        )

    resource_kind = classify_resource_path(path)
    if resource_kind in {
        ResourceKind.CONFIG,
        ResourceKind.CI_WORKFLOW,
        ResourceKind.DEPENDENCY_MANIFEST,
        ResourceKind.LOCKFILE,
        ResourceKind.POLICY,
        ResourceKind.SECRET,
    }:
        edges.append(
            _edge(
                kind=ResourceGraphEdgeKind.CONFIGURES,
                source_id=file_node_id,
                target_id=file_node_id,
                reason_codes=(f"resource_kind:{resource_kind.value}",),
            )
        )

    return tuple(edges)


def _file_node(path: str) -> ResourceGraphNode:
    normalized = normalize_repo_relative_path(path)
    return ResourceGraphNode(
        node_id=_node_id("file", normalized),
        kind=classify_resource_path(normalized),
        path=normalized,
        name=PurePosixPath(normalized).name,
        metadata={"identifier_kind": "repo_relative_path"},
    )


def _edge(
    *,
    kind: ResourceGraphEdgeKind,
    source_id: str,
    target_id: str,
    reason_codes: tuple[str, ...],
) -> ResourceGraphEdge:
    return ResourceGraphEdge(
        edge_id=_stable_id(
            {
                "kind": kind.value,
                "source_id": source_id,
                "target_id": target_id,
                "reason_codes": reason_codes,
            },
            prefix="edge",
        ),
        kind=kind,
        source_id=source_id,
        target_id=target_id,
        reason_codes=reason_codes,
    )


def _node_id(namespace: str, value: str) -> str:
    return f"resource:{namespace}:{value}"


def _stable_id(payload: dict[str, Any], *, prefix: str) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"resource_{prefix}_{hashlib.sha256(encoded).hexdigest()[:24]}"


def _is_secret_path(lowered_path: str) -> bool:
    return any(token in lowered_path for token in _SECRET_TOKENS)


def _is_policy_path(lowered_path: str) -> bool:
    return (
        lowered_path.startswith(".rygnal/")
        or "/policy" in lowered_path
        or lowered_path.startswith("policies/")
        or lowered_path.endswith("policy.yaml")
        or lowered_path.endswith("policy.yml")
    )


def _is_test_path(lowered_path: str) -> bool:
    path = PurePosixPath(lowered_path)
    return (
        lowered_path.startswith("tests/")
        or lowered_path.startswith("test/")
        or path.name.startswith("test_")
        or path.name.endswith("_test.py")
        or path.name.endswith("_test.rs")
    )
