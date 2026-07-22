"""Factories for persistent local Rygnal dependencies."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from rygnal.approval_authorization import ApprovalAuthorizationEngine
from rygnal.approval_queue import SQLiteApprovalQueue
from rygnal.approval_service import ApprovalArtifactService
from rygnal.audit_logger import AuditLogger
from rygnal.audit_storage import SQLiteAuditStore
from rygnal.local_paths import LocalPaths, resolve_local_paths
from rygnal.patch_artifact import PatchArtifactStore


@dataclass(frozen=True, slots=True)
class LocalRuntimeDependencies:
    """Persistent services used by a local Rygnal process."""

    paths: LocalPaths
    audit_logger: AuditLogger
    audit_store: SQLiteAuditStore
    approval_queue: SQLiteApprovalQueue
    artifact_store: PatchArtifactStore
    approval_service: ApprovalArtifactService


def create_local_audit_store(
    paths: LocalPaths,
) -> SQLiteAuditStore:
    """Create the local SQLite audit store."""
    return SQLiteAuditStore(paths.audit_db)


def create_local_audit_logger(
    paths: LocalPaths,
    *,
    storage_backend: SQLiteAuditStore | None = None,
) -> AuditLogger:
    """Create the local JSONL audit logger."""
    return AuditLogger(
        log_path=paths.audit_jsonl,
        storage_backend=storage_backend,
    )


def create_local_approval_queue(
    paths: LocalPaths,
    *,
    authorization_engine: ApprovalAuthorizationEngine | None = None,
) -> SQLiteApprovalQueue:
    """Create the local persistent approval queue."""
    return SQLiteApprovalQueue(
        db_path=paths.approval_db,
        authorization_engine=authorization_engine,
    )


def create_local_patch_artifact_store(
    paths: LocalPaths,
) -> PatchArtifactStore:
    """Create the local durable patch artifact store."""
    return PatchArtifactStore(paths.artifacts_dir)


def create_local_runtime_dependencies(
    *,
    data_dir: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    authorization_engine: ApprovalAuthorizationEngine | None = None,
) -> LocalRuntimeDependencies:
    """Create persistent local dependencies without global state."""
    paths = resolve_local_paths(
        data_dir=data_dir,
        create=True,
        environ=environ,
    )

    audit_store = create_local_audit_store(paths)
    audit_logger = create_local_audit_logger(
        paths,
        storage_backend=audit_store,
    )
    approval_queue = create_local_approval_queue(
        paths,
        authorization_engine=authorization_engine,
    )
    artifact_store = create_local_patch_artifact_store(paths)
    approval_service = ApprovalArtifactService(
        approval_queue=approval_queue,
        artifact_store=artifact_store,
        audit_logger=audit_logger,
    )

    return LocalRuntimeDependencies(
        paths=paths,
        audit_logger=audit_logger,
        audit_store=audit_store,
        approval_queue=approval_queue,
        artifact_store=artifact_store,
        approval_service=approval_service,
    )


__all__ = [
    "LocalRuntimeDependencies",
    "create_local_approval_queue",
    "create_local_patch_artifact_store",
    "create_local_audit_logger",
    "create_local_audit_store",
    "create_local_runtime_dependencies",
]
