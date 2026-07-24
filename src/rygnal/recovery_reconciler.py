"""Crash-recovery reconciliation for durable local Rygnal state."""

from __future__ import annotations

import math
import os
import re
import stat
import subprocess  # nosec B404
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from rygnal.approval_service import (
    ApprovalArtifactService,
    ApprovalOperationError,
)
from rygnal.approved_apply import (
    APPROVED_PATCH_APPLY_POLICY_ID,
)
from rygnal.audit_logger import AuditLogger
from rygnal.models import (
    ApprovalStatus,
    Decision,
    PolicyDecision,
    Severity,
    ToolRequest,
    new_trace_id,
)
from rygnal.operation_store import (
    OperationRecord,
    OperationRecoveryStatus,
    OperationStoreError,
    SQLiteOperationStore,
)
from rygnal.patch_artifact import (
    PATCH_ARTIFACT_STATE_CONSUMED,
    PATCH_ARTIFACT_STATE_PENDING,
    PatchArtifact,
    PatchArtifactError,
    PatchArtifactStore,
)
from rygnal.recovery_session import (
    CleanupStatus,
    RecoverySession,
    RecoverySessionConfig,
    RecoverySessionError,
    destroy_recovery_session,
    detect_trusted_repo_root,
)

OWNER_MARKER_SCHEMA = "rygnal-worktree-owner.v1"
ARTIFACT_LOCK_SCHEMA = "rygnal-artifact-lock.v1"
RECOVERY_POLICY_ID = "rygnal-local-recovery-reconciliation"
MAX_RECOVERY_METADATA_BYTES = 16 * 1024
MAX_LOCK_FUTURE_SKEW_SECONDS = 300

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class RecoveryReconciliationError(RuntimeError):
    """Raised when recovery cannot proceed safely."""


class RecoveryFindingStatus(StrEnum):
    """Outcome for one reconciled object."""

    RECOVERED = "recovered"
    QUARANTINED = "quarantined"
    MARKED_CONSUMED = "marked_consumed"
    EXPIRED_REJECTED = "expired_rejected"
    ACTIVE = "active"
    COHERENT = "coherent"
    UNRESOLVED = "unresolved"


_MUTATING_STATUSES = {
    RecoveryFindingStatus.RECOVERED,
    RecoveryFindingStatus.QUARANTINED,
    RecoveryFindingStatus.MARKED_CONSUMED,
    RecoveryFindingStatus.EXPIRED_REJECTED,
}


@dataclass(frozen=True, slots=True)
class RecoveryFinding:
    """Safe result for one recovery object."""

    kind: str
    identifier: str
    status: RecoveryFindingStatus
    message: str
    path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def mutated(self) -> bool:
        """Return whether reconciliation changed durable state."""
        return self.status in _MUTATING_STATUSES

    def to_dict(self) -> dict[str, Any]:
        """Return a stable machine-readable representation."""
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "status": self.status.value,
            "message": self.message,
            "path": self.path,
            "mutated": self.mutated,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    """Result of one complete recovery pass."""

    trace_id: str
    findings: tuple[RecoveryFinding, ...]
    scanned_workspaces: int
    scanned_guarded_locks: int
    scanned_artifact_locks: int
    scanned_artifacts: int

    @property
    def mutated_count(self) -> int:
        return sum(finding.mutated for finding in self.findings)

    @property
    def unresolved_count(self) -> int:
        return sum(finding.status == RecoveryFindingStatus.UNRESOLVED for finding in self.findings)

    @property
    def active_count(self) -> int:
        return sum(finding.status == RecoveryFindingStatus.ACTIVE for finding in self.findings)

    @property
    def coherent_count(self) -> int:
        return sum(finding.status == RecoveryFindingStatus.COHERENT for finding in self.findings)

    @property
    def successful(self) -> bool:
        return self.unresolved_count == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "successful": self.successful,
            "mutated_count": self.mutated_count,
            "unresolved_count": self.unresolved_count,
            "active_count": self.active_count,
            "coherent_count": self.coherent_count,
            "scanned": {
                "workspaces": self.scanned_workspaces,
                "guarded_locks": self.scanned_guarded_locks,
                "artifact_locks": self.scanned_artifact_locks,
                "artifacts": self.scanned_artifacts,
            },
            "findings": tuple(finding.to_dict() for finding in self.findings),
        }


class RecoveryReconciler:
    """Reconcile only verified Rygnal-owned local state."""

    def __init__(
        self,
        *,
        run_root: str | Path,
        approval_service: ApprovalArtifactService,
        audit_logger: AuditLogger,
        operation_store: SQLiteOperationStore | None = None,
    ) -> None:
        candidate = Path(run_root).expanduser()

        if not candidate.is_absolute():
            raise RecoveryReconciliationError("Recovery run root must be absolute.")

        self.run_root = candidate.resolve(strict=False)
        self.approval_service = approval_service
        self.artifact_store: PatchArtifactStore = approval_service.artifact_store
        self.audit_logger = audit_logger

        _ensure_private_directory(self.run_root)
        self._workspace_recovery_blocked_reason: str | None = None
        self._artifact_recovery_blocked_reason: str | None = None
        self.operation_store = operation_store

    def reconcile(
        self,
        *,
        trace_id: str | None = None,
    ) -> RecoveryReport:
        """Run one fail-closed, idempotent recovery pass."""
        workspace_block = _lock_root_block_reason(
            lock_root=self.run_root / ".rygnal-locks",
            pattern="*.lock",
            kind="guarded_run_lock",
            schema=None,
            identity_field="lock_identity",
            identity_from_path=lambda path: path.stem,
        )
        artifact_block = _lock_root_block_reason(
            lock_root=self.artifact_store.root,
            pattern=".*.lock",
            kind="artifact_lock",
            schema=ARTIFACT_LOCK_SCHEMA,
            identity_field="artifact_id",
            identity_from_path=lambda path: path.name[1:-5],
        )

        self._workspace_recovery_blocked_reason = workspace_block
        self._artifact_recovery_blocked_reason = artifact_block

        try:
            return self._reconcile_without_lock_gate(trace_id=trace_id)
        finally:
            self._workspace_recovery_blocked_reason = None
            self._artifact_recovery_blocked_reason = None

    def _reconcile_without_lock_gate(
        self,
        *,
        trace_id: str | None = None,
    ) -> RecoveryReport:
        """Run one idempotent reconciliation pass."""
        active_trace = trace_id or new_trace_id()
        findings: list[RecoveryFinding] = []

        workspace_findings, workspace_count = self._reconcile_workspaces(trace_id=active_trace)
        findings.extend(workspace_findings)

        guarded_lock_findings, guarded_lock_count = self._reconcile_guarded_locks(
            trace_id=active_trace
        )
        findings.extend(guarded_lock_findings)

        artifact_lock_findings, artifact_lock_count = self._reconcile_artifact_locks(
            trace_id=active_trace
        )
        findings.extend(artifact_lock_findings)

        artifact_findings, artifact_count = self._reconcile_artifacts(trace_id=active_trace)
        findings.extend(artifact_findings)

        report = RecoveryReport(
            trace_id=active_trace,
            findings=tuple(findings),
            scanned_workspaces=workspace_count,
            scanned_guarded_locks=guarded_lock_count,
            scanned_artifact_locks=artifact_lock_count,
            scanned_artifacts=artifact_count,
        )

        self._write_summary_audit(report)
        return report

    def _reconcile_workspaces(
        self,
        *,
        trace_id: str,
    ) -> tuple[list[RecoveryFinding], int]:
        blocked_reason = self._workspace_recovery_blocked_reason

        if blocked_reason is not None:
            active = blocked_reason.startswith("active:")
            finding = RecoveryFinding(
                kind="workspace_recovery",
                identifier="workspaces",
                status=(
                    RecoveryFindingStatus.ACTIVE if active else RecoveryFindingStatus.UNRESOLVED
                ),
                message=blocked_reason.split(
                    ":",
                    1,
                )[-1].strip(),
                path=(self.run_root / "workspaces").as_posix(),
            )

            if not active:
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )

            return [finding], 0

        workspaces_root = self.run_root / "workspaces"

        if not workspaces_root.exists():
            return [], 0

        if workspaces_root.is_symlink() or not workspaces_root.is_dir():
            finding = RecoveryFinding(
                kind="workspace_root",
                identifier="workspaces",
                status=RecoveryFindingStatus.UNRESOLVED,
                message=("Workspace root is not a regular non-symlink directory."),
                path=workspaces_root.as_posix(),
            )
            self._write_finding_audit(
                finding,
                trace_id=trace_id,
            )
            return [finding], 1

        findings: list[RecoveryFinding] = []
        entries = tuple(sorted(workspaces_root.iterdir()))

        for session_root in entries:
            finding = self._recover_workspace(session_root)
            findings.append(finding)

            if finding.mutated or finding.status == RecoveryFindingStatus.UNRESOLVED:
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )

        return findings, len(entries)

    def _recover_workspace(
        self,
        session_root: Path,
    ) -> RecoveryFinding:
        if session_root.is_symlink() or not session_root.is_dir():
            return RecoveryFinding(
                kind="workspace",
                identifier=session_root.name,
                status=RecoveryFindingStatus.UNRESOLVED,
                message=("Refusing recovery for a non-directory or symlinked workspace session."),
                path=session_root.as_posix(),
            )

        marker_path = session_root / ".rygnal-owner"

        try:
            marker = _read_owner_marker(marker_path)
            session = self._session_from_marker(
                session_root=session_root,
                marker=marker,
            )
        except RecoveryReconciliationError as exc:
            return RecoveryFinding(
                kind="workspace",
                identifier=session_root.name,
                status=RecoveryFindingStatus.UNRESOLVED,
                message=str(exc),
                path=session_root.as_posix(),
            )

        workspace = session.workspace_path
        trusted_repo = session.trusted_repo_path

        try:
            registered = workspace in _registered_worktrees(trusted_repo)
        except RecoveryReconciliationError as exc:
            return RecoveryFinding(
                kind="workspace",
                identifier=session.run_id,
                status=RecoveryFindingStatus.UNRESOLVED,
                message=str(exc),
                path=workspace.as_posix(),
            )

        if workspace.exists() and not registered:
            try:
                quarantine = self._quarantine_owned_session(
                    session_root,
                    session.run_id,
                )
            except RecoveryReconciliationError as exc:
                return RecoveryFinding(
                    kind="workspace",
                    identifier=session.run_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=str(exc),
                    path=session_root.as_posix(),
                )

            return RecoveryFinding(
                kind="workspace",
                identifier=session.run_id,
                status=RecoveryFindingStatus.QUARANTINED,
                message=(
                    "Verified Rygnal workspace was no longer "
                    "registered and was moved to quarantine."
                ),
                path=quarantine.as_posix(),
                metadata={
                    "trusted_repo_path": (trusted_repo.as_posix()),
                    "baseline_commit_sha": (session.baseline_commit_sha),
                },
            )

        if not workspace.exists():
            try:
                _run_git(
                    trusted_repo,
                    "worktree",
                    "prune",
                    "--expire",
                    "now",
                )
                residual = tuple(item for item in session_root.iterdir() if item != marker_path)

                if residual:
                    quarantine = self._quarantine_owned_session(
                        session_root,
                        session.run_id,
                    )
                    return RecoveryFinding(
                        kind="workspace",
                        identifier=session.run_id,
                        status=(RecoveryFindingStatus.QUARANTINED),
                        message=(
                            "Missing worktree registration was "
                            "pruned and residual owned state was "
                            "quarantined."
                        ),
                        path=quarantine.as_posix(),
                    )

                marker_path.unlink()
                session_root.rmdir()
            except (
                OSError,
                RecoveryReconciliationError,
            ) as exc:
                return RecoveryFinding(
                    kind="workspace",
                    identifier=session.run_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=(f"Failed to reconcile a missing owned workspace: {exc}"),
                    path=session_root.as_posix(),
                )

            return RecoveryFinding(
                kind="workspace",
                identifier=session.run_id,
                status=RecoveryFindingStatus.RECOVERED,
                message=(
                    "Pruned stale worktree metadata and removed verified empty ownership metadata."
                ),
                path=session_root.as_posix(),
            )

        cleanup = destroy_recovery_session(
            session,
            RecoverySessionConfig(
                trusted_repo_path=trusted_repo,
                rygnal_run_root=self.run_root,
                audit_logger=self.audit_logger,
            ),
        )

        if cleanup.status == CleanupStatus.CLEANED_GIT:
            return RecoveryFinding(
                kind="workspace",
                identifier=session.run_id,
                status=RecoveryFindingStatus.RECOVERED,
                message=cleanup.message,
                path=cleanup.workspace_path,
            )

        if cleanup.status == CleanupStatus.CLEANED_FALLBACK:
            return RecoveryFinding(
                kind="workspace",
                identifier=session.run_id,
                status=RecoveryFindingStatus.QUARANTINED,
                message=cleanup.message,
                path=(cleanup.quarantine_path or cleanup.workspace_path),
            )

        return RecoveryFinding(
            kind="workspace",
            identifier=session.run_id,
            status=RecoveryFindingStatus.UNRESOLVED,
            message=cleanup.message,
            path=cleanup.workspace_path,
        )

    def _session_from_marker(
        self,
        *,
        session_root: Path,
        marker: dict[str, str],
    ) -> RecoverySession:
        run_id = marker["run_id"]

        if run_id != session_root.name:
            raise RecoveryReconciliationError(
                "Ownership marker run ID does not match the workspace directory."
            )

        if not _IDENTIFIER_PATTERN.fullmatch(run_id):
            raise RecoveryReconciliationError("Ownership marker contains an invalid run ID.")

        baseline = marker["baseline_commit_sha"]

        if not _SHA_PATTERN.fullmatch(baseline):
            raise RecoveryReconciliationError("Ownership marker contains an invalid baseline.")

        trusted_repo = Path(marker["trusted_repo_path"]).expanduser()

        workspace = Path(marker["workspace_path"]).expanduser()

        if not trusted_repo.is_absolute() or not workspace.is_absolute():
            raise RecoveryReconciliationError("Ownership marker paths must be absolute.")

        trusted_repo = trusted_repo.resolve()
        workspace = workspace.resolve(strict=False)

        expected_workspace = (session_root / "workspace").resolve(strict=False)

        if workspace != expected_workspace:
            raise RecoveryReconciliationError(
                "Ownership marker workspace does not match its controlled session path."
            )

        workspaces_root = (self.run_root / "workspaces").resolve(strict=False)

        if not _strict_descendant(
            session_root.resolve(strict=False),
            workspaces_root,
        ):
            raise RecoveryReconciliationError(
                "Workspace session escaped the configured Rygnal workspaces root."
            )

        if workspace == trusted_repo:
            raise RecoveryReconciliationError(
                "Workspace marker resolves to the trusted repository."
            )

        detected_root = detect_trusted_repo_root(trusted_repo)

        if detected_root != trusted_repo:
            raise RecoveryReconciliationError(
                "Ownership marker trusted path is not the Git repository root."
            )

        return RecoverySession(
            run_id=run_id,
            trusted_repo_path=trusted_repo,
            execution_path=workspace,
            baseline_commit_sha=baseline.lower(),
            timeline_dir=(self.run_root / "timelines" / run_id),
        )

    def _quarantine_owned_session(
        self,
        session_root: Path,
        run_id: str,
    ) -> Path:
        quarantine_root = _ensure_private_directory(self.run_root / "quarantine")
        destination = quarantine_root / (f"recovered-{run_id}")

        if destination.exists():
            raise RecoveryReconciliationError("Workspace quarantine destination already exists.")

        os.replace(session_root, destination)
        return destination

    def _reconcile_guarded_locks(
        self,
        *,
        trace_id: str,
    ) -> tuple[list[RecoveryFinding], int]:
        lock_root = self.run_root / ".rygnal-locks"
        return self._reconcile_pid_locks(
            lock_root=lock_root,
            pattern="*.lock",
            kind="guarded_run_lock",
            schema=None,
            identity_field="lock_identity",
            identity_from_path=lambda path: path.stem,
            trace_id=trace_id,
        )

    def _reconcile_artifact_locks(
        self,
        *,
        trace_id: str,
    ) -> tuple[list[RecoveryFinding], int]:
        return self._reconcile_pid_locks(
            lock_root=self.artifact_store.root,
            pattern=".*.lock",
            kind="artifact_lock",
            schema=ARTIFACT_LOCK_SCHEMA,
            identity_field="artifact_id",
            identity_from_path=lambda path: path.name[1:-5],
            trace_id=trace_id,
        )

    def _reconcile_pid_locks(
        self,
        *,
        lock_root: Path,
        pattern: str,
        kind: str,
        schema: str | None,
        identity_field: str,
        identity_from_path,
        trace_id: str,
    ) -> tuple[list[RecoveryFinding], int]:
        if not lock_root.exists():
            return [], 0

        if lock_root.is_symlink() or not lock_root.is_dir():
            finding = RecoveryFinding(
                kind=kind,
                identifier=lock_root.name,
                status=RecoveryFindingStatus.UNRESOLVED,
                message=("Lock root is not a regular non-symlink directory."),
                path=lock_root.as_posix(),
            )
            self._write_finding_audit(
                finding,
                trace_id=trace_id,
            )
            return [finding], 1

        paths = tuple(sorted(lock_root.glob(pattern)))
        findings: list[RecoveryFinding] = []

        for lock_path in paths:
            identifier = identity_from_path(lock_path)

            if lock_path.is_symlink() or not lock_path.is_file():
                finding = RecoveryFinding(
                    kind=kind,
                    identifier=identifier,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=("Refusing to modify a non-regular or symlinked lock path."),
                    path=lock_path.as_posix(),
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            try:
                metadata = _read_key_value_file(lock_path)
                pid = _validate_lock_metadata(
                    metadata,
                    kind=kind,
                    schema=schema,
                    identity_field=identity_field,
                    expected_identity=identity_from_path(lock_path),
                )
            except RecoveryReconciliationError as exc:
                finding = RecoveryFinding(
                    kind=kind,
                    identifier=identifier,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=str(exc),
                    path=lock_path.as_posix(),
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            if _process_is_alive(pid):
                findings.append(
                    RecoveryFinding(
                        kind=kind,
                        identifier=identifier,
                        status=RecoveryFindingStatus.ACTIVE,
                        message=("Lock owner process is still active; the lock was retained."),
                        path=lock_path.as_posix(),
                        metadata={"pid": pid},
                    )
                )
                continue

            try:
                lock_path.unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                finding = RecoveryFinding(
                    kind=kind,
                    identifier=identifier,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=(f"Failed to remove a verified stale lock: {exc}"),
                    path=lock_path.as_posix(),
                    metadata={"pid": pid},
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            finding = RecoveryFinding(
                kind=kind,
                identifier=identifier,
                status=RecoveryFindingStatus.RECOVERED,
                message=("Removed a verified stale process lock."),
                path=lock_path.as_posix(),
                metadata={"stale_pid": pid},
            )
            findings.append(finding)
            self._write_finding_audit(
                finding,
                trace_id=trace_id,
            )

        return findings, len(paths)

    def _reconcile_operations(
        self,
        *,
        trace_id: str,
    ) -> list[RecoveryFinding]:
        if self.operation_store is None:
            return []

        try:
            results = self.operation_store.reconcile_incomplete(
                has_apply_evidence=(self._operation_has_apply_evidence)
            )
        except OperationStoreError as exc:
            finding = RecoveryFinding(
                kind="operation_store",
                identifier="operations",
                status=RecoveryFindingStatus.UNRESOLVED,
                message=str(exc),
            )
            self._write_finding_audit(
                finding,
                trace_id=trace_id,
            )
            return [finding]

        findings: list[RecoveryFinding] = []

        for result in results:
            if result.status == OperationRecoveryStatus.ACTIVE:
                status = RecoveryFindingStatus.ACTIVE
            elif result.status == OperationRecoveryStatus.UNRESOLVED:
                status = RecoveryFindingStatus.UNRESOLVED
            else:
                status = RecoveryFindingStatus.RECOVERED

            finding = RecoveryFinding(
                kind="artifact_apply_operation",
                identifier=result.operation_key,
                status=status,
                message=result.message,
                path=result.target_repo_path,
                metadata={
                    "artifact_id": result.artifact_id,
                    "operation_status": (result.status.value),
                },
            )
            findings.append(finding)

            if finding.mutated or status == RecoveryFindingStatus.UNRESOLVED:
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )

        return findings

    def _operation_has_apply_evidence(
        self,
        operation: OperationRecord,
    ) -> bool:
        storage = getattr(
            self.audit_logger,
            "storage_backend",
            None,
        )
        reader = getattr(
            storage,
            "read_events",
            None,
        )

        if not callable(reader):
            reader = self.audit_logger.read_events

        for event in reader():
            if event.policy_id != APPROVED_PATCH_APPLY_POLICY_ID:
                continue

            metadata = event.metadata or {}

            if (
                metadata.get("approval_id") == operation.approval_id
                and metadata.get("patch_sha256") == operation.patch_sha256
                and metadata.get("baseline_commit_sha") == operation.baseline_commit_sha
            ):
                return True

        return False

    def _reconcile_artifacts(
        self,
        *,
        trace_id: str,
    ) -> tuple[list[RecoveryFinding], int]:
        blocked_reason = self._artifact_recovery_blocked_reason

        if blocked_reason is not None:
            active = blocked_reason.startswith("active:")
            finding = RecoveryFinding(
                kind="artifact_recovery",
                identifier="artifacts",
                status=(
                    RecoveryFindingStatus.ACTIVE if active else RecoveryFindingStatus.UNRESOLVED
                ),
                message=blocked_reason.split(
                    ":",
                    1,
                )[-1].strip(),
                path=self.artifact_store.root.as_posix(),
            )

            if not active:
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )

            return [finding], 0

        root = self.artifact_store.root
        artifact_paths = tuple(sorted(root.glob("*.json")))
        queue_items = self.approval_service.approval_queue.list()

        approvals_by_artifact: dict[
            str,
            list[Any],
        ] = {}

        for item in queue_items:
            artifact_id = item.request.metadata.get("artifact_id")

            if isinstance(artifact_id, str):
                approvals_by_artifact.setdefault(
                    artifact_id,
                    [],
                ).append(item)

        findings: list[RecoveryFinding] = []
        findings.extend(self._reconcile_operations(trace_id=trace_id))
        discovered_ids: set[str] = set()

        for artifact_path in artifact_paths:
            artifact_id = artifact_path.stem
            discovered_ids.add(artifact_id)

            if artifact_path.is_symlink() or not artifact_path.is_file():
                finding = RecoveryFinding(
                    kind="artifact",
                    identifier=artifact_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=("Artifact path is not a regular non-symlink file."),
                    path=artifact_path.as_posix(),
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            try:
                artifact = self.artifact_store.load(
                    artifact_id,
                    allow_expired=True,
                    allow_consumed=True,
                )
            except PatchArtifactError as exc:
                finding = RecoveryFinding(
                    kind="artifact",
                    identifier=artifact_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=str(exc),
                    path=artifact_path.as_posix(),
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            matches = approvals_by_artifact.get(
                artifact_id,
                [],
            )

            if not matches:
                try:
                    quarantine = self._quarantine_orphan_artifact(artifact_path)
                except RecoveryReconciliationError as exc:
                    finding = RecoveryFinding(
                        kind="artifact",
                        identifier=artifact_id,
                        status=(RecoveryFindingStatus.UNRESOLVED),
                        message=str(exc),
                        path=artifact_path.as_posix(),
                    )
                else:
                    finding = RecoveryFinding(
                        kind="artifact",
                        identifier=artifact_id,
                        status=(RecoveryFindingStatus.QUARANTINED),
                        message=(
                            "Artifact had no authoritative approval binding and was quarantined."
                        ),
                        path=quarantine.as_posix(),
                    )

                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            if len(matches) != 1:
                finding = RecoveryFinding(
                    kind="artifact",
                    identifier=artifact_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=("Multiple approvals reference the same durable artifact."),
                    path=artifact_path.as_posix(),
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            queued = matches[0]

            try:
                _validate_artifact_binding(
                    artifact,
                    queued,
                )
            except RecoveryReconciliationError as exc:
                finding = RecoveryFinding(
                    kind="artifact",
                    identifier=artifact_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=str(exc),
                    path=artifact_path.as_posix(),
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            try:
                applied_evidence = self._has_apply_evidence(artifact)
            except RecoveryReconciliationError as exc:
                finding = RecoveryFinding(
                    kind="artifact",
                    identifier=artifact_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=(f"Could not verify durable approved-apply evidence safely: {exc}"),
                    path=artifact_path.as_posix(),
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            if artifact.state == PATCH_ARTIFACT_STATE_PENDING and applied_evidence:
                try:
                    self.artifact_store.mark_consumed(artifact_id)
                except PatchArtifactError as exc:
                    finding = RecoveryFinding(
                        kind="artifact",
                        identifier=artifact_id,
                        status=(RecoveryFindingStatus.UNRESOLVED),
                        message=(
                            "Durable approved-apply evidence "
                            "exists, but artifact consumption "
                            f"failed: {exc}"
                        ),
                        path=artifact_path.as_posix(),
                    )
                else:
                    finding = RecoveryFinding(
                        kind="artifact",
                        identifier=artifact_id,
                        status=(RecoveryFindingStatus.MARKED_CONSUMED),
                        message=(
                            "Recovered an interrupted approved "
                            "apply by marking its artifact consumed."
                        ),
                        path=artifact_path.as_posix(),
                        metadata={
                            "approval_id": (artifact.approval_request_id),
                            "patch_sha256": (artifact.patch_sha256),
                            "baseline_commit_sha": (artifact.baseline_commit_sha),
                        },
                    )

                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            if artifact.state == PATCH_ARTIFACT_STATE_CONSUMED and not applied_evidence:
                finding = RecoveryFinding(
                    kind="artifact",
                    identifier=artifact_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=(
                        "Consumed artifact has no matching durable approved-apply audit evidence."
                    ),
                    path=artifact_path.as_posix(),
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            if (
                artifact.state == PATCH_ARTIFACT_STATE_PENDING
                and artifact.expired
                and queued.status == ApprovalStatus.PENDING
            ):
                try:
                    self.approval_service.reject(
                        queued.approval_id,
                        decided_by="rygnal_recovery",
                        reason=("Expired durable patch artifact rejected during crash recovery."),
                    )
                except ApprovalOperationError as exc:
                    finding = RecoveryFinding(
                        kind="artifact",
                        identifier=artifact_id,
                        status=(RecoveryFindingStatus.UNRESOLVED),
                        message=(f"Expired artifact could not be rejected safely: {exc}"),
                        path=artifact_path.as_posix(),
                    )
                else:
                    finding = RecoveryFinding(
                        kind="artifact",
                        identifier=artifact_id,
                        status=(RecoveryFindingStatus.EXPIRED_REJECTED),
                        message=("Rejected a pending approval whose durable artifact had expired."),
                        path=artifact_path.as_posix(),
                        metadata={"approval_id": queued.approval_id},
                    )

                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            if (
                artifact.state == PATCH_ARTIFACT_STATE_PENDING
                and artifact.expired
                and queued.status == ApprovalStatus.APPROVED
            ):
                finding = RecoveryFinding(
                    kind="artifact",
                    identifier=artifact_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=(
                        "Approved artifact expired before trusted "
                        "application and requires explicit operator "
                        "resolution."
                    ),
                    path=artifact_path.as_posix(),
                    metadata={
                        "approval_id": queued.approval_id,
                    },
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )
                continue

            findings.append(
                RecoveryFinding(
                    kind="artifact",
                    identifier=artifact_id,
                    status=RecoveryFindingStatus.COHERENT,
                    message=("Artifact and approval lifecycle state are coherent."),
                    path=artifact_path.as_posix(),
                    metadata={
                        "artifact_state": artifact.state,
                        "approval_status": (queued.status.value),
                        "expired": artifact.expired,
                        "applied_evidence": (applied_evidence),
                    },
                )
            )

        for queued in queue_items:
            artifact_id = queued.request.metadata.get("artifact_id")

            if isinstance(artifact_id, str) and artifact_id not in discovered_ids:
                finding = RecoveryFinding(
                    kind="approval",
                    identifier=queued.approval_id,
                    status=RecoveryFindingStatus.UNRESOLVED,
                    message=("Approval references a missing durable patch artifact."),
                    metadata={
                        "artifact_id": artifact_id,
                        "approval_status": (queued.status.value),
                    },
                )
                findings.append(finding)
                self._write_finding_audit(
                    finding,
                    trace_id=trace_id,
                )

        return findings, len(artifact_paths)

    def _quarantine_orphan_artifact(
        self,
        artifact_path: Path,
    ) -> Path:
        if artifact_path.is_symlink() or not artifact_path.is_file():
            raise RecoveryReconciliationError("Refusing to quarantine a non-regular artifact path.")

        quarantine_root = _ensure_private_directory(self.artifact_store.root / "quarantine")
        destination = quarantine_root / artifact_path.name

        if destination.exists():
            raise RecoveryReconciliationError("Artifact quarantine destination already exists.")

        os.replace(artifact_path, destination)
        return destination

    def _has_apply_evidence(
        self,
        artifact: PatchArtifact,
    ) -> bool:
        storage = getattr(
            self.audit_logger,
            "storage_backend",
            None,
        )

        if storage is not None:
            read_events = getattr(
                storage,
                "read_events",
                None,
            )

            if not callable(read_events):
                raise RecoveryReconciliationError(
                    "Audit storage cannot provide durable replay history."
                )

            events = tuple(read_events())
        else:
            events = tuple(self.audit_logger.read_events())

        for event in events:
            if event.policy_id != APPROVED_PATCH_APPLY_POLICY_ID:
                continue

            metadata = event.metadata or {}

            if (
                metadata.get("approval_id") == artifact.approval_request_id
                and metadata.get("patch_sha256") == artifact.patch_sha256
                and metadata.get("baseline_commit_sha") == artifact.baseline_commit_sha
            ):
                return True

        return False

    def _write_finding_audit(
        self,
        finding: RecoveryFinding,
        *,
        trace_id: str,
    ) -> None:
        unresolved = finding.status == RecoveryFindingStatus.UNRESOLVED

        request = ToolRequest(
            tool_name="rygnal_recovery",
            action=f"reconcile_{finding.kind}",
            target=finding.identifier,
            input=finding.to_dict(),
            user_id="local_operator",
            agent_id="rygnal_recovery",
            environment="local",
            metadata={
                "trace_id": trace_id,
                "event_type": ("recovery.reconciliation_item"),
            },
        )
        decision = PolicyDecision(
            decision=(Decision.BLOCK if unresolved else Decision.ALLOW),
            allowed=not unresolved,
            severity=(Severity.HIGH if unresolved else Severity.MEDIUM),
            reason=finding.message,
            policy_id=RECOVERY_POLICY_ID,
        )

        self.audit_logger.log_decision(
            request,
            decision,
            metadata=finding.to_dict(),
        )

    def _write_summary_audit(
        self,
        report: RecoveryReport,
    ) -> None:
        request = ToolRequest(
            tool_name="rygnal_recovery",
            action="reconcile_local_state",
            target=self.run_root.as_posix(),
            input={
                "mutated_count": report.mutated_count,
                "unresolved_count": (report.unresolved_count),
            },
            user_id="local_operator",
            agent_id="rygnal_recovery",
            environment="local",
            metadata={
                "trace_id": report.trace_id,
                "event_type": ("recovery.reconciliation_completed"),
            },
        )
        decision = PolicyDecision(
            decision=(Decision.ALLOW if report.successful else Decision.BLOCK),
            allowed=report.successful,
            severity=(Severity.LOW if report.successful else Severity.HIGH),
            reason=(
                "Local Rygnal state reconciliation completed successfully."
                if report.successful
                else ("Local Rygnal state reconciliation completed with unresolved items.")
            ),
            policy_id=RECOVERY_POLICY_ID,
        )

        self.audit_logger.log_decision(
            request,
            decision,
            metadata=report.to_dict(),
        )


def _lock_root_block_reason(
    *,
    lock_root: Path,
    pattern: str,
    kind: str,
    schema: str | None,
    identity_field: str,
    identity_from_path,
) -> str | None:
    """Return why related recovery must be deferred."""
    if not lock_root.exists():
        return None

    if lock_root.is_symlink() or not lock_root.is_dir():
        return "uncertain: Lock root is not a regular non-symlink directory."

    for lock_path in sorted(lock_root.glob(pattern)):
        if lock_path.is_symlink() or not lock_path.is_file():
            return "uncertain: A lock path is not a regular non-symlink file."

        try:
            metadata = _read_key_value_file(lock_path)
            pid = _validate_lock_metadata(
                metadata,
                kind=kind,
                schema=schema,
                identity_field=identity_field,
                expected_identity=identity_from_path(lock_path),
            )
        except RecoveryReconciliationError as exc:
            return f"uncertain: Lock ownership could not be verified: {exc}"

        if _process_is_alive(pid):
            return "active: An active process lock protects this recovery category."

    return None


def _validate_lock_metadata(
    metadata: dict[str, str],
    *,
    kind: str,
    schema: str | None,
    identity_field: str,
    expected_identity: str,
) -> int:
    """Validate exact lock ownership metadata."""
    if kind == "guarded_run_lock":
        required = {
            "pid",
            "trace_id",
            "trusted_repo_path",
            "lock_identity",
            "created_at_unix",
        }
    elif kind == "artifact_lock":
        required = {
            "schema",
            "pid",
            "artifact_id",
            "created_at_unix",
        }
    else:
        raise RecoveryReconciliationError(f"Unsupported recovery lock kind: {kind}")

    if set(metadata) != required:
        raise RecoveryReconciliationError("Lock fields are incomplete or unsupported.")

    if metadata.get(identity_field) != expected_identity:
        raise RecoveryReconciliationError("Lock identity does not match its filename.")

    if schema is not None and metadata.get("schema") != schema:
        raise RecoveryReconciliationError("Lock schema is missing or unsupported.")

    pid = _parse_positive_pid(metadata.get("pid"))

    _parse_lock_created_at(metadata.get("created_at_unix"))

    if kind == "guarded_run_lock":
        _validate_guarded_lock_repository(metadata["trusted_repo_path"])

    return pid


def _parse_lock_created_at(
    raw: str | None,
) -> float:
    try:
        created_at = float(raw or "")
    except ValueError as exc:
        raise RecoveryReconciliationError("Lock creation time is invalid.") from exc

    if not math.isfinite(created_at) or created_at <= 0:
        raise RecoveryReconciliationError("Lock creation time must be a finite positive timestamp.")

    if created_at > time.time() + MAX_LOCK_FUTURE_SKEW_SECONDS:
        raise RecoveryReconciliationError("Lock creation time is unreasonably far in the future.")

    return created_at


def _validate_guarded_lock_repository(
    value: str,
) -> Path:
    candidate = Path(value).expanduser()

    if not candidate.is_absolute():
        raise RecoveryReconciliationError("Guarded-run lock repository path must be absolute.")

    try:
        resolved = candidate.resolve()
        detected = detect_trusted_repo_root(resolved)
    except (
        OSError,
        RecoverySessionError,
    ) as exc:
        raise RecoveryReconciliationError(
            "Guarded-run lock repository identity could not be verified."
        ) from exc

    if detected != resolved:
        raise RecoveryReconciliationError(
            "Guarded-run lock path is not the trusted Git repository root."
        )

    return resolved


def _read_owner_marker(
    marker_path: Path,
) -> dict[str, str]:
    if marker_path.is_symlink() or not marker_path.is_file():
        raise RecoveryReconciliationError("Verified workspace ownership marker is missing.")

    marker = _read_key_value_file(marker_path)
    required = {
        "schema",
        "run_id",
        "trusted_repo_path",
        "baseline_commit_sha",
        "workspace_path",
    }

    if set(marker) != required:
        raise RecoveryReconciliationError("Ownership marker fields are incomplete or unsupported.")

    if marker["schema"] != OWNER_MARKER_SCHEMA:
        raise RecoveryReconciliationError("Ownership marker schema is unsupported.")

    return marker


def _read_key_value_file(
    path: Path,
) -> dict[str, str]:
    """Read bounded metadata without following symlinks."""
    if path.is_symlink():
        raise RecoveryReconciliationError("Recovery metadata must not be a symlink.")

    flags = os.O_RDONLY

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RecoveryReconciliationError(f"Could not open recovery metadata: {exc}") from exc

    try:
        before = os.fstat(descriptor)

        if not stat.S_ISREG(before.st_mode):
            raise RecoveryReconciliationError("Recovery metadata must be a regular file.")

        if before.st_size <= 0 or before.st_size > MAX_RECOVERY_METADATA_BYTES:
            raise RecoveryReconciliationError("Recovery metadata has an invalid or excessive size.")

        with os.fdopen(
            descriptor,
            "rb",
            closefd=False,
        ) as handle:
            raw = handle.read(MAX_RECOVERY_METADATA_BYTES + 1)

        after = os.fstat(descriptor)
    except Exception:
        os.close(descriptor)
        raise
    else:
        os.close(descriptor)

    if len(raw) > MAX_RECOVERY_METADATA_BYTES:
        raise RecoveryReconciliationError("Recovery metadata exceeds the size limit.")

    if len(raw) != before.st_size:
        raise RecoveryReconciliationError("Recovery metadata changed while being read.")

    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise RecoveryReconciliationError("Recovery metadata changed during inspection.")

    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RecoveryReconciliationError("Recovery metadata is not valid UTF-8.") from exc

    values: dict[str, str] = {}

    for line in lines:
        if "=" not in line:
            raise RecoveryReconciliationError("Recovery metadata contains a malformed line.")

        key, value = line.split("=", 1)

        if not key or key in values:
            raise RecoveryReconciliationError(
                "Recovery metadata contains an invalid or duplicate field."
            )

        values[key] = value

    if not values:
        raise RecoveryReconciliationError("Recovery metadata is empty.")

    return values


def _validate_artifact_binding(
    artifact: PatchArtifact,
    queued: Any,
) -> None:
    if artifact.approval_request_id != queued.approval_id:
        raise RecoveryReconciliationError("Artifact is bound to a different approval.")

    if queued.request.target != artifact.patch_sha256:
        raise RecoveryReconciliationError("Approval target does not match artifact digest.")

    baseline = queued.request.metadata.get("baseline_commit_sha")

    if baseline is not None and baseline != artifact.baseline_commit_sha:
        raise RecoveryReconciliationError("Approval baseline does not match artifact.")


def _parse_positive_pid(
    raw: str | None,
) -> int:
    try:
        pid = int(raw or "")
    except ValueError as exc:
        raise RecoveryReconciliationError("Lock metadata contains an invalid PID.") from exc

    if pid <= 0:
        raise RecoveryReconciliationError("Lock PID must be positive.")

    return pid


def _process_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False

    return True


def _registered_worktrees(
    trusted_repo: Path,
) -> tuple[Path, ...]:
    output = _run_git(
        trusted_repo,
        "worktree",
        "list",
        "--porcelain",
    )
    paths: list[Path] = []

    for line in output.splitlines():
        if line.startswith("worktree "):
            paths.append(Path(line.removeprefix("worktree ").strip()).resolve(strict=False))

    return tuple(paths)


def _run_git(
    repo: Path,
    *args: str,
) -> str:
    environment = os.environ.copy()
    environment.pop("GIT_DIR", None)
    environment.pop("GIT_WORK_TREE", None)

    completed = subprocess.run(  # nosec B603 B607
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    if completed.returncode != 0:
        detail = (
            completed.stderr.strip() or completed.stdout.strip() or f"git {' '.join(args)} failed"
        )
        raise RecoveryReconciliationError(detail)

    return completed.stdout.strip()


def _strict_descendant(
    candidate: Path,
    root: Path,
) -> bool:
    return candidate != root and root in candidate.parents


def _ensure_private_directory(path: Path) -> Path:
    if path.is_symlink():
        raise RecoveryReconciliationError(f"Refusing symlinked recovery directory: {path}")

    path.mkdir(parents=True, exist_ok=True)

    if not path.is_dir():
        raise RecoveryReconciliationError(f"Recovery path is not a directory: {path}")

    try:
        path.chmod(0o700)
    except OSError as exc:
        raise RecoveryReconciliationError(f"Unable to secure recovery directory: {path}") from exc

    return path.resolve()


__all__ = [
    "ARTIFACT_LOCK_SCHEMA",
    "RECOVERY_POLICY_ID",
    "RecoveryFinding",
    "RecoveryFindingStatus",
    "RecoveryReconciler",
    "RecoveryReconciliationError",
    "RecoveryReport",
]
