"""Canonical local operations for approvals and durable patch artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rygnal.approval_queue import (
    ApprovalQueueError,
    InMemoryApprovalQueue,
    QueuedApproval,
)
from rygnal.approved_apply import (
    ApprovedPatchApplyError,
    ApprovedPatchApplyOutcome,
    ApprovedPatchApplyResult,
)
from rygnal.audit_logger import AuditLogger
from rygnal.models import ApprovalDecision, ApprovalStatus
from rygnal.operation_store import (
    OperationConflictError,
    OperationRecoveryRequiredError,
    OperationStoreError,
    SQLiteOperationStore,
)
from rygnal.patch_approval import (
    PatchApprovalError,
    approve_patch_request,
    reject_patch_request,
    write_patch_approval_decision_audit_event,
)
from rygnal.patch_artifact import (
    PatchArtifact,
    PatchArtifactError,
    PatchArtifactStore,
)
from rygnal.security import redact_sensitive_value


class ApprovalOperationError(RuntimeError):
    """Base error for approval and artifact operational failures."""


class ApprovalArtifactBindingError(ApprovalOperationError):
    """Raised when an approval and artifact are not bound coherently."""


class ApprovalOperationStateError(ApprovalOperationError):
    """Raised when an operation is invalid for the current lifecycle state."""


@dataclass(frozen=True, slots=True)
class ApprovalArtifactView:
    """Safe operational view without raw patch content."""

    approval_id: str
    approval_status: str
    approval_created_at: str
    requested_by: str
    severity: str
    reason: str

    artifact_id: str
    artifact_state: str
    artifact_expired: bool
    artifact_created_at: str
    artifact_expires_at: str

    patch_sha256: str
    patch_size_bytes: int
    baseline_commit_sha: str
    changed_file_count: int

    decision_status: str | None
    decided_by: str | None
    decided_at: str | None
    decision_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a stable, redacted operational representation."""
        payload = {
            "approval": {
                "approval_id": self.approval_id,
                "status": self.approval_status,
                "created_at": self.approval_created_at,
                "requested_by": self.requested_by,
                "severity": self.severity,
                "reason": self.reason,
                "decision": {
                    "status": self.decision_status,
                    "decided_by": self.decided_by,
                    "decided_at": self.decided_at,
                    "reason": self.decision_reason,
                },
            },
            "artifact": {
                "artifact_id": self.artifact_id,
                "state": self.artifact_state,
                "expired": self.artifact_expired,
                "created_at": self.artifact_created_at,
                "expires_at": self.artifact_expires_at,
                "patch_sha256": self.patch_sha256,
                "patch_size_bytes": self.patch_size_bytes,
                "baseline_commit_sha": self.baseline_commit_sha,
                "changed_file_count": self.changed_file_count,
            },
        }

        redacted = redact_sensitive_value(payload)

        if not isinstance(redacted, dict):
            raise ApprovalOperationError("Approval operation redaction returned invalid data.")

        return redacted


class ApprovalArtifactService:
    """One authority for durable approval and artifact operations."""

    def __init__(
        self,
        *,
        approval_queue: InMemoryApprovalQueue,
        artifact_store: PatchArtifactStore,
        audit_logger: AuditLogger,
        operation_store: SQLiteOperationStore | None = None,
    ) -> None:
        self.approval_queue = approval_queue
        self.artifact_store = artifact_store
        self.audit_logger = audit_logger
        self.operation_store = operation_store

    def list(
        self,
        *,
        status: ApprovalStatus | None = None,
    ) -> tuple[ApprovalArtifactView, ...]:
        """List approval-backed artifacts in queue order."""
        return tuple(
            self._view_for_queued(item)
            for item in self.approval_queue.list(status=status)
            if _artifact_id_from_request(item) is not None
        )

    def inspect_approval(
        self,
        approval_id: str,
    ) -> ApprovalArtifactView:
        """Inspect one approval and its bound artifact."""
        return self._view_for_queued(self.approval_queue.get(approval_id))

    def inspect_artifact(
        self,
        artifact_id: str,
    ) -> ApprovalArtifactView:
        """Inspect one artifact through its authoritative approval."""
        return self._view_for_queued(self._queued_for_artifact(artifact_id))

    def approve(
        self,
        approval_id: str,
        *,
        decided_by: str,
        reason: str,
    ) -> ApprovalArtifactView:
        """Create and persist a signed patch-bound approval decision."""
        queued = self.approval_queue.get(approval_id)
        artifact = self._load_bound_artifact(
            queued,
            allow_expired=False,
            allow_consumed=False,
        )

        try:
            decision = approve_patch_request(
                queued.request,
                decided_by=decided_by,
                reason=reason,
                patch_sha256=artifact.patch_sha256,
            )
            updated = self.approval_queue.record_decision(
                approval_id,
                approval_decision=decision,
            )
        except (ApprovalQueueError, PatchApprovalError) as exc:
            raise ApprovalOperationError(str(exc)) from exc

        write_patch_approval_decision_audit_event(
            self.audit_logger,
            updated.request,
            _required_decision(updated),
        )

        return self._view_for_queued(updated)

    def reject(
        self,
        approval_id: str,
        *,
        decided_by: str,
        reason: str,
    ) -> ApprovalArtifactView:
        """Persist a patch-bound rejection decision."""
        queued = self.approval_queue.get(approval_id)
        artifact = self._load_bound_artifact(
            queued,
            allow_expired=True,
            allow_consumed=True,
        )

        try:
            decision = reject_patch_request(
                queued.request,
                decided_by=decided_by,
                reason=reason,
                patch_sha256=artifact.patch_sha256,
            )
            updated = self.approval_queue.record_decision(
                approval_id,
                approval_decision=decision,
            )
        except (ApprovalQueueError, PatchApprovalError) as exc:
            raise ApprovalOperationError(str(exc)) from exc

        write_patch_approval_decision_audit_event(
            self.audit_logger,
            updated.request,
            _required_decision(updated),
        )

        return self._view_for_queued(updated)

    def apply_artifact(
        self,
        artifact_id: str,
        target_repo_path: str | Path,
    ) -> ApprovedPatchApplyResult:
        """Apply with a durable cross-process reservation."""
        queued = self._queued_for_artifact(artifact_id)

        if queued.status != ApprovalStatus.APPROVED:
            raise ApprovalOperationStateError(
                "Patch artifact cannot be applied because "
                f"its approval status is "
                f"'{queued.status.value}'."
            )

        decision = _required_decision(queued)
        artifact = self._load_bound_artifact(
            queued,
            allow_expired=True,
            allow_consumed=True,
        )

        if self.operation_store is None:
            try:
                return self.artifact_store.apply_approved(
                    artifact_id,
                    target_repo_path,
                    approval_request=queued.request,
                    approval_decision=decision,
                    logger=self.audit_logger,
                )
            except (
                ApprovedPatchApplyError,
                PatchArtifactError,
            ) as exc:
                raise ApprovalOperationError(str(exc)) from exc

        try:
            reservation = self.operation_store.reserve_artifact_apply(
                artifact_id=artifact.artifact_id,
                approval_id=queued.approval_id,
                patch_sha256=(artifact.patch_sha256),
                baseline_commit_sha=(artifact.baseline_commit_sha),
                target_repo_path=target_repo_path,
            )
        except (
            OperationConflictError,
            OperationRecoveryRequiredError,
            OperationStoreError,
        ) as exc:
            raise ApprovalOperationStateError(str(exc)) from exc

        if reservation.replayed:
            return _replayed_apply_result(
                artifact=artifact,
                queued=queued,
                operation_result=(reservation.record.result),
                target_repo_path=target_repo_path,
            )

        applying = self.operation_store.mark_applying(reservation)
        reservation = reservation.__class__(
            record=applying,
            acquired=True,
            replayed=False,
        )

        try:
            result = self.artifact_store.apply_approved(
                artifact_id,
                target_repo_path,
                approval_request=queued.request,
                approval_decision=decision,
                logger=self.audit_logger,
            )
        except (
            ApprovedPatchApplyError,
            PatchArtifactError,
            OSError,
            RuntimeError,
        ) as exc:
            try:
                released = self.operation_store.fail_or_preserve_ambiguous(
                    reservation,
                    error=str(exc),
                )
            except OperationStoreError as state_exc:
                raise ApprovalOperationError(
                    "Artifact application failed and "
                    "its durable operation state could "
                    "not be finalized safely."
                ) from state_exc

            if released:
                raise ApprovalOperationError(str(exc)) from exc

            raise ApprovalOperationStateError(
                "Artifact application may have mutated "
                "the trusted repository, but durable "
                "completion was not established. "
                "Run crash recovery before continuing."
            ) from exc

        try:
            self.operation_store.mark_applied(
                reservation,
                result.audit_summary,
            )
        except OperationStoreError as exc:
            raise ApprovalOperationStateError(
                "Patch applied, but durable operation "
                "completion could not be recorded. "
                "Run crash recovery before continuing."
            ) from exc

        return result

    def _queued_for_artifact(
        self,
        artifact_id: str,
    ) -> QueuedApproval:
        matches = tuple(
            item
            for item in self.approval_queue.list()
            if _artifact_id_from_request(item) == artifact_id
        )

        if not matches:
            raise ApprovalArtifactBindingError(
                f"No approval is bound to patch artifact: {artifact_id}"
            )

        if len(matches) != 1:
            raise ApprovalArtifactBindingError(
                "Multiple approvals are bound to the same patch artifact."
            )

        return matches[0]

    def _load_bound_artifact(
        self,
        queued: QueuedApproval,
        *,
        allow_expired: bool,
        allow_consumed: bool,
    ) -> PatchArtifact:
        artifact_id = _artifact_id_from_request(queued)

        if artifact_id is None:
            raise ApprovalArtifactBindingError(
                "Approval request has no durable patch artifact binding."
            )

        try:
            artifact = self.artifact_store.load(
                artifact_id,
                allow_expired=allow_expired,
                allow_consumed=allow_consumed,
            )
        except PatchArtifactError as exc:
            raise ApprovalOperationError(str(exc)) from exc

        if artifact.approval_request_id != queued.approval_id:
            raise ApprovalArtifactBindingError(
                "Patch artifact is bound to a different approval request."
            )

        request_patch_sha = queued.request.metadata.get(
            "patch_sha256",
            queued.request.target,
        )

        if request_patch_sha != artifact.patch_sha256:
            raise ApprovalArtifactBindingError(
                "Approval patch digest does not match its durable artifact."
            )

        request_baseline = queued.request.metadata.get("baseline_commit_sha")

        if request_baseline is not None and request_baseline != artifact.baseline_commit_sha:
            raise ApprovalArtifactBindingError(
                "Approval baseline does not match its durable artifact."
            )

        return artifact

    def _view_for_queued(
        self,
        queued: QueuedApproval,
    ) -> ApprovalArtifactView:
        artifact = self._load_bound_artifact(
            queued,
            allow_expired=True,
            allow_consumed=True,
        )
        patch_diff = artifact.to_patch_diff()
        decision: ApprovalDecision | None = queued.decision

        return ApprovalArtifactView(
            approval_id=queued.approval_id,
            approval_status=queued.status.value,
            approval_created_at=queued.request.created_at,
            requested_by=queued.request.requested_by,
            severity=queued.request.severity.value,
            reason=queued.request.reason,
            artifact_id=artifact.artifact_id,
            artifact_state=artifact.state,
            artifact_expired=artifact.expired,
            artifact_created_at=artifact.created_at,
            artifact_expires_at=artifact.expires_at,
            patch_sha256=artifact.patch_sha256,
            patch_size_bytes=artifact.patch_size_bytes,
            baseline_commit_sha=artifact.baseline_commit_sha,
            changed_file_count=patch_diff.changed_file_count,
            decision_status=(decision.status.value if decision is not None else None),
            decided_by=(decision.decided_by if decision is not None else None),
            decided_at=(decision.decided_at if decision is not None else None),
            decision_reason=(decision.reason if decision is not None else None),
        )


def _replayed_apply_result(
    *,
    artifact: PatchArtifact,
    queued: QueuedApproval,
    operation_result: dict[str, Any] | None,
    target_repo_path: str | Path,
) -> ApprovedPatchApplyResult:
    decision = _required_decision(queued)
    result = operation_result or {}

    return ApprovedPatchApplyResult(
        outcome=ApprovedPatchApplyOutcome.APPLIED,
        target_repo_path=str(
            result.get(
                "target_repo_path",
                Path(target_repo_path).expanduser().resolve().as_posix(),
            )
        ),
        patch_sha256=artifact.patch_sha256,
        baseline_commit_sha=(artifact.baseline_commit_sha),
        approval_id=queued.approval_id,
        approved_by=str(
            result.get(
                "approved_by",
                decision.decided_by,
            )
        ),
        files=tuple(file.path for file in artifact.to_patch_diff().files),
        risk_report=artifact.to_risk_report(),
    )


def _artifact_id_from_request(
    queued: QueuedApproval,
) -> str | None:
    value = queued.request.metadata.get("artifact_id")

    if isinstance(value, str) and value.strip():
        return value

    return None


def _required_decision(
    queued: QueuedApproval,
) -> ApprovalDecision:
    if queued.decision is None:
        raise ApprovalOperationStateError("Approval queue item has no persisted decision.")

    return queued.decision


__all__ = [
    "ApprovalArtifactBindingError",
    "ApprovalArtifactService",
    "ApprovalArtifactView",
    "ApprovalOperationError",
    "ApprovalOperationStateError",
]
