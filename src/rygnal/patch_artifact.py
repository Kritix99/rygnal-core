"""Durable, tamper-evident patch artifacts for approval workflows."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from rygnal.approved_apply import ApprovedPatchApplyResult, apply_approved_patch
from rygnal.audit_logger import AuditLogger
from rygnal.change_risk import (
    ChangeRiskReason,
    ChangeRiskReport,
    FileRiskClassification,
    RustCriticalityShadow,
)
from rygnal.changed_files import (
    ChangedFileKind,
    IgnoredChangedFile,
    IgnoredFileReason,
)
from rygnal.models import ApprovalDecision, ApprovalRequest
from rygnal.patch_diff import PatchDiff, PatchFileDiff
from rygnal.risk_engine import RiskLevel

PATCH_ARTIFACT_SCHEMA_VERSION = "patch-artifact.v1"
PATCH_ARTIFACT_STATE_PENDING = "pending"
PATCH_ARTIFACT_STATE_CONSUMED = "consumed"
DEFAULT_PATCH_ARTIFACT_TTL_SECONDS = 60 * 60
MAX_PATCH_ARTIFACT_BYTES = 64 * 1024 * 1024
LOCK_RETRY_SECONDS = 0.05
LOCK_RETRY_COUNT = 40


class PatchArtifactError(RuntimeError):
    """Raised when a durable patch artifact cannot be trusted or processed."""


class PatchArtifactNotFoundError(PatchArtifactError):
    """Raised when the requested artifact does not exist."""


class PatchArtifactTamperedError(PatchArtifactError):
    """Raised when persisted artifact content fails integrity verification."""


class PatchArtifactExpiredError(PatchArtifactError):
    """Raised when a pending artifact is outside its approval lifetime."""


class PatchArtifactConsumedError(PatchArtifactError):
    """Raised when an already-consumed artifact is used again."""


@dataclass(frozen=True)
class PatchArtifact:
    schema_version: str
    artifact_id: str
    run_id: str
    trace_id: str
    approval_request_id: str
    trusted_repo_path: str
    trusted_repo_identity_sha256: str
    baseline_commit_sha: str
    workspace_path: str
    patch_base64: str
    patch_sha256: str
    patch_size_bytes: int
    files: tuple[dict[str, Any], ...]
    ignored_files: tuple[dict[str, Any], ...]
    risk_summary: dict[str, Any]
    intent_summary: dict[str, Any]
    created_at: str
    expires_at: str
    state: str = PATCH_ARTIFACT_STATE_PENDING
    consumed_at: str | None = None
    artifact_digest: str = ""

    @property
    def patch_bytes(self) -> bytes:
        try:
            value = base64.b64decode(
                self.patch_base64.encode("ascii"),
                validate=True,
            )
        except (ValueError, UnicodeError) as exc:
            raise PatchArtifactTamperedError(
                "Patch artifact contains invalid base64 patch data."
            ) from exc

        return value

    @property
    def patch_text(self) -> str:
        return self.patch_bytes.decode(
            "utf-8",
            errors="surrogateescape",
        )

    @property
    def expired(self) -> bool:
        return _parse_timestamp(self.expires_at) < datetime.now(UTC)

    def to_payload(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "artifact_id": self.artifact_id,
            "run_id": self.run_id,
            "trace_id": self.trace_id,
            "approval_request_id": self.approval_request_id,
            "trusted_repo_path": self.trusted_repo_path,
            "trusted_repo_identity_sha256": self.trusted_repo_identity_sha256,
            "baseline_commit_sha": self.baseline_commit_sha,
            "workspace_path": self.workspace_path,
            "patch_base64": self.patch_base64,
            "patch_sha256": self.patch_sha256,
            "patch_size_bytes": self.patch_size_bytes,
            "files": list(self.files),
            "ignored_files": list(self.ignored_files),
            "risk_summary": self.risk_summary,
            "intent_summary": self.intent_summary,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "state": self.state,
            "consumed_at": self.consumed_at,
        }

        if include_digest:
            payload["artifact_digest"] = self.artifact_digest

        return payload

    def to_patch_diff(self) -> PatchDiff:
        patch_bytes = self.patch_bytes
        actual_sha = hashlib.sha256(patch_bytes).hexdigest()

        if actual_sha != self.patch_sha256:
            raise PatchArtifactTamperedError(
                "Patch bytes do not match the persisted patch SHA-256."
            )

        if len(patch_bytes) != self.patch_size_bytes:
            raise PatchArtifactTamperedError("Patch bytes do not match the persisted patch length.")

        files = tuple(
            PatchFileDiff(
                path=str(item["path"]),
                old_path=_optional_string(item.get("old_path")),
                kind=ChangedFileKind(str(item["kind"])),
                additions=_optional_integer(item.get("additions")),
                deletions=_optional_integer(item.get("deletions")),
                binary=bool(item.get("binary", False)),
                old_mode=_optional_string(item.get("old_mode")),
                new_mode=_optional_string(item.get("new_mode")),
                mode_changed=bool(item.get("mode_changed", False)),
            )
            for item in self.files
        )

        ignored_files = tuple(
            IgnoredChangedFile(
                path=str(item["path"]),
                reason=IgnoredFileReason(str(item["reason"])),
            )
            for item in self.ignored_files
        )

        return PatchDiff(
            workspace_path=self.workspace_path,
            baseline_commit_sha=self.baseline_commit_sha,
            patch=self.patch_text,
            patch_sha256=self.patch_sha256,
            patch_size_bytes=self.patch_size_bytes,
            files=files,
            ignored_files=ignored_files,
        )

    def to_risk_report(self) -> ChangeRiskReport:
        decoded = _decode_lossless_value(self.risk_summary)

        if not isinstance(decoded, dict):
            raise PatchArtifactTamperedError("Decoded risk summary must be an object.")

        return _risk_report_from_summary(decoded)


class PatchArtifactStore:
    """Private atomic store for pending guarded-patch artifacts."""

    def __init__(self, root: str | Path) -> None:
        candidate = Path(root).expanduser()
        candidate.mkdir(mode=0o700, parents=True, exist_ok=True)

        if candidate.is_symlink():
            raise PatchArtifactError(f"Refusing to use symlinked artifact root: {candidate}")

        if not candidate.is_dir():
            raise PatchArtifactError(f"Patch artifact root is not a directory: {candidate}")

        try:
            candidate.chmod(0o700)
        except OSError as exc:
            raise PatchArtifactError(f"Unable to secure patch artifact root: {candidate}") from exc

        self.root = candidate.resolve()

    def persist(
        self,
        *,
        patch_diff: PatchDiff,
        run_id: str,
        trace_id: str,
        approval_request: ApprovalRequest,
        trusted_repo_path: str | Path,
        risk_report: ChangeRiskReport,
        intent_summary: Mapping[str, Any] | None = None,
        ttl_seconds: int = DEFAULT_PATCH_ARTIFACT_TTL_SECONDS,
    ) -> PatchArtifact:
        if ttl_seconds <= 0:
            raise PatchArtifactError("Patch artifact TTL must be positive.")

        trusted_repo = Path(trusted_repo_path).expanduser().resolve()

        if not trusted_repo.is_dir():
            raise PatchArtifactError(f"Trusted repository does not exist: {trusted_repo}")

        if approval_request.target != patch_diff.patch_sha256:
            raise PatchArtifactError("Approval request target does not match patch digest.")

        request_baseline = approval_request.metadata.get("baseline_commit_sha")
        if request_baseline != patch_diff.baseline_commit_sha:
            raise PatchArtifactError("Approval request baseline does not match patch baseline.")

        patch_bytes = patch_diff.patch.encode(
            "utf-8",
            errors="surrogateescape",
        )
        actual_sha = hashlib.sha256(patch_bytes).hexdigest()

        if actual_sha != patch_diff.patch_sha256:
            raise PatchArtifactError("Patch content does not match PatchDiff SHA-256.")

        if len(patch_bytes) != patch_diff.patch_size_bytes:
            raise PatchArtifactError("Patch content does not match PatchDiff byte length.")

        artifact_id = uuid.uuid4().hex
        created = datetime.now(UTC)
        expires = created + timedelta(seconds=ttl_seconds)

        artifact = PatchArtifact(
            schema_version=PATCH_ARTIFACT_SCHEMA_VERSION,
            artifact_id=artifact_id,
            run_id=_require_identifier(run_id, "run ID"),
            trace_id=_require_identifier(trace_id, "trace ID"),
            approval_request_id=approval_request.approval_id,
            trusted_repo_path=trusted_repo.as_posix(),
            trusted_repo_identity_sha256=_repo_identity(trusted_repo),
            baseline_commit_sha=patch_diff.baseline_commit_sha,
            workspace_path=patch_diff.workspace_path,
            patch_base64=base64.b64encode(patch_bytes).decode("ascii"),
            patch_sha256=patch_diff.patch_sha256,
            patch_size_bytes=patch_diff.patch_size_bytes,
            files=tuple(
                {
                    "path": file.path,
                    "old_path": file.old_path,
                    "kind": file.kind.value,
                    "additions": file.additions,
                    "deletions": file.deletions,
                    "binary": file.binary,
                    "old_mode": file.old_mode,
                    "new_mode": file.new_mode,
                    "mode_changed": file.mode_changed,
                }
                for file in patch_diff.files
            ),
            ignored_files=tuple(
                {
                    "path": file.path,
                    "reason": file.reason.value,
                }
                for file in patch_diff.ignored_files
            ),
            risk_summary=_encode_lossless_value(risk_report.audit_summary),
            intent_summary=_encode_lossless_value(dict(intent_summary or {})),
            created_at=created.isoformat(),
            expires_at=expires.isoformat(),
        )
        artifact = _with_integrity_digest(artifact)

        with self._artifact_lock(artifact_id):
            path = self._artifact_path(artifact_id)

            if path.exists():
                raise PatchArtifactError(f"Artifact ID collision: {artifact_id}")

            self._atomic_write(path, artifact.to_payload())

        loaded = self.load(
            artifact_id,
            allow_expired=True,
            allow_consumed=True,
        )

        if loaded.artifact_digest != artifact.artifact_digest:
            raise PatchArtifactTamperedError(
                "Persisted artifact verification did not reproduce its digest."
            )

        return loaded

    def load(
        self,
        artifact_id: str,
        *,
        allow_expired: bool = False,
        allow_consumed: bool = False,
    ) -> PatchArtifact:
        normalized_id = _require_identifier(
            artifact_id,
            "artifact ID",
        )
        path = self._artifact_path(normalized_id)

        if not path.exists():
            raise PatchArtifactNotFoundError(f"Patch artifact was not found: {normalized_id}")

        if path.is_symlink() or not path.is_file():
            raise PatchArtifactTamperedError(
                "Patch artifact path is not a regular non-symlink file."
            )

        size = path.stat().st_size
        if size <= 0 or size > MAX_PATCH_ARTIFACT_BYTES:
            raise PatchArtifactTamperedError(f"Patch artifact has invalid size: {size}")

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PatchArtifactTamperedError("Patch artifact is not valid UTF-8 JSON.") from exc

        artifact = _artifact_from_payload(payload)
        _verify_artifact(artifact)

        if artifact.artifact_id != normalized_id:
            raise PatchArtifactTamperedError("Patch artifact ID does not match its filename.")

        if artifact.state == PATCH_ARTIFACT_STATE_CONSUMED and not allow_consumed:
            raise PatchArtifactConsumedError(
                f"Patch artifact has already been consumed: {artifact_id}"
            )

        if artifact.expired and not allow_expired:
            raise PatchArtifactExpiredError(f"Patch artifact has expired: {artifact_id}")

        return artifact

    def delete(self, artifact_id: str) -> None:
        normalized_id = _require_identifier(
            artifact_id,
            "artifact ID",
        )

        with self._artifact_lock(normalized_id):
            path = self._artifact_path(normalized_id)

            if path.exists():
                if path.is_symlink() or not path.is_file():
                    raise PatchArtifactTamperedError(
                        "Refusing to delete a non-regular artifact path."
                    )
                path.unlink()

    def mark_consumed(
        self,
        artifact_id: str,
    ) -> PatchArtifact:
        """Atomically mark one pending artifact consumed."""
        normalized_id = _require_identifier(
            artifact_id,
            "artifact ID",
        )

        with self._artifact_lock(normalized_id):
            artifact = self.load(
                normalized_id,
                allow_expired=True,
                allow_consumed=True,
            )
            return self._mark_consumed_unlocked(artifact)

    def apply_approved(
        self,
        artifact_id: str,
        target_repo_path: str | Path,
        *,
        approval_request: ApprovalRequest,
        approval_decision: ApprovalDecision,
        logger: AuditLogger | None = None,
    ) -> ApprovedPatchApplyResult:
        """Hold the artifact lock through apply and consume."""
        normalized_id = _require_identifier(
            artifact_id,
            "artifact ID",
        )

        with self._artifact_lock(normalized_id):
            artifact = self.load(
                normalized_id,
                allow_expired=False,
                allow_consumed=False,
            )

            if artifact.approval_request_id != approval_request.approval_id:
                raise PatchArtifactError("Patch artifact is bound to a different approval request.")

            metadata_artifact_id = approval_request.metadata.get("artifact_id")

            if metadata_artifact_id is not None and metadata_artifact_id != artifact.artifact_id:
                raise PatchArtifactError("Approval request artifact binding does not match.")

            target_repo = Path(target_repo_path).expanduser().resolve()

            if _repo_identity(target_repo) != artifact.trusted_repo_identity_sha256:
                raise PatchArtifactError(
                    "Patch artifact is bound to a different trusted repository."
                )

            result = apply_approved_patch(
                artifact.to_patch_diff(),
                target_repo,
                approval_request=approval_request,
                approval_decision=approval_decision,
                risk_report=artifact.to_risk_report(),
                logger=logger,
            )

            self._mark_consumed_unlocked(artifact)
            return result

    def _mark_consumed_unlocked(
        self,
        artifact: PatchArtifact,
    ) -> PatchArtifact:
        if artifact.state == PATCH_ARTIFACT_STATE_CONSUMED:
            raise PatchArtifactConsumedError(
                f"Patch artifact has already been consumed: {artifact.artifact_id}"
            )

        consumed = PatchArtifact(
            **{
                **artifact.to_payload(include_digest=False),
                "state": (PATCH_ARTIFACT_STATE_CONSUMED),
                "consumed_at": (datetime.now(UTC).isoformat()),
                "artifact_digest": "",
            }
        )
        consumed = _with_integrity_digest(consumed)

        self._atomic_write(
            self._artifact_path(artifact.artifact_id),
            consumed.to_payload(),
        )

        return self.load(
            artifact.artifact_id,
            allow_expired=True,
            allow_consumed=True,
        )

    def _artifact_path(self, artifact_id: str) -> Path:
        candidate = self.root.joinpath(f"{artifact_id}.json")
        resolved_parent = candidate.parent.resolve()

        if resolved_parent != self.root:
            raise PatchArtifactError("Patch artifact path escaped the configured root.")

        return candidate

    @contextmanager
    def _artifact_lock(
        self,
        artifact_id: str,
    ) -> Iterator[None]:
        lock_path = self.root.joinpath(f".{artifact_id}.lock")
        descriptor: int | None = None

        for _ in range(LOCK_RETRY_COUNT):
            try:
                descriptor = os.open(
                    lock_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                break
            except FileExistsError:
                time.sleep(LOCK_RETRY_SECONDS)

        if descriptor is None:
            raise PatchArtifactError(f"Patch artifact is locked: {artifact_id}")

        try:
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(
                    "schema=rygnal-artifact-lock.v1\n"
                    f"pid={os.getpid()}\n"
                    f"artifact_id={artifact_id}\n"
                    f"created_at_unix={time.time()}\n"
                )
                handle.flush()
                os.fsync(handle.fileno())

            yield
        finally:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass

    def _atomic_write(
        self,
        path: Path,
        payload: Mapping[str, Any],
    ) -> None:
        serialized = _canonical_json(payload).encode("utf-8")

        if len(serialized) > MAX_PATCH_ARTIFACT_BYTES:
            raise PatchArtifactError("Serialized patch artifact exceeds the configured size limit.")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.stem}.",
            suffix=".tmp",
            dir=self.root,
        )
        temporary_path = Path(temporary_name)

        try:
            os.fchmod(descriptor, 0o600)

            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temporary_path, path)
            path.chmod(0o600)

            directory_descriptor = os.open(
                self.root,
                os.O_RDONLY,
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)

            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise


def bind_artifact_to_approval(
    approval_request: ApprovalRequest,
    artifact: PatchArtifact,
) -> ApprovalRequest:
    """Return a frozen approval request carrying artifact identity only."""
    metadata = {
        **approval_request.metadata,
        "artifact_id": artifact.artifact_id,
        "artifact_schema_version": artifact.schema_version,
        "artifact_expires_at": artifact.expires_at,
    }

    return approval_request.model_copy(update={"metadata": metadata})


def _artifact_from_payload(payload: Any) -> PatchArtifact:
    if not isinstance(payload, dict):
        raise PatchArtifactTamperedError("Patch artifact root must be a JSON object.")

    required = {
        "schema_version",
        "artifact_id",
        "run_id",
        "trace_id",
        "approval_request_id",
        "trusted_repo_path",
        "trusted_repo_identity_sha256",
        "baseline_commit_sha",
        "workspace_path",
        "patch_base64",
        "patch_sha256",
        "patch_size_bytes",
        "files",
        "ignored_files",
        "risk_summary",
        "intent_summary",
        "created_at",
        "expires_at",
        "state",
        "consumed_at",
        "artifact_digest",
    }

    missing = required.difference(payload)
    extra = set(payload).difference(required)

    if missing:
        raise PatchArtifactTamperedError(
            "Patch artifact is missing fields: " + ", ".join(sorted(missing))
        )

    if extra:
        raise PatchArtifactTamperedError(
            "Patch artifact contains unknown fields: " + ", ".join(sorted(extra))
        )

    try:
        return PatchArtifact(
            schema_version=str(payload["schema_version"]),
            artifact_id=str(payload["artifact_id"]),
            run_id=str(payload["run_id"]),
            trace_id=str(payload["trace_id"]),
            approval_request_id=str(payload["approval_request_id"]),
            trusted_repo_path=str(payload["trusted_repo_path"]),
            trusted_repo_identity_sha256=str(payload["trusted_repo_identity_sha256"]),
            baseline_commit_sha=str(payload["baseline_commit_sha"]),
            workspace_path=str(payload["workspace_path"]),
            patch_base64=str(payload["patch_base64"]),
            patch_sha256=str(payload["patch_sha256"]),
            patch_size_bytes=int(payload["patch_size_bytes"]),
            files=tuple(dict(item) for item in payload["files"]),
            ignored_files=tuple(dict(item) for item in payload["ignored_files"]),
            risk_summary=dict(payload["risk_summary"]),
            intent_summary=dict(payload["intent_summary"]),
            created_at=str(payload["created_at"]),
            expires_at=str(payload["expires_at"]),
            state=str(payload["state"]),
            consumed_at=_optional_string(payload["consumed_at"]),
            artifact_digest=str(payload["artifact_digest"]),
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise PatchArtifactTamperedError("Patch artifact fields have invalid types.") from exc


def _verify_artifact(artifact: PatchArtifact) -> None:
    if artifact.schema_version != PATCH_ARTIFACT_SCHEMA_VERSION:
        raise PatchArtifactTamperedError(
            f"Unsupported patch artifact schema: {artifact.schema_version}"
        )

    _require_identifier(artifact.artifact_id, "artifact ID")
    _require_identifier(artifact.run_id, "run ID")
    _require_identifier(artifact.trace_id, "trace ID")
    _require_identifier(
        artifact.approval_request_id,
        "approval request ID",
    )

    if artifact.state not in {
        PATCH_ARTIFACT_STATE_PENDING,
        PATCH_ARTIFACT_STATE_CONSUMED,
    }:
        raise PatchArtifactTamperedError(f"Invalid patch artifact state: {artifact.state}")

    if artifact.state == PATCH_ARTIFACT_STATE_CONSUMED and artifact.consumed_at is None:
        raise PatchArtifactTamperedError("Consumed artifact is missing consumed_at.")

    if artifact.state == PATCH_ARTIFACT_STATE_PENDING and artifact.consumed_at is not None:
        raise PatchArtifactTamperedError("Pending artifact must not have consumed_at.")

    created = _parse_timestamp(artifact.created_at)
    expires = _parse_timestamp(artifact.expires_at)

    if expires <= created:
        raise PatchArtifactTamperedError("Patch artifact expiration must follow creation.")

    patch_bytes = artifact.patch_bytes

    if hashlib.sha256(patch_bytes).hexdigest() != artifact.patch_sha256:
        raise PatchArtifactTamperedError("Patch artifact patch digest is invalid.")

    if len(patch_bytes) != artifact.patch_size_bytes:
        raise PatchArtifactTamperedError("Patch artifact patch byte length is invalid.")

    expected_repo_identity = _repo_identity(Path(artifact.trusted_repo_path))
    if expected_repo_identity != artifact.trusted_repo_identity_sha256:
        raise PatchArtifactTamperedError("Patch artifact trusted repository identity is invalid.")

    expected_digest = _artifact_digest(artifact.to_payload(include_digest=False))
    if expected_digest != artifact.artifact_digest:
        raise PatchArtifactTamperedError("Patch artifact integrity digest is invalid.")


def _with_integrity_digest(
    artifact: PatchArtifact,
) -> PatchArtifact:
    digest = _artifact_digest(artifact.to_payload(include_digest=False))

    return PatchArtifact(
        **{
            **artifact.to_payload(include_digest=False),
            "artifact_digest": digest,
        }
    )


def _artifact_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


_LOSSLESS_TYPE_KEY = "__rygnal_serialized_type__"
_LOSSLESS_ITEMS_KEY = "items"


def _encode_lossless_value(value: Any) -> Any:
    """Encode JSON-compatible data without losing tuple/list identity."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    if isinstance(value, tuple):
        return {
            _LOSSLESS_TYPE_KEY: "tuple",
            _LOSSLESS_ITEMS_KEY: [_encode_lossless_value(item) for item in value],
        }

    if isinstance(value, list):
        return [_encode_lossless_value(item) for item in value]

    if isinstance(value, dict):
        if all(isinstance(key, str) for key in value) and _LOSSLESS_TYPE_KEY not in value:
            return {key: _encode_lossless_value(item) for key, item in value.items()}

        return {
            _LOSSLESS_TYPE_KEY: "mapping",
            _LOSSLESS_ITEMS_KEY: [
                [
                    _encode_lossless_value(key),
                    _encode_lossless_value(item),
                ]
                for key, item in value.items()
            ],
        }

    raise PatchArtifactError(
        f"Patch artifact metadata contains an unsupported value type: {type(value).__name__}"
    )


def _decode_lossless_value(value: Any) -> Any:
    """Decode data written by _encode_lossless_value."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    if isinstance(value, list):
        return [_decode_lossless_value(item) for item in value]

    if not isinstance(value, dict):
        raise PatchArtifactTamperedError("Encoded artifact value has an unsupported type.")

    marker = value.get(_LOSSLESS_TYPE_KEY)

    if marker is None:
        return {str(key): _decode_lossless_value(item) for key, item in value.items()}

    if set(value) != {
        _LOSSLESS_TYPE_KEY,
        _LOSSLESS_ITEMS_KEY,
    }:
        raise PatchArtifactTamperedError("Encoded artifact container has unexpected fields.")

    items = value.get(_LOSSLESS_ITEMS_KEY)

    if not isinstance(items, list):
        raise PatchArtifactTamperedError("Encoded artifact container items must be a list.")

    if marker == "tuple":
        return tuple(_decode_lossless_value(item) for item in items)

    if marker == "mapping":
        decoded: dict[Any, Any] = {}

        for pair in items:
            if not isinstance(pair, list) or len(pair) != 2:
                raise PatchArtifactTamperedError("Encoded mapping item must contain two values.")

            key = _decode_lossless_value(pair[0])
            item = _decode_lossless_value(pair[1])

            try:
                if key in decoded:
                    raise PatchArtifactTamperedError("Encoded mapping contains a duplicate key.")
                decoded[key] = item
            except TypeError as exc:
                raise PatchArtifactTamperedError(
                    "Encoded mapping contains an unhashable key."
                ) from exc

        return decoded

    raise PatchArtifactTamperedError(f"Unknown encoded artifact container: {marker}")


def _repo_identity(path: Path) -> str:
    resolved = path.expanduser().resolve()
    return hashlib.sha256(resolved.as_posix().encode("utf-8")).hexdigest()


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PatchArtifactTamperedError(f"Invalid artifact timestamp: {value}") from exc

    if parsed.tzinfo is None:
        raise PatchArtifactTamperedError("Artifact timestamps must include timezone information.")

    return parsed.astimezone(UTC)


def _require_identifier(value: str, label: str) -> str:
    normalized = str(value).strip()

    if not normalized:
        raise PatchArtifactError(f"{label} must not be blank.")

    if any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        for character in normalized
    ):
        raise PatchArtifactError(f"{label} contains unsupported characters.")

    if len(normalized) > 160:
        raise PatchArtifactError(f"{label} is too long.")

    return normalized


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_integer(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _risk_reason_from_summary(
    summary: Mapping[str, Any],
) -> ChangeRiskReason:
    evidence = summary.get("evidence", {})

    if not isinstance(evidence, dict):
        raise PatchArtifactTamperedError("Risk reason evidence must be an object.")

    return ChangeRiskReason(
        code=str(summary["code"]),
        risk_level=RiskLevel(str(summary["risk_level"])),
        reason=str(summary["reason"]),
        evidence=tuple(sorted((str(key), value) for key, value in evidence.items())),
    )


def _rust_shadow_from_summary(
    summary: Mapping[str, Any] | None,
) -> RustCriticalityShadow | None:
    if summary is None:
        return None

    semantic_metrics = summary.get("semantic_metrics")
    if semantic_metrics is not None:
        semantic_metrics = dict(semantic_metrics)

    return RustCriticalityShadow(
        available=bool(summary.get("available", False)),
        criticality_index=(
            float(summary["criticality_index"])
            if summary.get("criticality_index") is not None
            else None
        ),
        risk_level=_optional_string(summary.get("risk_level")),
        reasons=tuple(str(item) for item in summary.get("reasons", ())),
        semantic_metrics=semantic_metrics,
        path_category=_optional_string(summary.get("path_category")),
        path_severity=_optional_string(summary.get("path_severity")),
        error_code=_optional_string(summary.get("error_code")),
        error_reason=_optional_string(summary.get("error_reason")),
        criticality_bypass_verdict=_optional_string(summary.get("criticality_bypass_verdict")),
        criticality_bypass_reason=_optional_string(summary.get("criticality_bypass_reason")),
    )


def _risk_report_from_summary(
    summary: Mapping[str, Any],
) -> ChangeRiskReport:
    files_raw = summary.get("files", ())
    report_reasons_raw = summary.get("report_reasons", ())

    files = tuple(
        FileRiskClassification(
            path=str(item["path"]),
            old_path=_optional_string(item.get("old_path")),
            kind=ChangedFileKind(str(item["kind"])),
            risk_level=RiskLevel(str(item["risk_level"])),
            additions=_optional_integer(item.get("additions")),
            deletions=_optional_integer(item.get("deletions")),
            binary=bool(item.get("binary", False)),
            old_mode=_optional_string(item.get("old_mode")),
            new_mode=_optional_string(item.get("new_mode")),
            mode_changed=bool(item.get("mode_changed", False)),
            reasons=tuple(_risk_reason_from_summary(reason) for reason in item.get("reasons", ())),
            rust_criticality=_rust_shadow_from_summary(item.get("rust_criticality")),
        )
        for item in files_raw
    )

    report_reasons = tuple(_risk_reason_from_summary(reason) for reason in report_reasons_raw)

    return ChangeRiskReport(
        baseline_commit_sha=str(summary["baseline_commit_sha"]),
        patch_sha256=str(summary["patch_sha256"]),
        files=files,
        report_reasons=report_reasons,
    )


__all__ = [
    "DEFAULT_PATCH_ARTIFACT_TTL_SECONDS",
    "PATCH_ARTIFACT_SCHEMA_VERSION",
    "PatchArtifact",
    "PatchArtifactConsumedError",
    "PatchArtifactError",
    "PatchArtifactExpiredError",
    "PatchArtifactNotFoundError",
    "PatchArtifactStore",
    "PatchArtifactTamperedError",
    "bind_artifact_to_approval",
]
