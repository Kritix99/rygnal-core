"""Durable cross-process operation and repository leases."""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import sqlite3
import subprocess  # nosec B404
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from rygnal.sqlite_migrations import migrate_operation_database
from rygnal.sqlite_runtime import (
    connect_sqlite,
    initialize_sqlite_database,
)

OPERATION_STORE_SCHEMA = "operation-store.v1"
OPERATION_TYPE_ARTIFACT_APPLY = "artifact_apply"


class OperationStoreError(RuntimeError):
    """Base error for durable operation coordination."""


class OperationConflictError(OperationStoreError):
    """Raised when an active operation owns a resource."""


class OperationRecoveryRequiredError(OperationStoreError):
    """Raised when an incomplete operation needs recovery."""


class OperationTerminalError(OperationStoreError):
    """Raised for a non-retryable terminal operation."""


class OperationState(StrEnum):
    RESERVED = "reserved"
    APPLYING = "applying"
    APPLIED = "applied"
    FAILED = "failed"


class OperationRecoveryStatus(StrEnum):
    ACTIVE = "active"
    RELEASED = "released"
    APPLIED_RECOVERED = "applied_recovered"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class OperationRecord:
    operation_key: str
    operation_type: str
    resource_key: str
    artifact_id: str
    approval_id: str
    patch_sha256: str
    baseline_commit_sha: str
    target_repo_path: str
    state: OperationState
    owner_token: str
    owner_pid: int
    owner_start_token: str
    created_at_unix: float
    updated_at_unix: float
    retryable: bool
    result: dict[str, Any] | None
    error: str | None


@dataclass(frozen=True, slots=True)
class OperationReservation:
    record: OperationRecord
    acquired: bool
    replayed: bool


@dataclass(frozen=True, slots=True)
class OperationRecoveryResult:
    operation_key: str
    artifact_id: str
    status: OperationRecoveryStatus
    message: str
    target_repo_path: str


class SQLiteOperationStore:
    """Coordinate repository mutation across processes."""

    def __init__(
        self,
        db_path: str | Path,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        initialize_sqlite_database(self.db_path)
        self._initialize()

    def reserve_artifact_apply(
        self,
        *,
        artifact_id: str,
        approval_id: str,
        patch_sha256: str,
        baseline_commit_sha: str,
        target_repo_path: str | Path,
    ) -> OperationReservation:
        """Reserve one artifact and trusted repository."""
        target_repo = Path(target_repo_path).expanduser().resolve()

        operation_key = artifact_apply_operation_key(
            artifact_id=artifact_id,
            approval_id=approval_id,
            patch_sha256=patch_sha256,
            baseline_commit_sha=baseline_commit_sha,
            target_repo_path=target_repo,
        )
        resource_key = repository_resource_key(target_repo)
        owner_token = uuid.uuid4().hex
        owner_pid = os.getpid()
        owner_start_token = process_identity_token(owner_pid)
        now = time.time()

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")

            existing = self._read_operation(
                connection,
                operation_key,
            )

            if existing is not None:
                if existing.state == OperationState.APPLIED:
                    connection.commit()
                    return OperationReservation(
                        record=existing,
                        acquired=False,
                        replayed=True,
                    )

                if existing.state == OperationState.FAILED and existing.retryable:
                    connection.execute(
                        """
                        DELETE FROM resource_leases
                        WHERE operation_key = ?
                        """,
                        (operation_key,),
                    )
                    connection.execute(
                        """
                        DELETE FROM operations
                        WHERE operation_key = ?
                        """,
                        (operation_key,),
                    )
                elif existing.state in {
                    OperationState.RESERVED,
                    OperationState.APPLYING,
                }:
                    connection.rollback()

                    if owner_record_is_active(existing):
                        raise OperationConflictError(
                            "Artifact application is already active in another process."
                        )

                    raise OperationRecoveryRequiredError(
                        "An incomplete artifact application must be reconciled before retry."
                    )
                else:
                    connection.rollback()
                    raise OperationTerminalError(
                        existing.error or "Artifact application previously failed."
                    )

            resource = connection.execute(
                """
                SELECT operation_key, owner_pid,
                       owner_start_token
                FROM resource_leases
                WHERE resource_key = ?
                """,
                (resource_key,),
            ).fetchone()

            if resource is not None:
                connection.rollback()

                if process_identity_matches(
                    int(resource["owner_pid"]),
                    str(resource["owner_start_token"]),
                ):
                    raise OperationConflictError(
                        "Trusted repository is already owned by another active mutation."
                    )

                raise OperationRecoveryRequiredError(
                    "Trusted repository has a stale or ambiguous mutation lease."
                )

            connection.execute(
                """
                INSERT INTO operations (
                    schema_version,
                    operation_key,
                    operation_type,
                    resource_key,
                    artifact_id,
                    approval_id,
                    patch_sha256,
                    baseline_commit_sha,
                    target_repo_path,
                    state,
                    owner_token,
                    owner_pid,
                    owner_start_token,
                    created_at_unix,
                    updated_at_unix,
                    retryable,
                    result_json,
                    error_text
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, 0, NULL, NULL
                )
                """,
                (
                    OPERATION_STORE_SCHEMA,
                    operation_key,
                    OPERATION_TYPE_ARTIFACT_APPLY,
                    resource_key,
                    artifact_id,
                    approval_id,
                    patch_sha256,
                    baseline_commit_sha,
                    target_repo.as_posix(),
                    OperationState.RESERVED.value,
                    owner_token,
                    owner_pid,
                    owner_start_token,
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO resource_leases (
                    resource_key,
                    operation_key,
                    owner_token,
                    owner_pid,
                    owner_start_token,
                    created_at_unix
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    resource_key,
                    operation_key,
                    owner_token,
                    owner_pid,
                    owner_start_token,
                    now,
                ),
            )
            connection.commit()

            record = self.get(operation_key)

            if record is None:
                raise OperationStoreError("Reserved operation could not be reloaded.")

            return OperationReservation(
                record=record,
                acquired=True,
                replayed=False,
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def mark_applying(
        self,
        reservation: OperationReservation,
    ) -> OperationRecord:
        """Move an owned reservation to applying."""
        return self._owned_transition(
            reservation,
            expected=OperationState.RESERVED,
            next_state=OperationState.APPLYING,
            result=None,
            error=None,
            retryable=False,
            release_resource=False,
        )

    def mark_applied(
        self,
        reservation: OperationReservation,
        result: dict[str, Any],
    ) -> OperationRecord:
        """Persist a terminal successful result."""
        return self._owned_transition(
            reservation,
            expected=OperationState.APPLYING,
            next_state=OperationState.APPLIED,
            result=result,
            error=None,
            retryable=False,
            release_resource=True,
        )

    def fail_or_preserve_ambiguous(
        self,
        reservation: OperationReservation,
        *,
        error: str,
    ) -> bool:
        """Release only when repository mutation did not occur."""
        record = self.get(reservation.record.operation_key)

        if record is None:
            raise OperationStoreError("Operation disappeared during failure handling.")

        repository = inspect_repository_state(Path(record.target_repo_path))

        if repository["head"] == record.baseline_commit_sha.lower() and repository["clean"]:
            self._owned_transition(
                reservation,
                expected=OperationState.APPLYING,
                next_state=OperationState.FAILED,
                result=None,
                error=error,
                retryable=True,
                release_resource=True,
            )
            return True

        return False

    def get(
        self,
        operation_key: str,
    ) -> OperationRecord | None:
        connection = self._connect()

        try:
            return self._read_operation(
                connection,
                operation_key,
            )
        finally:
            connection.close()

    def list_incomplete(
        self,
    ) -> tuple[OperationRecord, ...]:
        connection = self._connect()

        try:
            rows = connection.execute(
                """
                SELECT *
                FROM operations
                WHERE state IN (?, ?)
                ORDER BY created_at_unix ASC
                """,
                (
                    OperationState.RESERVED.value,
                    OperationState.APPLYING.value,
                ),
            ).fetchall()
        finally:
            connection.close()

        return tuple(_record_from_row(row) for row in rows)

    def reconcile_incomplete(
        self,
        *,
        has_apply_evidence: Callable[
            [OperationRecord],
            bool,
        ],
    ) -> tuple[OperationRecoveryResult, ...]:
        """Recover stale operations without guessing mutation."""
        results: list[OperationRecoveryResult] = []

        for record in self.list_incomplete():
            if owner_record_is_active(record):
                results.append(
                    OperationRecoveryResult(
                        operation_key=record.operation_key,
                        artifact_id=record.artifact_id,
                        status=OperationRecoveryStatus.ACTIVE,
                        message=("Operation owner process is still active."),
                        target_repo_path=(record.target_repo_path),
                    )
                )
                continue

            if has_apply_evidence(record):
                result = {
                    "outcome": "applied",
                    "applied": True,
                    "target_repo_path": (record.target_repo_path),
                    "patch_sha256": record.patch_sha256,
                    "baseline_commit_sha": (record.baseline_commit_sha),
                    "approval_id": record.approval_id,
                    "artifact_id": record.artifact_id,
                    "recovered": True,
                }
                self._recover_terminal(
                    record,
                    next_state=OperationState.APPLIED,
                    result=result,
                    error=None,
                    retryable=False,
                )
                results.append(
                    OperationRecoveryResult(
                        operation_key=record.operation_key,
                        artifact_id=record.artifact_id,
                        status=(OperationRecoveryStatus.APPLIED_RECOVERED),
                        message=(
                            "Recovered completed operation from durable approved-apply evidence."
                        ),
                        target_repo_path=(record.target_repo_path),
                    )
                )
                continue

            try:
                repository = inspect_repository_state(Path(record.target_repo_path))
            except OperationStoreError as exc:
                results.append(
                    OperationRecoveryResult(
                        operation_key=record.operation_key,
                        artifact_id=record.artifact_id,
                        status=(OperationRecoveryStatus.UNRESOLVED),
                        message=str(exc),
                        target_repo_path=(record.target_repo_path),
                    )
                )
                continue

            if repository["clean"] and repository["head"] == record.baseline_commit_sha.lower():
                self._recover_terminal(
                    record,
                    next_state=OperationState.FAILED,
                    result=None,
                    error=(
                        "Stale operation released because the "
                        "trusted repository remained unmodified."
                    ),
                    retryable=True,
                )
                results.append(
                    OperationRecoveryResult(
                        operation_key=record.operation_key,
                        artifact_id=record.artifact_id,
                        status=(OperationRecoveryStatus.RELEASED),
                        message=("Released stale pre-mutation operation."),
                        target_repo_path=(record.target_repo_path),
                    )
                )
                continue

            results.append(
                OperationRecoveryResult(
                    operation_key=record.operation_key,
                    artifact_id=record.artifact_id,
                    status=(OperationRecoveryStatus.UNRESOLVED),
                    message=(
                        "Operation owner is gone, but repository "
                        "state is mutated or ambiguous and no "
                        "durable completion evidence exists."
                    ),
                    target_repo_path=(record.target_repo_path),
                )
            )

        return tuple(results)

    def pragma_snapshot(self) -> dict[str, Any]:
        connection = self._connect()

        try:
            names = (
                "journal_mode",
                "synchronous",
                "busy_timeout",
                "foreign_keys",
            )
            return {name: connection.execute(f"PRAGMA {name}").fetchone()[0] for name in names}
        finally:
            connection.close()

    def _owned_transition(
        self,
        reservation: OperationReservation,
        *,
        expected: OperationState,
        next_state: OperationState,
        result: dict[str, Any] | None,
        error: str | None,
        retryable: bool,
        release_resource: bool,
    ) -> OperationRecord:
        record = reservation.record
        now = time.time()
        result_json = (
            json.dumps(
                result,
                sort_keys=True,
                separators=(",", ":"),
            )
            if result is not None
            else None
        )

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE operations
                SET state = ?,
                    updated_at_unix = ?,
                    result_json = ?,
                    error_text = ?,
                    retryable = ?
                WHERE operation_key = ?
                  AND state = ?
                  AND owner_token = ?
                """,
                (
                    next_state.value,
                    now,
                    result_json,
                    error,
                    int(retryable),
                    record.operation_key,
                    expected.value,
                    record.owner_token,
                ),
            )

            if cursor.rowcount != 1:
                connection.rollback()
                raise OperationConflictError("Operation ownership or state changed.")

            if release_resource:
                connection.execute(
                    """
                    DELETE FROM resource_leases
                    WHERE resource_key = ?
                      AND operation_key = ?
                      AND owner_token = ?
                    """,
                    (
                        record.resource_key,
                        record.operation_key,
                        record.owner_token,
                    ),
                )

            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

        updated = self.get(record.operation_key)

        if updated is None:
            raise OperationStoreError("Updated operation could not be reloaded.")

        return updated

    def _recover_terminal(
        self,
        record: OperationRecord,
        *,
        next_state: OperationState,
        result: dict[str, Any] | None,
        error: str | None,
        retryable: bool,
    ) -> None:
        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE operations
                SET state = ?,
                    updated_at_unix = ?,
                    result_json = ?,
                    error_text = ?,
                    retryable = ?
                WHERE operation_key = ?
                  AND state IN (?, ?)
                """,
                (
                    next_state.value,
                    time.time(),
                    (
                        json.dumps(
                            result,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        if result is not None
                        else None
                    ),
                    error,
                    int(retryable),
                    record.operation_key,
                    OperationState.RESERVED.value,
                    OperationState.APPLYING.value,
                ),
            )

            if cursor.rowcount != 1:
                connection.rollback()
                raise OperationConflictError("Operation changed during recovery.")

            connection.execute(
                """
                DELETE FROM resource_leases
                WHERE operation_key = ?
                """,
                (record.operation_key,),
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        """Apply the versioned schema contract."""
        migrate_operation_database(self.db_path)

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.db_path)

    @staticmethod
    def _read_operation(
        connection: sqlite3.Connection,
        operation_key: str,
    ) -> OperationRecord | None:
        row = connection.execute(
            """
            SELECT *
            FROM operations
            WHERE operation_key = ?
            """,
            (operation_key,),
        ).fetchone()

        return _record_from_row(row) if row is not None else None


def artifact_apply_operation_key(
    *,
    artifact_id: str,
    approval_id: str,
    patch_sha256: str,
    baseline_commit_sha: str,
    target_repo_path: Path,
) -> str:
    payload = "\0".join(
        (
            OPERATION_TYPE_ARTIFACT_APPLY,
            artifact_id,
            approval_id,
            patch_sha256,
            baseline_commit_sha.lower(),
            target_repo_path.as_posix(),
        )
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def repository_resource_key(
    target_repo_path: Path,
) -> str:
    return hashlib.sha256(target_repo_path.resolve().as_posix().encode("utf-8")).hexdigest()


def process_identity_token(pid: int) -> str:
    """Return a process-start identity, not merely a PID."""
    if pid <= 0:
        raise OperationStoreError("Process identity requires a positive PID.")

    proc_stat = Path(f"/proc/{pid}/stat")

    if proc_stat.is_file():
        try:
            fields = proc_stat.read_text(encoding="utf-8").split()
        except OSError as exc:
            raise OperationStoreError("Could not inspect process identity.") from exc

        if len(fields) < 22:
            raise OperationStoreError("Linux process identity is incomplete.")

        payload = f"proc:{pid}:{fields[21]}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    ps = shutil.which("ps")

    if ps is None:
        raise OperationStoreError("Process start identity cannot be verified.")

    completed = subprocess.run(  # nosec B603
        [
            ps,
            "-p",
            str(pid),
            "-o",
            "lstart=",
            "-o",
            "command=",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        raise OperationStoreError("Process start identity cannot be read.")

    normalized = " ".join(completed.stdout.split())

    if not normalized:
        raise OperationStoreError("Process start identity is empty.")

    return hashlib.sha256(f"ps:{pid}:{normalized}".encode()).hexdigest()


def process_identity_matches(
    pid: int,
    expected_token: str,
) -> bool:
    try:
        actual = process_identity_token(pid)
    except OperationStoreError:
        return False

    return actual == expected_token


def owner_record_is_active(
    record: OperationRecord,
) -> bool:
    return process_identity_matches(
        record.owner_pid,
        record.owner_start_token,
    )


def inspect_repository_state(
    repository: Path,
) -> dict[str, Any]:
    resolved = repository.expanduser().resolve()

    if not resolved.is_dir():
        raise OperationStoreError("Trusted repository does not exist.")

    git = shutil.which("git")

    if git is None:
        raise OperationStoreError("Git executable is unavailable.")

    def run(*args: str) -> str:
        completed = subprocess.run(  # nosec B603
            [git, *args],
            cwd=resolved,
            capture_output=True,
            text=True,
            check=False,
        )

        if completed.returncode != 0:
            raise OperationStoreError(
                completed.stderr.strip()
                or completed.stdout.strip()
                or "Git repository inspection failed."
            )

        return completed.stdout.strip()

    root = Path(run("rev-parse", "--show-toplevel")).resolve()

    if root != resolved:
        raise OperationStoreError("Target path is not the Git repository root.")

    head = run("rev-parse", "HEAD").lower()
    status = run(
        "status",
        "--porcelain",
        "--untracked-files=all",
    )

    return {
        "head": head,
        "clean": not bool(status),
    }


def _record_from_row(
    row: sqlite3.Row,
) -> OperationRecord:
    created = float(row["created_at_unix"])
    updated = float(row["updated_at_unix"])

    if not math.isfinite(created) or not math.isfinite(updated):
        raise OperationStoreError("Operation timestamps are invalid.")

    result_json = row["result_json"]

    return OperationRecord(
        operation_key=str(row["operation_key"]),
        operation_type=str(row["operation_type"]),
        resource_key=str(row["resource_key"]),
        artifact_id=str(row["artifact_id"]),
        approval_id=str(row["approval_id"]),
        patch_sha256=str(row["patch_sha256"]),
        baseline_commit_sha=str(row["baseline_commit_sha"]),
        target_repo_path=str(row["target_repo_path"]),
        state=OperationState(str(row["state"])),
        owner_token=str(row["owner_token"]),
        owner_pid=int(row["owner_pid"]),
        owner_start_token=str(row["owner_start_token"]),
        created_at_unix=created,
        updated_at_unix=updated,
        retryable=bool(row["retryable"]),
        result=(json.loads(result_json) if result_json is not None else None),
        error=(str(row["error_text"]) if row["error_text"] is not None else None),
    )


__all__ = [
    "OPERATION_STORE_SCHEMA",
    "OperationConflictError",
    "OperationRecord",
    "OperationRecoveryRequiredError",
    "OperationRecoveryResult",
    "OperationRecoveryStatus",
    "OperationReservation",
    "OperationState",
    "OperationStoreError",
    "OperationTerminalError",
    "SQLiteOperationStore",
    "artifact_apply_operation_key",
    "inspect_repository_state",
    "owner_record_is_active",
    "process_identity_matches",
    "process_identity_token",
    "repository_resource_key",
]
