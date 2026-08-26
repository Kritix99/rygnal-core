"""Versioned transactional SQLite migrations for local state."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from rygnal.sqlite_runtime import (
    connect_sqlite,
    initialize_sqlite_database,
)

SCHEMA_METADATA_TABLE = "rygnal_schema_metadata"
MIGRATION_HISTORY_TABLE = "rygnal_migration_history"
CURRENT_SCHEMA_VERSION = 1
_PRIVATE_FILE_MODE = 0o600

MigrationFunction = Callable[
    [sqlite3.Connection],
    None,
]
ValidationFunction = Callable[
    [sqlite3.Connection],
    None,
]


class SQLiteMigrationError(RuntimeError):
    """Base migration failure."""


class SQLiteFutureSchemaError(SQLiteMigrationError):
    """Database was produced by a newer Rygnal version."""


class SQLiteSchemaChecksumError(SQLiteMigrationError):
    """Recorded schema checksum does not match code."""


class SQLiteSchemaValidationError(SQLiteMigrationError):
    """Migrated or legacy schema is malformed."""


@dataclass(frozen=True, slots=True)
class SchemaMigrationPlan:
    """One component's ordered schema contract."""

    component: str
    target_version: int
    signature: str
    domain_tables: tuple[str, ...]
    apply: MigrationFunction
    validate: ValidationFunction

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.signature.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class MigrationSnapshot:
    """Public migration status without sensitive data."""

    component: str
    version: int
    target_version: int
    checksum_valid: bool
    integrity_valid: bool

    @property
    def ready(self) -> bool:
        return self.version == self.target_version and self.checksum_valid and self.integrity_valid


APPROVAL_SCHEMA_SIGNATURE = """
approval_queue.v1:
approval_queue(
 id integer primary key autoincrement,
 approval_id text unique not null,
 status text not null,
 request_json text not null,
 decision_json text,
 created_at text not null,
 updated_at text not null
)
index(status)
""".strip()

AUDIT_SCHEMA_SIGNATURE = """
audit_events.v1:
audit_events(
 id integer primary key autoincrement,
 event_id text unique not null,
 timestamp text not null,
 trace_id text not null,
 user_id text not null,
 agent_id text not null,
 environment text not null,
 tool_name text not null,
 action text,
 decision text not null,
 allowed integer not null,
 severity text not null,
 policy_id text,
 reason text not null,
 prev_event_hash text,
 event_hash text unique not null,
 payload_json text not null
)
indexes(trace_id,policy_id,tool_name,decision)
""".strip()

OPERATION_SCHEMA_SIGNATURE = """
operations.v1:
operations(
 schema_version text not null,
 operation_key text primary key,
 operation_type text not null,
 resource_key text not null,
 artifact_id text not null,
 approval_id text not null,
 patch_sha256 text not null,
 baseline_commit_sha text not null,
 target_repo_path text not null,
 state text not null,
 owner_token text not null,
 owner_pid integer not null,
 owner_start_token text not null,
 created_at_unix real not null,
 updated_at_unix real not null,
 retryable integer not null,
 result_json text,
 error_text text
)
resource_leases(resource_key primary key,operation_key unique)
indexes(state,artifact_id)
""".strip()


def migrate_approval_database(
    database: str | Path,
    *,
    backup_retention_count: int = 5,
) -> MigrationSnapshot:
    """Create or adopt the approval schema."""
    return migrate_sqlite_schema(
        database,
        SchemaMigrationPlan(
            component="approval_queue",
            target_version=1,
            signature=APPROVAL_SCHEMA_SIGNATURE,
            domain_tables=("approval_queue",),
            apply=_apply_approval_schema,
            validate=_validate_approval_schema,
        ),
        backup_retention_count=(backup_retention_count),
    )


def migrate_audit_database(
    database: str | Path,
    *,
    backup_retention_count: int = 5,
) -> MigrationSnapshot:
    """Create or adopt the audit schema."""
    return migrate_sqlite_schema(
        database,
        SchemaMigrationPlan(
            component="audit_store",
            target_version=1,
            signature=AUDIT_SCHEMA_SIGNATURE,
            domain_tables=("audit_events",),
            apply=_apply_audit_schema,
            validate=_validate_audit_schema,
        ),
        backup_retention_count=(backup_retention_count),
    )


def migrate_operation_database(
    database: str | Path,
    *,
    backup_retention_count: int = 5,
) -> MigrationSnapshot:
    """Create or adopt the operation schema."""
    return migrate_sqlite_schema(
        database,
        SchemaMigrationPlan(
            component="operation_store",
            target_version=1,
            signature=OPERATION_SCHEMA_SIGNATURE,
            domain_tables=(
                "operations",
                "resource_leases",
            ),
            apply=_apply_operation_schema,
            validate=_validate_operation_schema,
        ),
        backup_retention_count=(backup_retention_count),
    )


def migrate_sqlite_schema(
    database: str | Path,
    plan: SchemaMigrationPlan,
    *,
    backup_retention_count: int = 5,
) -> MigrationSnapshot:
    """Migrate one database under a cross-process lock."""
    if plan.target_version <= 0:
        raise ValueError("Target schema version must be positive.")

    if not plan.component.strip():
        raise ValueError("Schema component must not be empty.")

    if not 1 <= backup_retention_count <= 50:
        raise ValueError("Backup retention must be between 1 and 50.")

    database_path = Path(database).expanduser()

    if not database_path.is_absolute():
        database_path = database_path.absolute()

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    _reject_symlink_path(database_path)
    initialize_sqlite_database(database_path)
    _secure_database_file(database_path)

    with _migration_lock(database_path):
        _recover_interrupted_migration(database_path)

        connection = connect_sqlite(database_path)

        try:
            _assert_integrity(connection)
            current = _read_schema_record(connection)
            user_version = _user_version(connection)

            if user_version > plan.target_version:
                raise SQLiteFutureSchemaError("Database schema is newer than this Rygnal build.")

            if current is not None:
                component = str(current["component"])
                version = int(current["version"])
                checksum = str(current["checksum"])

                if component != plan.component:
                    raise SQLiteSchemaValidationError(
                        "Database schema component does not match the selected store."
                    )

                if version > plan.target_version:
                    raise SQLiteFutureSchemaError(
                        "Database schema is newer than this Rygnal build."
                    )

                if version == plan.target_version and checksum != plan.checksum:
                    raise SQLiteSchemaChecksumError(
                        "Database schema checksum does not match this Rygnal build."
                    )

                if version == plan.target_version:
                    plan.validate(connection)
                    return MigrationSnapshot(
                        component=plan.component,
                        version=version,
                        target_version=(plan.target_version),
                        checksum_valid=True,
                        integrity_valid=True,
                    )

            has_domain_state = any(
                _table_exists(
                    connection,
                    table,
                )
                for table in plan.domain_tables
            )
        finally:
            connection.close()

        backup = (
            _create_verified_backup(
                database_path,
                component=plan.component,
                retention=(backup_retention_count),
            )
            if has_domain_state
            else None
        )

        marker_path = _write_migration_marker(
            database_path,
            plan=plan,
            backup=backup,
        )
        connection = connect_sqlite(database_path)

        try:
            connection.execute("BEGIN EXCLUSIVE")
            _create_metadata_tables(connection)
            current = _read_schema_record(connection)
            current_version = int(current["version"]) if current is not None else 0

            if current_version > plan.target_version:
                raise SQLiteFutureSchemaError("Database schema is newer than this Rygnal build.")

            plan.apply(connection)
            plan.validate(connection)
            now = datetime.now(UTC).isoformat()

            connection.execute(
                """
                INSERT INTO rygnal_schema_metadata (
                    singleton_id,
                    component,
                    version,
                    checksum,
                    state,
                    updated_at
                )
                VALUES (1, ?, ?, ?, 'ready', ?)
                ON CONFLICT(singleton_id)
                DO UPDATE SET
                    component = excluded.component,
                    version = excluded.version,
                    checksum = excluded.checksum,
                    state = excluded.state,
                    updated_at = excluded.updated_at
                """,
                (
                    plan.component,
                    plan.target_version,
                    plan.checksum,
                    now,
                ),
            )
            connection.execute(
                f"""
                INSERT OR IGNORE INTO
                {MIGRATION_HISTORY_TABLE} (
                    component,
                    version,
                    checksum,
                    applied_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    plan.component,
                    plan.target_version,
                    plan.checksum,
                    now,
                ),
            )
            connection.execute(f"PRAGMA user_version = {plan.target_version}")
            _assert_integrity(connection)
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()

            marker_path.unlink(missing_ok=True)
            raise
        finally:
            connection.close()

        marker_path.unlink(missing_ok=True)

        return schema_snapshot(
            database_path,
            component=plan.component,
            target_version=(plan.target_version),
            checksum=plan.checksum,
            validator=plan.validate,
        )


def schema_snapshot(
    database: str | Path,
    *,
    component: str,
    target_version: int,
    checksum: str,
    validator: ValidationFunction | None = None,
) -> MigrationSnapshot:
    """Read current schema readiness."""
    path = Path(database)
    connection = connect_sqlite(path)

    try:
        integrity_valid = _integrity_value(connection) == "ok"
        record = _read_schema_record(connection)

        if record is None:
            return MigrationSnapshot(
                component=component,
                version=0,
                target_version=target_version,
                checksum_valid=False,
                integrity_valid=integrity_valid,
            )

        recorded_component = str(record["component"])
        version = int(record["version"])
        recorded_checksum = str(record["checksum"])
        checksum_valid = recorded_component == component and recorded_checksum == checksum

        if validator is not None and integrity_valid and checksum_valid:
            try:
                validator(connection)
            except SQLiteMigrationError:
                integrity_valid = False

        return MigrationSnapshot(
            component=recorded_component,
            version=version,
            target_version=target_version,
            checksum_valid=checksum_valid,
            integrity_valid=integrity_valid,
        )
    finally:
        connection.close()


def approval_schema_ready(
    database: str | Path,
) -> bool:
    return schema_snapshot(
        database,
        component="approval_queue",
        target_version=1,
        checksum=hashlib.sha256(APPROVAL_SCHEMA_SIGNATURE.encode("utf-8")).hexdigest(),
        validator=_validate_approval_schema,
    ).ready


def audit_schema_ready(
    database: str | Path,
) -> bool:
    return schema_snapshot(
        database,
        component="audit_store",
        target_version=1,
        checksum=hashlib.sha256(AUDIT_SCHEMA_SIGNATURE.encode("utf-8")).hexdigest(),
        validator=_validate_audit_schema,
    ).ready


def operation_schema_ready(
    database: str | Path,
) -> bool:
    return schema_snapshot(
        database,
        component="operation_store",
        target_version=1,
        checksum=hashlib.sha256(OPERATION_SCHEMA_SIGNATURE.encode("utf-8")).hexdigest(),
        validator=_validate_operation_schema,
    ).ready


def _apply_approval_schema(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS approval_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            approval_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            request_json TEXT NOT NULL,
            decision_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            CHECK (
                (
                    status = 'pending'
                    AND decision_json IS NULL
                )
                OR
                (
                    status IN (
                        'approved',
                        'rejected'
                    )
                    AND decision_json IS NOT NULL
                )
            )
        )
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_approval_queue_status
        ON approval_queue(status)
        """
    )


def _apply_audit_schema(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            trace_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            environment TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            action TEXT,
            decision TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            severity TEXT NOT NULL,
            policy_id TEXT,
            reason TEXT NOT NULL,
            prev_event_hash TEXT,
            event_hash TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL
        )
        """
    )

    columns = _column_names(
        connection,
        "audit_events",
    )

    if "prev_event_hash" not in columns:
        connection.execute(
            """
            ALTER TABLE audit_events
            ADD COLUMN prev_event_hash TEXT
            """
        )

    for name, column in (
        (
            "idx_audit_events_trace_id",
            "trace_id",
        ),
        (
            "idx_audit_events_policy_id",
            "policy_id",
        ),
        (
            "idx_audit_events_tool_name",
            "tool_name",
        ),
        (
            "idx_audit_events_decision",
            "decision",
        ),
    ):
        connection.execute(
            f"""
            CREATE INDEX IF NOT EXISTS {name}
            ON audit_events({column})
            """
        )


def _apply_operation_schema(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS operations (
            schema_version TEXT NOT NULL,
            operation_key TEXT PRIMARY KEY,
            operation_type TEXT NOT NULL,
            resource_key TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            approval_id TEXT NOT NULL,
            patch_sha256 TEXT NOT NULL,
            baseline_commit_sha TEXT NOT NULL,
            target_repo_path TEXT NOT NULL,
            state TEXT NOT NULL,
            owner_token TEXT NOT NULL,
            owner_pid INTEGER NOT NULL,
            owner_start_token TEXT NOT NULL,
            created_at_unix REAL NOT NULL,
            updated_at_unix REAL NOT NULL,
            retryable INTEGER NOT NULL DEFAULT 0,
            result_json TEXT,
            error_text TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS resource_leases (
            resource_key TEXT PRIMARY KEY,
            operation_key TEXT NOT NULL UNIQUE,
            owner_token TEXT NOT NULL,
            owner_pid INTEGER NOT NULL,
            owner_start_token TEXT NOT NULL,
            created_at_unix REAL NOT NULL,
            FOREIGN KEY(operation_key)
                REFERENCES operations(operation_key)
                ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_operations_state
        ON operations(state)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_operations_artifact
        ON operations(artifact_id)
        """
    )


def _validate_approval_schema(
    connection: sqlite3.Connection,
) -> None:
    _require_columns(
        connection,
        "approval_queue",
        {
            "id",
            "approval_id",
            "status",
            "request_json",
            "decision_json",
            "created_at",
            "updated_at",
        },
    )


def _validate_audit_schema(
    connection: sqlite3.Connection,
) -> None:
    _require_columns(
        connection,
        "audit_events",
        {
            "id",
            "event_id",
            "timestamp",
            "trace_id",
            "user_id",
            "agent_id",
            "environment",
            "tool_name",
            "action",
            "decision",
            "allowed",
            "severity",
            "policy_id",
            "reason",
            "prev_event_hash",
            "event_hash",
            "payload_json",
        },
    )


def _validate_operation_schema(
    connection: sqlite3.Connection,
) -> None:
    _require_columns(
        connection,
        "operations",
        {
            "schema_version",
            "operation_key",
            "operation_type",
            "resource_key",
            "artifact_id",
            "approval_id",
            "patch_sha256",
            "baseline_commit_sha",
            "target_repo_path",
            "state",
            "owner_token",
            "owner_pid",
            "owner_start_token",
            "created_at_unix",
            "updated_at_unix",
            "retryable",
            "result_json",
            "error_text",
        },
    )
    _require_columns(
        connection,
        "resource_leases",
        {
            "resource_key",
            "operation_key",
            "owner_token",
            "owner_pid",
            "owner_start_token",
            "created_at_unix",
        },
    )


def _require_columns(
    connection: sqlite3.Connection,
    table: str,
    required: set[str],
) -> None:
    columns = _column_names(
        connection,
        table,
    )
    missing = required - columns

    if missing:
        raise SQLiteSchemaValidationError(f"Database table {table} is missing required columns.")


def _column_names(
    connection: sqlite3.Connection,
    table: str,
) -> set[str]:
    if not _table_exists(
        connection,
        table,
    ):
        return set()

    return {
        str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _create_metadata_tables(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        f"""
        CREATE TABLE IF NOT EXISTS
        {SCHEMA_METADATA_TABLE} (
            singleton_id INTEGER PRIMARY KEY
                CHECK(singleton_id = 1),
            component TEXT NOT NULL,
            version INTEGER NOT NULL
                CHECK(version > 0),
            checksum TEXT NOT NULL,
            state TEXT NOT NULL
                CHECK(state = 'ready'),
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        f"""
        CREATE TABLE IF NOT EXISTS
        {MIGRATION_HISTORY_TABLE} (
            component TEXT NOT NULL,
            version INTEGER NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            PRIMARY KEY(component, version)
        )
        """
    )


def _read_schema_record(
    connection: sqlite3.Connection,
) -> sqlite3.Row | None:
    if not _table_exists(
        connection,
        SCHEMA_METADATA_TABLE,
    ):
        return None

    rows = connection.execute(
        """
        SELECT component, version, checksum, state
        FROM rygnal_schema_metadata
        """
    ).fetchall()

    if len(rows) > 1:
        raise SQLiteSchemaValidationError("Database contains conflicting schema metadata.")

    if not rows:
        return None

    row = rows[0]

    if str(row["state"]) != "ready":
        raise SQLiteSchemaValidationError("Database schema metadata is not ready.")

    return row


def _user_version(
    connection: sqlite3.Connection,
) -> int:
    row = connection.execute("PRAGMA user_version").fetchone()

    return int(row[0]) if row is not None else 0


def _table_exists(
    connection: sqlite3.Connection,
    table: str,
) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (table,),
    ).fetchone()

    return row is not None


def _integrity_value(
    connection: sqlite3.Connection,
) -> str:
    row = connection.execute("PRAGMA integrity_check").fetchone()

    if row is None:
        return ""

    return str(row[0]).lower()


def _assert_integrity(
    connection: sqlite3.Connection,
) -> None:
    if _integrity_value(connection) != "ok":
        raise SQLiteSchemaValidationError("SQLite integrity validation failed.")


def _create_verified_backup(
    database: Path,
    *,
    component: str,
    retention: int,
) -> Path:
    backup_directory = database.parent / f"{database.name}.backups"
    _ensure_private_directory(backup_directory)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = backup_directory / (f"{database.stem}.{component}.{timestamp}.bak")

    source_connection = sqlite3.connect(
        f"file:{database}?mode=ro",
        uri=True,
        timeout=10,
    )
    backup_connection = sqlite3.connect(
        destination,
        timeout=10,
    )

    try:
        source_connection.backup(backup_connection)
        backup_connection.commit()
    finally:
        backup_connection.close()
        source_connection.close()

    os.chmod(
        destination,
        _PRIVATE_FILE_MODE,
    )

    verification = sqlite3.connect(
        f"file:{destination}?mode=ro",
        uri=True,
        timeout=10,
    )

    try:
        row = verification.execute("PRAGMA integrity_check").fetchone()

        if row is None or str(row[0]).lower() != "ok":
            raise SQLiteMigrationError("Pre-migration backup failed integrity validation.")
    finally:
        verification.close()

    backups = sorted(
        backup_directory.glob("*.bak"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )

    for stale in backups[retention:]:
        stale.unlink(missing_ok=True)

    return destination


def _write_migration_marker(
    database: Path,
    *,
    plan: SchemaMigrationPlan,
    backup: Path | None,
) -> Path:
    marker = database.with_name(database.name + ".migration.json")
    temporary = marker.with_name(marker.name + f".{os.getpid()}.tmp")
    payload = {
        "component": plan.component,
        "target_version": plan.target_version,
        "checksum": plan.checksum,
        "backup": (backup.as_posix() if backup is not None else None),
        "created_at_unix": time.time(),
    }
    descriptor = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        _PRIVATE_FILE_MODE,
    )

    try:
        data = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        os.write(
            descriptor,
            data,
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    os.replace(
        temporary,
        marker,
    )
    return marker


def _recover_interrupted_migration(
    database: Path,
) -> None:
    marker = database.with_name(database.name + ".migration.json")

    if not marker.exists():
        return

    if marker.is_symlink():
        raise SQLiteMigrationError("Migration marker is a symlink.")

    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except Exception:
        raise SQLiteMigrationError("Migration marker is malformed.") from None

    connection = connect_sqlite(database)

    try:
        valid = _integrity_value(connection) == "ok"
    finally:
        connection.close()

    if valid:
        marker.unlink(missing_ok=True)
        return

    backup_value = payload.get("backup")

    if not isinstance(backup_value, str) or not backup_value:
        raise SQLiteMigrationError("Interrupted migration has no valid backup.")

    backup = Path(backup_value)

    if backup.is_symlink() or not backup.is_file():
        raise SQLiteMigrationError("Interrupted migration backup is unavailable.")

    temporary = database.with_name(database.name + ".restore.tmp")
    shutil.copy2(
        backup,
        temporary,
        follow_symlinks=False,
    )
    os.replace(
        temporary,
        database,
    )
    _secure_database_file(database)
    marker.unlink(missing_ok=True)


@contextlib.contextmanager
def _migration_lock(
    database: Path,
) -> Iterator[None]:
    lock_path = database.with_name(database.name + ".migration.lock")

    if lock_path.is_symlink():
        raise SQLiteMigrationError("Migration lock path is a symlink.")

    flags = os.O_CREAT | os.O_RDWR

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = os.open(
        lock_path,
        flags,
        _PRIVATE_FILE_MODE,
    )

    try:
        os.chmod(
            lock_path,
            _PRIVATE_FILE_MODE,
        )

        if os.name == "nt":
            import msvcrt

            os.lseek(
                descriptor,
                0,
                os.SEEK_SET,
            )

            if os.fstat(descriptor).st_size == 0:
                os.write(
                    descriptor,
                    b"\0",
                )
                os.lseek(
                    descriptor,
                    0,
                    os.SEEK_SET,
                )

            msvcrt.locking(
                descriptor,
                msvcrt.LK_LOCK,
                1,
            )
        else:
            import fcntl

            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX,
            )

        yield
    finally:
        if os.name == "nt":
            import msvcrt

            os.lseek(
                descriptor,
                0,
                os.SEEK_SET,
            )
            with contextlib.suppress(OSError):
                msvcrt.locking(
                    descriptor,
                    msvcrt.LK_UNLCK,
                    1,
                )
        else:
            import fcntl

            with contextlib.suppress(OSError):
                fcntl.flock(
                    descriptor,
                    fcntl.LOCK_UN,
                )

        os.close(descriptor)


def _reject_symlink_path(
    path: Path,
) -> None:
    if path.is_symlink():
        raise SQLiteMigrationError("Refusing symlink SQLite database.")

    current = Path(path.anchor)

    for component in path.parts[1:-1]:
        current /= component

        if current.is_symlink():
            raise SQLiteMigrationError("SQLite path traverses a symlink.")


def _secure_database_file(
    path: Path,
) -> None:
    metadata = path.stat(follow_symlinks=False)

    if not stat.S_ISREG(metadata.st_mode):
        raise SQLiteMigrationError("SQLite database is not a regular file.")

    if os.name != "nt":
        trusted_owners = {
            0,
            os.getuid(),
        }

        if metadata.st_uid not in trusted_owners:
            raise SQLiteMigrationError("SQLite database has an untrusted owner.")

        os.chmod(
            path,
            _PRIVATE_FILE_MODE,
        )


def _ensure_private_directory(
    path: Path,
) -> None:
    if path.is_symlink():
        raise SQLiteMigrationError("Private directory path is a symlink.")

    path.mkdir(
        mode=0o700,
        parents=True,
        exist_ok=True,
    )

    if not path.is_dir():
        raise SQLiteMigrationError("Private path is not a directory.")

    if os.name != "nt":
        os.chmod(
            path,
            0o700,
        )


__all__ = [
    "APPROVAL_SCHEMA_SIGNATURE",
    "AUDIT_SCHEMA_SIGNATURE",
    "CURRENT_SCHEMA_VERSION",
    "MIGRATION_HISTORY_TABLE",
    "MigrationSnapshot",
    "OPERATION_SCHEMA_SIGNATURE",
    "SCHEMA_METADATA_TABLE",
    "SQLiteFutureSchemaError",
    "SQLiteMigrationError",
    "SQLiteSchemaChecksumError",
    "SQLiteSchemaValidationError",
    "SchemaMigrationPlan",
    "approval_schema_ready",
    "audit_schema_ready",
    "migrate_approval_database",
    "migrate_audit_database",
    "migrate_operation_database",
    "migrate_sqlite_schema",
    "operation_schema_ready",
    "schema_snapshot",
]
