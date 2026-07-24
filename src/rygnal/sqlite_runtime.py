"""Shared production SQLite connection configuration."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

SQLITE_BUSY_TIMEOUT_MS = 10_000
SQLITE_CONNECT_TIMEOUT_SECONDS = SQLITE_BUSY_TIMEOUT_MS / 1000

SQLITE_INITIALIZATION_RETRY_COUNT = 100
SQLITE_INITIALIZATION_RETRY_SECONDS = 0.05


def connect_sqlite(
    database: str | Path,
    *,
    isolation_level: str | None = "",
) -> sqlite3.Connection:
    """Open one consistently hardened SQLite connection."""
    database_path = Path(database)
    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        database_path,
        timeout=SQLITE_CONNECT_TIMEOUT_SECONDS,
        isolation_level=isolation_level,
    )
    connection.row_factory = sqlite3.Row

    connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")

    return connection


def initialize_sqlite_database(
    database: str | Path,
) -> None:
    """Enable WAL safely during concurrent startup.

    ``PRAGMA journal_mode = WAL`` requires an exclusive
    transition when a database is first created. Several
    processes may initialize the same local database at the
    same time, so this operation must be retried outside any
    active transaction.

    Once WAL is enabled, subsequent initializers only verify
    the existing mode and return.
    """
    database_path = Path(database)
    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    last_error: sqlite3.OperationalError | None = None

    for attempt in range(SQLITE_INITIALIZATION_RETRY_COUNT):
        connection: sqlite3.Connection | None = None

        try:
            connection = connect_sqlite(database_path)

            current_row = connection.execute("PRAGMA journal_mode").fetchone()
            current_mode = str(current_row[0]).lower() if current_row is not None else ""

            if current_mode == "wal":
                selected_mode = current_mode
            else:
                selected_row = connection.execute("PRAGMA journal_mode = WAL").fetchone()
                selected_mode = str(selected_row[0]).lower() if selected_row is not None else ""

            if selected_mode != "wal":
                raise sqlite3.OperationalError("SQLite WAL mode could not be enabled.")

            connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")

            return

        except sqlite3.OperationalError as exc:
            last_error = exc

            if not _is_retryable_lock_error(exc):
                raise

            if attempt + 1 >= SQLITE_INITIALIZATION_RETRY_COUNT:
                break

        finally:
            if connection is not None:
                connection.close()

        time.sleep(SQLITE_INITIALIZATION_RETRY_SECONDS)

    raise sqlite3.OperationalError(
        f"SQLite initialization remained locked after {SQLITE_INITIALIZATION_RETRY_COUNT} attempts."
    ) from last_error


def _is_retryable_lock_error(
    error: sqlite3.OperationalError,
) -> bool:
    message = str(error).lower()

    return "locked" in message or "busy" in message


__all__ = [
    "SQLITE_BUSY_TIMEOUT_MS",
    "SQLITE_CONNECT_TIMEOUT_SECONDS",
    "SQLITE_INITIALIZATION_RETRY_COUNT",
    "SQLITE_INITIALIZATION_RETRY_SECONDS",
    "connect_sqlite",
    "initialize_sqlite_database",
]
