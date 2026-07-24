from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from rygnal.api import create_app
from rygnal.approval_queue import (
    SQLiteApprovalQueue,
)
from rygnal.audit_storage import SQLiteAuditStore
from rygnal.local_app import create_local_app
from rygnal.operation_store import (
    SQLiteOperationStore,
)
from rygnal.runtime_config import (
    ApiRuntimeConfig,
    RuntimeConfigError,
    RuntimeConfigV1,
    RuntimeEnvironment,
    load_runtime_config,
)
from rygnal.sqlite_migrations import (
    SCHEMA_METADATA_TABLE,
    SchemaMigrationPlan,
    SQLiteFutureSchemaError,
    SQLiteSchemaChecksumError,
    approval_schema_ready,
    audit_schema_ready,
    migrate_approval_database,
    migrate_sqlite_schema,
    operation_schema_ready,
)


def private_file(
    path: Path,
    content: str,
) -> Path:
    path.write_text(
        content,
        encoding="utf-8",
    )

    if os.name != "nt":
        path.chmod(0o600)

    return path


def production_config(
    token: str = ("M16M17-production-token-0123456789-ABCDEFGHIJKLMN"),
    **api_overrides: Any,
) -> RuntimeConfigV1:
    values: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": 8787,
        "allow_remote": False,
        "auth_required": True,
        "operator_token": token,
        "docs_enabled": False,
    }
    values.update(api_overrides)

    return RuntimeConfigV1(
        environment=(RuntimeEnvironment.PRODUCTION),
        api=ApiRuntimeConfig(**values),
    )


def valid_evaluate_payload() -> dict[str, Any]:
    return {
        "tool_name": "file_read",
        "action": "read",
        "target": "README.md",
    }


def test_config_rejects_unknown_nested_field(
    tmp_path: Path,
) -> None:
    config = private_file(
        tmp_path / "runtime.json",
        json.dumps(
            {
                "schema_version": ("rygnal.runtime.v1"),
                "api": {
                    "unknown_security_switch": True,
                },
            }
        ),
    )

    with pytest.raises(
        RuntimeConfigError,
        match="validation failed",
    ):
        load_runtime_config(config_path=config)


@pytest.mark.skipif(
    os.name == "nt",
    reason="POSIX permission contract.",
)
def test_config_rejects_broad_permissions(
    tmp_path: Path,
) -> None:
    config = tmp_path / "runtime.json"
    config.write_text(
        json.dumps({"schema_version": ("rygnal.runtime.v1")}),
        encoding="utf-8",
    )
    config.chmod(0o644)

    with pytest.raises(
        RuntimeConfigError,
        match="permissions",
    ):
        load_runtime_config(config_path=config)


def test_secure_token_file_and_secret_redaction(
    tmp_path: Path,
) -> None:
    token = "secure-token-file-0123456789-ABCDEFGHIJKLMN"
    token_file = private_file(
        tmp_path / "operator.token",
        token + "\n",
    )
    config_file = private_file(
        tmp_path / "runtime.json",
        json.dumps(
            {
                "schema_version": ("rygnal.runtime.v1"),
                "environment": "production",
                "api": {
                    "auth_required": True,
                    "docs_enabled": False,
                    "operator_token_file": (token_file.as_posix()),
                },
            }
        ),
    )

    config = load_runtime_config(config_path=config_file)

    assert config.api.operator_token_value() == token
    assert token not in repr(config)
    assert token not in json.dumps(config.model_dump(mode="json"))


def test_configuration_precedence(
    tmp_path: Path,
) -> None:
    config_file = private_file(
        tmp_path / "runtime.json",
        json.dumps(
            {
                "schema_version": ("rygnal.runtime.v1"),
                "api": {
                    "port": 8001,
                },
            }
        ),
    )

    config = load_runtime_config(
        config_path=config_file,
        environ={
            "RYGNAL_API_PORT": "8002",
        },
        overrides={
            "api": {
                "port": 8003,
            }
        },
    )

    assert config.api.port == 8003


def test_production_environment_requires_versioned_file() -> None:
    with pytest.raises(
        RuntimeConfigError,
        match="versioned",
    ):
        load_runtime_config(environ={"RYGNAL_ENVIRONMENT": ("production")})


def test_remote_binding_requires_authentication() -> None:
    with pytest.raises(ValueError):
        RuntimeConfigV1(
            api=ApiRuntimeConfig(
                host="0.0.0.0",
                allow_remote=True,
                auth_required=False,
            )
        )


def test_all_local_databases_are_versioned(
    tmp_path: Path,
) -> None:
    app = create_local_app(
        data_dir=tmp_path / "data",
        environ={},
    )
    dependencies = app.state.rygnal_local_dependencies

    assert audit_schema_ready(dependencies.paths.audit_db)
    assert approval_schema_ready(dependencies.paths.approval_db)
    assert operation_schema_ready(dependencies.operation_store.db_path)

    for path in (
        dependencies.paths.audit_db,
        dependencies.paths.approval_db,
        dependencies.operation_store.db_path,
    ):
        with sqlite3.connect(path) as connection:
            row = connection.execute(
                f"""
                SELECT version, state
                FROM {SCHEMA_METADATA_TABLE}
                """
            ).fetchone()

        assert row == (1, "ready")


def test_legacy_approval_schema_is_adopted_with_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "approval.db"
    connection = sqlite3.connect(database)
    connection.execute(
        """
        CREATE TABLE approval_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            approval_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            request_json TEXT NOT NULL,
            decision_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.commit()
    connection.close()

    migrate_approval_database(database)

    assert approval_schema_ready(database)
    backups = tuple((database.parent / f"{database.name}.backups").glob("*.bak"))
    assert len(backups) == 1


def test_future_database_version_is_rejected(
    tmp_path: Path,
) -> None:
    database = tmp_path / "future.db"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA user_version = 99")
    connection.commit()
    connection.close()

    with pytest.raises(SQLiteFutureSchemaError):
        migrate_approval_database(database)


def test_schema_checksum_tampering_is_rejected(
    tmp_path: Path,
) -> None:
    database = tmp_path / "approval.db"
    SQLiteApprovalQueue(database)

    with sqlite3.connect(database) as connection:
        connection.execute(
            f"""
            UPDATE {SCHEMA_METADATA_TABLE}
            SET checksum = 'tampered'
            """
        )
        connection.commit()

    with pytest.raises(SQLiteSchemaChecksumError):
        SQLiteApprovalQueue(database)


def test_failed_migration_rolls_back_atomically(
    tmp_path: Path,
) -> None:
    database = tmp_path / "failure.db"

    def apply(
        connection: sqlite3.Connection,
    ) -> None:
        connection.execute(
            """
            CREATE TABLE must_rollback (
                value TEXT NOT NULL
            )
            """
        )
        raise RuntimeError("injected migration failure")

    def validate(
        _connection: sqlite3.Connection,
    ) -> None:
        return None

    plan = SchemaMigrationPlan(
        component="failure_test",
        target_version=1,
        signature="failure-test.v1",
        domain_tables=("must_rollback",),
        apply=apply,
        validate=validate,
    )

    with pytest.raises(
        RuntimeError,
        match="injected",
    ):
        migrate_sqlite_schema(
            database,
            plan,
        )

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'must_rollback'
            """
        ).fetchone()

    assert row is None


def test_health_and_readiness_are_public_and_hardened() -> None:
    client = TestClient(create_app(runtime_config=production_config()))

    health = client.get("/health")
    ready = client.get("/ready")

    assert health.status_code == 200
    assert ready.status_code == 200

    for response in (
        health,
        ready,
    ):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["cache-control"] == "no-store"


def test_production_requires_bearer_authentication() -> None:
    token = "production-bearer-0123456789-ABCDEFGHIJKLMN"
    client = TestClient(create_app(runtime_config=(production_config(token))))

    missing = client.post(
        "/v1/evaluate",
        json=valid_evaluate_payload(),
    )
    wrong = client.post(
        "/v1/evaluate",
        json=valid_evaluate_payload(),
        headers={"Authorization": ("Bearer wrong-credential")},
    )
    accepted = client.post(
        "/v1/evaluate",
        json=valid_evaluate_payload(),
        headers={"Authorization": (f"Bearer {token}")},
    )

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert accepted.status_code == 200
    assert missing.json()["error"]["code"] == "authentication_failed"
    assert "token" not in missing.text.lower()


def test_request_body_limit_is_enforced_before_parsing() -> None:
    token = "body-limit-token-0123456789-ABCDEFGHIJKLMN"
    config = production_config(
        token,
        max_request_body_bytes=1024,
    )
    client = TestClient(create_app(runtime_config=config))

    response = client.post(
        "/v1/evaluate",
        content=b"x" * 2048,
        headers={
            "Authorization": (f"Bearer {token}"),
            "Content-Type": ("application/json"),
        },
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_body_too_large"


def test_invalid_request_id_is_replaced() -> None:
    client = TestClient(create_app())
    response = client.get(
        "/health",
        headers={"X-Request-ID": ("../../unsafe request id")},
    )

    request_id = response.headers["x-request-id"]

    assert request_id.startswith("req_")
    assert ".." not in request_id
    assert " " not in request_id


def test_request_timeout_returns_stable_error() -> None:
    config = RuntimeConfigV1(
        api=ApiRuntimeConfig(
            request_timeout_seconds=0.05,
        )
    )
    app = create_app(runtime_config=config)

    @app.get("/v1/slow")
    async def slow() -> dict[str, bool]:
        await asyncio.sleep(0.5)
        return {"done": True}

    client = TestClient(app)
    response = client.get("/v1/slow")

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "request_timeout"


def test_concurrency_overload_is_fail_fast() -> None:
    async def scenario() -> None:
        config = RuntimeConfigV1(
            api=ApiRuntimeConfig(
                max_concurrency=1,
                request_timeout_seconds=2,
            )
        )
        app = create_app(runtime_config=config)
        entered = asyncio.Event()
        release = asyncio.Event()

        @app.get("/v1/hold")
        async def hold() -> dict[str, bool]:
            entered.set()
            await release.wait()
            return {"released": True}

        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            first = asyncio.create_task(client.get("/v1/hold"))
            await asyncio.wait_for(
                entered.wait(),
                timeout=1,
            )
            started = time.monotonic()
            overloaded = await client.get("/health")
            elapsed = time.monotonic() - started
            release.set()
            completed = await first

        assert overloaded.status_code == 429
        assert overloaded.json()["error"]["code"] == "request_overloaded"
        assert elapsed < 0.5
        assert completed.status_code == 200

    asyncio.run(scenario())


def test_store_constructors_remain_compatible(
    tmp_path: Path,
) -> None:
    audit = SQLiteAuditStore(tmp_path / "audit.db")
    approval = SQLiteApprovalQueue(tmp_path / "approval.db")
    operations = SQLiteOperationStore(tmp_path / "operations.db")

    assert audit_schema_ready(audit.db_path)
    assert approval_schema_ready(approval.db_path)
    assert operation_schema_ready(operations.db_path)


def test_development_legacy_operator_token_remains_compatible(
    tmp_path: Path,
) -> None:
    app = create_local_app(
        data_dir=tmp_path / "data",
        environ={"RYGNAL_OPERATOR_TOKEN": ("operator-secret")},
    )

    assert app.state.rygnal_runtime_config.api.operator_token_value() == "operator-secret"


def test_authenticated_mode_rejects_short_token() -> None:
    with pytest.raises(ValueError):
        RuntimeConfigV1(
            api=ApiRuntimeConfig(
                auth_required=True,
                operator_token="operator-secret",
            )
        )


def test_production_mode_rejects_short_token() -> None:
    with pytest.raises(ValueError):
        RuntimeConfigV1(
            environment=(RuntimeEnvironment.PRODUCTION),
            api=ApiRuntimeConfig(
                auth_required=True,
                docs_enabled=False,
                operator_token="operator-secret",
            ),
        )


def test_remote_mode_rejects_short_token() -> None:
    with pytest.raises(ValueError):
        RuntimeConfigV1(
            api=ApiRuntimeConfig(
                host="0.0.0.0",
                allow_remote=True,
                auth_required=True,
                operator_token="operator-secret",
            )
        )
