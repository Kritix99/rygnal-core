"""Persistent local FastAPI application for Rygnal."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from fastapi import FastAPI

from rygnal.api import create_app
from rygnal.local_runtime import create_local_runtime_dependencies
from rygnal.production_containment import verify_production_bubblewrap
from rygnal.runtime_config import (
    RuntimeConfigV1,
    RuntimeEnvironment,
    load_runtime_config,
)
from rygnal.sqlite_migrations import (
    approval_schema_ready,
    audit_schema_ready,
    operation_schema_ready,
)


def create_local_app(
    *,
    data_dir: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    runtime_config: RuntimeConfigV1 | None = None,
) -> FastAPI:
    """Create a validated durable local application."""
    environment = os.environ if environ is None else environ
    active_config = (
        runtime_config
        if runtime_config is not None
        else load_runtime_config(
            environ=environment,
            allow_implicit_development=True,
        )
    )
    configured_data_dir = data_dir if data_dir is not None else active_config.storage.data_dir

    dependencies = create_local_runtime_dependencies(
        data_dir=configured_data_dir,
        environ=environment,
    )

    def readiness_probe() -> bool:
        containment_ready = True

        if active_config.environment == RuntimeEnvironment.PRODUCTION:
            containment_ready = verify_production_bubblewrap().eligible

        return (
            containment_ready
            and audit_schema_ready(dependencies.paths.audit_db)
            and approval_schema_ready(dependencies.paths.approval_db)
            and operation_schema_ready(dependencies.operation_store.db_path)
            and dependencies.audit_logger.verify_integrity()
        )

    app = create_app(
        audit_logger=dependencies.audit_logger,
        approval_queue=dependencies.approval_queue,
        approval_service=dependencies.approval_service,
        operator_token=(active_config.api.operator_token_value()),
        runtime_config=active_config,
        readiness_probe=readiness_probe,
    )

    app.state.rygnal_local_paths = dependencies.paths
    app.state.rygnal_local_dependencies = dependencies
    app.state.rygnal_runtime_config = active_config

    return app


__all__ = ["create_local_app"]
