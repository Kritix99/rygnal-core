"""Persistent local FastAPI application for Rygnal."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from fastapi import FastAPI

from rygnal.api import create_app
from rygnal.local_runtime import create_local_runtime_dependencies


def create_local_app(
    *,
    data_dir: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> FastAPI:
    """Create a private local app backed by durable local storage."""
    dependencies = create_local_runtime_dependencies(
        data_dir=data_dir,
        environ=environ,
    )

    app = create_app(
        audit_logger=dependencies.audit_logger,
        approval_queue=dependencies.approval_queue,
    )

    app.state.rygnal_local_paths = dependencies.paths
    app.state.rygnal_local_dependencies = dependencies

    return app


__all__ = ["create_local_app"]
