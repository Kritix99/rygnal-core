"""Private localhost server command for Rygnal."""

from __future__ import annotations

import ipaddress
import threading
import webbrowser

from rygnal.local_app import create_local_app
from rygnal.local_paths import resolve_local_paths
from rygnal.runtime_config import (
    load_runtime_config,
)


def is_loopback_host(host: str) -> bool:
    """Return whether a host is explicitly loopback-only."""
    normalized = host.strip().lower()

    if normalized == "localhost":
        return True

    candidate = normalized.strip("[]")

    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _browser_host(host: str) -> str:
    if host == "0.0.0.0":
        return "127.0.0.1"

    if host in {"::", "[::]"}:
        return "[::1]"

    if ":" in host and not host.startswith("["):
        return f"[{host}]"

    return host


def run_serve_cli(args: object) -> int:
    """Start the validated local FastAPI service."""
    host = str(getattr(args, "host", "127.0.0.1"))
    port = int(getattr(args, "port", 8787))
    allow_network = bool(getattr(args, "allow_network", False))

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    if not is_loopback_host(host) and not allow_network:
        raise ValueError(
            "Refusing non-loopback binding. "
            "Use --allow-network only when remote "
            "access is intentionally required."
        )

    runtime_config = load_runtime_config(
        overrides={
            "api": {
                "host": host,
                "port": port,
                "allow_remote": allow_network,
            }
        },
        allow_implicit_development=True,
    )
    data_dir = getattr(
        args,
        "data_dir",
        None,
    )
    paths = resolve_local_paths(
        data_dir=(data_dir if data_dir is not None else runtime_config.storage.data_dir),
        create=True,
    )
    app = create_local_app(
        data_dir=paths.root,
        runtime_config=runtime_config,
    )

    browser_host = _browser_host(host)
    base_url = f"http://{browser_host}:{port}"
    docs_url = f"{base_url}/docs"

    print("Rygnal local service")
    print(f"API:  {base_url}")

    if runtime_config.api.docs_enabled:
        print(f"Docs: {docs_url}")

    print(f"Data: {paths.root}")
    print("Stop: Ctrl+C")

    if not is_loopback_host(host):
        print()
        print("WARNING: Rygnal is listening beyond localhost. Bearer authentication is required.")

    if runtime_config.api.docs_enabled and bool(
        getattr(
            args,
            "open_browser",
            False,
        )
    ):
        timer = threading.Timer(
            0.8,
            webbrowser.open,
            args=(docs_url,),
        )
        timer.daemon = True
        timer.start()

    import uvicorn

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=str(
            getattr(
                args,
                "log_level",
                "info",
            )
        ),
        access_log=not bool(
            getattr(
                args,
                "no_access_log",
                False,
            )
        ),
        reload=False,
        limit_concurrency=(runtime_config.api.max_concurrency),
        timeout_keep_alive=5,
        server_header=False,
        date_header=False,
    )

    return 0


__all__ = ["is_loopback_host", "run_serve_cli"]
