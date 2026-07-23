from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from rygnal.cli import build_parser
from rygnal.cli_serve import is_loopback_host, run_serve_cli
from rygnal.local_app import create_local_app
from rygnal.local_runtime import create_local_runtime_dependencies
from rygnal.models import ToolRequest
from rygnal.policy_engine import load_default_policy_engine


def run_cli(
    *args: str,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"src{os.pathsep}{env.get('PYTHONPATH', '')}"

    if environment is not None:
        env.update(environment)

    return subprocess.run(
        [sys.executable, "-m", "rygnal.cli", *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_cli_registers_local_commands():
    parser = build_parser()

    doctor = parser.parse_args(["doctor", "--skip-containment"])
    audit = parser.parse_args(["audit"])
    serve = parser.parse_args(["serve"])

    assert doctor.command_name == "doctor"
    assert audit.command_name == "audit"
    assert serve.command_name == "serve"
    assert serve.host == "127.0.0.1"
    assert serve.port == 8787


def test_doctor_json_reports_required_components(
    tmp_path: Path,
):
    data_dir = tmp_path / "local-data"

    result = run_cli(
        "doctor",
        "--json",
        "--skip-containment",
        "--data-dir",
        str(data_dir),
    )

    assert result.returncode == 0, result.stderr

    payload = json.loads(result.stdout)
    checks = {check["name"]: check for check in payload["checks"]}

    assert payload["ready"] is True
    assert checks["python"]["status"] == "ok"
    assert checks["git"]["status"] == "ok"
    assert checks["policies"]["status"] == "ok"
    assert checks["fastapi"]["status"] == "ok"
    assert checks["uvicorn"]["status"] == "ok"

    assert not data_dir.exists()


def test_audit_cli_reads_persistent_local_events(
    tmp_path: Path,
):
    data_dir = tmp_path / "local-data"
    dependencies = create_local_runtime_dependencies(
        data_dir=data_dir,
        environ={},
    )

    request = ToolRequest(
        tool_name="file_read",
        action="read_file",
        target=".env",
    )
    decision = load_default_policy_engine().evaluate(request)

    dependencies.audit_logger.log_decision(
        request,
        decision,
        metadata={"source": "test"},
    )

    result = run_cli(
        "audit",
        "--json",
        "--data-dir",
        str(data_dir),
    )

    assert result.returncode == 0, result.stderr

    payload = json.loads(result.stdout)
    assert payload["returned_count"] == 1
    assert payload["events"][0]["tool_name"] == "file_read"
    assert payload["events"][0]["decision"] == "block"


def test_local_app_persists_audit_events_across_restart(
    tmp_path: Path,
):
    data_dir = tmp_path / "local-data"

    first_app = create_local_app(data_dir=data_dir)

    with TestClient(first_app) as client:
        response = client.post(
            "/v1/evaluate",
            json={
                "tool_name": "file_read",
                "action": "read_file",
                "target": ".env",
            },
        )

        assert response.status_code == 200
        assert response.json()["audit_event"] is not None

    second_app = create_local_app(data_dir=data_dir)

    with TestClient(second_app) as client:
        response = client.get("/v1/audit/events")

        assert response.status_code == 200
        payload = response.json()
        assert payload["returned_count"] == 1
        assert payload["events"][0]["tool_name"] == "file_read"


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("192.168.1.10", False),
        ("example.com", False),
    ],
)
def test_loopback_host_detection(
    host: str,
    expected: bool,
):
    assert is_loopback_host(host) is expected


def test_serve_rejects_public_binding_without_opt_in(
    tmp_path: Path,
):
    args = SimpleNamespace(
        host="0.0.0.0",
        port=8787,
        data_dir=tmp_path / "data",
        allow_network=False,
        open_browser=False,
        log_level="info",
        no_access_log=True,
    )

    with pytest.raises(
        ValueError,
        match="Refusing non-loopback binding",
    ):
        run_serve_cli(args)
