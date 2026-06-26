from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from rygnal.engine_api import _build_guarded_config
from rygnal.schemas import EngineRequest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_engine_api_rejects_invalid_json_without_stdout_text_leak() -> None:
    completed = _run_engine_api("not-json\n")

    assert completed.returncode == 1
    assert completed.stderr == ""

    events = _parse_ndjson(completed.stdout)
    assert [event["event"] for event in events] == ["engine.started", "engine.error"]
    assert events[-1]["ok"] is False
    assert events[-1]["status"] == "invalid_json"
    assert events[-1]["error"]["code"] == "invalid_json"


def test_engine_api_rejects_relative_trusted_repo_path() -> None:
    request = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "relative-path-test",
        "trusted_repo_path": ".",
        "command": [sys.executable, "-c", "print('hello')"],
        "unsafe_local_requested": True,
    }

    completed = _run_engine_api(json.dumps(request) + "\n")

    assert completed.returncode == 1
    events = _parse_ndjson(completed.stdout)
    assert events[-1]["event"] == "engine.error"
    assert events[-1]["status"] == "invalid_request"
    assert events[-1]["ok"] is False


def test_engine_api_rejects_shell_string_command(tmp_path: Path) -> None:
    repo = _create_repo(tmp_path / "trusted")
    request = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "shell-string-test",
        "trusted_repo_path": repo.as_posix(),
        "command": "python -c 'print(1)'",
        "unsafe_local_requested": True,
    }

    completed = _run_engine_api(json.dumps(request) + "\n")

    assert completed.returncode == 1
    events = _parse_ndjson(completed.stdout)
    assert events[-1]["event"] == "engine.error"
    assert events[-1]["status"] == "invalid_request"


def test_engine_api_streams_successful_guarded_run_without_raw_payloads(tmp_path: Path) -> None:
    repo = _create_repo(tmp_path / "trusted")
    request = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "success-test",
        "trusted_repo_path": repo.as_posix(),
        "command": [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "Path('agent_output.txt').write_text('hello from agent\\n')"
            ),
        ],
        "unsafe_local_requested": True,
        "run_root": (tmp_path / "runs").as_posix(),
    }

    completed = _run_engine_api(json.dumps(request) + "\n")

    assert completed.returncode == 0
    assert completed.stderr == ""

    events = _parse_ndjson(completed.stdout)
    event_names = [event["event"] for event in events]

    assert event_names[0] == "engine.started"
    assert "request.accepted" in event_names
    assert "run.started" in event_names
    assert "command.started" in event_names
    assert "command.finished" in event_names
    assert "workspace.cleaned" in event_names
    assert event_names[-1] == "run.completed"

    final = events[-1]
    assert final["ok"] is True
    assert final["status"] == "completed"
    assert final["request_id"] == "success-test"

    data = final["data"]
    assert data["changes"]["changed_file_count"] == 1
    assert data["changes"]["files"][0]["path"] == "agent_output.txt"
    assert data["patch"]["generated"] is True
    assert data["patch"]["sha256"]
    assert data["patch"]["size_bytes"] > 0
    assert "raw" not in data["patch"]
    assert "raw" not in data["command"]["stdout"]
    assert "raw" not in data["command"]["stderr"]
    assert data["workspace_path_returned"] is False
    assert data["trusted_repo"]["absolute_path_returned"] is False

    assert not (repo / "agent_output.txt").exists()


def test_engine_api_approval_required_summary_includes_risk_block(
    tmp_path: Path,
) -> None:
    repo = _create_repo(tmp_path / "trusted")
    request = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "approval-required-risk-test",
        "trusted_repo_path": repo.as_posix(),
        "command": [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "Path('pyproject.toml').write_text("
                "'[project]\\nname = \\\"changed\\\"\\n'"
                ")"
            ),
        ],
        "unsafe_local_requested": True,
        "run_root": (tmp_path / "runs").as_posix(),
    }

    completed = _run_engine_api(json.dumps(request) + "\n")

    assert completed.returncode == 0
    assert completed.stderr == ""

    events = _parse_ndjson(completed.stdout)
    event_names = [event["event"] for event in events]
    approval_event = next(event for event in events if event["event"] == "approval.required")
    final = events[-1]

    assert event_names.index("approval.required") < event_names.index("run.completed")
    assert approval_event["ok"] is True
    assert approval_event["status"] == "approval_required"
    assert approval_event["data"]["status"] == "approval_required"

    assert final["event"] == "run.completed"
    assert final["ok"] is True
    assert final["status"] == "approval_required"

    data = final["data"]
    assert approval_event["data"]["approval"] == data["approval"]
    assert approval_event["data"]["risk"] == data["risk"]
    assert data["status"] == "approval_required"
    assert data["approval"]["required"] is True
    assert data["approval"]["approval_id"]
    assert data["approval"]["target"] == data["patch"]["sha256"]
    assert data["risk"]["present"] is True
    assert data["risk"]["level"] == "high"
    assert "dependency-file-change" in data["risk"]["reasons"]
    assert data["risk"]["counts"]["high"] >= 1
    assert "raw" not in data["patch"]
    assert not (repo / "pyproject.toml").exists()


def test_engine_api_approval_required_wins_over_agent_failure(tmp_path: Path) -> None:
    repo = _create_repo(tmp_path / "trusted")
    request = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "approval-required-agent-failure-test",
        "trusted_repo_path": repo.as_posix(),
        "command": [
            sys.executable,
            "-c",
            (
                "import sys; "
                "from pathlib import Path; "
                "Path('pyproject.toml').write_text("
                "'[project]\\nname = \\\"changed\\\"\\n'"
                "); "
                "sys.exit(7)"
            ),
        ],
        "unsafe_local_requested": True,
        "run_root": (tmp_path / "runs").as_posix(),
    }

    completed = _run_engine_api(json.dumps(request) + "\n")

    assert completed.returncode == 0
    assert completed.stderr == ""

    events = _parse_ndjson(completed.stdout)
    event_names = [event["event"] for event in events]
    approval_event = next(event for event in events if event["event"] == "approval.required")
    final = events[-1]

    assert event_names.index("approval.required") < event_names.index("run.completed")
    assert approval_event["status"] == "approval_required"

    assert final["event"] == "run.completed"
    assert final["ok"] is True
    assert final["status"] == "approval_required"
    assert final["data"]["status"] == "approval_required"
    assert final["data"]["command"]["exit_code"] == 7
    assert final["data"]["approval"]["required"] is True
    assert final["data"]["risk"]["present"] is True
    assert "dependency-file-change" in final["data"]["risk"]["reasons"]


def test_engine_api_treats_agent_failure_as_successful_engine_run(tmp_path: Path) -> None:
    repo = _create_repo(tmp_path / "trusted")
    request = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "agent-failure-test",
        "trusted_repo_path": repo.as_posix(),
        "command": [sys.executable, "-c", "import sys; sys.exit(7)"],
        "unsafe_local_requested": True,
        "run_root": (tmp_path / "runs").as_posix(),
    }

    completed = _run_engine_api(json.dumps(request) + "\n")

    assert completed.returncode == 0

    events = _parse_ndjson(completed.stdout)
    final = events[-1]

    assert final["event"] == "run.completed"
    assert final["ok"] is True
    assert final["status"] == "command_failed"
    assert final["data"]["status"] == "command_failed"
    assert final["data"]["command"]["exit_code"] == 7


def _run_engine_api(stdin: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)

    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "rygnal.engine_api"],
        input=stdin,
        text=True,
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=env,
        check=False,
    )


def _parse_ndjson(stdout: str) -> list[dict[str, Any]]:
    lines = [line for line in stdout.splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def _create_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Rygnal Test")
    (path / "README.md").write_text("# trusted repo\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "initial")
    return path.resolve()


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=True,
    )


def test_engine_api_builds_guarded_config_with_intent_contract(tmp_path: Path) -> None:
    repo = _create_repo(tmp_path / "trusted")
    request = EngineRequest.model_validate(
        {
            "protocol_version": "rygnal.engine.v1",
            "action": "guarded_run.start",
            "request_id": "engine-intent-config-test",
            "trusted_repo_path": repo.as_posix(),
            "command": [sys.executable, "-c", "print('hello')"],
            "unsafe_local_requested": True,
            "run_root": (tmp_path / "runs").as_posix(),
            "intent_contract": {
                "source": "json",
                "task_objective": "Refactor authentication middleware",
                "allowed_actions": ["modify"],
                "target_scopes": [
                    {
                        "type": "path_glob",
                        "value": "src/auth/**",
                    }
                ],
            },
        }
    )

    config = _build_guarded_config(request)

    assert config.intent_contract is not None
    assert config.intent_contract.task_objective == "Refactor authentication middleware"
    assert config.intent_contract.target_scopes[0].value == "src/auth/**"


def test_engine_api_rejects_invalid_intent_contract_json(tmp_path: Path) -> None:
    repo = _create_repo(tmp_path / "trusted")
    request = {
        "protocol_version": "rygnal.engine.v1",
        "action": "guarded_run.start",
        "request_id": "engine-invalid-intent-test",
        "trusted_repo_path": repo.as_posix(),
        "command": [sys.executable, "-c", "print('hello')"],
        "unsafe_local_requested": True,
        "intent_contract": {
            "source": "json",
            "task_objective": "Modify source without target scope",
            "allowed_actions": ["modify"],
        },
    }

    completed = _run_engine_api(json.dumps(request) + "\n")

    assert completed.returncode == 1
    events = _parse_ndjson(completed.stdout)
    assert events[-1]["event"] == "engine.error"
    assert events[-1]["status"] == "invalid_request"
    assert events[-1]["error"]["code"] == "invalid_request"
