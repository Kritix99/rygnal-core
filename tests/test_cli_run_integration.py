import json
import os
import subprocess
import sys
from pathlib import Path

from tests.guarded_runner_helpers import create_trusted_repo, git_status_porcelain

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROJECT_ROOT / 'src'}{os.pathsep}{env.get('PYTHONPATH', '')}"

    return subprocess.run(
        [sys.executable, "-m", "rygnal.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_cli_run_unsafe_local_writes_only_guarded_workspace(tmp_path: Path) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_cli(
        "run",
        "--unsafe-local",
        "--run-root",
        str(tmp_path / "runs"),
        "--",
        sys.executable,
        "-c",
        "from pathlib import Path; Path('agent_output.txt').write_text('hello\\n')",
        cwd=trusted,
    )

    assert result.returncode == 0
    assert "Status: completed" in result.stdout
    assert "Backend: unsafe_local" in result.stdout
    assert "Containment verified: no" in result.stdout
    assert "agent_output.txt" in result.stdout
    assert "Patch SHA-256:" in result.stdout
    assert "Unsafe local execution is not a containment backend" in result.stdout
    assert git_status_porcelain(trusted) == "?? agent_output.txt"
    assert (trusted / "agent_output.txt").exists()


def test_cli_run_json_output_is_machine_readable(tmp_path: Path) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_cli(
        "run",
        "--unsafe-local",
        "--json",
        "--run-root",
        str(tmp_path / "runs"),
        "--",
        sys.executable,
        "-c",
        "from pathlib import Path; Path('json_output.txt').write_text('hello\\n')",
        cwd=trusted,
    )

    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["status"] == "completed"
    assert payload["changes"]["changed_paths"] == ["json_output.txt"]
    assert payload["patch"]["generated"] is True
    assert payload["patch"]["sha256"]
    assert git_status_porcelain(trusted) == "?? json_output.txt"
    assert (trusted / "json_output.txt").exists()


def test_cli_run_dirty_repo_blocks_without_allow_dirty(tmp_path: Path) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    (trusted / "README.md").write_text("dirty\n", encoding="utf-8")

    result = run_cli(
        "run",
        "--unsafe-local",
        "--run-root",
        str(tmp_path / "runs"),
        "--",
        sys.executable,
        "-c",
        "print('should not run')",
        cwd=trusted,
    )

    assert result.returncode == 2
    assert "Status: blocked" in result.stdout
    assert "Workspace: not_created" in result.stdout
    assert "`--allow-dirty`" in result.stdout


def test_cli_run_allow_dirty_is_explicit_override(tmp_path: Path) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    (trusted / "README.md").write_text("dirty\n", encoding="utf-8")

    result = run_cli(
        "run",
        "--unsafe-local",
        "--allow-dirty",
        "--run-root",
        str(tmp_path / "runs"),
        "--",
        sys.executable,
        "-c",
        "from pathlib import Path; Path('dirty_allowed.txt').write_text('ok\\n')",
        cwd=trusted,
    )

    assert result.returncode == 0
    assert "Status: completed" in result.stdout
    assert "dirty_allowed.txt" in result.stdout
    assert (trusted / "dirty_allowed.txt").exists()


def test_cli_run_audit_log_file_is_created(tmp_path: Path) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    audit_log = tmp_path / "audit.jsonl"

    result = run_cli(
        "run",
        "--unsafe-local",
        "--audit-log",
        str(audit_log),
        "--run-root",
        str(tmp_path / "runs"),
        "--",
        sys.executable,
        "-c",
        "from pathlib import Path; Path('audit_output.txt').write_text('audit\\n')",
        cwd=trusted,
    )

    audit_text = audit_log.read_text(encoding="utf-8")

    assert result.returncode == 0
    assert audit_log.exists()
    assert "guarded_run.requested" in audit_text
    assert "guarded_run.command_completed" in audit_text
    assert "guarded_run.patch_generated" in audit_text
    assert "diff --git" not in audit_text


def test_cli_run_preserve_workspace_prints_existing_workspace_path(tmp_path: Path) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")
    run_root = tmp_path / "runs"

    result = run_cli(
        "run",
        "--unsafe-local",
        "--preserve-workspace",
        "--run-root",
        str(run_root),
        "--",
        sys.executable,
        "-c",
        "from pathlib import Path; Path('preserved.txt').write_text('keep\\n')",
        cwd=trusted,
    )

    workspace_lines = [
        line for line in result.stdout.splitlines() if line.startswith("Workspace: preserved:")
    ]

    assert result.returncode == 0
    assert workspace_lines
    workspace_path = Path(workspace_lines[0].split("Workspace: preserved:", 1)[1].strip())
    assert workspace_path.exists()
    assert workspace_path.is_dir()
    assert workspace_path == trusted
    assert (workspace_path / "preserved.txt").exists()
    assert (trusted / "preserved.txt").exists()


def test_cli_run_failed_command_reports_changes_without_mutating_trusted_repo(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_cli(
        "run",
        "--unsafe-local",
        "--run-root",
        str(tmp_path / "runs"),
        "--",
        sys.executable,
        "-c",
        ("from pathlib import Path; Path('before_fail.txt').write_text('x'); raise SystemExit(7)"),
        cwd=trusted,
    )

    assert result.returncode == 1
    assert "Status: failed" in result.stdout
    assert "before_fail.txt" in result.stdout
    assert "Patch SHA-256:" in result.stdout
    assert (trusted / "before_fail.txt").exists()
    assert git_status_porcelain(trusted) == "?? before_fail.txt"


def test_cli_run_timeout_returns_timeout_exit_code_and_keeps_repo_clean(
    tmp_path: Path,
) -> None:
    trusted = create_trusted_repo(tmp_path / "trusted")

    result = run_cli(
        "run",
        "--unsafe-local",
        "--timeout",
        "1",
        "--run-root",
        str(tmp_path / "runs"),
        "--",
        sys.executable,
        "-c",
        "import time; time.sleep(30)",
        cwd=trusted,
    )

    assert result.returncode == 4
    assert "Status: timed_out" in result.stdout
    assert "Timed out: yes" in result.stdout
    assert git_status_porcelain(trusted) == ""
