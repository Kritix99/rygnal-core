import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from rygnal import cli_run
from rygnal.cli import build_parser, main
from rygnal.guarded_runner import GuardedRunStatus


def fake_result(
    status: GuardedRunStatus = GuardedRunStatus.COMPLETED,
    *,
    stdout: str = "hidden stdout\n",
    stderr: str = "hidden stderr\n",
    patch_text: str = "diff --git raw patch",
    warnings: tuple[str, ...] = (),
) -> SimpleNamespace:
    command = None
    changed_report = None
    patch = None
    blocked_reason = None

    if status != GuardedRunStatus.BLOCKED:
        command = SimpleNamespace(
            exit_code=0 if status == GuardedRunStatus.COMPLETED else 7,
            timed_out=status == GuardedRunStatus.TIMED_OUT,
            duration_ms=123,
            stdout=stdout,
            stderr=stderr,
        )
        changed_file = SimpleNamespace(path="agent_output.txt")
        changed_report = SimpleNamespace(
            files=(changed_file,),
            ignored_files=(),
            changed_file_count=1,
            ignored_file_count=0,
        )
        patch = SimpleNamespace(
            patch=patch_text,
            patch_sha256="abc123patchsha",
            patch_size_bytes=len(patch_text.encode("utf-8")),
            files=(changed_file,),
            ignored_files=(),
        )

    if status == GuardedRunStatus.BLOCKED:
        blocked_reason = "No verified containment backend is available."

    return SimpleNamespace(
        status=status,
        blocked_reason=blocked_reason,
        backend_name="unsafe_local",
        backend_safe_by_default=False,
        containment_verified=False,
        trusted_repo_path="/repo",
        workspace_path="/runs/worktree",
        baseline_commit_sha="abcdef1234567890",
        cleanup_performed=status != GuardedRunStatus.CLEANUP_FAILED,
        cleanup_status="reset_success",
        command_result=command,
        changed_file_report=changed_report,
        patch_diff=patch,
        warnings=warnings,
    )


def test_run_subcommand_exists_in_parser() -> None:
    parser = build_parser()
    help_text = parser.format_help()

    assert "run" in help_text
    assert "Run an agent command inside a guarded workspace" in help_text


def test_normalize_agent_command_strips_separator() -> None:
    command = cli_run.normalize_agent_command(["--", "python", "-c", "print(1)"])

    assert command == ("python", "-c", "print(1)")


def test_missing_agent_command_returns_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["run", "--"])
    captured = capsys.readouterr()

    assert exit_code == cli_run.EXIT_USAGE_ERROR
    assert "Missing agent command" in captured.err


def test_cli_passes_expected_config_to_run_guarded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured_config = {}

    def fake_run_guarded(config):
        captured_config["config"] = config
        return fake_result()

    monkeypatch.setattr(cli_run, "run_guarded", fake_run_guarded)

    repo = tmp_path / "repo"
    run_root = tmp_path / "runs"
    audit_log = tmp_path / "audit.jsonl"

    exit_code = main(
        [
            "run",
            "--repo",
            str(repo),
            "--timeout",
            "9",
            "--run-root",
            str(run_root),
            "--preserve-workspace",
            "--unsafe-local",
            "--allow-dirty",
            "--audit-log",
            str(audit_log),
            "--",
            "python",
            "-c",
            "print(1)",
        ]
    )

    config = captured_config["config"]

    assert exit_code == 0
    assert config.trusted_repo_path == repo
    assert config.command == ("python", "-c", "print(1)")
    assert config.timeout_seconds == 9
    assert config.rygnal_run_root == run_root
    assert config.preserve_workspace is True
    assert config.unsafe_local_requested is True
    assert config.allow_dirty_override is True
    assert config.audit_logger is not None
    assert config.environment == "cli"
    assert config.user_id == "cli_user"
    assert config.agent_id == "cli_agent"


@pytest.mark.parametrize(
    ("status", "expected_exit"),
    [
        (GuardedRunStatus.COMPLETED, cli_run.EXIT_COMPLETED),
        (GuardedRunStatus.FAILED, cli_run.EXIT_COMMAND_FAILED),
        (GuardedRunStatus.APPROVAL_REQUIRED, cli_run.EXIT_APPROVAL_REQUIRED),
        (GuardedRunStatus.BLOCKED, cli_run.EXIT_BLOCKED),
        (GuardedRunStatus.TIMED_OUT, cli_run.EXIT_TIMED_OUT),
        (GuardedRunStatus.CLEANUP_FAILED, cli_run.EXIT_CLEANUP_FAILED),
    ],
)
def test_exit_code_mapping(status: GuardedRunStatus, expected_exit: int) -> None:
    assert cli_run.exit_code_for_result(fake_result(status)) == expected_exit


def test_summary_contains_safe_core_facts() -> None:
    summary = cli_run.render_guarded_run_summary(
        fake_result(warnings=("Unsafe local execution is not a containment backend.",))
    )

    assert "Status: completed" in summary
    assert "Backend: unsafe_local" in summary
    assert "Containment verified: no" in summary
    assert "Changed files: 1" in summary
    assert "Patch SHA-256: abc123patchsha" in summary
    assert "agent_output.txt" in summary
    assert "Unsafe local execution is not a containment backend." in summary


def test_blocked_summary_uses_cli_language() -> None:
    result = fake_result(GuardedRunStatus.BLOCKED)
    result.blocked_reason = (
        "Tracked uncommitted changes detected. "
        "Commit or stash tracked changes, or pass allow_dirty_override=True."
    )
    result.workspace_path = None
    result.cleanup_performed = False

    summary = cli_run.render_guarded_run_summary(result)

    assert "Workspace: not_created" in summary
    assert "`--allow-dirty`" in summary
    assert "allow_dirty_override=True" not in summary
    assert "Fix the blocked reason" in summary


def test_summary_does_not_print_raw_patch_or_streams_by_default(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_run_guarded(_config):
        return fake_result(
            stdout="SHOULD_NOT_PRINT_STDOUT\n",
            stderr="SHOULD_NOT_PRINT_STDERR\n",
            patch_text="SHOULD_NOT_PRINT_PATCH",
        )

    monkeypatch.setattr(cli_run, "run_guarded", fake_run_guarded)

    exit_code = main(["run", "--unsafe-local", "--", "python", "-c", "print(1)"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "SHOULD_NOT_PRINT_PATCH" not in captured.out
    assert "SHOULD_NOT_PRINT_STDOUT" not in captured.out
    assert "SHOULD_NOT_PRINT_STDERR" not in captured.out
    assert "SHOULD_NOT_PRINT_STDERR" not in captured.err


def test_show_stdout_and_stderr_flags_print_streams(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_run_guarded(_config):
        return fake_result(stdout="visible stdout\n", stderr="visible stderr\n")

    monkeypatch.setattr(cli_run, "run_guarded", fake_run_guarded)

    exit_code = main(
        [
            "run",
            "--unsafe-local",
            "--show-stdout",
            "--show-stderr",
            "--",
            "python",
            "-c",
            "print(1)",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "visible stdout" in captured.out
    assert "visible stderr" in captured.err


def test_json_output_is_safe_json_without_raw_patch_or_streams(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_run_guarded(_config):
        return fake_result(
            stdout="JSON_STDOUT_SECRET",
            stderr="JSON_STDERR_SECRET",
            patch_text="JSON_PATCH_SECRET",
        )

    monkeypatch.setattr(cli_run, "run_guarded", fake_run_guarded)

    exit_code = main(["run", "--unsafe-local", "--json", "--", "python", "-c", "print(1)"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["status"] == "completed"
    assert payload["changes"]["changed_paths"] == ["agent_output.txt"]
    assert payload["patch"]["sha256"] == "abc123patchsha"
    assert "JSON_PATCH_SECRET" not in captured.out
    assert "JSON_STDOUT_SECRET" not in captured.out
    assert "JSON_STDERR_SECRET" not in captured.out


def test_cli_run_module_does_not_import_subprocess() -> None:
    source = Path("src/rygnal/cli_run.py").read_text(encoding="utf-8")

    assert "import subprocess" not in source
    assert "shell=True" not in source


def test_summary_and_json_deduplicate_warnings() -> None:
    result = fake_result(
        warnings=(
            "Unsafe local execution is not a containment backend.",
            "Unsafe local execution is not a containment backend.",
        )
    )

    summary = cli_run.render_guarded_run_summary(result)
    payload = cli_run.to_safe_json_summary(result)

    assert summary.count("Unsafe local execution is not a containment backend.") == 1
    assert payload["warnings"] == ["Unsafe local execution is not a containment backend."]


def test_parser_exposes_run_command_and_captures_remainder() -> None:
    parser = build_parser()

    args = parser.parse_args(["run", "--unsafe-local", "--", "python", "-c", "print('hi')"])

    assert args.command_name == "run"
    assert args.unsafe_local is True
    assert args.agent_command == ["--", "python", "-c", "print('hi')"]


def test_missing_agent_command_does_not_call_guarded_runner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden_run_guarded(_config):
        raise AssertionError("run_guarded must not be called without an agent command")

    monkeypatch.setattr(cli_run, "run_guarded", forbidden_run_guarded)

    exit_code = main(["run"])

    captured = capsys.readouterr()

    assert exit_code == cli_run.EXIT_USAGE_ERROR
    assert "Missing agent command" in captured.err


def test_run_calls_guarded_runner_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def fake_run_guarded(_config):
        nonlocal calls
        calls += 1
        return fake_result()

    monkeypatch.setattr(cli_run, "run_guarded", fake_run_guarded)

    exit_code = main(["run", "--unsafe-local", "--", "python", "-c", "print('ok')"])

    assert exit_code == 0
    assert calls == 1


def test_cli_does_not_directly_execute_agent_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_subprocess_run(*_args, **_kwargs):
        raise AssertionError("CLI must not directly call subprocess.run for agent command")

    def fake_run_guarded(_config):
        return fake_result()

    monkeypatch.setattr(subprocess, "run", forbidden_subprocess_run)
    monkeypatch.setattr(cli_run, "run_guarded", fake_run_guarded)

    exit_code = main(["run", "--unsafe-local", "--", "python", "-c", "print('ok')"])

    assert exit_code == 0


def test_cli_loads_intent_yaml_and_passes_contract_to_guarded_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured_config = {}

    def fake_run_guarded(config):
        captured_config["config"] = config
        return fake_result()

    monkeypatch.setattr(cli_run, "run_guarded", fake_run_guarded)

    intent_file = tmp_path / "intent.yaml"
    intent_file.write_text(
        """
source: yaml
task_objective: Refactor authentication middleware
allowed_actions:
  - modify
target_scopes:
  - type: path_glob
    value: src/auth/**
enforcement_mode: shadow
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "run",
            "--unsafe-local",
            "--intent",
            str(intent_file),
            "--",
            "python",
            "-c",
            "print(1)",
        ]
    )

    config = captured_config["config"]

    assert exit_code == 0
    assert config.intent_contract is not None
    assert config.intent_contract.task_objective == "Refactor authentication middleware"
    assert config.intent_contract.target_scopes[0].value == "src/auth/**"


def test_cli_invalid_intent_yaml_returns_usage_error_without_running_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden_run_guarded(_config):
        raise AssertionError("run_guarded must not run when intent validation fails")

    monkeypatch.setattr(cli_run, "run_guarded", forbidden_run_guarded)

    intent_file = tmp_path / "intent.yaml"
    intent_file.write_text("source: [", encoding="utf-8")

    exit_code = main(
        [
            "run",
            "--unsafe-local",
            "--intent",
            str(intent_file),
            "--",
            "python",
            "-c",
            "print(1)",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == cli_run.EXIT_USAGE_ERROR
    assert "Intent file invalid" in captured.err
    assert "invalid_intent_yaml" in captured.err


def test_parser_exposes_intent_argument() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "run",
            "--unsafe-local",
            "--intent",
            ".rygnal/intent.yaml",
            "--",
            "python",
            "-c",
            "print('hi')",
        ]
    )

    assert args.intent == Path(".rygnal/intent.yaml")


def test_json_summary_includes_normalized_action_telemetry() -> None:
    from rygnal.action_normalizer import normalize_command_action

    result = fake_result()
    result.normalized_actions = (normalize_command_action(("python", "-m", "pytest")),)

    payload = cli_run.to_safe_json_summary(result)

    assert payload["normalized_actions"]["action_count"] == 1
    assert payload["normalized_actions"]["operation_counts"] == {"test": 1}
    assert payload["normalized_actions"]["source_counts"] == {"command": 1}


def test_json_summary_includes_intent_evaluation() -> None:
    from rygnal.intent_contract import (
        IntentDecisionHint,
        IntentEnforcementMode,
        IntentMatchResult,
        IntentMatchState,
    )
    from rygnal.intent_fallback_policy import IntentFallbackEvaluation

    result = fake_result()
    result.intent_match_results = (
        IntentMatchResult(
            match_state=IntentMatchState.UNKNOWN,
            contract_id="intent_1",
            action_id="action_1",
            reason_codes=("scope-unknown:no-affected-paths",),
            decision_hint=IntentDecisionHint.REQUIRE_APPROVAL,
        ),
    )
    result.intent_fallback_evaluation = IntentFallbackEvaluation(
        contract_id="intent_1",
        enforcement_mode=IntentEnforcementMode.ENFORCE,
        match_state=IntentMatchState.UNKNOWN,
        recommended_hint=IntentDecisionHint.REQUIRE_APPROVAL,
        effective_hint=IntentDecisionHint.REQUIRE_APPROVAL,
        reason_codes=("fallback:unknown-resource-or-operation",),
        result_count=1,
        metadata={},
    )

    payload = cli_run.to_safe_json_summary(result)

    assert payload["intent"]["evaluated"] is True
    assert payload["intent"]["matches"]["result_count"] == 1
    assert payload["intent"]["fallback"]["effective_hint"] == "require_approval"


def test_json_summary_includes_intent_decision_receipt() -> None:
    from rygnal.intent_receipt import IntentDecisionReceipt

    result = fake_result()
    result.intent_decision_receipt = IntentDecisionReceipt(
        schema_version="intent-decision-receipt.v1",
        receipt_hash="a" * 64,
        trace_id="trace_receipt",
        contract_id="intent_1",
        session_id="intent_session_1",
        enforcement_mode="enforce",
        match_state="unknown",
        recommended_hint="require_approval",
        effective_hint="require_approval",
        result_count=1,
        action_ids=("action_1",),
        reason_codes=("fallback:unknown-resource-or-operation",),
    )

    payload = cli_run.to_safe_json_summary(result)

    assert payload["intent"]["receipt"]["receipt_hash"] == "a" * 64
    assert payload["intent"]["receipt"]["trace_id"] == "trace_receipt"
