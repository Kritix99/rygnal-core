from rygnal.action_normalizer import (
    normalize_changed_file_action,
    normalize_changed_file_actions,
    normalize_command_action,
    normalize_guarded_actions,
    normalized_actions_audit_summary,
)
from rygnal.changed_files import ChangedFile, ChangedFileKind, ChangedFileReport
from rygnal.intent_contract import IntentOperation, NormalizedActionSource, ResourceKind
from rygnal.patch_diff import PatchDiff, PatchFileDiff

BASELINE_SHA = "a" * 40


def test_normalize_test_command_before_execution() -> None:
    action = normalize_command_action(("python", "-m", "pytest", "tests/test_api.py", "-q"))

    assert action.source == NormalizedActionSource.COMMAND
    assert action.operation == IntentOperation.TEST
    assert action.affected_paths == ("tests/test_api.py",)
    assert action.resource_kind == ResourceKind.TEST
    assert "source:command" in action.reason_codes
    assert action.action_id.startswith("normalized_action_")


def test_normalize_dependency_command_redacts_sensitive_args() -> None:
    action = normalize_command_action(
        (
            "pip",
            "install",
            "requests",
            "--extra-index-url=https://token:secret@example.com/simple",
            "--password=super-secret",
        )
    )

    assert action.operation == IntentOperation.DEPENDENCY_CHANGE
    assert action.raw_evidence["argv_redacted"][-1] == "--password=[REDACTED]"
    assert "super-secret" not in str(action.raw_evidence)


def test_normalize_destructive_recursive_command() -> None:
    action = normalize_command_action(("rm", "-rf", "dist"))

    assert action.operation == IntentOperation.DELETE_FOLDER
    assert "operation:delete_folder" in action.reason_codes


def test_normalize_unknown_command_as_explicit_command_action() -> None:
    action = normalize_command_action(("custom-agent-tool", "--flag"))

    assert action.operation == IntentOperation.COMMAND
    assert action.resource_kind == ResourceKind.UNKNOWN
    assert "executable:custom-agent-tool" in action.reason_codes


def test_normalize_added_python_file_action() -> None:
    changed_file = ChangedFile(path="src/rygnal/new_module.py", kind=ChangedFileKind.ADDED)

    action = normalize_changed_file_action(changed_file)

    assert action.source == NormalizedActionSource.FILESYSTEM
    assert action.operation == IntentOperation.CREATE
    assert action.affected_paths == ("src/rygnal/new_module.py",)
    assert action.resource_kind == ResourceKind.PYTHON_MODULE
    assert action.diff_metadata["file_patch_present"] is False


def test_normalize_deleted_secret_file_action() -> None:
    changed_file = ChangedFile(path=".env", kind=ChangedFileKind.DELETED)

    action = normalize_changed_file_action(changed_file)

    assert action.operation == IntentOperation.DELETE_FILE
    assert action.resource_kind == ResourceKind.SENSITIVE
    assert "resource_kind:sensitive" in action.reason_codes


def test_normalize_renamed_file_preserves_old_and_new_paths() -> None:
    changed_file = ChangedFile(
        path="src/new_name.py",
        kind=ChangedFileKind.RENAMED,
        old_path="src/old_name.py",
    )

    action = normalize_changed_file_action(changed_file)

    assert action.operation == IntentOperation.RENAME
    assert action.old_path == "src/old_name.py"
    assert action.new_path == "src/new_name.py"
    assert action.affected_paths == ("src/old_name.py", "src/new_name.py")


def test_normalize_mode_changed_file_action() -> None:
    changed_file = ChangedFile(
        path="scripts/deploy.sh",
        kind=ChangedFileKind.MODE_CHANGED,
        old_mode="100644",
        new_mode="100755",
        mode_changed=True,
    )

    action = normalize_changed_file_action(changed_file)

    assert action.operation == IntentOperation.MODIFY
    assert action.raw_evidence["mode_changed"] is True
    assert action.raw_evidence["old_mode"] == "100644"
    assert action.raw_evidence["new_mode"] == "100755"


def test_normalize_changed_files_with_patch_metadata() -> None:
    changed_file = ChangedFile(path="pyproject.toml", kind=ChangedFileKind.MODIFIED)
    report = ChangedFileReport(
        workspace_path="/tmp/workspace",
        baseline_commit_sha=BASELINE_SHA,
        files=(changed_file,),
    )
    patch_diff = PatchDiff(
        workspace_path="/tmp/workspace",
        baseline_commit_sha=BASELINE_SHA,
        patch="diff --git a/pyproject.toml b/pyproject.toml\n",
        patch_sha256="b" * 64,
        patch_size_bytes=42,
        files=(
            PatchFileDiff(
                path="pyproject.toml",
                kind=ChangedFileKind.MODIFIED,
                additions=3,
                deletions=1,
            ),
        ),
    )

    actions = normalize_changed_file_actions(report, patch_diff=patch_diff)

    assert len(actions) == 1
    action = actions[0]
    assert action.operation == IntentOperation.MODIFY
    assert action.resource_kind == ResourceKind.DEPENDENCY_MANIFEST
    assert action.diff_metadata["file_patch_present"] is True
    assert action.diff_metadata["patch_sha256"] == "b" * 64
    assert action.diff_metadata["additions"] == 3
    assert action.diff_metadata["deletions"] == 1


def test_normalize_guarded_actions_includes_command_and_effects() -> None:
    report = ChangedFileReport(
        workspace_path="/tmp/workspace",
        baseline_commit_sha=BASELINE_SHA,
        files=(
            ChangedFile(path="src/app.py", kind=ChangedFileKind.MODIFIED),
            ChangedFile(path=".github/workflows/ci.yml", kind=ChangedFileKind.ADDED),
        ),
    )

    actions = normalize_guarded_actions(("python", "-m", "pytest"), changed_file_report=report)

    assert [action.operation for action in actions] == [
        IntentOperation.TEST,
        IntentOperation.MODIFY,
        IntentOperation.CREATE,
    ]
    assert actions[2].resource_kind == ResourceKind.CI_WORKFLOW


def test_normalize_guarded_actions_noop_run_keeps_pre_action() -> None:
    actions = normalize_guarded_actions(("git", "status"))

    assert len(actions) == 1
    assert actions[0].source == NormalizedActionSource.COMMAND


def test_normalized_actions_have_stable_ids() -> None:
    first = normalize_command_action(("python", "-m", "pytest", "tests/test_api.py"))
    second = normalize_command_action(("python", "-m", "pytest", "tests/test_api.py"))

    assert first.action_id == second.action_id


def test_normalized_actions_audit_summary_is_queryable_and_safe() -> None:
    actions = (
        normalize_command_action(("python", "-m", "pytest")),
        normalize_changed_file_action(
            ChangedFile(path="src/app.py", kind=ChangedFileKind.MODIFIED)
        ),
    )

    summary = normalized_actions_audit_summary(actions)

    assert summary["action_count"] == 2
    assert summary["operation_counts"] == {"test": 1, "modify": 1}
    assert summary["source_counts"] == {"command": 1, "filesystem": 1}
    assert summary["actions"][0]["action_id"].startswith("normalized_action_")


def test_python_inline_code_is_not_treated_as_repo_path_or_raw_telemetry() -> None:
    marker = "raw-patch-secret-marker"
    action = normalize_command_action(
        (
            "python",
            "-c",
            f"from pathlib import Path; Path('secret.txt').write_text('{marker}')",
        )
    )

    assert action.affected_paths == ()
    assert action.raw_evidence["argv_redacted"] == (
        "python",
        "-c",
        "[REDACTED_INLINE_CODE]",
    )
    assert marker not in str(action.model_dump(mode="json"))


def test_rename_resource_kind_considers_old_sensitive_path() -> None:
    from rygnal.action_normalizer import normalize_changed_file_action
    from rygnal.changed_files import ChangedFile, ChangedFileKind
    from rygnal.intent_contract import IntentOperation, ResourceKind

    action = normalize_changed_file_action(
        ChangedFile(
            path="docs/allowed/env.txt",
            kind=ChangedFileKind.RENAMED,
            old_path=".env",
        )
    )

    assert action.operation == IntentOperation.RENAME
    assert action.old_path == ".env"
    assert action.new_path == "docs/allowed/env.txt"
    assert action.resource_kind == ResourceKind.SENSITIVE
