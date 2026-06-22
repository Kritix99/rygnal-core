import subprocess
from pathlib import Path

from rygnal.change_risk import (
    ChangeRiskReason,
    classify_patch_risk,
    extract_added_lines_by_path,
)
from rygnal.changed_files import ChangedFileKind
from rygnal.patch_diff import PatchDiff, PatchFileDiff, generate_patch_diff
from rygnal.risk_engine import RiskLevel


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def create_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()

    run_git(repo, "init")
    run_git(repo, "config", "user.email", "test@example.com")
    run_git(repo, "config", "user.name", "Test User")
    run_git(repo, "config", "core.filemode", "true")

    (repo / "README.md").write_text("# Project\n", encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "baseline")

    return repo


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def risk_for_path(report, path: str):
    return next(file for file in report.files if file.path == path)


def classify_repo_changes(repo: Path):
    return classify_patch_risk(generate_patch_diff(repo, baseline_sha(repo)))


def test_documentation_changes_are_low_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    docs = repo / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Usage\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "docs/usage.md")
    assert file_risk.risk_level == RiskLevel.LOW
    assert file_risk.reasons[0].code == "documentation-change"
    assert report.overall_risk_level == RiskLevel.LOW


def test_normal_source_changes_are_medium_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/app.py")
    assert file_risk.risk_level == RiskLevel.MEDIUM
    assert file_risk.reasons[0].code == "source-code-change"


def test_simple_test_changes_are_low_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "tests/test_app.py")
    assert file_risk.risk_level == RiskLevel.LOW
    assert file_risk.reasons[0].code == "test-change"


def test_dependency_manifest_changes_are_high_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    (repo / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "pyproject.toml")
    assert file_risk.risk_level == RiskLevel.HIGH
    assert any(reason.code == "dependency-file-change" for reason in file_risk.reasons)


def test_ci_workflow_changes_are_high_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    workflow = repo / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "ci.yml").write_text("name: ci\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, ".github/workflows/ci.yml")
    assert file_risk.risk_level == RiskLevel.HIGH
    assert any(reason.code == "ci-config-change" for reason in file_risk.reasons)


def test_secret_paths_are_critical_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    (repo / ".env").write_text("TOKEN=example\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, ".env")
    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert any(reason.code == "security-sensitive-path" for reason in file_risk.reasons)


def test_added_secret_content_is_critical_and_audit_safe(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    secret_value = "sk-1234567890abcdefABCDEF"
    src = repo / "src"
    src.mkdir()
    (src / "config.py").write_text(
        f'OPENAI_API_KEY = "{secret_value}"\n',
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/config.py")
    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert any(reason.code == "added-secret-openai-api-key" for reason in file_risk.reasons)
    assert secret_value not in str(report.audit_summary)


def test_destructive_script_content_is_critical(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    scripts = repo / "scripts"
    scripts.mkdir()
    (scripts / "cleanup.sh").write_text("#!/bin/sh\nrm -rf /tmp/demo\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "scripts/cleanup.sh")
    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert any(
        reason.code == "destructive-command-recursive-force-delete" for reason in file_risk.reasons
    )


def test_binary_file_changes_are_high_risk(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    (repo / "artifact.bin").write_bytes(b"\x00\x01\x02\x03")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "artifact.bin")
    assert file_risk.risk_level == RiskLevel.HIGH
    assert any(reason.code == "binary-file-change" for reason in file_risk.reasons)
    assert any(reason.code == "generated-executable-artifact" for reason in file_risk.reasons)


def test_symlink_changes_are_critical_risk() -> None:
    patch_file = PatchFileDiff(
        path="escape-link",
        kind=ChangedFileKind.UNTRACKED,
        additions=1,
        deletions=0,
        new_mode="120000",
    )
    patch = PatchDiff(
        workspace_path="/tmp/workspace",
        baseline_commit_sha="a" * 40,
        patch="diff --git a/escape-link b/escape-link\n",
        patch_sha256="b" * 64,
        patch_size_bytes=42,
        files=(patch_file,),
    )

    report = classify_patch_risk(patch)

    file_risk = risk_for_path(report, "escape-link")
    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert any(reason.code == "symlink-change" for reason in file_risk.reasons)


def test_validation_reasons_can_raise_report_level_without_file_changes() -> None:
    reason = ChangeRiskReason(
        code="validator-large-diff",
        risk_level=RiskLevel.HIGH,
        reason="External validator marked patch as large.",
        evidence=(("changed_file_count", 200),),
    )
    patch = PatchDiff(
        workspace_path="/tmp/workspace",
        baseline_commit_sha="a" * 40,
        patch="",
        patch_sha256="b" * 64,
        patch_size_bytes=0,
    )

    report = classify_patch_risk(patch, validation_reasons=(reason,))

    assert report.files == ()
    assert report.overall_risk_level == RiskLevel.HIGH
    assert report.audit_summary["report_reasons"][0]["code"] == "validator-large-diff"


def test_extract_added_lines_ignores_patch_headers() -> None:
    patch = """diff --git a/app.py b/app.py
index 0000000..1111111 100644
--- a/app.py
+++ b/app.py
@@ -1 +1,2 @@
-old
+new
+token = "abc123456789"
"""

    added_lines = extract_added_lines_by_path(patch)

    assert added_lines == {"app.py": ("new", 'token = "abc123456789"')}


def test_common_credential_paths_are_critical(tmp_path: Path) -> None:
    repo = create_repo(tmp_path)
    sensitive_paths = (
        ".aws/credentials",
        ".ssh/id_rsa",
        ".config/gcloud/application_default_credentials.json",
        ".docker/config.json",
        ".netrc",
    )

    for sensitive_path in sensitive_paths:
        target = repo / sensitive_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fake credential material\n", encoding="utf-8")

    report = classify_repo_changes(repo)
    risks_by_path = {file.path: file for file in report.files}

    for sensitive_path in sensitive_paths:
        assert sensitive_path in risks_by_path
        assert risks_by_path[sensitive_path].risk_level == RiskLevel.CRITICAL
        assert any(
            reason.code == "security-sensitive-path"
            for reason in risks_by_path[sensitive_path].reasons
        )


def test_rust_criticality_available_critical_result_raises_medium_python_risk(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    def fake_evaluate(criticality_input):
        assert criticality_input.file_path == "src/app.py"
        assert criticality_input.action_type == "untracked"
        assert criticality_input.old_code == ""
        assert criticality_input.new_code == "print('hello')\n"
        return RustCriticalityAssessment(
            criticality_index=9.0,
            risk_level="critical",
            reasons=("shadow-only criticality",),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=0,
                new_node_count=1,
                old_token_count=0,
                new_token_count=3,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="source",
            path_severity="medium",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/app.py")
    assert file_risk.risk_level == RiskLevel.HIGH
    assert report.overall_risk_level == RiskLevel.HIGH
    assert any(reason.code == "rust-criticality-signal" for reason in file_risk.reasons)

    shadow = file_risk.audit_summary["rust_criticality"]
    assert shadow["available"] is True
    assert shadow["criticality_index"] == 9.0
    assert shadow["risk_level"] == "critical"
    assert shadow["reasons"] == ("shadow-only criticality",)

    assert file_risk.risk_level == RiskLevel.HIGH
    assert report.overall_risk_level == RiskLevel.HIGH
    assert report.risk_counts["high"] == 1


def test_rust_criticality_available_critical_result_raises_low_python_risk(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = create_repo(tmp_path)
    docs = repo / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Usage\n", encoding="utf-8")

    python_only_report = classify_repo_changes(repo)

    def fake_evaluate(criticality_input):
        return RustCriticalityAssessment(
            criticality_index=10.0,
            risk_level="critical",
            reasons=("shadow-only criticality",),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=0,
                new_node_count=1,
                old_token_count=0,
                new_token_count=1,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="docs",
            path_severity="low",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    shadow_report = classify_repo_changes(repo)

    assert python_only_report.overall_risk_level == RiskLevel.LOW
    assert shadow_report.overall_risk_level == RiskLevel.HIGH
    assert shadow_report.risk_counts["high"] == 1

    file_risk = risk_for_path(shadow_report, "docs/usage.md")
    assert file_risk.risk_level == RiskLevel.HIGH
    assert file_risk.audit_summary["rust_criticality"]["risk_level"] == "critical"
    assert any(reason.code == "rust-criticality-signal" for reason in file_risk.reasons)


def test_rust_criticality_shadow_missing_kernel_does_not_crash(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustKernelUnavailableError

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    def fail_evaluate(criticality_input):
        raise RustKernelUnavailableError(
            "optional Rust kernel extension is not installed or failed to load"
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fail_evaluate)

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/app.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert file_risk.risk_level == RiskLevel.MEDIUM
    assert report.overall_risk_level == RiskLevel.MEDIUM
    assert shadow["available"] is False
    assert shadow["error_code"] == "rust-kernel-unavailable"
    assert "failed to load" in shadow["error_reason"]


def test_rust_criticality_shadow_generic_adapter_error_does_not_crash(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustKernelError

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    def fail_evaluate(criticality_input):
        raise RustKernelError("rust kernel returned invalid JSON")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fail_evaluate)

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/app.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert file_risk.risk_level == RiskLevel.MEDIUM
    assert report.overall_risk_level == RiskLevel.MEDIUM
    assert shadow["available"] is False
    assert shadow["error_code"] == "rust-kernel-error"
    assert shadow["error_reason"] == "rust kernel returned invalid JSON"


def test_rust_criticality_shadow_structured_domain_error_is_preserved(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityEvaluationError

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    def fail_evaluate(criticality_input):
        raise RustCriticalityEvaluationError(
            error_code="parent-traversal",
            reason="path must not traverse outside repository",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fail_evaluate)

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/app.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert file_risk.risk_level == RiskLevel.MEDIUM
    assert report.overall_risk_level == RiskLevel.MEDIUM
    assert shadow["available"] is False
    assert shadow["error_code"] == "parent-traversal"
    assert shadow["error_reason"] == "path must not traverse outside repository"


def test_rust_criticality_shadow_bypasses_binary_files(
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for binary files")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    patch_file = PatchFileDiff(
        path="artifact.bin",
        kind=ChangedFileKind.UNTRACKED,
        additions=None,
        deletions=None,
        binary=True,
    )
    patch = PatchDiff(
        workspace_path="/tmp/workspace",
        baseline_commit_sha="a" * 40,
        patch="diff --git a/artifact.bin b/artifact.bin\n",
        patch_sha256="b" * 64,
        patch_size_bytes=42,
        files=(patch_file,),
    )

    report = classify_patch_risk(patch)

    file_risk = risk_for_path(report, "artifact.bin")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert file_risk.risk_level == RiskLevel.HIGH
    assert shadow["available"] is False
    assert shadow["error_code"] == "binary-file"
    assert shadow["error_reason"] == (
        "binary files are excluded from Rust criticality shadow analysis"
    )


def test_rust_criticality_shadow_bypasses_massive_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.change_risk import MAX_CRITICALITY_SHADOW_BYTES

    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for oversized files")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    large_file = repo / "large.json"
    large_file.write_text("x" * (MAX_CRITICALITY_SHADOW_BYTES + 1), encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "large.json")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert file_risk.risk_level == RiskLevel.MEDIUM
    assert shadow["available"] is False
    assert shadow["error_code"] == "file-too-large"
    assert shadow["error_reason"] == "file size exceeds shadow mode criticality limits"


def _low_rust_criticality_assessment():
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    return RustCriticalityAssessment(
        criticality_index=1.0,
        risk_level="low",
        reasons=(),
        semantic_metrics=RustSemanticMetrics(
            old_node_count=0,
            new_node_count=1,
            old_token_count=0,
            new_token_count=1,
            matched_node_count=0,
            survival_ratio=1.0,
        ),
        path_category="source",
        path_severity="low",
    )


def test_rust_criticality_shadow_bypasses_verified_root_lockfile(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for verified lockfiles")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    (repo / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {}}\n',
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)
    file_risk = risk_for_path(report, "package-lock.json")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert shadow["available"] is False
    assert shadow["error_code"] == "criticality-bypass"
    assert shadow["criticality_bypass_verdict"] == "bypassed"
    assert shadow["criticality_bypass_reason"] == "bypassed:lockfile-root-valid-json"


def test_rust_criticality_shadow_invokes_rust_for_nested_lockfile(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0
    captured = {}

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        captured["input"] = criticality_input
        return _low_rust_criticality_assessment()

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    nested = repo / "src"
    nested.mkdir()
    (nested / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {}}\n',
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)
    file_risk = risk_for_path(report, "src/package-lock.json")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 1
    assert captured["input"].file_path == "src/package-lock.json"
    assert shadow["available"] is True
    assert shadow["criticality_bypass_verdict"] == "rust-invoked"
    assert shadow["criticality_bypass_reason"] == "rust-invoked:lockfile-nested-path"


def test_rust_criticality_shadow_invokes_rust_for_malformed_root_lockfile(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        assert criticality_input.elevated is True
        assert criticality_input.elevated_weight is None
        nonlocal calls
        calls += 1
        return _low_rust_criticality_assessment()

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    (repo / "package-lock.json").write_text(
        '{"not": "a real lockfile"\n',
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)
    file_risk = risk_for_path(report, "package-lock.json")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 1
    assert file_risk.risk_level == RiskLevel.HIGH
    assert shadow["available"] is True
    assert shadow["criticality_bypass_verdict"] == "elevated-risk"
    assert shadow["criticality_bypass_reason"] == "lockfile-claim-invalid-structure"
    assert any(reason.code == "lockfile-claim-invalid-structure" for reason in file_risk.reasons)


def test_rust_criticality_shadow_invokes_rust_for_generated_marker_spoof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0
    captured = {}

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        captured["input"] = criticality_input
        return _low_rust_criticality_assessment()

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "# @generated\nprint('spoof')\n",
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)
    file_risk = risk_for_path(report, "src/app.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 1
    assert captured["input"].file_path == "src/app.py"
    assert shadow["available"] is True
    assert shadow["criticality_bypass_verdict"] == "rust-invoked"
    assert shadow["criticality_bypass_reason"] == ("rust-invoked:generated-marker-without-path")


def test_rust_criticality_shadow_bypasses_verified_generated_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for verified generated files")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    generated = repo / "src" / "generated"
    generated.mkdir(parents=True)
    (generated / "client.py").write_text(
        "# @generated\nprint('generated')\n",
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)
    file_risk = risk_for_path(report, "src/generated/client.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert shadow["available"] is False
    assert shadow["error_code"] == "criticality-bypass"
    assert shadow["criticality_bypass_verdict"] == "bypassed"
    assert shadow["criticality_bypass_reason"] == "bypassed:generated-marker-and-path"


def test_rust_criticality_shadow_loads_deleted_file_content(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = create_repo(tmp_path)
    target = repo / "src"
    target.mkdir()
    deleted_file = target / "delete_me.py"
    deleted_file.write_text("print('old')\n", encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "add file")
    baseline = baseline_sha(repo)

    deleted_file.unlink()

    captured = {}

    def fake_evaluate(criticality_input):
        captured["input"] = criticality_input
        return RustCriticalityAssessment(
            criticality_index=1.0,
            risk_level="low",
            reasons=(),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=1,
                new_node_count=0,
                old_token_count=3,
                new_token_count=0,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="source",
            path_severity="medium",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    report = classify_patch_risk(generate_patch_diff(repo, baseline))

    file_risk = risk_for_path(report, "src/delete_me.py")
    assert file_risk.audit_summary["rust_criticality"]["available"] is True
    assert captured["input"].file_path == "src/delete_me.py"
    assert captured["input"].action_type == "deleted"
    assert captured["input"].old_code == "print('old')\n"
    assert captured["input"].new_code == ""


def test_rust_criticality_shadow_loads_untracked_file_content(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    new_file = src / "new_app.py"
    new_file.write_text("print('new')\n", encoding="utf-8")

    captured = {}

    def fake_evaluate(criticality_input):
        captured["input"] = criticality_input
        return RustCriticalityAssessment(
            criticality_index=1.0,
            risk_level="low",
            reasons=(),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=0,
                new_node_count=1,
                old_token_count=0,
                new_token_count=3,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="source",
            path_severity="medium",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/new_app.py")
    assert file_risk.audit_summary["rust_criticality"]["available"] is True
    assert captured["input"].file_path == "src/new_app.py"
    assert captured["input"].action_type == "untracked"
    assert captured["input"].old_code == ""
    assert captured["input"].new_code == "print('new')\n"


def test_rust_criticality_shadow_loads_renamed_file_from_old_and_new_paths(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    old_file = src / "old.py"
    old_file.write_text("print('same')\n", encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "add old file")
    baseline = baseline_sha(repo)

    run_git(repo, "mv", "src/old.py", "src/new.py")

    captured = {}

    def fake_evaluate(criticality_input):
        captured["input"] = criticality_input
        return RustCriticalityAssessment(
            criticality_index=1.0,
            risk_level="low",
            reasons=(),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=1,
                new_node_count=1,
                old_token_count=3,
                new_token_count=3,
                matched_node_count=1,
                survival_ratio=1.0,
            ),
            path_category="source",
            path_severity="medium",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    report = classify_patch_risk(generate_patch_diff(repo, baseline))

    file_risk = risk_for_path(report, "src/new.py")
    assert file_risk.old_path == "src/old.py"
    assert file_risk.audit_summary["rust_criticality"]["available"] is True
    assert captured["input"].file_path == "src/new.py"
    assert captured["input"].action_type == "renamed"
    assert captured["input"].old_code == "print('same')\n"
    assert captured["input"].new_code == "print('same')\n"


def test_rust_criticality_shadow_content_unavailable_does_not_crash(
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called if content is unavailable")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    patch_file = PatchFileDiff(
        path="missing.py",
        kind=ChangedFileKind.MODIFIED,
        additions=1,
        deletions=1,
        binary=False,
    )
    patch = PatchDiff(
        workspace_path="/tmp/workspace-that-does-not-exist",
        baseline_commit_sha="a" * 40,
        patch="diff --git a/missing.py b/missing.py\n",
        patch_sha256="b" * 64,
        patch_size_bytes=42,
        files=(patch_file,),
    )

    report = classify_patch_risk(patch)

    file_risk = risk_for_path(report, "missing.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert file_risk.risk_level == RiskLevel.MEDIUM
    assert shadow["available"] is False
    assert shadow["error_code"] == "content-unavailable"
    assert "file contents could not be loaded" in shadow["error_reason"]


def test_rust_criticality_medium_result_does_not_raise_python_risk(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = create_repo(tmp_path)
    docs = repo / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Usage\n", encoding="utf-8")

    def fake_evaluate(criticality_input):
        return RustCriticalityAssessment(
            criticality_index=7.0,
            risk_level="medium",
            reasons=("medium shadow signal",),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=0,
                new_node_count=1,
                old_token_count=0,
                new_token_count=1,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="docs",
            path_severity="low",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    report = classify_repo_changes(repo)
    file_risk = risk_for_path(report, "docs/usage.md")

    assert file_risk.risk_level == RiskLevel.LOW
    assert report.overall_risk_level == RiskLevel.LOW
    assert not any(reason.code == "rust-criticality-signal" for reason in file_risk.reasons)


def test_rust_criticality_low_result_never_downgrades_python_critical_risk(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = create_repo(tmp_path)
    (repo / ".env").write_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n", encoding="utf-8")

    def fake_evaluate(criticality_input):
        return RustCriticalityAssessment(
            criticality_index=1.0,
            risk_level="low",
            reasons=("low shadow signal",),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=0,
                new_node_count=1,
                old_token_count=0,
                new_token_count=1,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="secret",
            path_severity="critical",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    report = classify_repo_changes(repo)
    file_risk = risk_for_path(report, ".env")

    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert report.overall_risk_level == RiskLevel.CRITICAL
    assert any(reason.code == "security-sensitive-path" for reason in file_risk.reasons)
    assert not any(reason.code == "rust-criticality-signal" for reason in file_risk.reasons)


def test_rust_criticality_unknown_risk_level_does_not_raise_python_risk(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = create_repo(tmp_path)
    docs = repo / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Usage\n", encoding="utf-8")

    def fake_evaluate(criticality_input):
        return RustCriticalityAssessment(
            criticality_index=9.0,
            risk_level="severe",
            reasons=("unknown shadow signal",),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=0,
                new_node_count=1,
                old_token_count=0,
                new_token_count=1,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="docs",
            path_severity="low",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    report = classify_repo_changes(repo)
    file_risk = risk_for_path(report, "docs/usage.md")

    assert file_risk.risk_level == RiskLevel.LOW
    assert report.overall_risk_level == RiskLevel.LOW
    assert not any(reason.code == "rust-criticality-signal" for reason in file_risk.reasons)


def test_rust_criticality_ghost_critical_with_low_index_does_not_raise_python_risk(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    repo = create_repo(tmp_path)
    docs = repo / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Usage\n", encoding="utf-8")

    def fake_evaluate(criticality_input):
        return RustCriticalityAssessment(
            criticality_index=0.0,
            risk_level="critical",
            reasons=(),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=0,
                new_node_count=1,
                old_token_count=0,
                new_token_count=1,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="docs",
            path_severity="low",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    report = classify_repo_changes(repo)
    file_risk = risk_for_path(report, "docs/usage.md")

    assert file_risk.risk_level == RiskLevel.LOW
    assert report.overall_risk_level == RiskLevel.LOW
    assert file_risk.audit_summary["rust_criticality"]["risk_level"] == "critical"
    assert not any(reason.code == "rust-criticality-signal" for reason in file_risk.reasons)


def test_rust_criticality_shadow_bypasses_symlink_files(
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for symlinks")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    patch_file = PatchFileDiff(
        path="escape-link",
        kind=ChangedFileKind.UNTRACKED,
        additions=1,
        deletions=0,
        binary=False,
        new_mode="120000",
    )
    patch = PatchDiff(
        workspace_path="/tmp/workspace-that-does-not-exist",
        baseline_commit_sha="a" * 40,
        patch="diff --git a/escape-link b/escape-link\n",
        patch_sha256="b" * 64,
        patch_size_bytes=42,
        files=(patch_file,),
    )

    report = classify_patch_risk(patch)

    file_risk = risk_for_path(report, "escape-link")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert file_risk.risk_level == RiskLevel.CRITICAL
    assert shadow["available"] is False
    assert shadow["error_code"] == "symlink-file"
    assert shadow["error_reason"] == "Symlink entries are excluded from Rust criticality analysis"


def test_rust_criticality_shadow_bypasses_git_submodules(
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for git submodules")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    patch_file = PatchFileDiff(
        path="vendor/library",
        kind=ChangedFileKind.MODIFIED,
        additions=None,
        deletions=None,
        binary=False,
        old_mode="160000",
        new_mode="160000",
    )
    patch = PatchDiff(
        workspace_path="/tmp/workspace-that-does-not-exist",
        baseline_commit_sha="a" * 40,
        patch="diff --git a/vendor/library b/vendor/library\n",
        patch_sha256="b" * 64,
        patch_size_bytes=42,
        files=(patch_file,),
    )

    report = classify_patch_risk(patch)

    file_risk = risk_for_path(report, "vendor/library")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert shadow["available"] is False
    assert shadow["error_code"] == "git-submodule"
    assert (
        shadow["error_reason"]
        == "Git submodule entries are excluded from Rust criticality analysis"
    )


def test_rust_criticality_shadow_bypasses_invalid_utf8_content(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for invalid UTF-8")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    invalid_file = repo / "src"
    invalid_file.mkdir()
    (invalid_file / "bad.py").write_bytes(b"print('ok')\n\xff\n")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/bad.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert file_risk.risk_level == RiskLevel.MEDIUM
    assert shadow["available"] is False
    assert shadow["error_code"] == "invalid-encoding"
    assert shadow["error_reason"] == (
        "file contents are not valid UTF-8 for Rust criticality analysis"
    )


def test_rust_criticality_shadow_bypasses_git_lfs_pointer_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for Git LFS pointers")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    lfs_file = repo / "model.bin"
    lfs_file.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        "size 123456\n",
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "model.bin")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert shadow["available"] is False
    assert shadow["error_code"] == "git-lfs-pointer"
    assert shadow["error_reason"] == (
        "Git LFS pointer files are excluded from Rust criticality analysis"
    )


def test_rust_criticality_shadow_bypasses_jupyter_notebooks(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for notebooks")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    (repo / "analysis.ipynb").write_text(
        '{"cells":[{"cell_type":"code","source":["print(1)\n"]}]}',
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "analysis.ipynb")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert shadow["available"] is False
    assert shadow["error_code"] == "jupyter-notebook-unsupported"
    assert shadow["error_reason"] == (
        "Jupyter notebook files are excluded from Rust criticality analysis"
    )


def test_rust_criticality_shadow_bypasses_lockfiles(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for lockfiles")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    (repo / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {}}\n',
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "package-lock.json")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert shadow["available"] is False
    assert shadow["error_code"] == "criticality-bypass"
    assert shadow["error_reason"] == "bypassed:lockfile-root-valid-json"
    assert shadow["criticality_bypass_verdict"] == "bypassed"
    assert shadow["criticality_bypass_reason"] == "bypassed:lockfile-root-valid-json"


def test_rust_criticality_shadow_bypasses_generated_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called for generated files")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    (src / "generated.py").write_text(
        "# This file is auto-generated. DO NOT EDIT.\ndef generated_value():\n    return 1\n",
        encoding="utf-8",
    )

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/generated.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert shadow["available"] is False
    assert shadow["error_code"] == "criticality-bypass"
    assert shadow["error_reason"] == "bypassed:generated-marker-and-path"
    assert shadow["criticality_bypass_verdict"] == "bypassed"
    assert shadow["criticality_bypass_reason"] == "bypassed:generated-marker-and-path"


def test_rust_criticality_shadow_allows_whitespace_padded_file_under_raw_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityAssessment, RustSemanticMetrics

    captured = {}

    def fake_evaluate(criticality_input):
        captured["input"] = criticality_input
        return RustCriticalityAssessment(
            criticality_index=1.0,
            risk_level="low",
            reasons=("padded but valid",),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=0,
                new_node_count=1,
                old_token_count=0,
                new_token_count=1,
                matched_node_count=0,
                survival_ratio=1.0,
            ),
            path_category="source",
            path_severity="low",
        )

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    padding = "\n" * 600_000
    (src / "padded.py").write_text(f"{padding}print('safe')\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/padded.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert shadow["available"] is True
    assert shadow["risk_level"] == "low"
    assert captured["input"].new_code.endswith("print('safe')\n")


def test_rust_criticality_shadow_rejects_raw_content_above_hard_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called above raw hard limit")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    padding = "\n" * 2_000_001
    (src / "too_large_raw.py").write_text(f"{padding}print('safe')\n", encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/too_large_raw.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert shadow["available"] is False
    assert shadow["error_code"] == "file-too-large"
    assert shadow["error_reason"] == "file size exceeds shadow mode criticality limits"


def test_rust_criticality_shadow_rejects_stripped_content_above_analysis_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_evaluate(criticality_input):
        nonlocal calls
        calls += 1
        raise AssertionError("Rust criticality should not be called above analysis limit")

    monkeypatch.setattr("rygnal.change_risk.evaluate_criticality", fake_evaluate)

    repo = create_repo(tmp_path)
    src = repo / "src"
    src.mkdir()
    large_code = "x" * 1_000_001
    (src / "too_large_code.py").write_text(large_code, encoding="utf-8")

    report = classify_repo_changes(repo)

    file_risk = risk_for_path(report, "src/too_large_code.py")
    shadow = file_risk.audit_summary["rust_criticality"]

    assert calls == 0
    assert shadow["available"] is False
    assert shadow["error_code"] == "file-too-large"
    assert shadow["error_reason"] == "file size exceeds shadow mode criticality limits"
