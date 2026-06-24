from __future__ import annotations

import subprocess  # nosec B404
from pathlib import Path

import pytest

from rygnal.change_risk import FileRiskClassification
from rygnal.changed_files import ChangedFileKind
from rygnal.patch_diff import PatchFileDiff
from rygnal.risk_engine import RiskLevel
from rygnal.rust_kernel import (
    RustSemanticMetrics,
    RustSubjectiveRiskAssessment,
)
from rygnal.subjective_risk import (
    DEFAULT_UNKNOWN_OWNERSHIP_RATIO,
    SubjectiveRiskCollectionError,
    SubjectiveRiskFileAssessment,
    collect_subjective_patch_reasons,
    collect_subjective_risk_input,
    subjective_assessment_to_reason,
)

SECONDS_PER_DAY = 86_400.0


def test_collect_subjective_risk_input_reads_old_new_and_human_context(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    old_path = repo / "src" / "service.py"
    old_path.parent.mkdir()
    old_path.write_text(
        "def important_rule():\n    threshold = 3\n    return threshold\n",
        encoding="utf-8",
    )
    baseline = _commit_all(repo, "initial human service", author_name="Human Developer")
    now = _commit_timestamp(repo, baseline) + (2 * SECONDS_PER_DAY)

    old_path.write_text(
        "def important_rule():\n    threshold = 4\n    return threshold\n",
        encoding="utf-8",
    )

    risk_input = collect_subjective_risk_input(
        workspace_path=repo,
        baseline_commit_sha=baseline,
        file_diff=PatchFileDiff(
            path="src/service.py",
            kind=ChangedFileKind.MODIFIED,
            additions=1,
            deletions=1,
        ),
        system_risk=6.0,
        now=now,
    )

    assert risk_input.file_path == "src/service.py"
    assert risk_input.action_type == "modified"
    assert "threshold = 3" in risk_input.old_code
    assert "threshold = 4" in risk_input.new_code
    assert 1.99 <= risk_input.human_context.days_since_edit <= 2.01
    assert 1.99 <= risk_input.human_context.days_since_burst <= 2.01
    assert risk_input.human_context.line_ownership_ratio == 1.0
    assert risk_input.human_context.is_explicitly_locked is False


def test_collect_subjective_risk_input_detects_lock_marker(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    source = repo / "src" / "payment.py"
    source.parent.mkdir()
    source.write_text(
        "# rygnal:lock\ndef charge():\n    return True\n",
        encoding="utf-8",
    )
    baseline = _commit_all(repo, "locked payment code")
    source.write_text(
        "# rygnal:lock\ndef charge():\n    return False\n",
        encoding="utf-8",
    )

    risk_input = collect_subjective_risk_input(
        workspace_path=repo,
        baseline_commit_sha=baseline,
        file_diff=PatchFileDiff(
            path="src/payment.py",
            kind=ChangedFileKind.MODIFIED,
            additions=1,
            deletions=1,
        ),
        system_risk=1.0,
        now=_commit_timestamp(repo, baseline),
    )

    assert risk_input.human_context.is_explicitly_locked is True


def test_collect_subjective_risk_input_handles_deleted_file(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    source = repo / "src" / "legacy.py"
    source.parent.mkdir()
    source.write_text("def legacy():\n    return True\n", encoding="utf-8")
    baseline = _commit_all(repo, "legacy code")

    source.unlink()

    risk_input = collect_subjective_risk_input(
        workspace_path=repo,
        baseline_commit_sha=baseline,
        file_diff=PatchFileDiff(
            path="src/legacy.py",
            kind=ChangedFileKind.DELETED,
            additions=0,
            deletions=2,
        ),
        system_risk=7.0,
        now=_commit_timestamp(repo, baseline),
    )

    assert "def legacy" in risk_input.old_code
    assert risk_input.new_code == ""
    assert risk_input.action_type == "deleted"


def test_collect_subjective_risk_input_uses_unknown_ownership_for_empty_blame(
    tmp_path: Path,
) -> None:
    repo = _init_repo(tmp_path)
    new_file = repo / "src" / "new_service.py"
    new_file.parent.mkdir()
    baseline = _commit_all(repo, "empty baseline")
    new_file.write_text("def created():\n    return True\n", encoding="utf-8")

    risk_input = collect_subjective_risk_input(
        workspace_path=repo,
        baseline_commit_sha=baseline,
        file_diff=PatchFileDiff(
            path="src/new_service.py",
            kind=ChangedFileKind.ADDED,
            additions=2,
            deletions=0,
        ),
        system_risk=2.0,
        now=_commit_timestamp(repo, baseline),
    )

    assert risk_input.old_code == ""
    assert "def created" in risk_input.new_code
    assert risk_input.human_context.line_ownership_ratio == DEFAULT_UNKNOWN_OWNERSHIP_RATIO


def test_collect_subjective_risk_input_rejects_missing_modified_file(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    baseline = _commit_all(repo, "empty baseline")

    with pytest.raises(SubjectiveRiskCollectionError, match="does not exist"):
        collect_subjective_risk_input(
            workspace_path=repo,
            baseline_commit_sha=baseline,
            file_diff=PatchFileDiff(
                path="src/missing.py",
                kind=ChangedFileKind.MODIFIED,
                additions=1,
                deletions=1,
            ),
            system_risk=2.0,
            now=_commit_timestamp(repo, baseline),
        )


def test_collect_subjective_patch_reasons_uses_normalized_path_for_low_risk_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _init_repo(tmp_path)
    source = repo / "src" / "service.py"
    source.parent.mkdir()
    source.write_text("def service():\n    return 1\n", encoding="utf-8")
    baseline = _commit_all(repo, "initial service")

    source.write_text("def service():\n    return 2\n", encoding="utf-8")

    def fail_evaluate_subjective_risk(_risk_input: object) -> object:
        raise AssertionError("subjective evaluation should be skipped for normalized low-risk file")

    monkeypatch.setattr(
        "rygnal.subjective_risk.evaluate_subjective_risk",
        fail_evaluate_subjective_risk,
    )

    reasons = collect_subjective_patch_reasons(
        workspace_path=repo,
        baseline_commit_sha=baseline,
        files=(
            PatchFileDiff(
                path="./src/service.py",
                kind=ChangedFileKind.MODIFIED,
                additions=1,
                deletions=1,
            ),
        ),
        system_risk_by_path={"src/service.py": 9.0},
        file_risk_by_path={
            "src/service.py": FileRiskClassification(
                path="src/service.py",
                kind=ChangedFileKind.MODIFIED,
                risk_level=RiskLevel.LOW,
                reasons=(),
            )
        },
        now=_commit_timestamp(repo, baseline),
    )

    assert reasons == ()


def test_subjective_assessment_to_reason_returns_none_for_allow() -> None:
    result = SubjectiveRiskFileAssessment(
        file_path="src/service.py",
        assessment=_assessment(judgment="allow", total_criticality=2.0),
    )

    assert subjective_assessment_to_reason(result) is None


def test_subjective_assessment_to_reason_maps_approval_and_block() -> None:
    approval_result = SubjectiveRiskFileAssessment(
        file_path="src/service.py",
        assessment=_assessment(judgment="approval_required", total_criticality=5.0),
    )
    block_result = SubjectiveRiskFileAssessment(
        file_path="src/payment.py",
        assessment=_assessment(judgment="block", total_criticality=10.0),
    )

    approval_reason = subjective_assessment_to_reason(approval_result)
    block_reason = subjective_assessment_to_reason(block_result)

    assert approval_reason is not None
    assert approval_reason.code == "subjective-human-context-risk"
    assert approval_reason.risk_level == RiskLevel.HIGH
    assert dict(approval_reason.evidence)["judgment"] == "approval_required"

    assert block_reason is not None
    assert block_reason.risk_level == RiskLevel.CRITICAL
    assert dict(block_reason.evidence)["path"] == "src/payment.py"


def _assessment(*, judgment: str, total_criticality: float) -> RustSubjectiveRiskAssessment:
    return RustSubjectiveRiskAssessment(
        total_criticality=total_criticality,
        judgment=judgment,
        reasons=("reason",),
        human_multiplier=1.0,
        destruction_penalty=1.0,
        semantic_metrics=RustSemanticMetrics(
            old_node_count=1,
            new_node_count=1,
            old_token_count=1,
            new_token_count=1,
            matched_node_count=0,
            survival_ratio=0.0,
        ),
    )


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "human@example.com")
    _git(repo, "config", "user.name", "Human Developer")
    return repo


def _commit_all(repo: Path, message: str, *, author_name: str = "Human Developer") -> str:
    _git(repo, "add", ".")
    _git(
        repo,
        "-c",
        f"user.name={author_name}",
        "-c",
        "user.email=human@example.com",
        "commit",
        "--allow-empty",
        "-m",
        message,
    )
    return _git(repo, "rev-parse", "HEAD").strip()


def _commit_timestamp(repo: Path, commit_sha: str) -> float:
    return float(_git(repo, "show", "-s", "--format=%ct", commit_sha).strip())


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(  # nosec B603
        ["git", *args],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout
