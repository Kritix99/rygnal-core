"""Human-context and semantic subjective risk enrichment for guarded patches.

This module collects Git-backed human context from the guarded workspace and
delegates deterministic subjective scoring to the optional Rust kernel. It does
not replace the existing deterministic patch-risk classifier; it produces
additional validation reasons that can be fed into that classifier.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from rygnal.change_risk import ChangeRiskReason, FileRiskClassification
from rygnal.changed_files import ChangedFileKind, normalize_repo_relative_path
from rygnal.patch_diff import PatchFileDiff
from rygnal.risk_engine import RiskLevel
from rygnal.rust_kernel import (
    RustHumanContext,
    RustKernelError,
    RustKernelUnavailableError,
    RustSubjectiveRiskAssessment,
    RustSubjectiveRiskInput,
    evaluate_subjective_risk,
)

SECONDS_PER_DAY = 86_400.0
BURST_WINDOW_DAYS = 7.0
BURST_MIN_COMMITS = 3
DEFAULT_UNKNOWN_HISTORY_DAYS = 3_650.0
DEFAULT_UNKNOWN_OWNERSHIP_RATIO = 0.5
MAX_COLLECTED_SOURCE_BYTES = 512 * 1024

DOC_EXTENSIONS = {
    ".adoc",
    ".md",
    ".rst",
    ".txt",
}

DOC_FILE_NAMES = {
    "changelog",
    "code_of_conduct",
    "contributing",
    "license",
    "readme",
    "security",
}

DOC_PATH_SEGMENTS = {
    "doc",
    "docs",
    "documentation",
}

BOT_AUTHOR_MARKERS = (
    "[bot]",
    "bot",
    "github-actions",
    "dependabot",
    "renovate",
    "copilot",
    "automation",
    "agent",
)

EXPLICIT_LOCK_MARKERS = (
    "rygnal:lock",
    "@rygnal-lock",
    "RYGNAL_LOCK",
    "do-not-ai-edit",
    "DO NOT AI EDIT",
    "DO NOT AUTONOMOUSLY EDIT",
)


class SubjectiveRiskCollectionError(RuntimeError):
    """Raised when subjective-risk context cannot be collected safely."""


@dataclass(frozen=True)
class SubjectiveRiskSnapshot:
    """Collected source and human context for one changed file."""

    file_path: str
    action_type: str
    system_risk: float
    old_code: str
    new_code: str
    human_context: RustHumanContext


@dataclass(frozen=True)
class SubjectiveRiskFileAssessment:
    """Subjective-risk result for one changed file."""

    file_path: str
    assessment: RustSubjectiveRiskAssessment


def collect_subjective_risk_input(
    *,
    workspace_path: str | Path,
    baseline_commit_sha: str,
    file_diff: PatchFileDiff,
    system_risk: float,
    now: float | None = None,
    explicitly_locked_paths: Iterable[str] = (),
) -> RustSubjectiveRiskInput:
    """Collect old/new code and human context for a changed guarded file."""

    workspace = Path(workspace_path).resolve()
    if not workspace.exists() or not workspace.is_dir():
        raise SubjectiveRiskCollectionError(f"Guarded workspace does not exist: {workspace}")

    path = normalize_repo_relative_path(file_diff.path)
    old_path = normalize_repo_relative_path(file_diff.old_path or file_diff.path)
    action_type = file_diff.kind.value
    current_time = time.time() if now is None else now

    old_code = _read_old_code(
        workspace=workspace,
        baseline_commit_sha=baseline_commit_sha,
        path=old_path,
        kind=file_diff.kind,
    )
    new_code = _read_new_code(workspace=workspace, path=path, kind=file_diff.kind)

    days_since_edit = _days_since_last_edit(
        workspace=workspace,
        baseline_commit_sha=baseline_commit_sha,
        path=old_path,
        now=current_time,
    )
    days_since_burst = _days_since_recent_burst(
        workspace=workspace,
        baseline_commit_sha=baseline_commit_sha,
        path=old_path,
        now=current_time,
        fallback_days_since_edit=days_since_edit,
    )
    line_ownership_ratio = _line_ownership_ratio(
        workspace=workspace,
        baseline_commit_sha=baseline_commit_sha,
        path=old_path,
    )
    is_explicitly_locked = _is_explicitly_locked(
        path=path,
        old_code=old_code,
        new_code=new_code,
        explicitly_locked_paths=explicitly_locked_paths,
    )

    return RustSubjectiveRiskInput(
        file_path=path,
        action_type=action_type,
        system_risk=system_risk,
        old_code=old_code,
        new_code=new_code,
        human_context=RustHumanContext(
            days_since_edit=days_since_edit,
            days_since_burst=days_since_burst,
            line_ownership_ratio=line_ownership_ratio,
            is_explicitly_locked=is_explicitly_locked,
        ),
    )


def evaluate_subjective_patch_file(
    *,
    workspace_path: str | Path,
    baseline_commit_sha: str,
    file_diff: PatchFileDiff,
    system_risk: float,
    now: float | None = None,
    explicitly_locked_paths: Iterable[str] = (),
) -> SubjectiveRiskFileAssessment | None:
    """Collect and evaluate subjective risk for one file.

    Returns None when the optional Rust kernel is unavailable so guarded runs can
    still operate in environments that have not installed the extension.
    """

    risk_input = collect_subjective_risk_input(
        workspace_path=workspace_path,
        baseline_commit_sha=baseline_commit_sha,
        file_diff=file_diff,
        system_risk=system_risk,
        now=now,
        explicitly_locked_paths=explicitly_locked_paths,
    )

    try:
        assessment = evaluate_subjective_risk(risk_input)
    except RustKernelUnavailableError:
        return None
    except RustKernelError as exc:
        raise SubjectiveRiskCollectionError(str(exc)) from exc

    return SubjectiveRiskFileAssessment(file_path=risk_input.file_path, assessment=assessment)


def locked_file_change_to_reason(file_path: str) -> ChangeRiskReason:
    """Return a critical reason for an explicit Rygnal locked-file edit.

    This is intentionally independent of the optional Rust subjective kernel.
    A user-authored lock marker is a deterministic safety boundary and must
    fail closed even when semantic analysis is unavailable.
    """

    return ChangeRiskReason(
        code="subjective-human-context-risk",
        risk_level=RiskLevel.CRITICAL,
        reason=(f"Explicit Rygnal lock marker raised guarded patch risk for {file_path}."),
        evidence=(
            ("path", file_path),
            ("judgment", "block"),
            ("total_criticality", 10.0),
            ("human_multiplier", 1.0),
            ("destruction_penalty", 0.0),
            ("semantic_survival_ratio", 1.0),
            ("explicitly_locked", True),
            ("fallback", "deterministic-lock-marker"),
        ),
    )


def subjective_assessment_to_reason(
    result: SubjectiveRiskFileAssessment,
    *,
    critical_block: bool = True,
) -> ChangeRiskReason | None:
    """Convert subjective Rust assessment into an existing change-risk reason.

    Standalone callers can preserve a Rust ``block`` judgment as CRITICAL.
    Guarded-run integration normally treats subjective block as HIGH so the
    existing approval flow remains stable, except for explicit locked-file
    evidence where CRITICAL blocking is intentional.
    """

    judgment = result.assessment.judgment

    if judgment == "allow":
        return None

    risk_level = RiskLevel.CRITICAL if judgment == "block" and critical_block else RiskLevel.HIGH

    return ChangeRiskReason(
        code="subjective-human-context-risk",
        risk_level=risk_level,
        reason=(
            "Human-context and semantic-survival analysis raised guarded patch risk "
            f"for {result.file_path}."
        ),
        evidence=(
            ("path", result.file_path),
            ("judgment", judgment),
            ("total_criticality", round(result.assessment.total_criticality, 4)),
            ("human_multiplier", round(result.assessment.human_multiplier, 4)),
            ("destruction_penalty", round(result.assessment.destruction_penalty, 4)),
            (
                "semantic_survival_ratio",
                round(result.assessment.semantic_metrics.survival_ratio, 4),
            ),
        ),
    )


def collect_subjective_patch_reasons(
    *,
    workspace_path: str | Path,
    baseline_commit_sha: str,
    files: Iterable[PatchFileDiff],
    system_risk_by_path: dict[str, float],
    file_risk_by_path: dict[str, FileRiskClassification] | None = None,
    now: float | None = None,
    explicitly_locked_paths: Iterable[str] = (),
) -> tuple[ChangeRiskReason, ...]:
    """Evaluate all changed files and return report-level subjective reasons.

    Explicit Rygnal lock markers are deterministic safety boundaries. They must
    block even when the optional Rust subjective-risk kernel is unavailable.
    """

    reasons: list[ChangeRiskReason] = []

    for file_diff in files:
        normalized_path = normalize_repo_relative_path(file_diff.path)
        system_risk = system_risk_by_path.get(normalized_path, 0.0)

        risk_input = collect_subjective_risk_input(
            workspace_path=workspace_path,
            baseline_commit_sha=baseline_commit_sha,
            file_diff=file_diff,
            system_risk=system_risk,
            now=now,
            explicitly_locked_paths=explicitly_locked_paths,
        )

        if risk_input.human_context.is_explicitly_locked:
            reasons.append(locked_file_change_to_reason(risk_input.file_path))
            continue

        file_risk = (file_risk_by_path or {}).get(normalized_path)
        if file_risk is not None and file_risk.risk_level == RiskLevel.LOW:
            continue

        try:
            assessment = evaluate_subjective_risk(risk_input)
        except RustKernelUnavailableError:
            continue
        except RustKernelError as exc:
            raise SubjectiveRiskCollectionError(str(exc)) from exc

        result = SubjectiveRiskFileAssessment(
            file_path=risk_input.file_path,
            assessment=assessment,
        )
        reason = subjective_assessment_to_reason(result, critical_block=False)

        if reason is not None:
            reasons.append(reason)

    return tuple(reasons)


def _is_low_risk_documentation_change(
    path: str,
    file_risk: FileRiskClassification | None,
) -> bool:
    if file_risk is None or file_risk.risk_level != RiskLevel.LOW:
        return False

    lower_path = path.lower()
    path_obj = Path(lower_path)
    suffix = path_obj.suffix
    stem = path_obj.stem
    segments = set(path_obj.parts)

    return suffix in DOC_EXTENSIONS or stem in DOC_FILE_NAMES or bool(segments & DOC_PATH_SEGMENTS)


def _read_old_code(
    *,
    workspace: Path,
    baseline_commit_sha: str,
    path: str,
    kind: ChangedFileKind,
) -> str:
    if kind in {ChangedFileKind.ADDED, ChangedFileKind.UNTRACKED}:
        return ""

    output = _run_git(
        ["show", f"{baseline_commit_sha}:{_safe_git_object_path(path)}"],
        cwd=workspace,
        allow_missing=kind == ChangedFileKind.DELETED,
    )

    return _decode_limited(output)


def _read_new_code(*, workspace: Path, path: str, kind: ChangedFileKind) -> str:
    if kind == ChangedFileKind.DELETED:
        return ""

    file_path = _safe_workspace_file_path(workspace, path)

    if not file_path.exists():
        raise SubjectiveRiskCollectionError(f"Changed file does not exist in workspace: {path}")
    if not file_path.is_file():
        raise SubjectiveRiskCollectionError(f"Changed path is not a regular file: {path}")

    return _decode_limited(file_path.read_bytes())


def _days_since_last_edit(
    *,
    workspace: Path,
    baseline_commit_sha: str,
    path: str,
    now: float,
) -> float:
    output = _run_git(
        ["log", "-1", "--format=%ct", baseline_commit_sha, "--", path],
        cwd=workspace,
        allow_missing=True,
    ).strip()

    if not output:
        return DEFAULT_UNKNOWN_HISTORY_DAYS

    try:
        timestamp = float(output)
    except ValueError:
        return DEFAULT_UNKNOWN_HISTORY_DAYS

    return _days_since(timestamp, now)


def _days_since_recent_burst(
    *,
    workspace: Path,
    baseline_commit_sha: str,
    path: str,
    now: float,
    fallback_days_since_edit: float,
) -> float:
    output = _run_git(
        ["log", "--format=%ct", "--max-count=20", baseline_commit_sha, "--", path],
        cwd=workspace,
        allow_missing=True,
    )

    timestamps: list[float] = []
    for line in output.splitlines():
        try:
            timestamps.append(float(line.strip()))
        except ValueError:
            continue

    if len(timestamps) < BURST_MIN_COMMITS:
        return fallback_days_since_edit

    burst_window_seconds = BURST_WINDOW_DAYS * SECONDS_PER_DAY

    for index in range(0, len(timestamps) - BURST_MIN_COMMITS + 1):
        newest = timestamps[index]
        oldest_in_window = timestamps[index + BURST_MIN_COMMITS - 1]
        if newest - oldest_in_window <= burst_window_seconds:
            return _days_since(newest, now)

    return fallback_days_since_edit


def _line_ownership_ratio(
    *,
    workspace: Path,
    baseline_commit_sha: str,
    path: str,
) -> float:
    output = _run_git(
        ["blame", "--line-porcelain", baseline_commit_sha, "--", path],
        cwd=workspace,
        allow_missing=True,
    )

    authors: list[str] = []
    for line in output.splitlines():
        if line.startswith(b"author "):
            authors.append(_decode_git_output(line.removeprefix(b"author ")).strip())

    if not authors:
        return DEFAULT_UNKNOWN_OWNERSHIP_RATIO

    human_lines = sum(1 for author in authors if _is_human_author(author))
    return max(0.0, min(1.0, human_lines / len(authors)))


def _is_explicitly_locked(
    *,
    path: str,
    old_code: str,
    new_code: str,
    explicitly_locked_paths: Iterable[str],
) -> bool:
    locked_paths = {normalize_repo_relative_path(item) for item in explicitly_locked_paths}

    if path in locked_paths:
        return True

    combined = f"{old_code}\n{new_code}"

    return any(marker in combined for marker in EXPLICIT_LOCK_MARKERS)


def _is_human_author(author: str) -> bool:
    normalized = author.strip().lower()

    if not normalized:
        return False

    return not any(marker in normalized for marker in BOT_AUTHOR_MARKERS)


def _days_since(timestamp: float, now: float) -> float:
    if timestamp > now:
        return 0.0

    return max(0.0, (now - timestamp) / SECONDS_PER_DAY)


def _safe_workspace_file_path(workspace: Path, path: str) -> Path:
    normalized_path = normalize_repo_relative_path(path)
    candidate = (workspace / normalized_path).resolve()

    if candidate != workspace and workspace not in candidate.parents:
        raise SubjectiveRiskCollectionError(f"Changed file escapes workspace: {path}")

    return candidate


def _safe_git_object_path(path: str) -> str:
    normalized_path = normalize_repo_relative_path(path)

    if ":" in normalized_path or "\x00" in normalized_path:
        raise SubjectiveRiskCollectionError(f"Unsafe Git object path: {path}")

    return normalized_path


def _decode_limited(raw: bytes) -> str:
    if len(raw) > MAX_COLLECTED_SOURCE_BYTES:
        raw = raw[:MAX_COLLECTED_SOURCE_BYTES]

    return _decode_git_output(raw)


def _run_git(
    args: list[str],
    *,
    cwd: Path,
    allow_missing: bool = False,
) -> bytes:
    result = subprocess.run(  # nosec B603
        [_git_executable(), *args],
        cwd=cwd,
        check=False,
        capture_output=True,
    )

    if result.returncode != 0:
        if allow_missing:
            return b""

        stderr = _decode_git_output(result.stderr).strip()
        raise SubjectiveRiskCollectionError(f"Git command failed: git {' '.join(args)}: {stderr}")

    return result.stdout


def _git_executable() -> str:
    git_path = shutil.which("git")

    if git_path is None:
        raise SubjectiveRiskCollectionError("Git executable was not found on PATH.")

    return git_path


def _decode_git_output(output: bytes) -> str:
    return output.decode("utf-8", errors="surrogateescape")


__all__ = [
    "SubjectiveRiskCollectionError",
    "SubjectiveRiskFileAssessment",
    "SubjectiveRiskSnapshot",
    "collect_subjective_patch_reasons",
    "collect_subjective_risk_input",
    "evaluate_subjective_patch_file",
    "locked_file_change_to_reason",
    "subjective_assessment_to_reason",
]
