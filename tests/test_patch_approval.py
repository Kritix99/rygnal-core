import shutil
import subprocess
from datetime import UTC
from pathlib import Path

import pytest

from rygnal.approval_receipt import (
    APPROVAL_RECEIPT_HASH_KEY,
    APPROVAL_RECEIPT_SCHEMA_VERSION_KEY,
    ReceiptStatus,
    verify_approval_receipt,
)
from rygnal.audit_logger import AuditLogger
from rygnal.change_risk import ChangeRiskReason, classify_patch_risk
from rygnal.patch_approval import (
    PatchApprovalError,
    approve_patch_request,
    assert_patch_approval_granted,
    create_patch_approval_request,
    evaluate_patch_approval_requirement,
    reject_patch_request,
    requires_patch_approval,
    write_patch_approval_decision_audit_event,
    write_patch_approval_request_audit_event,
)
from rygnal.patch_diff import generate_patch_diff
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


def create_repo(path: Path) -> Path:
    path.mkdir()

    run_git(path, "init")
    run_git(path, "config", "user.email", "test@example.com")
    run_git(path, "config", "user.name", "Test User")

    (path / "README.md").write_text("# Project\n", encoding="utf-8")
    docs = path / "docs"
    docs.mkdir()
    (docs / "usage.md").write_text("Before\n", encoding="utf-8")
    run_git(path, "add", ".")
    run_git(path, "commit", "-m", "baseline")

    return path


def clone_fixture(tmp_path: Path) -> tuple[Path, Path]:
    baseline = create_repo(tmp_path / "baseline")
    guarded = tmp_path / "guarded"
    trusted = tmp_path / "trusted"

    shutil.copytree(baseline, guarded)
    shutil.copytree(baseline, trusted)

    return guarded, trusted


def baseline_sha(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD")


def test_source_patch_requires_approval_and_does_not_apply(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")

    assert requires_patch_approval(patch) is True
    assert request.target == patch.patch_sha256
    assert request.reason == "Risky guarded workspace patch requires approval before apply."
    assert not (trusted / "src" / "app.py").exists()


def test_dependency_patch_requires_approval(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    (guarded / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    requirement = evaluate_patch_approval_requirement(patch)
    request = create_patch_approval_request(patch, requested_by="test_user")

    assert requirement.required is True
    assert any(reason.code == "dependency-file-change" for reason in requirement.reasons)
    assert request.severity == "high"


def test_networked_resolver_validation_reason_requires_approval(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "usage.md").write_text("After\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    risk_report = classify_patch_risk(
        patch,
        validation_reasons=(
            ChangeRiskReason(
                code="networked-resolver-activity",
                risk_level=RiskLevel.HIGH,
                reason="Dependency resolver contacted a network service.",
                evidence=(("resolver", "pip"),),
            ),
        ),
    )
    requirement = evaluate_patch_approval_requirement(patch, risk_report=risk_report)

    assert requirement.required is True
    assert any(reason.code == "overall-risk" for reason in requirement.reasons)


def test_blocked_patch_cannot_request_approval(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    (guarded / ".env").write_text("TOKEN=example\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))

    with pytest.raises(PatchApprovalError, match="Blocked"):
        create_patch_approval_request(patch, requested_by="test_user")


def test_low_risk_documentation_patch_does_not_require_approval(
    tmp_path: Path,
) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    (guarded / "docs" / "usage.md").write_text("After\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))

    assert requires_patch_approval(patch) is False
    with pytest.raises(PatchApprovalError, match="does not require"):
        create_patch_approval_request(patch, requested_by="test_user")


def test_approval_request_grant_and_rejection_are_audited(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(
        patch,
        requested_by="test_user",
        agent_id="test_agent",
        environment="test",
        trace_id="trace_approval",
    )
    approved = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )
    rejected = reject_patch_request(
        request,
        decided_by="reviewer",
        reason="reject because token=abcdef123456",
        patch_sha256=patch.patch_sha256,
    )

    logger = AuditLogger(tmp_path / "audit.jsonl")
    write_patch_approval_request_audit_event(logger, request)
    write_patch_approval_decision_audit_event(logger, request, approved)
    write_patch_approval_decision_audit_event(logger, request, rejected)

    events = logger.read_events()
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")

    assert [event.decision for event in events] == ["require_approval", "allow", "block"]
    assert logger.verify_integrity() is True
    assert "token=abcdef123456" not in audit_text


def test_rejection_keeps_trusted_repo_unchanged(tmp_path: Path) -> None:
    guarded, trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")
    decision = reject_patch_request(request, decided_by="reviewer")

    assert decision.approved is False
    assert not (trusted / "src" / "app.py").exists()
    with pytest.raises(PatchApprovalError, match="not granted"):
        assert_patch_approval_granted(request, decision, patch)


def test_approval_is_bound_to_patch_digest(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")

    with pytest.raises(PatchApprovalError, match="digest mismatch"):
        approve_patch_request(request, decided_by="reviewer", patch_sha256="bad-digest")

    approved = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )
    assert_patch_approval_granted(request, approved, patch)


def test_approved_decision_carries_request_baseline_binding(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")
    approved = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    assert approved.metadata["patch_sha256"] == patch.patch_sha256
    assert approved.metadata["baseline_commit_sha"] == patch.baseline_commit_sha
    assert approved.metadata[APPROVAL_RECEIPT_HASH_KEY]
    assert verify_approval_receipt(request, approved) == ReceiptStatus.VALID


def test_stale_patch_approval_is_rejected(tmp_path: Path) -> None:
    from datetime import datetime, timedelta

    guarded, _trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")

    stale_created_at = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    stale_request = request.model_copy(update={"created_at": stale_created_at})
    approved = approve_patch_request(
        stale_request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    with pytest.raises(PatchApprovalError, match="stale|expired"):
        assert_patch_approval_granted(stale_request, approved, patch)


def test_approval_request_baseline_mismatch_is_rejected(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")
    mismatched_request = request.model_copy(
        update={
            "metadata": {
                **request.metadata,
                "baseline_commit_sha": "deadbeef",
            }
        }
    )
    approved = approve_patch_request(
        mismatched_request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    with pytest.raises(PatchApprovalError, match="baseline"):
        assert_patch_approval_granted(mismatched_request, approved, patch)


def test_malformed_pending_approval_decision_is_rejected_as_invalid_transition(
    tmp_path: Path,
) -> None:
    from rygnal.models import ApprovalDecision, ApprovalStatus, utc_now_iso

    guarded, _trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")
    malformed_decision = ApprovalDecision(
        approval_id=request.approval_id,
        status=ApprovalStatus.PENDING,
        approved=True,
        decided_by="reviewer",
        decided_at=utc_now_iso(),
        reason="Malformed approval.",
        metadata={
            "patch_sha256": patch.patch_sha256,
            "baseline_commit_sha": patch.baseline_commit_sha,
        },
    )

    with pytest.raises(PatchApprovalError, match="Invalid approval state transition"):
        assert_patch_approval_granted(request, malformed_decision, patch)


def test_patch_approval_receipt_tampering_is_rejected(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")
    approved = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    tampered = approved.model_copy(update={"reason": "Tampered approval reason."})

    assert verify_approval_receipt(request, approved) == ReceiptStatus.VALID
    assert verify_approval_receipt(request, tampered) == ReceiptStatus.TAMPERED

    with pytest.raises(PatchApprovalError, match="receipt hash"):
        assert_patch_approval_granted(request, tampered, patch)


def test_rejected_patch_decision_does_not_get_receipt_hash(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")
    rejected = reject_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    assert rejected.approved is False
    assert APPROVAL_RECEIPT_HASH_KEY not in rejected.metadata


def test_approved_patch_decision_without_receipt_is_rejected(tmp_path: Path) -> None:
    guarded, _trusted = clone_fixture(tmp_path)
    src = guarded / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')\n", encoding="utf-8")

    patch = generate_patch_diff(guarded, baseline_sha(guarded))
    request = create_patch_approval_request(patch, requested_by="test_user")
    approved = approve_patch_request(
        request,
        decided_by="reviewer",
        patch_sha256=patch.patch_sha256,
    )

    legacy_metadata = {
        key: value
        for key, value in approved.metadata.items()
        if key
        not in {
            APPROVAL_RECEIPT_HASH_KEY,
            APPROVAL_RECEIPT_SCHEMA_VERSION_KEY,
        }
    }
    legacy_approved = approved.model_copy(update={"metadata": legacy_metadata})

    assert legacy_approved.approved is True
    assert verify_approval_receipt(request, legacy_approved) == ReceiptStatus.MISSING

    with pytest.raises(PatchApprovalError, match="receipt hash"):
        assert_patch_approval_granted(request, legacy_approved, patch)
