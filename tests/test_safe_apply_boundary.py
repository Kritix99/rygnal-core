from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import rygnal.safe_apply as safe_apply_module
from rygnal.patch_diff import generate_patch_diff
from rygnal.safe_apply import (
    SafePatchApplyError,
    auto_apply_safe_patch,
)
from tests.test_safe_apply import (
    baseline_sha,
    clone_fixture,
    run_git,
)


def test_auto_apply_rejects_target_head_drift_before_mutation(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_fixture(tmp_path)

    (guarded / "docs" / "usage.md").write_text(
        "After\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        guarded,
        baseline_sha(guarded),
    )

    (trusted / "README.md").write_text(
        "# Drifted\n",
        encoding="utf-8",
    )

    run_git(trusted, "add", ".")
    run_git(
        trusted,
        "commit",
        "-m",
        "drift target",
    )

    with pytest.raises(
        SafePatchApplyError,
        match="HEAD does not match",
    ):
        auto_apply_safe_patch(
            patch,
            trusted,
        )

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"


def test_auto_apply_rejects_patch_digest_mismatch_before_mutation(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_fixture(tmp_path)

    (guarded / "docs" / "usage.md").write_text(
        "After\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        guarded,
        baseline_sha(guarded),
    )

    tampered = replace(
        patch,
        patch_sha256="0" * 64,
    )

    with pytest.raises(
        SafePatchApplyError,
        match="declared SHA-256",
    ):
        auto_apply_safe_patch(
            tampered,
            trusted,
        )

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"

    assert (
        run_git(
            trusted,
            "status",
            "--porcelain",
            "--untracked-files=all",
        )
        == ""
    )


def test_post_apply_verification_failure_rolls_back_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guarded, trusted = clone_fixture(tmp_path)

    (guarded / "docs" / "usage.md").write_text(
        "After\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        guarded,
        baseline_sha(guarded),
    )

    real_generate = safe_apply_module.generate_patch_diff

    def mismatched_generate(
        path: str | Path,
        baseline_commit_sha: str,
    ):
        generated = real_generate(
            path,
            baseline_commit_sha,
        )

        return replace(
            generated,
            patch_sha256="f" * 64,
        )

    monkeypatch.setattr(
        safe_apply_module,
        "generate_patch_diff",
        mismatched_generate,
    )

    with pytest.raises(
        SafePatchApplyError,
        match="rolled back safely",
    ):
        auto_apply_safe_patch(
            patch,
            trusted,
        )

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"

    assert (
        run_git(
            trusted,
            "status",
            "--porcelain",
            "--untracked-files=all",
        )
        == ""
    )


def test_audit_failure_after_apply_rolls_back_target(
    tmp_path: Path,
) -> None:
    guarded, trusted = clone_fixture(tmp_path)

    (guarded / "docs" / "usage.md").write_text(
        "After\n",
        encoding="utf-8",
    )

    patch = generate_patch_diff(
        guarded,
        baseline_sha(guarded),
    )

    class FailingAuditLogger:
        def log_decision(
            self,
            *args: object,
            **kwargs: object,
        ) -> None:
            raise OSError("forced audit persistence failure")

    with pytest.raises(
        SafePatchApplyError,
        match="rolled back safely",
    ):
        auto_apply_safe_patch(
            patch,
            trusted,
            logger=FailingAuditLogger(),  # type: ignore[arg-type]
        )

    assert (trusted / "docs" / "usage.md").read_text(encoding="utf-8") == "Before\n"

    assert (
        run_git(
            trusted,
            "status",
            "--porcelain",
            "--untracked-files=all",
        )
        == ""
    )
