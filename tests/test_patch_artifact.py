from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from rygnal.change_risk import classify_patch_risk
from rygnal.patch_approval import create_patch_approval_request
from rygnal.patch_artifact import (
    PatchArtifactExpiredError,
    PatchArtifactStore,
    PatchArtifactTamperedError,
    bind_artifact_to_approval,
)
from rygnal.patch_diff import generate_patch_diff


def git(repo: Path, *args: str) -> str:
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
    git(path, "init")
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "user.name", "Test User")
    (path / "README.md").write_text("before\n", encoding="utf-8")
    git(path, "add", ".")
    git(path, "commit", "-m", "baseline")
    return path.resolve()


def create_pending_artifact(
    tmp_path: Path,
    *,
    ttl_seconds: int = 3600,
):
    trusted = create_repo(tmp_path / "trusted")
    workspace = tmp_path / "workspace"
    subprocess.run(
        ["git", "clone", "--quiet", trusted.as_posix(), workspace.as_posix()],
        check=True,
    )

    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "changed"\n',
        encoding="utf-8",
    )

    baseline = git(workspace, "rev-parse", "HEAD")
    patch = generate_patch_diff(workspace, baseline)
    risk = classify_patch_risk(patch)
    approval = create_patch_approval_request(
        patch,
        risk_report=risk,
        requested_by="tester",
        agent_id="agent",
        environment="test",
        trace_id="trace-artifact",
    )

    store = PatchArtifactStore(tmp_path / "artifacts")
    artifact = store.persist(
        patch_diff=patch,
        run_id="run-artifact",
        trace_id="trace-artifact",
        approval_request=approval,
        trusted_repo_path=trusted,
        risk_report=risk,
        intent_summary={"effective_hint": "require_approval"},
        ttl_seconds=ttl_seconds,
    )
    bound = bind_artifact_to_approval(approval, artifact)
    return trusted, patch, risk, approval, bound, store, artifact


def test_patch_artifact_round_trip_preserves_exact_patch(
    tmp_path: Path,
) -> None:
    (
        trusted,
        patch,
        risk,
        approval,
        bound,
        store,
        artifact,
    ) = create_pending_artifact(tmp_path)

    loaded = store.load(artifact.artifact_id)
    reconstructed = loaded.to_patch_diff()
    reconstructed_risk = loaded.to_risk_report()

    assert reconstructed.patch == patch.patch
    assert reconstructed.patch_sha256 == patch.patch_sha256
    assert reconstructed.patch_size_bytes == patch.patch_size_bytes
    assert reconstructed.files == patch.files
    assert reconstructed.ignored_files == patch.ignored_files
    assert reconstructed_risk.audit_summary == risk.audit_summary
    assert loaded.approval_request_id == approval.approval_id
    assert bound.metadata["artifact_id"] == artifact.artifact_id
    assert bound.metadata["artifact_schema_version"] == artifact.schema_version
    assert loaded.trusted_repo_path == trusted.as_posix()


def test_patch_artifact_detects_json_tampering(
    tmp_path: Path,
) -> None:
    *_, store, artifact = create_pending_artifact(tmp_path)
    path = store.root / f"{artifact.artifact_id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["patch_sha256"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PatchArtifactTamperedError):
        store.load(artifact.artifact_id)


def test_patch_artifact_detects_patch_byte_tampering_even_with_json(
    tmp_path: Path,
) -> None:
    *_, store, artifact = create_pending_artifact(tmp_path)
    path = store.root / f"{artifact.artifact_id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["patch_base64"] = "YWJj"
    payload_without_digest = {
        key: value for key, value in payload.items() if key != "artifact_digest"
    }
    payload["artifact_digest"] = hashlib.sha256(
        json.dumps(
            payload_without_digest,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    with pytest.raises(PatchArtifactTamperedError):
        store.load(artifact.artifact_id)


def test_patch_artifact_expiration_fails_closed(
    tmp_path: Path,
) -> None:
    *_, store, artifact = create_pending_artifact(
        tmp_path,
        ttl_seconds=1,
    )
    path = store.root / f"{artifact.artifact_id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["created_at"] = "1999-01-01T00:00:00+00:00"
    payload["expires_at"] = "2000-01-01T00:00:00+00:00"
    payload_without_digest = {
        key: value for key, value in payload.items() if key != "artifact_digest"
    }
    payload["artifact_digest"] = hashlib.sha256(
        json.dumps(
            payload_without_digest,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    with pytest.raises(PatchArtifactExpiredError):
        store.load(artifact.artifact_id)


def test_artifact_root_rejects_symlink(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(Exception, match="symlink"):
        PatchArtifactStore(link)


def test_patch_artifact_rejects_expiration_before_creation(
    tmp_path: Path,
) -> None:
    *_, store, artifact = create_pending_artifact(tmp_path)
    path = store.root / f"{artifact.artifact_id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    payload["expires_at"] = "2000-01-01T00:00:00+00:00"

    payload_without_digest = {
        key: value for key, value in payload.items() if key != "artifact_digest"
    }
    payload["artifact_digest"] = hashlib.sha256(
        json.dumps(
            payload_without_digest,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        PatchArtifactTamperedError,
        match="expiration must follow creation",
    ):
        store.load(artifact.artifact_id)
