from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from rygnal.api import create_app
from rygnal.local_app import create_local_app
from rygnal.production_containment import (
    BubblewrapVerification,
)
from rygnal.production_qualification import (
    ProductionQualificationError,
    QualificationCheck,
    _asgi_request,
    qualify_production_host,
    validate_qualification_report,
    write_qualification_report,
)
from rygnal.runtime_config import (
    ApiRuntimeConfig,
    RuntimeConfigV1,
    RuntimeEnvironment,
)


def ineligible_verification() -> BubblewrapVerification:
    return BubblewrapVerification(
        eligible=False,
        platform_name=platform.system().lower(),
        executable_path=None,
        executable_sha256=None,
        version=None,
        reasons=("qualification unavailable",),
        features={
            "production_mode": True,
            "linux_host": (platform.system() == "Linux"),
        },
    )


def private_production_config(
    root: Path,
) -> tuple[Path, Path]:
    root.mkdir(
        mode=0o700,
        parents=True,
        exist_ok=True,
    )

    token_path = root / "operator.token"
    config_path = root / "runtime.json"
    data_path = root / "data"

    token_path.write_text(
        ("M18-production-token-0123456789-ABCDEFGHIJKLMN\n"),
        encoding="utf-8",
    )
    config_path.write_text(
        json.dumps(
            {
                "schema_version": ("rygnal.runtime.v1"),
                "environment": "production",
                "api": {
                    "auth_required": True,
                    "operator_token_file": (token_path.as_posix()),
                    "docs_enabled": False,
                },
            }
        ),
        encoding="utf-8",
    )
    data_path.mkdir(mode=0o700)

    if os.name != "nt":
        root.chmod(0o700)
        token_path.chmod(0o600)
        config_path.chmod(0o600)
        data_path.chmod(0o700)

    return config_path, data_path


def test_qualification_check_rejects_unstable_names() -> None:
    with pytest.raises(ValueError):
        QualificationCheck(
            name="../../unsafe",
            passed=True,
            required=True,
            code="ok",
            duration_ms=0,
        )


def test_unqualified_report_is_strict_and_private(
    tmp_path: Path,
) -> None:
    config_path, data_path = private_production_config(tmp_path / "config")
    report = qualify_production_host(
        config_path=config_path,
        data_dir=data_path,
        commit_sha="a" * 40,
        verification=(ineligible_verification()),
    )
    destination = tmp_path / "evidence" / "qualification.json"
    digest = write_qualification_report(
        report,
        destination,
    )
    payload = validate_qualification_report(
        destination,
        expected_commit_sha="a" * 40,
        require_qualified=False,
    )

    assert len(digest) == 64
    assert payload["qualified"] is False
    assert payload["schema_version"] == "rygnal.production-qualification.v1"
    assert all(
        set(check)
        == {
            "name",
            "passed",
            "required",
            "code",
            "duration_ms",
        }
        for check in payload["checks"]
    )

    body = destination.read_text(encoding="utf-8")

    assert "M18-production-token" not in body

    if os.name != "nt":
        assert destination.stat().st_mode & 0o077 == 0


def test_release_gate_rejects_unqualified_report(
    tmp_path: Path,
) -> None:
    config_path, data_path = private_production_config(tmp_path / "config")
    report = qualify_production_host(
        config_path=config_path,
        data_dir=data_path,
        commit_sha="b" * 40,
        verification=(ineligible_verification()),
    )
    destination = tmp_path / "report.json"

    write_qualification_report(
        report,
        destination,
    )

    with pytest.raises(
        ProductionQualificationError,
        match="did not pass",
    ):
        validate_qualification_report(
            destination,
            expected_commit_sha="b" * 40,
        )


def test_report_gate_rejects_commit_mismatch(
    tmp_path: Path,
) -> None:
    config_path, data_path = private_production_config(tmp_path / "config")
    report = qualify_production_host(
        config_path=config_path,
        data_dir=data_path,
        commit_sha="c" * 40,
        verification=(ineligible_verification()),
    )
    destination = tmp_path / "report.json"

    write_qualification_report(
        report,
        destination,
    )

    with pytest.raises(
        ProductionQualificationError,
        match="commit",
    ):
        validate_qualification_report(
            destination,
            expected_commit_sha="d" * 40,
            require_qualified=False,
        )


def test_production_readiness_requires_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "rygnal.local_app.verify_production_bubblewrap",
        ineligible_verification,
    )
    token = "M18-readiness-token-0123456789-ABCDEFGHIJKLMN"
    config = RuntimeConfigV1(
        environment=(RuntimeEnvironment.PRODUCTION),
        api=ApiRuntimeConfig(
            auth_required=True,
            docs_enabled=False,
            operator_token=token,
        ),
    )
    app = create_local_app(
        data_dir=tmp_path / "data",
        environ={},
        runtime_config=config,
    )
    client = TestClient(app)
    response = client.get("/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_production_qualification_workflow_contract() -> None:
    workflow = Path(".github/workflows/production-qualification.yml")
    source = workflow.read_text(encoding="utf-8")
    parsed = yaml.safe_load(source)

    assert isinstance(parsed, dict)
    assert "jobs" in parsed
    assert "runs-on: ubuntu-24.04" in source
    assert "sudo apt-get install" in source
    assert "bubblewrap" in source
    assert "continue-on-error: true" in source
    assert "if: always()" in source
    assert "actions/upload-artifact@v4" in source
    assert "production_qualification" in source
    assert "verify-report" in source
    assert "--require-installed" in source
    assert "if-no-files-found: warn" in source


@pytest.mark.skipif(
    platform.system() != "Linux" or shutil.which("bwrap") is None,
    reason=("Actual production qualification requires Linux and Bubblewrap."),
)
def test_actual_linux_release_qualification(
    tmp_path: Path,
) -> None:
    config_path, data_path = private_production_config(tmp_path / "config")
    report = qualify_production_host(
        config_path=config_path,
        data_dir=data_path,
        commit_sha="e" * 40,
    )
    destination = tmp_path / "qualification.json"

    write_qualification_report(
        report,
        destination,
    )
    payload = validate_qualification_report(
        destination,
        expected_commit_sha="e" * 40,
    )

    assert report.qualified is True
    assert payload["qualified"] is True

    checks = {check["name"]: check for check in payload["checks"]}

    assert checks["bubblewrap.behavioral_verification"]["passed"]
    assert checks["sandbox.hostile_boundary"]["passed"]
    assert checks["sandbox.output_bounded"]["passed"]
    assert checks["sandbox.descendant_timeout_cleanup"]["passed"]
    assert checks["runtime.production_api_startup"]["passed"]


def test_asgi_qualification_helper_auth_flow() -> None:
    token = "M18-ASGI-helper-token-0123456789-ABCDEFGHIJKLMN"
    app = create_app(
        runtime_config=RuntimeConfigV1(
            environment=(RuntimeEnvironment.PRODUCTION),
            api=ApiRuntimeConfig(
                auth_required=True,
                docs_enabled=False,
                operator_token=token,
            ),
        )
    )
    payload = json.dumps(
        {
            "tool_name": "file_read",
            "action": "read",
            "target": "README.md",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    async def scenario() -> None:
        health = await _asgi_request(
            app,
            method="GET",
            path="/health",
        )
        denied = await _asgi_request(
            app,
            method="POST",
            path="/v1/evaluate",
            body=payload,
        )
        accepted = await _asgi_request(
            app,
            method="POST",
            path="/v1/evaluate",
            body=payload,
            authorization=f"Bearer {token}",
        )

        assert health[0] == 200
        assert denied[0] == 401
        assert accepted[0] == 200
        assert json.loads(denied[2])["error"]["code"] == "authentication_failed"
        assert "policy_decision" in json.loads(accepted[2])

    asyncio.run(scenario())
