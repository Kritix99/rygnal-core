from importlib import resources
from pathlib import Path

import pytest

from rygnal.api import create_app
from rygnal.models import Decision, RuntimeMode
from rygnal.policy_engine import PolicyEngine, load_default_policy_engine


def test_default_policy_loads_outside_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.chdir(tmp_path)

    engine = load_default_policy_engine()

    assert engine.default_decision == Decision.BLOCK
    assert engine.policy_version == "policy.v2"
    assert engine.rules


def test_production_policy_loads_outside_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.chdir(tmp_path)

    engine = load_default_policy_engine(RuntimeMode.PRODUCTION_SAFE)

    assert engine.default_decision == Decision.REQUIRE_APPROVAL
    assert engine.policy_version == "policy.v2"
    assert engine.rules


def test_fastapi_constructs_outside_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.chdir(tmp_path)

    app = create_app()

    paths = {route.path for route in app.routes}
    assert "/health" in paths
    assert "/v1/evaluate" in paths


def test_explicit_external_policy_path_still_works(
    tmp_path: Path,
):
    policy_path = tmp_path / "custom-policy.yaml"
    policy_path.write_text(
        """
policy_version: policy.v2
default_decision: block
rules: []
""".strip(),
        encoding="utf-8",
    )

    engine = PolicyEngine.from_file(policy_path)

    assert engine.default_decision == Decision.BLOCK


def test_bundled_policy_resources_are_discoverable():
    package = resources.files("rygnal.resources.policies")

    assert package.joinpath("default_policy.yaml").is_file()
    assert package.joinpath("production_safe_policy.yaml").is_file()


def test_packaged_policies_match_repository_sources():
    repository_root = Path(__file__).resolve().parents[1]
    package = resources.files("rygnal.resources.policies")

    for name in (
        "default_policy.yaml",
        "production_safe_policy.yaml",
    ):
        repository_text = (repository_root / "policies" / name).read_text(encoding="utf-8")

        packaged_text = package.joinpath(name).read_text(encoding="utf-8")

        assert packaged_text == repository_text


def test_yaml_text_errors_include_source_name():
    with pytest.raises(
        ValueError,
        match="invalid packaged policy",
    ):
        PolicyEngine.from_yaml_text(
            "- not-a-mapping",
            source="invalid packaged policy",
        )


def test_default_policy_path_override_remains_supported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import rygnal.policy_engine as policy_engine_module

    policy_path = tmp_path / "overridden-default-policy.yaml"
    policy_path.write_text(
        """
policy_version: policy.v2
default_decision: block
rules:
  - id: overridden-rule
    priority: 10
    tool_name: file_read
    target_equals: OVERRIDDEN.md
    decision: allow
    severity: low
    reason: Explicit override loaded successfully.
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        policy_engine_module,
        "DEFAULT_POLICY_PATH",
        policy_path,
    )

    engine = load_default_policy_engine()

    assert engine.default_decision == Decision.BLOCK
    assert [rule.id for rule in engine.rules] == ["overridden-rule"]
