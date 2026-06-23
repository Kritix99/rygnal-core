from pathlib import Path

import pytest

from rygnal.audit_logger import AuditLogger
from rygnal.core import Rygnal
from rygnal.interceptor import RygnalInterceptor
from rygnal.models import Decision, ExecutionStatus, RuntimeMode, ToolRequest
from rygnal.policy_engine import load_default_policy_engine
from rygnal.risk_engine import RiskEngine
from rygnal.tool_executor import ToolExecutor


def build_interceptor(tmp_path: Path) -> RygnalInterceptor:
    executor = ToolExecutor()
    executor.register(
        "file_read",
        lambda request: {"target": request.target, "content": "safe"},
    )

    return RygnalInterceptor(
        policy_engine=load_default_policy_engine(RuntimeMode.PRODUCTION_SAFE),
        audit_logger=AuditLogger(tmp_path / "audit_log.jsonl"),
        tool_executor=executor,
        risk_engine=RiskEngine(),
        runtime_mode=RuntimeMode.PRODUCTION_SAFE,
    )


def test_rygnal_from_defaults_honors_production_safe_policy_mode(tmp_path: Path) -> None:
    rygnal = Rygnal.from_defaults(
        runtime_mode=RuntimeMode.PRODUCTION_SAFE,
        audit_log_path=tmp_path / "audit_log.jsonl",
    )

    assert rygnal.runtime_mode == RuntimeMode.PRODUCTION_SAFE
    assert rygnal.policy_engine.default_decision == Decision.REQUIRE_APPROVAL


def test_rygnal_from_defaults_default_mode_does_not_load_production_safe_policy(
    tmp_path: Path,
) -> None:
    rygnal = Rygnal.from_defaults(
        audit_log_path=tmp_path / "audit_log.jsonl",
    )

    assert rygnal.runtime_mode != RuntimeMode.PRODUCTION_SAFE
    assert rygnal.policy_engine.default_decision == Decision.BLOCK


def test_load_default_policy_engine_uses_production_safe_policy() -> None:
    engine = load_default_policy_engine(RuntimeMode.PRODUCTION_SAFE)

    assert engine.default_decision == Decision.REQUIRE_APPROVAL


def test_production_safe_policy_blocks_critical_risk(tmp_path: Path) -> None:
    interceptor = build_interceptor(tmp_path)

    result = interceptor.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target=".env")
    )

    assert result.risk_assessment["risk_level"] == "critical"
    assert result.policy_decision.decision == Decision.BLOCK
    assert result.policy_decision.policy_id == "block-critical-risk"
    assert result.execution.status == ExecutionStatus.SKIPPED


def test_production_safe_policy_requires_approval_for_unmatched_safe_read(tmp_path: Path) -> None:
    interceptor = build_interceptor(tmp_path)

    result = interceptor.intercept(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )

    assert result.policy_decision.decision == Decision.REQUIRE_APPROVAL
    assert result.policy_decision.policy_id == "production-safe-terminal-approval"
    assert result.policy_decision.explanation is not None
    assert result.policy_decision.explanation.default_decision is False
    assert result.policy_decision.explanation.matched is True
    assert result.execution.status == ExecutionStatus.SKIPPED


def test_default_policy_remains_fail_closed_with_explicit_safe_read_allow() -> None:
    engine = load_default_policy_engine()

    allowed_read = engine.evaluate(
        ToolRequest(tool_name="file_read", action="read_file", target="README.md")
    )
    unmatched = engine.evaluate(ToolRequest(tool_name="unknown_tool", action="noop"))

    assert engine.default_decision == Decision.BLOCK
    assert allowed_read.decision == Decision.ALLOW
    assert allowed_read.allowed is True
    assert allowed_read.policy_id == "allow-readme-read"
    assert unmatched.decision == Decision.BLOCK
    assert unmatched.allowed is False


def test_production_safe_policy_rejects_missing_terminal_catch_all(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import rygnal.policy_engine as policy_engine_module
    from rygnal.policy_engine import PolicyLoadError

    policy_path = tmp_path / "missing_terminal_policy.yaml"
    policy_path.write_text(
        """
policy_version: policy.v2
default_decision: require_approval
rules:
  - id: block-env-read
    priority: 10
    tool_name: file_read
    target_contains: ".env"
    decision: block
    severity: high
    reason: Env reads are blocked.
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(policy_engine_module, "PRODUCTION_SAFE_POLICY_PATH", policy_path)

    with pytest.raises(PolicyLoadError, match="terminal catch-all"):
        load_default_policy_engine(RuntimeMode.PRODUCTION_SAFE)


def test_production_safe_policy_rejects_terminal_allow_rule(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import rygnal.policy_engine as policy_engine_module
    from rygnal.policy_engine import PolicyLoadError

    policy_path = tmp_path / "terminal_allow_policy.yaml"
    policy_path.write_text(
        """
policy_version: policy.v2
default_decision: require_approval
rules:
  - id: unsafe-terminal-allow
    priority: 1000
    decision: allow
    severity: low
    reason: This must not be allowed in production-safe mode.
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(policy_engine_module, "PRODUCTION_SAFE_POLICY_PATH", policy_path)

    with pytest.raises(PolicyLoadError, match="must not allow or simulate"):
        load_default_policy_engine(RuntimeMode.PRODUCTION_SAFE)


def test_production_safe_policy_rejects_terminal_rule_before_specific_rules(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import rygnal.policy_engine as policy_engine_module
    from rygnal.policy_engine import PolicyLoadError

    policy_path = tmp_path / "early_terminal_policy.yaml"
    policy_path.write_text(
        """
policy_version: policy.v2
default_decision: require_approval
rules:
  - id: early-terminal-approval
    priority: 1
    decision: require_approval
    severity: high
    reason: This catches everything too early.

  - id: block-env-read
    priority: 10
    tool_name: file_read
    target_contains: ".env"
    decision: block
    severity: high
    reason: Env reads are blocked.
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(policy_engine_module, "PRODUCTION_SAFE_POLICY_PATH", policy_path)

    with pytest.raises(PolicyLoadError, match="lowest precedence"):
        load_default_policy_engine(RuntimeMode.PRODUCTION_SAFE)


def test_production_safe_policy_rejects_default_allow_even_with_terminal_rule(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import rygnal.policy_engine as policy_engine_module
    from rygnal.policy_engine import PolicyLoadError

    policy_path = tmp_path / "default_allow_terminal_policy.yaml"
    policy_path.write_text(
        """
policy_version: policy.v2
default_decision: allow
rules:
  - id: terminal-approval
    priority: 1000
    decision: require_approval
    severity: high
    reason: Unknown actions require approval.
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(policy_engine_module, "PRODUCTION_SAFE_POLICY_PATH", policy_path)

    with pytest.raises(PolicyLoadError, match="fail-closed"):
        load_default_policy_engine(RuntimeMode.PRODUCTION_SAFE)
