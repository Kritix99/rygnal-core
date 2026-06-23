from __future__ import annotations

import json
import sys
import types

import pytest

from rygnal.rust_kernel import (
    RustAgentAction,
    RustKernelError,
    RustKernelUnavailableError,
    RustRiskAssessment,
    evaluate_agent_action,
    is_rust_kernel_available,
)


def test_rust_kernel_adapter_reports_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "rygnal_kernel", None)

    def fake_import_module(name: str) -> object:
        if name == "rygnal_kernel":
            raise ModuleNotFoundError(name)
        raise AssertionError(name)

    monkeypatch.setattr("importlib.import_module", fake_import_module)

    assert is_rust_kernel_available() is False

    with pytest.raises(RustKernelUnavailableError):
        evaluate_agent_action(
            RustAgentAction(
                file_path="src/main.py",
                action_type="modified",
                raw_code="",
            )
        )


def test_rust_kernel_adapter_returns_structured_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_kernel = types.SimpleNamespace(
        evaluate_agent_action=lambda payload: json.dumps(
            {
                "criticality_index": 6.0,
                "risk_level": "risky",
                "reasons": ["Contains system or external attribute calls"],
            }
        )
    )

    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    result = evaluate_agent_action(
        RustAgentAction(
            file_path="src/cleanup.py",
            action_type="modified",
            raw_code='import os\nos.remove("production.db")\n',
        )
    )

    assert result == RustRiskAssessment(
        criticality_index=6.0,
        risk_level="risky",
        reasons=("Contains system or external attribute calls",),
    )


def test_rust_kernel_adapter_wraps_rust_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_action(payload: str) -> str:
        raise ValueError("Invalid action payload")

    fake_kernel = types.SimpleNamespace(evaluate_agent_action=reject_action)
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="rust kernel rejected agent action"):
        evaluate_agent_action(
            RustAgentAction(
                file_path="src/main.py",
                action_type="modified",
                raw_code="",
            )
        )


def test_rust_kernel_adapter_rejects_invalid_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_kernel = types.SimpleNamespace(evaluate_agent_action=lambda payload: "not json")
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="invalid JSON"):
        evaluate_agent_action(
            RustAgentAction(
                file_path="src/main.py",
                action_type="modified",
                raw_code="",
            )
        )


def test_rust_kernel_adapter_rejects_invalid_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_kernel = types.SimpleNamespace(
        evaluate_agent_action=lambda payload: json.dumps({"risk_level": "safe"})
    )
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="invalid assessment shape"):
        evaluate_agent_action(
            RustAgentAction(
                file_path="src/main.py",
                action_type="modified",
                raw_code="",
            )
        )


def test_rust_kernel_adapter_returns_subjective_risk_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustHumanContext,
        RustSemanticMetrics,
        RustSubjectiveRiskAssessment,
        RustSubjectiveRiskInput,
        evaluate_subjective_risk,
    )

    fake_kernel = types.SimpleNamespace(
        evaluate_subjective_risk=lambda payload: json.dumps(
            {
                "total_criticality": 6.5,
                "judgment": "approval_required",
                "reasons": ["Python AST survival ratio is 0.5000."],
                "human_multiplier": 1.0,
                "destruction_penalty": 2.5,
                "semantic_metrics": {
                    "old_node_count": 10,
                    "new_node_count": 8,
                    "old_token_count": 4,
                    "new_token_count": 3,
                    "matched_node_count": 2,
                    "survival_ratio": 0.5,
                },
            }
        )
    )
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    result = evaluate_subjective_risk(
        RustSubjectiveRiskInput(
            file_path="src/service.py",
            action_type="modified",
            system_risk=6.0,
            old_code="def important():\n    return True\n",
            new_code="def important():\n    return False\n",
            human_context=RustHumanContext(
                days_since_edit=0.0,
                days_since_burst=0.0,
                line_ownership_ratio=0.8,
                is_explicitly_locked=False,
            ),
        )
    )

    assert result == RustSubjectiveRiskAssessment(
        total_criticality=6.5,
        judgment="approval_required",
        reasons=("Python AST survival ratio is 0.5000.",),
        human_multiplier=1.0,
        destruction_penalty=2.5,
        semantic_metrics=RustSemanticMetrics(
            old_node_count=10,
            new_node_count=8,
            old_token_count=4,
            new_token_count=3,
            matched_node_count=2,
            survival_ratio=0.5,
        ),
    )


def test_rust_kernel_adapter_wraps_missing_subjective_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustHumanContext,
        RustKernelError,
        RustSubjectiveRiskInput,
        evaluate_subjective_risk,
    )

    fake_kernel = types.SimpleNamespace()
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="does not expose evaluate_subjective_risk"):
        evaluate_subjective_risk(
            RustSubjectiveRiskInput(
                file_path="src/service.py",
                action_type="modified",
                system_risk=1.0,
                old_code="",
                new_code="",
                human_context=RustHumanContext(
                    days_since_edit=0.0,
                    days_since_burst=0.0,
                    line_ownership_ratio=0.5,
                ),
            )
        )


def test_rust_kernel_adapter_rejects_invalid_subjective_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustHumanContext,
        RustKernelError,
        RustSubjectiveRiskInput,
        evaluate_subjective_risk,
    )

    fake_kernel = types.SimpleNamespace(
        evaluate_subjective_risk=lambda payload: json.dumps(
            {
                "total_criticality": 1.0,
                "judgment": "allow",
                "reasons": [],
            }
        )
    )
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="invalid subjective risk shape"):
        evaluate_subjective_risk(
            RustSubjectiveRiskInput(
                file_path="src/service.py",
                action_type="modified",
                system_risk=1.0,
                old_code="",
                new_code="",
                human_context=RustHumanContext(
                    days_since_edit=0.0,
                    days_since_burst=0.0,
                    line_ownership_ratio=0.5,
                ),
            )
        )


def test_rust_kernel_adapter_returns_criticality_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustCriticalityAssessment,
        RustCriticalityInput,
        RustSemanticMetrics,
        evaluate_criticality,
    )

    fake_kernel = types.SimpleNamespace(
        evaluate_criticality=lambda payload: json.dumps(
            {
                "criticality_index": 6.0,
                "risk_level": "high",
                "reasons": ["Semantic destruction increases criticality by 3.0."],
                "semantic_metrics": {
                    "old_node_count": 10,
                    "new_node_count": 4,
                    "old_token_count": 5,
                    "new_token_count": 2,
                    "matched_node_count": 1,
                    "survival_ratio": 0.2,
                },
                "path_category": "normal",
                "path_severity": "medium",
            }
        )
    )
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    result = evaluate_criticality(
        RustCriticalityInput(
            file_path="src/service.py",
            action_type="modified",
            old_code="def important():\n    return True\n",
            new_code="def replacement():\n    return False\n",
        )
    )

    assert result == RustCriticalityAssessment(
        criticality_index=6.0,
        risk_level="high",
        reasons=("Semantic destruction increases criticality by 3.0.",),
        semantic_metrics=RustSemanticMetrics(
            old_node_count=10,
            new_node_count=4,
            old_token_count=5,
            new_token_count=2,
            matched_node_count=1,
            survival_ratio=0.2,
        ),
        path_category="normal",
        path_severity="medium",
    )


def test_rust_kernel_adapter_serializes_elevated_criticality_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import RustCriticalityInput, evaluate_criticality

    captured = {}

    def fake_evaluate(payload: str) -> str:
        captured["payload"] = json.loads(payload)
        return json.dumps(
            {
                "criticality_index": 6.0,
                "risk_level": "high",
                "reasons": ["Python elevated risk signal increases criticality by 1.5."],
                "semantic_metrics": {
                    "old_node_count": 0,
                    "new_node_count": 0,
                    "old_token_count": 0,
                    "new_token_count": 0,
                    "matched_node_count": 0,
                    "survival_ratio": 1.0,
                },
                "path_category": "dependency",
                "path_severity": "high",
            }
        )

    fake_kernel = types.SimpleNamespace(evaluate_criticality=fake_evaluate)
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    evaluate_criticality(
        RustCriticalityInput(
            file_path="package-lock.json",
            action_type="modified",
            old_code="{}",
            new_code="{bad-json",
            elevated=True,
        )
    )

    assert captured["payload"]["elevated"] is True
    assert "elevated_weight" not in captured["payload"]


def test_rust_kernel_adapter_rejects_null_criticality_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustCriticalityInput,
        RustKernelError,
        evaluate_criticality,
    )

    fake_kernel = types.SimpleNamespace(
        evaluate_criticality=lambda payload: json.dumps(
            {
                "criticality_index": None,
                "risk_level": "low",
                "reasons": [],
                "semantic_metrics": {
                    "old_node_count": 1,
                    "new_node_count": 1,
                    "old_token_count": 1,
                    "new_token_count": 1,
                    "matched_node_count": 1,
                    "survival_ratio": 1.0,
                },
                "path_category": "normal",
                "path_severity": "medium",
            }
        )
    )
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="invalid or missing criticality_index"):
        evaluate_criticality(
            RustCriticalityInput(
                file_path="src/service.py",
                action_type="modified",
            )
        )


def test_rust_kernel_adapter_wraps_structured_criticality_domain_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustCriticalityEvaluationError,
        RustCriticalityInput,
        evaluate_criticality,
    )

    class CriticalityEvaluationError(Exception):
        pass

    def reject(payload: str) -> str:
        raise CriticalityEvaluationError(
            json.dumps(
                {
                    "error_code": "parent-traversal",
                    "reason": "path must not traverse outside repository",
                }
            )
        )

    fake_kernel = types.SimpleNamespace(
        CriticalityEvaluationError=CriticalityEvaluationError,
        evaluate_criticality=reject,
    )
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustCriticalityEvaluationError) as exc_info:
        evaluate_criticality(
            RustCriticalityInput(
                file_path="../evil.py",
                action_type="modified",
            )
        )

    assert exc_info.value.error_code == "parent-traversal"
    assert exc_info.value.reason == "path must not traverse outside repository"


def test_rust_kernel_adapter_wraps_missing_criticality_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustCriticalityInput,
        RustKernelError,
        evaluate_criticality,
    )

    fake_kernel = types.SimpleNamespace()
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="does not expose evaluate_criticality"):
        evaluate_criticality(
            RustCriticalityInput(
                file_path="src/service.py",
                action_type="modified",
            )
        )


def test_rust_kernel_adapter_rejects_invalid_criticality_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustCriticalityInput,
        RustKernelError,
        evaluate_criticality,
    )

    fake_kernel = types.SimpleNamespace(evaluate_criticality=lambda payload: "not json")
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="invalid JSON"):
        evaluate_criticality(
            RustCriticalityInput(
                file_path="src/service.py",
                action_type="modified",
            )
        )


def test_rust_kernel_adapter_wraps_unicode_boundary_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustCriticalityInput,
        RustKernelError,
        evaluate_criticality,
    )

    def reject(payload: str) -> str:
        raise UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed")

    fake_kernel = types.SimpleNamespace(evaluate_criticality=reject)
    monkeypatch.setattr("importlib.import_module", lambda name: fake_kernel)

    with pytest.raises(RustKernelError, match="native criticality boundary failed"):
        evaluate_criticality(
            RustCriticalityInput(
                file_path="src/service.py",
                action_type="modified",
                old_code="\ud800",
                new_code="def ok():\n    return True\n",
            )
        )


def test_rust_kernel_adapter_reports_native_load_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rygnal.rust_kernel import (
        RustCriticalityInput,
        RustKernelUnavailableError,
        evaluate_criticality,
    )

    def fail_import(name: str) -> object:
        raise ImportError("native wheel failed to load")

    monkeypatch.setattr("importlib.import_module", fail_import)

    with pytest.raises(RustKernelUnavailableError, match="failed to load"):
        evaluate_criticality(
            RustCriticalityInput(
                file_path="src/service.py",
                action_type="modified",
            )
        )
