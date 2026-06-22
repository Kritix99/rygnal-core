"""Optional Python adapter boundary for the Rygnal Rust kernel.

This module is the only production Python code that should import the optional
``rygnal_kernel`` PyO3 extension directly. Keep all Rust/Python JSON contracts
centralized here so callers receive typed Python dataclasses instead of raw
extension-module dictionaries or strings.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Literal

from rygnal.changed_files import normalize_repo_relative_path

CriticalityActionType = Literal[
    "added",
    "modified",
    "deleted",
    "renamed",
    "mode_changed",
    "untracked",
]


class RustKernelUnavailableError(RuntimeError):
    """Raised when the optional Rust kernel extension is not installed."""


class RustKernelError(RuntimeError):
    """Raised when the Rust kernel returns invalid or unusable output."""


class RustCriticalityEvaluationError(RustKernelError):
    """Raised when Rust rejects criticality evaluation with a structured code."""

    def __init__(self, *, error_code: str, reason: str) -> None:
        self.error_code = error_code
        self.reason = reason
        super().__init__(f"rust criticality evaluation failed [{error_code}]: {reason}")


@dataclass(frozen=True)
class RustAgentAction:
    file_path: str
    action_type: str
    raw_code: str = ""


@dataclass(frozen=True)
class RustRiskAssessment:
    criticality_index: float
    risk_level: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class RustHumanContext:
    days_since_edit: float
    days_since_burst: float
    line_ownership_ratio: float
    is_explicitly_locked: bool = False


@dataclass(frozen=True)
class RustSubjectiveRiskInput:
    file_path: str
    action_type: str
    system_risk: float
    old_code: str
    new_code: str
    human_context: RustHumanContext


@dataclass(frozen=True)
class RustSemanticMetrics:
    old_node_count: int
    new_node_count: int
    old_token_count: int
    new_token_count: int
    matched_node_count: int
    survival_ratio: float


@dataclass(frozen=True)
class RustCriticalityInput:
    file_path: str
    action_type: CriticalityActionType
    old_code: str = ""
    new_code: str = ""
    elevated: bool = False


@dataclass(frozen=True)
class RustCriticalityAssessment:
    criticality_index: float
    risk_level: str
    reasons: tuple[str, ...]
    semantic_metrics: RustSemanticMetrics
    path_category: str
    path_severity: str


@dataclass(frozen=True)
class RustSubjectiveRiskAssessment:
    total_criticality: float
    judgment: str
    reasons: tuple[str, ...]
    human_multiplier: float
    destruction_penalty: float
    semantic_metrics: RustSemanticMetrics


def is_rust_kernel_available() -> bool:
    try:
        importlib.import_module("rygnal_kernel")
    except ImportError:
        return False
    return True


def _load_kernel() -> Any:
    try:
        return importlib.import_module("rygnal_kernel")
    except ImportError as exc:
        raise RustKernelUnavailableError(
            "optional Rust kernel extension is not installed or failed to load"
        ) from exc


def evaluate_agent_action(action: RustAgentAction) -> RustRiskAssessment:
    payload = {
        "file_path": action.file_path,
        "action_type": action.action_type,
        "raw_code": action.raw_code,
    }

    result = _call_json_kernel_function(
        function_name="evaluate_agent_action",
        payload=payload,
        rejection_context="agent action",
    )

    try:
        return RustRiskAssessment(
            criticality_index=float(result["criticality_index"]),
            risk_level=str(result["risk_level"]),
            reasons=tuple(str(reason) for reason in result["reasons"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RustKernelError("rust kernel returned invalid assessment shape") from exc


def evaluate_criticality(
    criticality_input: RustCriticalityInput,
) -> RustCriticalityAssessment:
    payload = asdict(criticality_input)
    action_type = payload["action_type"]

    if hasattr(action_type, "value"):
        payload["action_type"] = action_type.value

    result = _call_criticality_kernel(payload)
    return _parse_criticality_assessment(result)


def evaluate_subjective_risk(
    risk_input: RustSubjectiveRiskInput,
) -> RustSubjectiveRiskAssessment:
    payload = {
        "file_path": risk_input.file_path,
        "action_type": risk_input.action_type,
        "system_risk": risk_input.system_risk,
        "old_code": risk_input.old_code,
        "new_code": risk_input.new_code,
        "human_context": {
            "days_since_edit": risk_input.human_context.days_since_edit,
            "days_since_burst": risk_input.human_context.days_since_burst,
            "line_ownership_ratio": risk_input.human_context.line_ownership_ratio,
            "is_explicitly_locked": risk_input.human_context.is_explicitly_locked,
        },
    }

    result = _call_json_kernel_function(
        function_name="evaluate_subjective_risk",
        payload=payload,
        rejection_context="subjective risk input",
    )

    try:
        metrics = result["semantic_metrics"]
        return RustSubjectiveRiskAssessment(
            total_criticality=float(result["total_criticality"]),
            judgment=str(result["judgment"]),
            reasons=tuple(str(reason) for reason in result["reasons"]),
            human_multiplier=float(result["human_multiplier"]),
            destruction_penalty=float(result["destruction_penalty"]),
            semantic_metrics=RustSemanticMetrics(
                old_node_count=int(metrics["old_node_count"]),
                new_node_count=int(metrics["new_node_count"]),
                old_token_count=int(metrics["old_token_count"]),
                new_token_count=int(metrics["new_token_count"]),
                matched_node_count=int(metrics["matched_node_count"]),
                survival_ratio=float(metrics["survival_ratio"]),
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RustKernelError("rust kernel returned invalid subjective risk shape") from exc


def _parse_criticality_assessment(result: dict[str, Any]) -> RustCriticalityAssessment:
    criticality_index = _require_number(
        result,
        "criticality_index",
        "rust kernel returned invalid or missing criticality_index",
    )
    risk_level = _require_string(
        result,
        "risk_level",
        "rust kernel returned invalid or missing risk_level",
    )
    reasons = _require_string_tuple(
        result,
        "reasons",
        "rust kernel returned invalid or missing reasons",
    )
    semantic_metrics = _require_dict(
        result,
        "semantic_metrics",
        "rust kernel returned invalid or missing semantic_metrics",
    )
    path_category = _require_string(
        result,
        "path_category",
        "rust kernel returned invalid or missing path_category",
    )
    path_severity = _require_string(
        result,
        "path_severity",
        "rust kernel returned invalid or missing path_severity",
    )

    return RustCriticalityAssessment(
        criticality_index=criticality_index,
        risk_level=risk_level,
        reasons=reasons,
        semantic_metrics=RustSemanticMetrics(
            old_node_count=_require_int(
                semantic_metrics,
                "old_node_count",
                "rust kernel returned invalid or missing semantic_metrics.old_node_count",
            ),
            new_node_count=_require_int(
                semantic_metrics,
                "new_node_count",
                "rust kernel returned invalid or missing semantic_metrics.new_node_count",
            ),
            old_token_count=_require_int(
                semantic_metrics,
                "old_token_count",
                "rust kernel returned invalid or missing semantic_metrics.old_token_count",
            ),
            new_token_count=_require_int(
                semantic_metrics,
                "new_token_count",
                "rust kernel returned invalid or missing semantic_metrics.new_token_count",
            ),
            matched_node_count=_require_int(
                semantic_metrics,
                "matched_node_count",
                "rust kernel returned invalid or missing semantic_metrics.matched_node_count",
            ),
            survival_ratio=_require_number(
                semantic_metrics,
                "survival_ratio",
                "rust kernel returned invalid or missing semantic_metrics.survival_ratio",
            ),
        ),
        path_category=path_category,
        path_severity=path_severity,
    )


def _call_criticality_kernel(payload: dict[str, Any]) -> dict[str, Any]:
    kernel = _load_kernel()

    try:
        function = kernel.evaluate_criticality
    except AttributeError as exc:
        raise RustKernelError("rust kernel does not expose evaluate_criticality") from exc

    try:
        raw_result = function(json.dumps(payload))
    except (UnicodeEncodeError, TypeError) as exc:
        raise RustKernelError(f"native criticality boundary failed: {exc}") from exc
    except ValueError as exc:
        raise RustKernelError(f"rust kernel rejected criticality input: {exc}") from exc
    except Exception as exc:
        error_type = getattr(kernel, "CriticalityEvaluationError", None)
        if error_type is not None and isinstance(exc, error_type):
            raise _criticality_error_from_native_exception(exc) from exc
        raise

    try:
        result = json.loads(raw_result)
    except json.JSONDecodeError as exc:
        raise RustKernelError("rust kernel returned invalid JSON") from exc

    if not isinstance(result, dict):
        raise RustKernelError("rust kernel returned non-object JSON")

    return result


def _criticality_error_from_native_exception(
    exc: Exception,
) -> RustCriticalityEvaluationError:
    try:
        payload = json.loads(str(exc))
    except json.JSONDecodeError as parse_exc:
        raise RustKernelError("rust kernel returned invalid criticality error JSON") from parse_exc

    if not isinstance(payload, dict):
        raise RustKernelError("rust kernel returned non-object criticality error JSON")

    error_code = payload.get("error_code")
    reason = payload.get("reason")

    if not isinstance(error_code, str) or not isinstance(reason, str):
        raise RustKernelError("rust kernel returned invalid criticality error shape")

    return RustCriticalityEvaluationError(error_code=error_code, reason=reason)


def _require_dict(
    source: dict[str, Any],
    key: str,
    error_message: str,
) -> dict[str, Any]:
    value = source.get(key)
    if not isinstance(value, dict):
        raise RustKernelError(error_message)
    return value


def _require_string(source: dict[str, Any], key: str, error_message: str) -> str:
    value = source.get(key)
    if not isinstance(value, str):
        raise RustKernelError(error_message)
    return value


def _require_string_tuple(
    source: dict[str, Any],
    key: str,
    error_message: str,
) -> tuple[str, ...]:
    value = source.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RustKernelError(error_message)
    return tuple(value)


def _require_int(source: dict[str, Any], key: str, error_message: str) -> int:
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise RustKernelError(error_message)
    return value


def _require_number(source: dict[str, Any], key: str, error_message: str) -> float:
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RustKernelError(error_message)
    return float(value)


def _call_json_kernel_function(
    *,
    function_name: str,
    payload: dict[str, Any],
    rejection_context: str,
) -> dict[str, Any]:
    kernel = _load_kernel()

    try:
        function = getattr(kernel, function_name)
    except AttributeError as exc:
        raise RustKernelError(f"rust kernel does not expose {function_name}") from exc

    try:
        raw_result = function(json.dumps(payload))
    except ValueError as exc:
        raise RustKernelError(f"rust kernel rejected {rejection_context}: {exc}") from exc

    try:
        result = json.loads(raw_result)
    except json.JSONDecodeError as exc:
        raise RustKernelError("rust kernel returned invalid JSON") from exc

    if not isinstance(result, dict):
        raise RustKernelError("rust kernel returned non-object JSON")

    return result


__all__ = [
    "RustAgentAction",
    "RustHumanContext",
    "RustKernelError",
    "RustCriticalityInput",
    "RustCriticalityEvaluationError",
    "RustCriticalityAssessment",
    "CriticalityActionType",
    "RustKernelUnavailableError",
    "RustRiskAssessment",
    "RustSemanticMetrics",
    "RustSubjectiveRiskAssessment",
    "RustSubjectiveRiskInput",
    "evaluate_agent_action",
    "evaluate_criticality",
    "evaluate_subjective_risk",
    "is_rust_kernel_available",
]


@dataclass(frozen=True)
class RustKernelStatus:
    available: bool
    version: str | None


def rust_kernel_status() -> RustKernelStatus:
    kernel = _load_kernel_optional()
    return RustKernelStatus(
        available=kernel is not None,
        version=engine_version() if kernel is not None else None,
    )


def engine_version() -> str:
    kernel = _load_kernel_optional()
    if kernel is not None and hasattr(kernel, "engine_version"):
        return str(kernel.engine_version())

    return "python-fallback"


def validate_repo_relative_path(path: str) -> dict[str, Any]:
    kernel = _load_kernel_optional()
    if kernel is not None and hasattr(kernel, "validate_repo_relative_path"):
        return dict(kernel.validate_repo_relative_path(path))

    precheck_code = _fallback_precheck_error_code(path)
    if precheck_code is not None:
        return _unsafe_path_outcome_from_code(path, precheck_code)

    try:
        normalized_path = normalize_repo_relative_path(path)
    except Exception as exc:  # noqa: BLE001 - fallback normalizes external errors into stable codes.
        return _unsafe_path_outcome(path, exc)

    return _safe_path_outcome(normalized_path)


def validate_patch_path(path: str) -> dict[str, Any]:
    kernel = _load_kernel_optional()
    if kernel is not None and hasattr(kernel, "validate_patch_path"):
        return dict(kernel.validate_patch_path(path))

    trimmed = path.strip()

    if trimmed == "/dev/null":
        return _safe_path_outcome(None, is_sentinel=True)

    if trimmed.startswith(("a/", "b/")):
        trimmed = trimmed[2:]

    precheck_code = _fallback_precheck_error_code(trimmed)
    if precheck_code is not None:
        return _unsafe_path_outcome_from_code(path, precheck_code)

    try:
        normalized_path = normalize_repo_relative_path(trimmed)
    except Exception as exc:  # noqa: BLE001 - fallback normalizes external errors into stable codes.
        return _unsafe_path_outcome(path, exc)

    return _safe_path_outcome(normalized_path)


def classify_path_sensitivity(path: str) -> dict[str, str]:
    kernel = _load_kernel_optional()
    if kernel is not None and hasattr(kernel, "classify_path_sensitivity"):
        return dict(kernel.classify_path_sensitivity(path))

    normalized = normalize_repo_relative_path(path)
    lower = normalized.lower()
    segments = lower.split("/")
    file_name = segments[-1]

    if _is_secret_path(segments, file_name):
        return _sensitivity("secret", "critical", "path appears to contain secrets or credentials")
    if _is_ci_path(segments):
        return _sensitivity(
            "ci", "high", "path modifies CI/CD automation or workflow configuration"
        )
    if _is_policy_path(segments):
        return _sensitivity("policy", "high", "path modifies Rygnal policy configuration")
    if _is_dependency_path(file_name):
        return _sensitivity(
            "dependency", "high", "path modifies dependency or package manager metadata"
        )
    if _is_config_path(segments, file_name):
        return _sensitivity("config", "medium", "path modifies configuration or settings")
    if _is_generated_path(segments):
        return _sensitivity(
            "generated", "low", "path is generated, cached, vendored, or build output"
        )
    if _is_test_path(segments, file_name):
        return _sensitivity("test", "low", "path appears to be test code or test data")
    if _is_documentation_path(segments, file_name):
        return _sensitivity("documentation", "low", "path appears to be documentation")

    return _sensitivity("normal", "medium", "path has no special sensitivity classification")


def _load_kernel_optional() -> Any | None:
    try:
        return _load_kernel()
    except RustKernelUnavailableError:
        return None


def _safe_path_outcome(
    normalized_path: str | None,
    *,
    is_sentinel: bool = False,
) -> dict[str, Any]:
    return {
        "safe": True,
        "normalized_path": normalized_path,
        "error_code": None,
        "reason": None,
        "is_sentinel": is_sentinel,
    }


def _unsafe_path_outcome(path: str, exc: Exception) -> dict[str, Any]:
    return {
        "safe": False,
        "normalized_path": None,
        "error_code": _fallback_error_code(path),
        "reason": str(exc),
        "is_sentinel": False,
    }


def _unsafe_path_outcome_from_code(path: str, error_code: str) -> dict[str, Any]:
    return {
        "safe": False,
        "normalized_path": None,
        "error_code": error_code,
        "reason": _fallback_reason_for_code(path, error_code),
        "is_sentinel": False,
    }


def _fallback_precheck_error_code(path: str) -> str | None:
    if "\0" in path:
        return "null-byte"

    normalized = path.replace("\\", "/").strip()

    if not normalized:
        return "empty-path"
    if normalized.startswith("/"):
        return "absolute-path"
    if len(normalized) >= 2 and normalized[1] == ":" and normalized[0].isalpha():
        return "windows-rooted-path"
    if any(part == ".." for part in normalized.split("/")):
        return "parent-traversal"

    return None


def _fallback_reason_for_code(path: str, error_code: str) -> str:
    if error_code == "empty-path":
        return "path must not be empty"
    if error_code == "absolute-path":
        return f"path must be repository-relative: {path}"
    if error_code == "parent-traversal":
        return f"path must not traverse outside the repository: {path}"
    if error_code == "windows-rooted-path":
        return f"windows-rooted path is not allowed: {path}"
    if error_code == "null-byte":
        return "path must not contain NUL bytes"

    return f"invalid path: {path}"


def _fallback_error_code(path: str) -> str:
    precheck_code = _fallback_precheck_error_code(path)
    if precheck_code is not None:
        return precheck_code

    return "invalid-path"


def _sensitivity(category: str, severity: str, reason: str) -> dict[str, str]:
    return {
        "category": category,
        "severity": severity,
        "reason": reason,
    }


def _is_secret_path(segments: list[str], file_name: str) -> bool:
    return (
        file_name == ".env"
        or file_name.startswith(".env.")
        or file_name.endswith((".pem", ".key", ".p12", ".pfx"))
        or any(
            segment in {"secrets", ".secrets", "credentials", ".credentials"}
            for segment in segments
        )
    )


def _is_ci_path(segments: list[str]) -> bool:
    return (
        segments[:2] == [".github", "workflows"]
        or segments[:1] == [".gitlab"]
        or ".circleci" in segments
    )


def _is_policy_path(segments: list[str]) -> bool:
    return segments[:1] == ["policies"] or "policies" in segments


def _is_dependency_path(file_name: str) -> bool:
    return file_name in {
        "go.mod",
        "go.sum",
        "cargo.toml",
        "cargo.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
    }


def _is_config_path(segments: list[str], file_name: str) -> bool:
    return (
        "config" in file_name
        or "settings" in file_name
        or file_name
        in {
            ".gitignore",
            ".dockerignore",
            "dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
        }
        or any(segment in {"config", "configs", ".config"} for segment in segments)
    )


def _is_generated_path(segments: list[str]) -> bool:
    return any(
        segment
        in {
            "node_modules",
            "__pycache__",
            ".pytest_cache",
            "target",
            "dist",
            "build",
            ".mypy_cache",
            ".ruff_cache",
            ".venv",
            "vendor",
        }
        for segment in segments
    )


def _is_test_path(segments: list[str], file_name: str) -> bool:
    return (
        any(segment in {"test", "tests", "__tests__"} for segment in segments)
        or file_name.startswith("test_")
        or file_name.endswith(("_test.py", "_test.go", ".test.ts", ".test.tsx"))
    )


def _is_documentation_path(segments: list[str], file_name: str) -> bool:
    return (
        any(segment in {"docs", "doc", "documentation"} for segment in segments)
        or file_name in {"readme.md", "license", "license.md"}
        or file_name.endswith((".md", ".rst"))
    )
