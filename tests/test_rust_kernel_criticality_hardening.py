import json
from typing import Any

import pytest


def _kernel():
    return pytest.importorskip("rygnal_kernel")


def _evaluate(payload: dict[str, Any]) -> dict[str, Any]:
    rygnal_kernel = _kernel()
    return json.loads(rygnal_kernel.evaluate_criticality(json.dumps(payload)))


def _criticality_payload(old_code: str, new_code: str) -> dict[str, str]:
    return {
        "file_path": "src/i18n.py",
        "action_type": "modified",
        "old_code": old_code,
        "new_code": new_code,
    }


def _assert_valid_semantic_metrics(result: dict[str, Any]) -> None:
    metrics = result["semantic_metrics"]

    assert isinstance(metrics["old_node_count"], int)
    assert isinstance(metrics["new_node_count"], int)
    assert isinstance(metrics["old_token_count"], int)
    assert isinstance(metrics["new_token_count"], int)
    assert isinstance(metrics["matched_node_count"], int)

    assert metrics["old_node_count"] >= 0
    assert metrics["new_node_count"] >= 0
    assert metrics["old_token_count"] >= 0
    assert metrics["new_token_count"] >= 0
    assert metrics["matched_node_count"] >= 0
    assert 0.0 <= metrics["survival_ratio"] <= 1.0


@pytest.mark.parametrize(
    ("case_name", "old_literal", "new_literal"),
    [
        (
            "devanagari_plus_emoji",
            "नमस्ते 🚀",
            "नमस्ते 🌍",
        ),
        (
            "cjk_ideographs",
            "東京",
            "大阪",
        ),
        (
            "rtl_arabic_and_hebrew",
            "مرحبا",
            "שלום",
        ),
        (
            "combining_mark_sequence",
            "cafe\u0301",
            "café",
        ),
        (
            "zero_width_joiner_emoji",
            "👨‍👩‍👧‍👦",
            "👩🏽‍💻",
        ),
        (
            "astral_plane_math_symbols",
            "𝛼 = 1",
            "𝛽 = 2",
        ),
        (
            "mixed_ascii_unicode_path_like_text",
            "config/सेवा/🚀",
            "config/サービス/🌍",
        ),
    ],
)
def test_criticality_handles_unicode_equivalence_classes_without_panic(
    case_name: str,
    old_literal: str,
    new_literal: str,
) -> None:
    old_code = f"def load_message():\n    message = {old_literal!r}\n    return message\n"
    new_code = f"def load_message():\n    message = {new_literal!r}\n    return message\n"

    result = _evaluate(_criticality_payload(old_code, new_code))

    assert result["path_category"] == "normal", case_name
    assert result["path_severity"] == "medium", case_name
    _assert_valid_semantic_metrics(result)


@pytest.mark.parametrize(
    ("case_name", "old_code", "new_code"),
    [
        (
            "many_broken_function_headers",
            "def broken_0(:\ndef broken_1(:\ndef broken_2(:\ndef broken_3(:\n",
            "def fixed_0():\n    return 0\n",
        ),
        (
            "unclosed_string_and_unmatched_parens",
            'def old():\n    value = "unterminated\n    return value(\n',
            'def new():\n    value = "fixed"\n    return value\n',
        ),
        (
            "broken_class_and_indent_mix",
            "class Broken(:\n def bad(:\n  return (\n",
            "class Fixed:\n    def ok(self):\n        return True\n",
        ),
    ],
)
def test_criticality_broken_python_uses_safe_fallback_not_ast_panic(
    case_name: str,
    old_code: str,
    new_code: str,
) -> None:
    result = _evaluate(_criticality_payload(old_code, new_code))

    assert result["path_category"] == "normal", case_name
    _assert_valid_semantic_metrics(result)

    # Broken Python must not use partially-corrupt AST metrics.
    assert result["semantic_metrics"]["old_node_count"] == 0
    assert result["semantic_metrics"]["new_node_count"] == 0


def test_criticality_broken_minified_python_does_not_reward_shared_error_line() -> None:
    result = _evaluate(
        _criticality_payload(
            "def broken(:\n" + ("x" * 2_000) + "\n",
            "def broken(:\n" + ("y" * 2_000) + "\n",
        )
    )

    _assert_valid_semantic_metrics(result)

    # Long/minified broken files should use bounded fallback and should not
    # accidentally count the shared invalid syntax line as meaningful survival.
    assert result["semantic_metrics"]["old_node_count"] == 0
    assert result["semantic_metrics"]["new_node_count"] == 0
    assert result["semantic_metrics"]["old_token_count"] == 2
    assert result["semantic_metrics"]["new_token_count"] == 2
    assert result["semantic_metrics"]["matched_node_count"] == 0
    assert result["semantic_metrics"]["survival_ratio"] == 0.0


def test_criticality_large_unicode_line_is_bounded_and_deterministic() -> None:
    old_line = "🚀" * 1_500
    new_line = "🌍" * 1_500

    result = _evaluate(
        _criticality_payload(
            f"def old():\n    value = {old_line!r}\n",
            f"def old():\n    value = {new_line!r}\n",
        )
    )

    _assert_valid_semantic_metrics(result)

    # This verifies the path does not panic or hang on very large multi-byte lines.
    assert result["semantic_metrics"]["old_token_count"] >= 0
    assert result["semantic_metrics"]["new_token_count"] >= 0


def test_criticality_rejects_invalid_json_without_native_crash() -> None:
    rygnal_kernel = _kernel()

    with pytest.raises(ValueError, match="Invalid criticality payload"):
        rygnal_kernel.evaluate_criticality("{not-json}")


def test_criticality_rejects_unsafe_path_with_structured_error() -> None:
    rygnal_kernel = _kernel()

    payload = {
        "file_path": "../evil.py",
        "action_type": "modified",
        "old_code": "def old():\n    return 1\n",
        "new_code": "def new():\n    return 2\n",
    }

    with pytest.raises(rygnal_kernel.CriticalityEvaluationError) as exc_info:
        rygnal_kernel.evaluate_criticality(json.dumps(payload))

    error_payload = json.loads(exc_info.value.args[0])

    assert error_payload["error_code"] == "parent-traversal"
    assert error_payload["reason"]
