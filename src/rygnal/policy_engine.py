"""Policy engine for Rygnal.

The policy engine decides whether an AI-agent tool request should be
allowed, blocked, simulated, or sent for human approval.
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from rygnal.models import (
    Decision,
    PolicyDecision,
    PolicyExplanation,
    PolicyRule,
    PolicySchema,
    RuntimeMode,
    Severity,
    ToolRequest,
)

DEFAULT_POLICY_PATH = Path("policies/default_policy.yaml")
PRODUCTION_SAFE_POLICY_PATH = Path("policies/production_safe_policy.yaml")

DEFAULT_POLICY_REGEX_MAX_PATTERN_BYTES = 2_048
DEFAULT_POLICY_REGEX_MAX_TARGET_BYTES = 8_192
POLICY_REGEX_MAX_PATTERN_BYTES_ENV = "RYGNAL_POLICY_REGEX_MAX_PATTERN_BYTES"
POLICY_REGEX_MAX_TARGET_BYTES_ENV = "RYGNAL_POLICY_REGEX_MAX_TARGET_BYTES"


class PolicyLoadError(ValueError):
    """Raised when a policy file violates a safety invariant."""


class PolicyRuntimeGuardError(ValueError):
    """Raised when runtime policy evaluation hits a resource guard."""

    def __init__(
        self,
        *,
        rule_id: str,
        field_name: str,
        value_bytes: int,
        limit: int,
    ) -> None:
        self.rule_id = rule_id
        self.field_name = field_name
        self.value_bytes = value_bytes
        self.limit = limit
        self.reason_code = "policy_regex_target_too_large"
        super().__init__(
            f"{self.reason_code}: policy rule {rule_id!r} field {field_name!r} "
            f"target is {value_bytes} bytes, exceeding limit {limit}"
        )


def _configured_positive_int(env_name: str, default: int) -> int:
    raw_value = os.environ.get(env_name)

    if raw_value is None:
        return default

    try:
        value = int(raw_value)
    except ValueError:
        return default

    if value <= 0:
        return default

    return value


def _utf8_len(value: str) -> int:
    return len(value.encode("utf-8"))


def _policy_regex_max_pattern_bytes() -> int:
    return _configured_positive_int(
        POLICY_REGEX_MAX_PATTERN_BYTES_ENV,
        DEFAULT_POLICY_REGEX_MAX_PATTERN_BYTES,
    )


def _policy_regex_max_target_bytes() -> int:
    return _configured_positive_int(
        POLICY_REGEX_MAX_TARGET_BYTES_ENV,
        DEFAULT_POLICY_REGEX_MAX_TARGET_BYTES,
    )


@dataclass(frozen=True)
class PolicyValidationProfile:
    """Safety invariants applied while loading a policy file.

    General test/custom policies may choose different defaults, but production
    profiles must make fail-closed behavior explicit and auditable.
    """

    name: str
    fail_closed_default: bool = False
    require_terminal_catch_all: bool = False
    terminal_disallowed_decisions: tuple[Decision, ...] = (
        Decision.ALLOW,
        Decision.SIMULATE,
    )


PRODUCTION_SAFE_POLICY_PROFILE = PolicyValidationProfile(
    name="production-safe",
    fail_closed_default=True,
    require_terminal_catch_all=True,
)


class PolicyEngine:
    """Evaluate AI-agent tool requests against policy rules."""

    def __init__(
        self,
        rules: list[PolicyRule] | None = None,
        policy_version: str = "policy.v1",
        default_decision: Decision = Decision.BLOCK,
    ) -> None:
        self.policy_version = policy_version
        self.default_decision = default_decision
        self.rules = sorted(rules or [], key=lambda rule: rule.priority)

    @classmethod
    def from_file(
        cls,
        policy_path: str | Path,
        *,
        validation_profile: PolicyValidationProfile | None = None,
    ) -> "PolicyEngine":
        """Load policy rules from a YAML file."""
        path = Path(policy_path)

        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        data = yaml.safe_load(path.read_text()) or {}

        if not isinstance(data, dict):
            raise ValueError("Policy file must be a YAML mapping.")

        policy_schema = PolicySchema(**data)
        cls._validate_policy_schema(
            policy_schema,
            validation_profile=validation_profile,
        )

        return cls(
            rules=policy_schema.rules,
            policy_version=policy_schema.policy_version,
            default_decision=policy_schema.default_decision,
        )

    @staticmethod
    def _validate_policy_schema(
        policy_schema: PolicySchema,
        *,
        validation_profile: PolicyValidationProfile | None = None,
    ) -> None:
        """Validate policy-level safety invariants before runtime evaluation."""
        seen_rule_ids: set[str] = set()

        for rule in policy_schema.rules:
            if rule.id in seen_rule_ids:
                raise ValueError(f"Duplicate policy rule id: {rule.id}")
            seen_rule_ids.add(rule.id)

            for field_name in ("target_matches", "target_not_matches"):
                pattern = getattr(rule, field_name)

                if pattern is None:
                    continue

                PolicyEngine._validate_policy_regex_pattern(
                    rule_id=rule.id,
                    field_name=field_name,
                    pattern=pattern,
                )

        if validation_profile is None:
            return

        PolicyEngine._validate_profile_default(policy_schema, validation_profile)

        if validation_profile.require_terminal_catch_all:
            PolicyEngine._validate_terminal_catch_all(policy_schema, validation_profile)

    @staticmethod
    def _validate_profile_default(
        policy_schema: PolicySchema,
        validation_profile: PolicyValidationProfile,
    ) -> None:
        if not validation_profile.fail_closed_default:
            return

        if policy_schema.default_decision in {Decision.ALLOW, Decision.SIMULATE}:
            raise PolicyLoadError(
                f"{validation_profile.name} policy must be fail-closed. "
                "default_decision must not allow or simulate unmatched actions."
            )

    @staticmethod
    def _validate_terminal_catch_all(
        policy_schema: PolicySchema,
        validation_profile: PolicyValidationProfile,
    ) -> None:
        terminal_rules = [
            rule for rule in policy_schema.rules if PolicyEngine._is_terminal_catch_all_rule(rule)
        ]

        if not terminal_rules:
            raise PolicyLoadError(
                f"{validation_profile.name} policy must define an explicit terminal catch-all rule."
            )

        if len(terminal_rules) > 1:
            raise PolicyLoadError(
                f"{validation_profile.name} policy must define exactly one terminal catch-all rule."
            )

        terminal_rule = terminal_rules[0]

        if terminal_rule.decision in validation_profile.terminal_disallowed_decisions:
            raise PolicyLoadError(
                f"{validation_profile.name} terminal catch-all rule must not allow "
                "or simulate unmatched actions."
            )

        for rule in policy_schema.rules:
            if rule.id == terminal_rule.id:
                continue

            if rule.priority >= terminal_rule.priority:
                raise PolicyLoadError(
                    f"{validation_profile.name} terminal catch-all rule must have "
                    "lowest precedence."
                )

    @staticmethod
    def _is_terminal_catch_all_rule(rule: PolicyRule) -> bool:
        return not PolicyEngine._matched_conditions(rule)

    def evaluate(
        self,
        request: ToolRequest,
        risk_assessment: Any | None = None,
    ) -> PolicyDecision:
        """Return the first matching policy decision with explain output."""
        evaluated_rule_ids: list[str] = []
        risk_context = self._risk_context(risk_assessment)

        for rule in self.rules:
            evaluated_rule_ids.append(rule.id)

            try:
                matched = self._matches(rule, request, risk_context)
            except PolicyRuntimeGuardError as exc:
                return PolicyDecision(
                    decision=Decision.BLOCK,
                    allowed=False,
                    severity=Severity.HIGH,
                    reason=str(exc),
                    policy_id=rule.id,
                    explanation=PolicyExplanation(
                        policy_version=self.policy_version,
                        matched=False,
                        matched_rule_id=rule.id,
                        matched_rule_priority=rule.priority,
                        matched_conditions=[exc.reason_code, exc.field_name],
                        evaluated_rule_ids=evaluated_rule_ids,
                        default_decision=False,
                    ),
                )

            if matched:
                return PolicyDecision(
                    decision=rule.decision,
                    allowed=self._is_allowed(rule.decision),
                    severity=rule.severity,
                    reason=rule.reason,
                    policy_id=rule.id,
                    explanation=PolicyExplanation(
                        policy_version=self.policy_version,
                        matched=True,
                        matched_rule_id=rule.id,
                        matched_rule_priority=rule.priority,
                        matched_conditions=self._matched_conditions(rule),
                        evaluated_rule_ids=evaluated_rule_ids,
                        default_decision=False,
                    ),
                )

        return PolicyDecision(
            decision=self.default_decision,
            allowed=self._is_allowed(self.default_decision),
            severity=Severity.LOW,
            reason=self._default_reason(),
            policy_id=None,
            explanation=PolicyExplanation(
                policy_version=self.policy_version,
                matched=False,
                matched_rule_id=None,
                matched_rule_priority=None,
                matched_conditions=[],
                evaluated_rule_ids=evaluated_rule_ids,
                default_decision=True,
            ),
        )

    def _matches(
        self,
        rule: PolicyRule,
        request: ToolRequest,
        risk_context: dict[str, Any],
    ) -> bool:
        target = request.target or ""

        if rule.tool_name and rule.tool_name != request.tool_name:
            return False

        if rule.action and rule.action != request.action:
            return False

        if rule.environment and rule.environment != request.environment:
            return False

        if rule.target_equals and rule.target_equals != target:
            return False

        if rule.target_contains and rule.target_contains not in target:
            return False

        if rule.target_matches and not self._safe_policy_regex_search(
            rule=rule,
            field_name="target_matches",
            pattern=rule.target_matches,
            value=target,
        ):
            return False

        if rule.target_not_matches and self._safe_policy_regex_search(
            rule=rule,
            field_name="target_not_matches",
            pattern=rule.target_not_matches,
            value=target,
        ):
            return False

        if rule.input_equals is not None and rule.input_equals != request.input:
            return False

        if rule.input_contains and rule.input_contains not in self._stringify(request.input):
            return False

        if rule.metadata_equals and not self._metadata_equals(
            request.metadata,
            rule.metadata_equals,
        ):
            return False

        if rule.metadata_contains and not self._metadata_contains(
            request.metadata,
            rule.metadata_contains,
        ):
            return False

        if rule.risk_level and rule.risk_level != risk_context.get("risk_level"):
            return False

        if rule.risk_score_min is not None:
            risk_score = risk_context.get("risk_score")
            if risk_score is None or risk_score < rule.risk_score_min:
                return False

        return True

    @staticmethod
    def _validate_policy_regex_pattern(
        *,
        rule_id: str,
        field_name: str,
        pattern: str,
    ) -> None:
        pattern_bytes = _utf8_len(pattern)
        pattern_limit = _policy_regex_max_pattern_bytes()

        if pattern_bytes > pattern_limit:
            raise PolicyLoadError(
                "policy_regex_pattern_too_large: "
                f"policy rule {rule_id!r} field {field_name!r} regex is "
                f"{pattern_bytes} bytes, exceeding limit {pattern_limit}"
            )

        try:
            re.compile(pattern)
        except re.error as exc:
            raise PolicyLoadError(
                f"Invalid regex in policy rule '{rule_id}' field '{field_name}': {exc}"
            ) from exc

    @staticmethod
    def _safe_policy_regex_search(
        *,
        rule: PolicyRule,
        field_name: str,
        pattern: str,
        value: str,
    ) -> bool:
        value_bytes = _utf8_len(value)
        value_limit = _policy_regex_max_target_bytes()

        if value_bytes > value_limit:
            raise PolicyRuntimeGuardError(
                rule_id=rule.id,
                field_name=field_name,
                value_bytes=value_bytes,
                limit=value_limit,
            )

        return re.search(pattern, value) is not None

    @staticmethod
    def _metadata_equals(
        request_metadata: dict[str, Any],
        expected_metadata: dict[str, Any],
    ) -> bool:
        """Return true when all expected metadata values match exactly."""
        for key, expected_value in expected_metadata.items():
            if request_metadata.get(key) != expected_value:
                return False

        return True

    @staticmethod
    def _metadata_contains(
        request_metadata: dict[str, Any],
        expected_metadata: dict[str, str],
    ) -> bool:
        """Return true when metadata string values contain expected text."""
        for key, expected_value in expected_metadata.items():
            actual_value = request_metadata.get(key)

            if expected_value not in PolicyEngine._stringify(actual_value):
                return False

        return True

    @staticmethod
    def _risk_context(risk_assessment: Any | None) -> dict[str, Any]:
        """Normalize optional risk assessment for policy evaluation."""
        if risk_assessment is None:
            return {}

        if hasattr(risk_assessment, "model_dump"):
            return risk_assessment.model_dump(mode="json")

        if isinstance(risk_assessment, dict):
            return risk_assessment

        return {}

    @staticmethod
    def _matched_conditions(rule: PolicyRule) -> list[str]:
        """Return the configured match conditions for a rule."""
        conditions: list[str] = []

        if rule.tool_name:
            conditions.append("tool_name")

        if rule.action:
            conditions.append("action")

        if rule.environment:
            conditions.append("environment")

        if rule.target_equals:
            conditions.append("target_equals")

        if rule.target_contains:
            conditions.append("target_contains")

        if rule.target_matches:
            conditions.append("target_matches")

        if rule.target_not_matches:
            conditions.append("target_not_matches")

        if rule.input_equals is not None:
            conditions.append("input_equals")

        if rule.input_contains:
            conditions.append("input_contains")

        if rule.metadata_equals:
            conditions.append("metadata_equals")

        if rule.metadata_contains:
            conditions.append("metadata_contains")

        if rule.risk_level:
            conditions.append("risk_level")

        if rule.risk_score_min is not None:
            conditions.append("risk_score_min")

        return conditions

    def _default_reason(self) -> str:
        if self.default_decision == Decision.ALLOW:
            return "No matching policy rule. Default allow."

        return f"No matching policy rule. Default decision: {self.default_decision.value}."

    @staticmethod
    def _is_allowed(decision: Decision) -> bool:
        return decision in {Decision.ALLOW, Decision.SIMULATE}

    @staticmethod
    def _stringify(value: Any) -> str:
        if value is None:
            return ""

        if isinstance(value, str):
            return value

        return str(value)


def load_default_policy_engine(
    runtime_mode: RuntimeMode | str = RuntimeMode.ENFORCE,
) -> PolicyEngine:
    """Load the default Rygnal policy engine for the requested runtime mode."""
    mode = RuntimeMode(runtime_mode)

    if mode == RuntimeMode.PRODUCTION_SAFE:
        return PolicyEngine.from_file(
            PRODUCTION_SAFE_POLICY_PATH,
            validation_profile=PRODUCTION_SAFE_POLICY_PROFILE,
        )

    engine = PolicyEngine.from_file(DEFAULT_POLICY_PATH)

    if engine.default_decision != Decision.BLOCK:
        raise PolicyLoadError(
            "default_policy.yaml must be fail-closed. default_decision must be 'block'."
        )

    return engine
