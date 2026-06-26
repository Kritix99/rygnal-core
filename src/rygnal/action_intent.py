"""Deterministic action-intent classification for agent and human operations.

This module infers observable operational intent from commands, changed paths,
and added diff lines. It does not infer hidden human motive and does not call an
AI model. It produces evidence-backed, multi-label intent reports that other
Rygnal layers can map to risk, audit, approval, or blocking decisions.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath


class ActionIntentCode(StrEnum):
    READ_ONLY_INSPECTION = "read_only_inspection"
    TEST_OR_BUILD = "test_or_build"
    SOURCE_CODE_CHANGE = "source_code_change"
    DEPENDENCY_CHANGE = "dependency_change"
    # Public intent-category label, not a credential value.
    SECRET_OR_CREDENTIAL_ACCESS = "secret_or_credential_access"  # nosec B105
    NETWORK_ACCESS = "network_access"
    EXTERNAL_DOWNLOAD = "external_download"
    FILESYSTEM_DESTRUCTIVE = "filesystem_destructive"
    DEPLOYMENT_OR_CI_CHANGE = "deployment_or_ci_change"
    CONTAINER_OR_INFRA_CHANGE = "container_or_infra_change"
    AUTH_OR_PERMISSION_CHANGE = "auth_or_permission_change"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUDIT_OR_APPROVAL_CHANGE = "audit_or_approval_change"
    APPROVAL_BYPASS_ATTEMPT = "approval_bypass_attempt"
    UNKNOWN_OR_AMBIGUOUS = "unknown_or_ambiguous"


class ActionIntentSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionIntentRecommendation(StrEnum):
    ALLOW = "allow"
    AUDIT = "audit"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


class ActionIntentEvidenceSource(StrEnum):
    COMMAND = "command"
    PATH = "path"
    DIFF = "diff"
    CONTEXT = "context"


_SEVERITY_ORDER: dict[ActionIntentSeverity, int] = {
    ActionIntentSeverity.LOW: 0,
    ActionIntentSeverity.MEDIUM: 1,
    ActionIntentSeverity.HIGH: 2,
    ActionIntentSeverity.CRITICAL: 3,
}

_RECOMMENDATION_ORDER: dict[ActionIntentRecommendation, int] = {
    ActionIntentRecommendation.ALLOW: 0,
    ActionIntentRecommendation.AUDIT: 1,
    ActionIntentRecommendation.REQUIRE_APPROVAL: 2,
    ActionIntentRecommendation.BLOCK: 3,
}


@dataclass(frozen=True)
class ActionIntentEvidence:
    source: ActionIntentEvidenceSource
    signal: str
    subject: str
    detail: str
    confidence_weight: float = 1.0


@dataclass(frozen=True)
class ActionIntent:
    code: ActionIntentCode
    severity: ActionIntentSeverity
    confidence: float
    recommendation: ActionIntentRecommendation
    reason: str
    evidence: tuple[ActionIntentEvidence, ...] = ()


@dataclass(frozen=True)
class ActionIntentReport:
    intents: tuple[ActionIntent, ...]
    unknown_signals: tuple[str, ...] = ()

    @property
    def primary_intent(self) -> ActionIntent | None:
        if not self.intents:
            return None
        return max(
            self.intents,
            key=lambda intent: (
                _SEVERITY_ORDER[intent.severity],
                _RECOMMENDATION_ORDER[intent.recommendation],
                intent.confidence,
                intent.code.value,
            ),
        )

    @property
    def max_severity(self) -> ActionIntentSeverity:
        primary = self.primary_intent
        return primary.severity if primary is not None else ActionIntentSeverity.LOW

    @property
    def recommended_action(self) -> ActionIntentRecommendation:
        if not self.intents:
            return ActionIntentRecommendation.ALLOW
        return max(
            (intent.recommendation for intent in self.intents),
            key=lambda recommendation: _RECOMMENDATION_ORDER[recommendation],
        )

    @property
    def intent_codes(self) -> tuple[str, ...]:
        return tuple(intent.code.value for intent in self.intents)

    def to_audit_metadata(self) -> dict[str, object]:
        return {
            "intent_codes": self.intent_codes,
            "max_severity": self.max_severity.value,
            "recommended_action": self.recommended_action.value,
            "unknown_signals": self.unknown_signals,
            "intents": tuple(
                {
                    "code": intent.code.value,
                    "severity": intent.severity.value,
                    "confidence": intent.confidence,
                    "recommendation": intent.recommendation.value,
                    "reason": intent.reason,
                    "evidence": tuple(
                        {
                            "source": evidence.source.value,
                            "signal": evidence.signal,
                            "subject": evidence.subject,
                            "detail": evidence.detail,
                            "confidence_weight": evidence.confidence_weight,
                        }
                        for evidence in intent.evidence
                    ),
                }
                for intent in self.intents
            ),
        }


@dataclass(frozen=True)
class _IntentProfile:
    severity: ActionIntentSeverity
    recommendation: ActionIntentRecommendation
    reason: str


_INTENT_PROFILES: dict[ActionIntentCode, _IntentProfile] = {
    ActionIntentCode.READ_ONLY_INSPECTION: _IntentProfile(
        ActionIntentSeverity.LOW,
        ActionIntentRecommendation.ALLOW,
        "Action appears to inspect repository or runtime context without mutation.",
    ),
    ActionIntentCode.TEST_OR_BUILD: _IntentProfile(
        ActionIntentSeverity.LOW,
        ActionIntentRecommendation.ALLOW,
        "Action appears to run tests, linting, formatting, or build validation.",
    ),
    ActionIntentCode.SOURCE_CODE_CHANGE: _IntentProfile(
        ActionIntentSeverity.MEDIUM,
        ActionIntentRecommendation.AUDIT,
        "Action changes source code or application behavior.",
    ),
    ActionIntentCode.DEPENDENCY_CHANGE: _IntentProfile(
        ActionIntentSeverity.HIGH,
        ActionIntentRecommendation.REQUIRE_APPROVAL,
        "Action changes dependency manifests, lockfiles, or package manager state.",
    ),
    ActionIntentCode.SECRET_OR_CREDENTIAL_ACCESS: _IntentProfile(
        ActionIntentSeverity.CRITICAL,
        ActionIntentRecommendation.BLOCK,
        "Action touches credentials, secrets, environment files, or private key material.",
    ),
    ActionIntentCode.NETWORK_ACCESS: _IntentProfile(
        ActionIntentSeverity.HIGH,
        ActionIntentRecommendation.REQUIRE_APPROVAL,
        "Action opens network access, remote transfer, or external communication.",
    ),
    ActionIntentCode.EXTERNAL_DOWNLOAD: _IntentProfile(
        ActionIntentSeverity.HIGH,
        ActionIntentRecommendation.REQUIRE_APPROVAL,
        "Action downloads or installs content from an external source.",
    ),
    ActionIntentCode.FILESYSTEM_DESTRUCTIVE: _IntentProfile(
        ActionIntentSeverity.CRITICAL,
        ActionIntentRecommendation.BLOCK,
        "Action can delete, overwrite, or irreversibly destroy filesystem state.",
    ),
    ActionIntentCode.DEPLOYMENT_OR_CI_CHANGE: _IntentProfile(
        ActionIntentSeverity.HIGH,
        ActionIntentRecommendation.REQUIRE_APPROVAL,
        "Action changes CI/CD, release, deployment, or automation behavior.",
    ),
    ActionIntentCode.CONTAINER_OR_INFRA_CHANGE: _IntentProfile(
        ActionIntentSeverity.HIGH,
        ActionIntentRecommendation.REQUIRE_APPROVAL,
        "Action changes container, infrastructure, runtime, or environment configuration.",
    ),
    ActionIntentCode.AUTH_OR_PERMISSION_CHANGE: _IntentProfile(
        ActionIntentSeverity.HIGH,
        ActionIntentRecommendation.REQUIRE_APPROVAL,
        "Action changes authentication, authorization, identity, or permission behavior.",
    ),
    ActionIntentCode.PRIVILEGE_ESCALATION: _IntentProfile(
        ActionIntentSeverity.CRITICAL,
        ActionIntentRecommendation.BLOCK,
        "Action attempts to elevate privileges or weaken least-privilege boundaries.",
    ),
    ActionIntentCode.AUDIT_OR_APPROVAL_CHANGE: _IntentProfile(
        ActionIntentSeverity.HIGH,
        ActionIntentRecommendation.REQUIRE_APPROVAL,
        "Action changes audit, approval, policy, or governance controls.",
    ),
    ActionIntentCode.APPROVAL_BYPASS_ATTEMPT: _IntentProfile(
        ActionIntentSeverity.CRITICAL,
        ActionIntentRecommendation.BLOCK,
        "Action appears to weaken, bypass, or disable approval or audit controls.",
    ),
    ActionIntentCode.UNKNOWN_OR_AMBIGUOUS: _IntentProfile(
        ActionIntentSeverity.MEDIUM,
        ActionIntentRecommendation.REQUIRE_APPROVAL,
        "Action contains ambiguous or unsupported signals that require review.",
    ),
}

_READ_ONLY_COMMANDS = {
    "awk",
    "cat",
    "cut",
    "find",
    "git",
    "grep",
    "head",
    "jq",
    "less",
    "ls",
    "rg",
    "sed",
    "tail",
    "tree",
    "wc",
}
_TEST_BUILD_COMMANDS = {
    "cargo",
    "go",
    "gradle",
    "make",
    "mvn",
    "npm",
    "pnpm",
    "poetry",
    "pytest",
    "python",
    "ruff",
    "tox",
    "uv",
    "yarn",
}
_NETWORK_COMMANDS = {
    "curl",
    "ftp",
    "gh",
    "git",
    "nc",
    "netcat",
    "nmap",
    "scp",
    "sftp",
    "ssh",
    "telnet",
    "wget",
}
_DOWNLOAD_COMMANDS = {
    "curl",
    "pip",
    "poetry",
    "pnpm",
    "npm",
    "uv",
    "wget",
    "yarn",
}
_DESTRUCTIVE_COMMANDS = {
    "dd",
    "docker",
    "git",
    "kubectl",
    "rm",
    "rmdir",
    "shred",
    "terraform",
}
_SECRET_COMMANDS = {
    "env",
    "gpg",
    "openssl",
    "pass",
    "printenv",
    "security",
    "ssh",
}
_PRIVILEGE_COMMANDS = {
    "chmod",
    "chown",
    "doas",
    "runas",
    "setcap",
    "su",
    "sudo",
}
_DEPENDENCY_COMMANDS = {
    "bundle",
    "cargo",
    "composer",
    "gem",
    "go",
    "gradle",
    "mvn",
    "npm",
    "pip",
    "pnpm",
    "poetry",
    "uv",
    "yarn",
}

_TEST_BUILD_SUBCOMMANDS = {
    "build",
    "check",
    "compile",
    "fmt",
    "format",
    "lint",
    "mypy",
    "pytest",
    "ruff",
    "test",
    "typecheck",
}
_DEPENDENCY_SUBCOMMANDS = {
    "add",
    "install",
    "lock",
    "remove",
    "sync",
    "update",
    "upgrade",
}
_NETWORK_SUBCOMMANDS = {
    "clone",
    "fetch",
    "pull",
    "push",
    "remote",
    "submodule",
}
_DESTRUCTIVE_SUBCOMMANDS = {
    "clean",
    "delete",
    "destroy",
    "drop",
    "prune",
    "remove",
    "rm",
}

_DEPENDENCY_FILE_NAMES = {
    "build.gradle",
    "cargo.lock",
    "cargo.toml",
    "composer.json",
    "composer.lock",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "gradle.lockfile",
    "package-lock.json",
    "package.json",
    "pipfile",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "pubspec.lock",
    "pubspec.yaml",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
}
_DEPENDENCY_NAME_PATTERNS = (
    "requirements-*.txt",
    "requirements_*.txt",
    "requirements*.in",
    "requirements*.txt",
)
_CI_PATH_PATTERNS = (
    ".circleci/*",
    ".github/actions/*",
    ".github/workflows/*",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    "buildkite.yml",
    "jenkinsfile",
)
_INFRA_PATH_PATTERNS = (
    ".dockerignore",
    "docker-compose*.yaml",
    "docker-compose*.yml",
    "dockerfile",
    "helm/*",
    "k8s/*",
    "kubernetes/*",
    "terraform/*",
    "*.tf",
)
_SECRET_PATH_PATTERNS = (
    ".aws/*",
    ".aws/credentials",
    ".azure/*",
    ".config/gcloud/*",
    ".docker/config.json",
    ".env",
    ".env.*",
    ".gnupg/*",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh/*",
    ".ssh/config",
    ".ssh/id_*",
    "*/.aws/*",
    "*/.aws/credentials",
    "*/.azure/*",
    "*/.config/gcloud/*",
    "*/.docker/config.json",
    "*/.env",
    "*/.env.*",
    "*/.gnupg/*",
    "*/.netrc",
    "*/.npmrc",
    "*/.pypirc",
    "*/.ssh/*",
)
_AUDIT_APPROVAL_PATH_SEGMENTS = {
    "approval",
    "approvals",
    "audit",
    "auditing",
    "governance",
    "policy",
    "policies",
}
_AUTH_SECURITY_PATH_SEGMENTS = {
    "auth",
    "authentication",
    "authorization",
    "identity",
    "iam",
    "oauth",
    "permission",
    "permissions",
    "rbac",
    "security",
    "session",
    "token",
}
_SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".swift",
    ".ts",
    ".tsx",
}
_DOC_EXTENSIONS = {".adoc", ".md", ".rst", ".txt"}
_DOC_FILE_NAMES = {"changelog", "code_of_conduct", "contributing", "license", "readme", "security"}

_SECRET_LITERAL_RE = re.compile(
    r"(?i)\b("
    r"api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"password|private[_-]?key|secret|sk-[a-z0-9_-]+"
    r")\b"
)
_NETWORK_LITERAL_RE = re.compile(r"(?i)\b(https?://|ssh://|git@|scp://|ftp://)")
_APPROVAL_BYPASS_RE = re.compile(
    r"(?i)\b("
    r"bypass approval|skip approval|disable approval|auto approve|self approval|"
    r"approval bypass|disable audit|skip audit|audit bypass|fail open"
    r")\b"
)
_DESTRUCTIVE_LITERAL_RE = re.compile(
    r"(?i)\b("
    r"rm\s+-[^\n]*r[^\n]*f|terraform\s+destroy|kubectl\s+delete|"
    r"drop\s+database|truncate\s+table"
    r")\b"
)
_PRIVILEGE_ESCALATION_RE = re.compile(
    r"(?i)\b("
    r"sudo|doas|runas|su\s+-|chmod\s+(\+s|[0-7]*[467][0-7]{2})|"
    r"chown\s+root|setcap|assume-role|iam:passrole"
    r")\b"
)
_ENCODED_EXECUTION_RE = re.compile(
    r"(?i)\b(base64\s+(-d|--decode)|xxd\s+-r|openssl\s+enc)\b"
    r".*(\|\s*(sh|bash|zsh|python|perl|ruby|node)\b|eval\b|exec\b)"
)
_DYNAMIC_EXECUTION_RE = re.compile(
    r"(?i)\b(eval|exec|os\.system|subprocess\.|child_process\.|Runtime\.getRuntime)\b"
)


def classify_action_intent(
    *,
    command: Iterable[str] = (),
    changed_paths: Iterable[str] = (),
    added_lines_by_path: Mapping[str, Iterable[str]] | None = None,
) -> ActionIntentReport:
    """Classify observable action intent from command, paths, and diff additions."""

    buckets: dict[ActionIntentCode, list[ActionIntentEvidence]] = {}
    unknown_signals: list[str] = []

    _collect_command_evidence(tuple(command), buckets, unknown_signals)
    for raw_path in changed_paths:
        _collect_path_evidence(raw_path, buckets)

    if added_lines_by_path:
        for raw_path, lines in added_lines_by_path.items():
            _collect_diff_evidence(raw_path, tuple(lines), buckets)

    intents = tuple(
        _build_intent(code, tuple(evidence))
        for code, evidence in sorted(buckets.items(), key=lambda item: item[0].value)
    )

    if unknown_signals:
        ambiguous_intent = _build_intent(
            ActionIntentCode.UNKNOWN_OR_AMBIGUOUS,
            _unknown_signal_evidence(unknown_signals),
        )
        intents = (*intents, ambiguous_intent)

    return ActionIntentReport(intents=intents, unknown_signals=tuple(unknown_signals))


def classify_command_intent(command: Iterable[str]) -> ActionIntentReport:
    return classify_action_intent(command=command)


def classify_path_intent(paths: Iterable[str]) -> ActionIntentReport:
    return classify_action_intent(changed_paths=paths)


def classify_diff_intent(
    added_lines_by_path: Mapping[str, Iterable[str]],
) -> ActionIntentReport:
    return classify_action_intent(added_lines_by_path=added_lines_by_path)


def _collect_command_evidence(
    command: tuple[str, ...],
    buckets: dict[ActionIntentCode, list[ActionIntentEvidence]],
    unknown_signals: list[str],
) -> None:
    if not command:
        return

    normalized = tuple(token.strip() for token in command if token and token.strip())
    if not normalized:
        return

    executable = PurePosixPath(normalized[0]).name.lower()
    lowered = tuple(token.lower() for token in normalized)
    command_text = " ".join(normalized)

    if executable in _READ_ONLY_COMMANDS and not _command_has_mutation_tokens(lowered):
        _add(
            buckets,
            ActionIntentCode.READ_ONLY_INSPECTION,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "read-only-command",
                executable,
                "Command family is commonly used for inspection.",
                0.65,
            ),
        )

    if _is_test_or_build_command(executable, lowered):
        _add(
            buckets,
            ActionIntentCode.TEST_OR_BUILD,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "test-build-command",
                executable,
                "Command appears to run test, lint, format, or build validation.",
                0.8,
            ),
        )

    if _is_dependency_command(executable, lowered):
        _add(
            buckets,
            ActionIntentCode.DEPENDENCY_CHANGE,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "dependency-command",
                executable,
                "Package manager command can change dependency state.",
                0.85,
            ),
        )

    if _is_network_command(executable, lowered):
        _add(
            buckets,
            ActionIntentCode.NETWORK_ACCESS,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "network-command",
                executable,
                "Command family or subcommand can access remote systems.",
                0.8,
            ),
        )

    if executable in _DOWNLOAD_COMMANDS and (
        executable in {"curl", "wget"} or _has_any_token(lowered, _DEPENDENCY_SUBCOMMANDS)
    ):
        _add(
            buckets,
            ActionIntentCode.EXTERNAL_DOWNLOAD,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "external-download-command",
                executable,
                "Command can download or install external content.",
                0.8,
            ),
        )

    if _is_destructive_command(executable, lowered, command_text):
        _add(
            buckets,
            ActionIntentCode.FILESYSTEM_DESTRUCTIVE,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "destructive-command",
                executable,
                "Command can delete, destroy, prune, or irreversibly modify state.",
                0.95,
            ),
        )

    if executable in _SECRET_COMMANDS or any(_is_secret_like_path(token) for token in lowered):
        _add(
            buckets,
            ActionIntentCode.SECRET_OR_CREDENTIAL_ACCESS,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "secret-access-command",
                executable,
                "Command or argument references credential, secret, or environment material.",
                0.9,
            ),
        )

    if _PRIVILEGE_ESCALATION_RE.search(command_text) or executable in _PRIVILEGE_COMMANDS:
        _add(
            buckets,
            ActionIntentCode.PRIVILEGE_ESCALATION,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "privilege-escalation-command",
                executable,
                "Command can elevate privileges or modify privileged ownership/capabilities.",
                0.95,
            ),
        )

    if _APPROVAL_BYPASS_RE.search(command_text):
        _add(
            buckets,
            ActionIntentCode.APPROVAL_BYPASS_ATTEMPT,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "approval-bypass-phrase",
                executable,
                "Command text references bypassing approval or audit controls.",
                0.95,
            ),
        )

    if _ENCODED_EXECUTION_RE.search(command_text):
        _add(
            buckets,
            ActionIntentCode.APPROVAL_BYPASS_ATTEMPT,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.COMMAND,
                "encoded-execution-wrapper",
                executable,
                "Command decodes or transforms content before dynamic execution.",
                0.95,
            ),
        )
        unknown_signals.append(f"{executable}:encoded-dynamic-execution")

    if _DYNAMIC_EXECUTION_RE.search(command_text):
        unknown_signals.append(f"{executable}:dynamic-execution")

    if executable in {"bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl"}:
        if any(token in {"-c", "--eval", "-e"} for token in lowered):
            unknown_signals.append(f"{executable}:inline-execution")


def _collect_path_evidence(
    raw_path: str,
    buckets: dict[ActionIntentCode, list[ActionIntentEvidence]],
) -> None:
    path = _normalize_path(raw_path)
    lower_path = path.lower()

    if _is_secret_like_path(lower_path):
        _add(
            buckets,
            ActionIntentCode.SECRET_OR_CREDENTIAL_ACCESS,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.PATH,
                "secret-sensitive-path",
                path,
                "Path indicates credential, key, token, or environment material.",
                0.95,
            ),
        )

    if _is_dependency_path(lower_path):
        _add(
            buckets,
            ActionIntentCode.DEPENDENCY_CHANGE,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.PATH,
                "dependency-path",
                path,
                "Path is a dependency manifest, lockfile, or package manager file.",
                0.9,
            ),
        )

    if _matches_any(lower_path, _CI_PATH_PATTERNS):
        _add(
            buckets,
            ActionIntentCode.DEPLOYMENT_OR_CI_CHANGE,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.PATH,
                "ci-cd-path",
                path,
                "Path is CI/CD workflow or pipeline configuration.",
                0.9,
            ),
        )

    if _matches_any(lower_path, _INFRA_PATH_PATTERNS):
        _add(
            buckets,
            ActionIntentCode.CONTAINER_OR_INFRA_CHANGE,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.PATH,
                "infra-container-path",
                path,
                "Path is container, infrastructure, or deployment configuration.",
                0.9,
            ),
        )

    if _has_any_segment(lower_path, _AUTH_SECURITY_PATH_SEGMENTS):
        _add(
            buckets,
            ActionIntentCode.AUTH_OR_PERMISSION_CHANGE,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.PATH,
                "auth-security-path",
                path,
                "Path indicates authentication, authorization, session, or permission code.",
                0.85,
            ),
        )

    if _is_audit_approval_control_path(lower_path, tuple(_segments(lower_path))):
        _add(
            buckets,
            ActionIntentCode.AUDIT_OR_APPROVAL_CHANGE,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.PATH,
                "audit-approval-policy-path",
                path,
                "Path indicates audit, approval, governance, or policy controls.",
                0.85,
            ),
        )

    if _is_source_path(lower_path):
        _add(
            buckets,
            ActionIntentCode.SOURCE_CODE_CHANGE,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.PATH,
                "source-code-path",
                path,
                "Path is source code or executable application logic.",
                0.65,
            ),
        )


def _collect_diff_evidence(
    raw_path: str,
    added_lines: tuple[str, ...],
    buckets: dict[ActionIntentCode, list[ActionIntentEvidence]],
) -> None:
    path = _normalize_path(raw_path)
    joined = "\n".join(added_lines)

    if not joined:
        return

    if _SECRET_LITERAL_RE.search(joined):
        _add(
            buckets,
            ActionIntentCode.SECRET_OR_CREDENTIAL_ACCESS,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.DIFF,
                "secret-like-added-content",
                path,
                "Added lines contain secret, token, password, or private key indicators.",
                0.9,
            ),
        )

    if _NETWORK_LITERAL_RE.search(joined):
        _add(
            buckets,
            ActionIntentCode.NETWORK_ACCESS,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.DIFF,
                "network-endpoint-added",
                path,
                "Added lines reference external network endpoints or remote transports.",
                0.75,
            ),
        )

    if _DESTRUCTIVE_LITERAL_RE.search(joined):
        _add(
            buckets,
            ActionIntentCode.FILESYSTEM_DESTRUCTIVE,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.DIFF,
                "destructive-operation-added",
                path,
                (
                    "Added lines include destructive filesystem, database, "
                    "or infrastructure operations."
                ),
                0.9,
            ),
        )

    if _APPROVAL_BYPASS_RE.search(joined):
        _add(
            buckets,
            ActionIntentCode.APPROVAL_BYPASS_ATTEMPT,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.DIFF,
                "approval-bypass-content",
                path,
                "Added lines reference bypassing approval or audit controls.",
                0.95,
            ),
        )

    if _ENCODED_EXECUTION_RE.search(joined):
        _add(
            buckets,
            ActionIntentCode.APPROVAL_BYPASS_ATTEMPT,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.DIFF,
                "encoded-execution-added",
                path,
                "Added lines decode or transform content before dynamic execution.",
                0.95,
            ),
        )
        _add(
            buckets,
            ActionIntentCode.UNKNOWN_OR_AMBIGUOUS,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.DIFF,
                "encoded-dynamic-execution-added",
                path,
                "Added encoded dynamic execution requires review.",
                0.7,
            ),
        )

    if _DYNAMIC_EXECUTION_RE.search(joined):
        _add(
            buckets,
            ActionIntentCode.UNKNOWN_OR_AMBIGUOUS,
            ActionIntentEvidence(
                ActionIntentEvidenceSource.DIFF,
                "dynamic-execution-added",
                path,
                "Added dynamic execution primitive requires review.",
                0.7,
            ),
        )


def _unknown_signal_evidence(
    unknown_signals: Iterable[str],
) -> tuple[ActionIntentEvidence, ...]:
    return tuple(
        ActionIntentEvidence(
            source=ActionIntentEvidenceSource.CONTEXT,
            signal="unknown-signal",
            subject=signal,
            detail="Signal could not be confidently mapped to a fully supported intent.",
            confidence_weight=0.5,
        )
        for signal in unknown_signals
    )


def _build_intent(
    code: ActionIntentCode,
    evidence: tuple[ActionIntentEvidence, ...],
) -> ActionIntent:
    profile = _INTENT_PROFILES[code]
    confidence = _noisy_or(e.confidence_weight for e in evidence)
    return ActionIntent(
        code=code,
        severity=profile.severity,
        confidence=confidence,
        recommendation=profile.recommendation,
        reason=profile.reason,
        evidence=evidence,
    )


def _add(
    buckets: dict[ActionIntentCode, list[ActionIntentEvidence]],
    code: ActionIntentCode,
    evidence: ActionIntentEvidence,
) -> None:
    buckets.setdefault(code, []).append(evidence)


def _noisy_or(weights: Iterable[float]) -> float:
    product = 1.0
    for weight in weights:
        bounded = min(max(weight, 0.0), 1.0)
        product *= 1.0 - bounded
    confidence = 1.0 - product
    if math.isclose(confidence, 1.0):
        return 1.0
    return round(confidence, 4)


def _normalize_path(raw_path: str) -> str:
    value = raw_path.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.lstrip("/")


def _path_name(path: str) -> str:
    return PurePosixPath(path).name.lower()


def _extension(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


def _segments(path: str) -> set[str]:
    segments: set[str] = set()
    for part in PurePosixPath(path).parts:
        if part in {"", "."}:
            continue
        lowered = part.lower()
        segments.add(lowered)
        segments.update(token for token in re.split(r"[^a-z0-9]+", lowered) if token)
    return segments


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(_matches(path, pattern) for pattern in patterns)


def _matches(path: str, pattern: str) -> bool:
    pattern = pattern.lower()
    return path == pattern or PurePosixPath(path).match(pattern)


def _has_any_segment(path: str, segments: set[str]) -> bool:
    return bool(_segments(path) & segments)


def _has_any_token(tokens: tuple[str, ...], expected: set[str]) -> bool:
    return any(token in expected for token in tokens)


def _is_dependency_path(path: str) -> bool:
    name = _path_name(path)
    return name in _DEPENDENCY_FILE_NAMES or any(
        PurePosixPath(name).match(pattern) for pattern in _DEPENDENCY_NAME_PATTERNS
    )


def _is_secret_like_path(path: str) -> bool:
    return _matches_any(path, _SECRET_PATH_PATTERNS)


def _is_audit_approval_control_path(
    path: str,
    segments: tuple[str, ...],
) -> bool:
    audit_approval_segments = {
        "approval",
        "approvals",
        "audit",
        "auditing",
        "governance",
        "policy",
        "policies",
    }
    if not _has_any_token(segments, audit_approval_segments):
        return False

    normalized = _normalize_path(path)
    parts = tuple(part for part in PurePosixPath(normalized).parts if part not in {"", "."})
    if not parts:
        return False

    first = parts[0]
    if first in {
        "doc",
        "docs",
        "documentation",
        "example",
        "examples",
        "sample",
        "samples",
    }:
        return False

    if first in {
        ".github",
        "config",
        "configs",
        "infra",
        "k8s",
        "policy",
        "policies",
        "scripts",
        "src",
        "terraform",
    }:
        return True

    suffix = PurePosixPath(normalized).suffix.lower()
    return suffix in {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".go",
        ".rs",
        ".java",
        ".yaml",
        ".yml",
        ".toml",
    }


def _is_non_source_document_or_output_path(path: str) -> bool:
    normalized = _normalize_path(path)
    parts = tuple(part for part in PurePosixPath(normalized).parts if part not in {"", "."})
    if not parts:
        return False

    first = parts[0]
    if first in {
        "doc",
        "docs",
        "documentation",
        "example",
        "examples",
        "sample",
        "samples",
    }:
        return True

    suffix = PurePosixPath(normalized).suffix.lower()
    if suffix in {".md", ".rst", ".txt"}:
        return True

    return False


def _is_source_path(path: str) -> bool:
    if _is_non_source_document_or_output_path(path):
        return False

    name = PurePosixPath(path).stem.lower()
    return _extension(path) in _SOURCE_EXTENSIONS or (
        _extension(path) in _DOC_EXTENSIONS and name not in _DOC_FILE_NAMES
    )


def _command_has_mutation_tokens(tokens: tuple[str, ...]) -> bool:
    return any(
        token
        in {
            ">",
            ">>",
            "--delete",
            "--force",
            "-d",
            "-f",
            "-i",
            "-rf",
            "-fr",
            "apply",
            "clean",
            "delete",
            "destroy",
            "fetch",
            "install",
            "merge",
            "move",
            "pull",
            "push",
            "rebase",
            "reset",
            "restore",
            "stash",
            "switch",
            "mv",
            "patch",
            "remove",
            "rm",
            "write",
        }
        for token in tokens
    )


def _is_test_or_build_command(executable: str, tokens: tuple[str, ...]) -> bool:
    if executable in {"pytest", "ruff", "tox"}:
        return True
    if executable == "python" and len(tokens) >= 3 and tokens[1] == "-m":
        return tokens[2] in {"pytest", "ruff", "mypy", "compileall"}
    return executable in _TEST_BUILD_COMMANDS and _has_any_token(
        tokens[1:], _TEST_BUILD_SUBCOMMANDS
    )


def _is_dependency_command(executable: str, tokens: tuple[str, ...]) -> bool:
    return executable in _DEPENDENCY_COMMANDS and _has_any_token(
        tokens[1:], _DEPENDENCY_SUBCOMMANDS
    )


def _is_network_command(executable: str, tokens: tuple[str, ...]) -> bool:
    direct_network_commands = _NETWORK_COMMANDS - {"git"}
    if executable in direct_network_commands:
        return True
    if executable == "git":
        return _has_any_token(tokens[1:], _NETWORK_SUBCOMMANDS)
    return False


def _is_destructive_command(executable: str, tokens: tuple[str, ...], command_text: str) -> bool:
    if executable == "rm":
        return any(
            token in {"-r", "-f", "-rf", "-fr", "--recursive", "--force"} for token in tokens[1:]
        )
    if executable in _DESTRUCTIVE_COMMANDS and _has_any_token(tokens[1:], _DESTRUCTIVE_SUBCOMMANDS):
        return True
    return bool(_DESTRUCTIVE_LITERAL_RE.search(command_text))
