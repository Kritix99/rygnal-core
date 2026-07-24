"""Strict versioned runtime configuration for Rygnal."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import tomllib
from collections.abc import Mapping
from copy import deepcopy
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

RUNTIME_CONFIG_SCHEMA_VERSION = "rygnal.runtime.v1"
RUNTIME_CONFIG_PATH_ENV = "RYGNAL_CONFIG_FILE"
RUNTIME_ENVIRONMENT_ENV = "RYGNAL_ENVIRONMENT"

MAX_CONFIG_FILE_BYTES = 64 * 1024
MAX_TOKEN_FILE_BYTES = 8 * 1024
MIN_OPERATOR_TOKEN_BYTES = 32
MAX_OPERATOR_TOKEN_BYTES = 4096

_TRUE_VALUES = frozenset(
    {
        "1",
        "true",
        "yes",
        "on",
    }
)
_FALSE_VALUES = frozenset(
    {
        "0",
        "false",
        "no",
        "off",
    }
)
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]{1,255}$")


class RuntimeConfigError(RuntimeError):
    """Raised when runtime configuration is unsafe or invalid."""


class RuntimeEnvironment(StrEnum):
    """Supported runtime security environments."""

    DEVELOPMENT = "development"
    PRODUCTION = "production"


class StorageRuntimeConfig(BaseModel):
    """Persistent-storage configuration."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    data_dir: Path | None = None
    backup_retention_count: int = Field(
        default=5,
        ge=1,
        le=50,
    )


class ApiRuntimeConfig(BaseModel):
    """FastAPI and network security configuration."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    host: str = "127.0.0.1"
    port: int = Field(
        default=8787,
        ge=1,
        le=65535,
    )
    allow_remote: bool = False
    auth_required: bool = False
    operator_token: SecretStr | None = Field(
        default=None,
        repr=False,
        exclude=True,
    )
    operator_token_file: Path | None = None

    max_request_body_bytes: int = Field(
        default=1024 * 1024,
        ge=1024,
        le=16 * 1024 * 1024,
    )
    max_header_bytes: int = Field(
        default=32 * 1024,
        ge=1024,
        le=256 * 1024,
    )
    max_header_count: int = Field(
        default=100,
        ge=1,
        le=500,
    )
    max_concurrency: int = Field(
        default=32,
        ge=1,
        le=1024,
    )
    request_timeout_seconds: float = Field(
        default=30.0,
        ge=0.05,
        le=300.0,
    )
    max_page_size: int = Field(
        default=500,
        ge=1,
        le=5000,
    )
    docs_enabled: bool = True

    allowed_hosts: tuple[str, ...] = (
        "127.0.0.1",
        "localhost",
        "[::1]",
        "::1",
        "testserver",
    )

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("API host must not be empty.")

        if not _SAFE_HOST_RE.fullmatch(normalized):
            raise ValueError("API host contains unsupported characters.")

        return normalized

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized: list[str] = []

        for value in values:
            host = value.strip().lower()

            if not host or host == "*" or not _SAFE_HOST_RE.fullmatch(host):
                raise ValueError("Allowed hosts must be explicit safe host names or addresses.")

            if host not in normalized:
                normalized.append(host)

        if not normalized:
            raise ValueError("At least one allowed HTTP host is required.")

        return tuple(normalized)

    @field_validator("operator_token_file")
    @classmethod
    def validate_token_file_path(
        cls,
        value: Path | None,
    ) -> Path | None:
        if value is None:
            return None

        candidate = value.expanduser()

        if not candidate.is_absolute():
            raise ValueError("Operator-token file must be absolute.")

        return candidate

    @field_validator("operator_token")
    @classmethod
    def validate_inline_token(
        cls,
        value: SecretStr | None,
    ) -> SecretStr | None:
        """Defer strength checks to the security context.

        Development loopback operation retains compatibility
        with the existing local operator-token contract.
        Production, authenticated, and remote modes apply the
        strict token policy in RuntimeConfigV1.
        """
        return value

    @model_validator(mode="after")
    def validate_auth_sources(
        self,
    ) -> ApiRuntimeConfig:
        if self.operator_token is not None and self.operator_token_file is not None:
            raise ValueError("Configure one operator-token source, not both.")

        return self

    def operator_token_value(self) -> str | None:
        """Return the secret token only at the execution boundary."""
        if self.operator_token is None:
            return None

        return self.operator_token.get_secret_value()


class RuntimeConfigV1(BaseModel):
    """Current production runtime configuration schema."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    schema_version: Literal["rygnal.runtime.v1"] = RUNTIME_CONFIG_SCHEMA_VERSION
    environment: RuntimeEnvironment = RuntimeEnvironment.DEVELOPMENT
    storage: StorageRuntimeConfig = Field(default_factory=StorageRuntimeConfig)
    api: ApiRuntimeConfig = Field(default_factory=ApiRuntimeConfig)

    @model_validator(mode="after")
    def validate_security_policy(
        self,
    ) -> RuntimeConfigV1:
        remote = not is_loopback_host(self.api.host)
        token_present = (
            self.api.operator_token is not None or self.api.operator_token_file is not None
        )

        if remote and not self.api.allow_remote:
            raise ValueError("Non-loopback binding requires explicit remote-access opt-in.")

        if remote and not self.api.auth_required:
            raise ValueError("Remote API access requires authentication.")

        if remote and not token_present:
            raise ValueError("Remote API access requires an operator token.")

        if self.environment == RuntimeEnvironment.PRODUCTION:
            if not self.api.auth_required:
                raise ValueError("Production API authentication is mandatory.")

            if not token_present:
                raise ValueError("Production requires an operator token.")

            if self.api.docs_enabled:
                raise ValueError("Production API documentation must be disabled.")

        security_sensitive_token = (
            self.environment == RuntimeEnvironment.PRODUCTION or self.api.auth_required or remote
        )

        if security_sensitive_token and self.api.operator_token is not None:
            try:
                validate_operator_token(self.api.operator_token.get_secret_value())
            except RuntimeConfigError:
                raise ValueError(
                    "Configured operator token does not meet security requirements."
                ) from None

        return self


def load_runtime_config(
    *,
    config_path: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
    allow_implicit_development: bool = True,
) -> RuntimeConfigV1:
    """Load file, environment, then explicit overrides."""
    environment = os.environ if environ is None else environ
    configured_path = (
        config_path if config_path is not None else environment.get(RUNTIME_CONFIG_PATH_ENV)
    )

    raw: dict[str, Any]

    if configured_path is not None:
        raw = _load_config_file(Path(configured_path))

        if "schema_version" not in raw:
            raise RuntimeConfigError("Versioned runtime configuration is required.")
    else:
        requested_environment = (
            environment.get(
                RUNTIME_ENVIRONMENT_ENV,
                RuntimeEnvironment.DEVELOPMENT.value,
            )
            .strip()
            .lower()
        )

        if requested_environment == RuntimeEnvironment.PRODUCTION.value:
            raise RuntimeConfigError(
                "Production requires an explicit versioned configuration file."
            )

        if not allow_implicit_development:
            raise RuntimeConfigError("An explicit versioned configuration file is required.")

        raw = {"schema_version": (RUNTIME_CONFIG_SCHEMA_VERSION)}

    merged = deepcopy(raw)
    _deep_merge(
        merged,
        _environment_overrides(environment),
    )

    if overrides is not None:
        _deep_merge(
            merged,
            dict(overrides),
        )

    try:
        config = RuntimeConfigV1.model_validate(merged)
    except Exception:
        raise RuntimeConfigError("Runtime configuration validation failed.") from None

    if config.api.operator_token is None and config.api.operator_token_file is not None:
        token = _secure_read_text(
            config.api.operator_token_file,
            maximum_bytes=MAX_TOKEN_FILE_BYTES,
            purpose="operator-token",
            require_private_permissions=True,
        ).strip()

        security_sensitive_token = (
            config.environment == RuntimeEnvironment.PRODUCTION
            or config.api.auth_required
            or not is_loopback_host(config.api.host)
        )

        if security_sensitive_token:
            try:
                validate_operator_token(token)
            except RuntimeConfigError:
                raise RuntimeConfigError("Operator-token configuration is invalid.") from None

        api = config.api.model_copy(
            update={
                "operator_token": SecretStr(token),
            }
        )
        config = config.model_copy(update={"api": api})

    return config


def validate_operator_token(token: str) -> None:
    """Validate a bearer token without returning it."""
    encoded = token.encode(
        "utf-8",
        errors="strict",
    )

    if not (MIN_OPERATOR_TOKEN_BYTES <= len(encoded) <= MAX_OPERATOR_TOKEN_BYTES):
        raise RuntimeConfigError("Operator token does not meet the required size bounds.")

    if token != token.strip():
        raise RuntimeConfigError("Operator token must not contain leading or trailing whitespace.")

    if len(set(encoded)) < 8 or encoded.count(encoded[:1]) == len(encoded):
        raise RuntimeConfigError("Operator token does not provide sufficient variation.")

    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise RuntimeConfigError("Operator token must use printable ASCII characters.")


def is_loopback_host(host: str) -> bool:
    """Return whether a bind host is explicitly loopback."""
    normalized = host.strip().lower()

    if normalized == "localhost":
        return True

    candidate = normalized.strip("[]")

    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _load_config_file(
    path: Path,
) -> dict[str, Any]:
    text = _secure_read_text(
        path,
        maximum_bytes=MAX_CONFIG_FILE_BYTES,
        purpose="runtime-configuration",
        require_private_permissions=True,
    )

    suffix = path.suffix.lower()

    try:
        if suffix == ".json":
            value = json.loads(text)
        elif suffix in {".toml", ".tml"}:
            value = tomllib.loads(text)
        else:
            raise RuntimeConfigError("Runtime configuration must be JSON or TOML.")
    except RuntimeConfigError:
        raise
    except Exception:
        raise RuntimeConfigError("Runtime configuration could not be parsed.") from None

    if not isinstance(value, dict):
        raise RuntimeConfigError("Runtime configuration root must be an object.")

    return value


def _secure_read_text(
    path: Path,
    *,
    maximum_bytes: int,
    purpose: str,
    require_private_permissions: bool,
) -> str:
    original = path.expanduser()

    if not original.is_absolute():
        raise RuntimeConfigError(f"{purpose} file must be absolute.")

    _reject_symlink_components(original)

    if original.is_symlink():
        raise RuntimeConfigError(f"Refusing symlink {purpose} file.")

    try:
        metadata = original.stat(follow_symlinks=False)
    except OSError:
        raise RuntimeConfigError(f"Unable to inspect {purpose} file.") from None

    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeConfigError(f"{purpose} path must be a regular file.")

    if metadata.st_size > maximum_bytes:
        raise RuntimeConfigError(f"{purpose} file exceeds its size limit.")

    if os.name != "nt":
        trusted_owners = {
            0,
            os.getuid(),
        }

        if metadata.st_uid not in trusted_owners:
            raise RuntimeConfigError(f"{purpose} file has an untrusted owner.")

        if require_private_permissions and metadata.st_mode & 0o077:
            raise RuntimeConfigError(f"{purpose} file permissions are too broad.")

    flags = os.O_RDONLY

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        descriptor = os.open(
            original,
            flags,
        )
    except OSError:
        raise RuntimeConfigError(f"Unable to open {purpose} file safely.") from None

    try:
        data = os.read(
            descriptor,
            maximum_bytes + 1,
        )
    finally:
        os.close(descriptor)

    if len(data) > maximum_bytes:
        raise RuntimeConfigError(f"{purpose} file exceeds its size limit.")

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeConfigError(f"{purpose} file must be strict UTF-8.") from None


def _reject_symlink_components(
    path: Path,
) -> None:
    current = Path(path.anchor)

    for component in path.parts[1:-1]:
        current /= component

        if current.is_symlink():
            raise RuntimeConfigError("Configuration path traverses a symlink.")


def _environment_overrides(
    environment: Mapping[str, str],
) -> dict[str, Any]:
    root: dict[str, Any] = {}

    mapping: tuple[
        tuple[str, tuple[str, ...], str],
        ...,
    ] = (
        (
            RUNTIME_ENVIRONMENT_ENV,
            ("environment",),
            "string",
        ),
        (
            "RYGNAL_DATA_DIR",
            ("storage", "data_dir"),
            "string",
        ),
        (
            "RYGNAL_API_HOST",
            ("api", "host"),
            "string",
        ),
        (
            "RYGNAL_API_PORT",
            ("api", "port"),
            "integer",
        ),
        (
            "RYGNAL_API_ALLOW_REMOTE",
            ("api", "allow_remote"),
            "boolean",
        ),
        (
            "RYGNAL_API_AUTH_REQUIRED",
            ("api", "auth_required"),
            "boolean",
        ),
        (
            "RYGNAL_API_TOKEN",
            ("api", "operator_token"),
            "string",
        ),
        (
            "RYGNAL_OPERATOR_TOKEN",
            ("api", "operator_token"),
            "string",
        ),
        (
            "RYGNAL_API_TOKEN_FILE",
            ("api", "operator_token_file"),
            "string",
        ),
        (
            "RYGNAL_API_MAX_BODY_BYTES",
            ("api", "max_request_body_bytes"),
            "integer",
        ),
        (
            "RYGNAL_API_MAX_HEADER_BYTES",
            ("api", "max_header_bytes"),
            "integer",
        ),
        (
            "RYGNAL_API_MAX_HEADERS",
            ("api", "max_header_count"),
            "integer",
        ),
        (
            "RYGNAL_API_MAX_CONCURRENCY",
            ("api", "max_concurrency"),
            "integer",
        ),
        (
            "RYGNAL_API_REQUEST_TIMEOUT",
            ("api", "request_timeout_seconds"),
            "float",
        ),
        (
            "RYGNAL_API_MAX_PAGE_SIZE",
            ("api", "max_page_size"),
            "integer",
        ),
        (
            "RYGNAL_API_DOCS_ENABLED",
            ("api", "docs_enabled"),
            "boolean",
        ),
    )

    for name, destination, value_type in mapping:
        if name not in environment:
            continue

        raw = environment[name]

        try:
            value = _parse_environment_value(
                raw,
                value_type,
            )
        except ValueError:
            raise RuntimeConfigError(f"Environment variable {name} has an invalid value.") from None

        _set_nested(
            root,
            destination,
            value,
        )

    return root


def _parse_environment_value(
    raw: str,
    value_type: str,
) -> Any:
    if value_type == "string":
        return raw

    if value_type == "integer":
        return int(raw, 10)

    if value_type == "float":
        return float(raw)

    if value_type == "boolean":
        normalized = raw.strip().lower()

        if normalized in _TRUE_VALUES:
            return True

        if normalized in _FALSE_VALUES:
            return False

        raise ValueError("invalid boolean")

    raise ValueError("unsupported environment conversion")


def _set_nested(
    root: dict[str, Any],
    destination: tuple[str, ...],
    value: Any,
) -> None:
    current = root

    for key in destination[:-1]:
        child = current.setdefault(key, {})

        if not isinstance(child, dict):
            raise RuntimeConfigError(
                "Configuration override path conflicts with an existing value."
            )

        current = child

    current[destination[-1]] = value


def _deep_merge(
    target: dict[str, Any],
    source: Mapping[str, Any],
) -> None:
    for key, value in source.items():
        existing = target.get(key)

        if isinstance(existing, dict) and isinstance(value, Mapping):
            _deep_merge(
                existing,
                value,
            )
        else:
            target[key] = deepcopy(value)


__all__ = [
    "ApiRuntimeConfig",
    "MAX_CONFIG_FILE_BYTES",
    "MAX_TOKEN_FILE_BYTES",
    "MAX_OPERATOR_TOKEN_BYTES",
    "MIN_OPERATOR_TOKEN_BYTES",
    "RUNTIME_CONFIG_PATH_ENV",
    "RUNTIME_CONFIG_SCHEMA_VERSION",
    "RuntimeConfigError",
    "RuntimeConfigV1",
    "RuntimeEnvironment",
    "StorageRuntimeConfig",
    "is_loopback_host",
    "load_runtime_config",
    "validate_operator_token",
]
