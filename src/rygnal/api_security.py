"""ASGI authentication and operational limits."""

from __future__ import annotations

import asyncio
import hmac
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

from rygnal.runtime_config import ApiRuntimeConfig

ASGIApp = Callable[
    [
        dict[str, Any],
        Callable[[], Awaitable[dict[str, Any]]],
        Callable[[dict[str, Any]], Awaitable[None]],
    ],
    Awaitable[None],
]

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{7,127}$")

_SECURITY_HEADERS: tuple[
    tuple[bytes, bytes],
    ...,
] = (
    (
        b"x-content-type-options",
        b"nosniff",
    ),
    (
        b"x-frame-options",
        b"DENY",
    ),
    (
        b"referrer-policy",
        b"no-referrer",
    ),
    (
        b"cache-control",
        b"no-store",
    ),
    (
        b"content-security-policy",
        b"default-src 'none'; frame-ancestors 'none'",
    ),
    (
        b"permissions-policy",
        b"camera=(), microphone=(), geolocation=()",
    ),
)


class RequestBodyLimitExceeded(Exception):
    """Raised while receiving an oversized body."""


class ApiRequestGuardMiddleware:
    """Fail-closed API boundary middleware."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: ApiRuntimeConfig,
        token: str | None,
    ) -> None:
        self.app = app
        self.config = config
        self.token = token
        self._admission_lock = asyncio.Lock()
        self._active_requests = 0

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[
            [],
            Awaitable[dict[str, Any]],
        ],
        send: Callable[
            [dict[str, Any]],
            Awaitable[None],
        ],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        headers = list(scope.get("headers", []))
        request_id = normalize_request_id(
            _first_header(
                headers,
                b"x-request-id",
            )
        )
        scope.setdefault(
            "state",
            {},
        )["request_id"] = request_id

        validation_error = self._validate_headers(headers)

        if validation_error is not None:
            await _send_error(
                send,
                status_code=validation_error[0],
                code=validation_error[1],
                message=validation_error[2],
                request_id=request_id,
            )
            return

        path = str(scope.get("path", ""))

        if self.config.auth_required and path not in {"/health", "/ready"}:
            candidate = bearer_token_from_headers(headers)

            if not _token_matches(
                candidate,
                self.token,
            ):
                await _send_error(
                    send,
                    status_code=401,
                    code="authentication_failed",
                    message="Authentication failed.",
                    request_id=request_id,
                    extra_headers=(
                        (
                            b"www-authenticate",
                            b"Bearer",
                        ),
                    ),
                )
                return

        if not await self._acquire():
            await _send_error(
                send,
                status_code=429,
                code="request_overloaded",
                message="Request capacity is exhausted.",
                request_id=request_id,
                retryable=True,
            )
            return

        received_bytes = 0
        response_started = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_bytes

            message = await receive()

            if message.get("type") == "http.request":
                body = message.get(
                    "body",
                    b"",
                )
                received_bytes += len(body)

                if received_bytes > self.config.max_request_body_bytes:
                    raise RequestBodyLimitExceeded

            return message

        async def guarded_send(
            message: dict[str, Any],
        ) -> None:
            nonlocal response_started

            if message.get("type") == "http.response.start":
                response_started = True
                response_headers = [
                    (
                        bytes(name).lower(),
                        bytes(value),
                    )
                    for name, value in message.get(
                        "headers",
                        [],
                    )
                    if bytes(name).lower()
                    not in {
                        b"server",
                        b"x-powered-by",
                    }
                ]
                existing = {name for name, _value in response_headers}

                for name, value in _SECURITY_HEADERS + (
                    (
                        b"x-request-id",
                        request_id.encode("ascii"),
                    ),
                ):
                    if name not in existing:
                        response_headers.append(
                            (
                                name,
                                value,
                            )
                        )

                message = {
                    **message,
                    "headers": response_headers,
                }

            await send(message)

        try:
            await asyncio.wait_for(
                self.app(
                    scope,
                    limited_receive,
                    guarded_send,
                ),
                timeout=(self.config.request_timeout_seconds),
            )
        except RequestBodyLimitExceeded:
            if not response_started:
                await _send_error(
                    send,
                    status_code=413,
                    code="request_body_too_large",
                    message=("Request body exceeds the configured limit."),
                    request_id=request_id,
                )
        except TimeoutError:
            if not response_started:
                await _send_error(
                    send,
                    status_code=504,
                    code="request_timeout",
                    message="Request timed out.",
                    request_id=request_id,
                    retryable=True,
                )
        finally:
            await self._release()

    def _validate_headers(
        self,
        headers: list[tuple[bytes, bytes]],
    ) -> tuple[int, str, str] | None:
        if len(headers) > self.config.max_header_count:
            return (
                431,
                "too_many_headers",
                "Request contains too many headers.",
            )

        total_bytes = sum(len(name) + len(value) for name, value in headers)

        if total_bytes > self.config.max_header_bytes:
            return (
                431,
                "headers_too_large",
                "Request headers exceed the configured limit.",
            )

        host_value = _first_header(
            headers,
            b"host",
        )

        if host_value is not None:
            host = _host_without_port(host_value)

            if host.lower() not in self.config.allowed_hosts:
                return (
                    400,
                    "invalid_host",
                    "HTTP host is not allowed.",
                )

        content_lengths = [
            value.strip() for name, value in headers if name.lower() == b"content-length"
        ]

        if content_lengths:
            if len(set(content_lengths)) != 1:
                return (
                    400,
                    "conflicting_content_length",
                    "Conflicting Content-Length headers.",
                )

            try:
                content_length = int(
                    content_lengths[0],
                    10,
                )
            except ValueError:
                return (
                    400,
                    "invalid_content_length",
                    "Content-Length is invalid.",
                )

            if content_length < 0:
                return (
                    400,
                    "invalid_content_length",
                    "Content-Length is invalid.",
                )

            if content_length > self.config.max_request_body_bytes:
                return (
                    413,
                    "request_body_too_large",
                    "Request body exceeds the configured limit.",
                )

        return None

    async def _acquire(self) -> bool:
        async with self._admission_lock:
            if self._active_requests >= self.config.max_concurrency:
                return False

            self._active_requests += 1
            return True

    async def _release(self) -> None:
        async with self._admission_lock:
            if self._active_requests > 0:
                self._active_requests -= 1


def normalize_request_id(
    candidate: str | None,
) -> str:
    """Validate an incoming request ID or generate one."""
    if candidate is not None and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate

    return f"req_{uuid4().hex}"


def bearer_token_from_headers(
    headers: Any,
) -> str:
    """Read one bounded RFC 6750 bearer credential."""
    if hasattr(headers, "get"):
        raw = headers.get(
            "authorization",
            "",
        )
    else:
        raw_bytes = _first_header(
            list(headers),
            b"authorization",
        )
        raw = raw_bytes or ""

    if not isinstance(raw, str):
        raw = str(raw)

    scheme, separator, credential = raw.partition(" ")

    if not separator or scheme.lower() != "bearer":
        return ""

    candidate = credential.strip()

    if not candidate or len(candidate.encode("utf-8")) > 4096:
        return ""

    return candidate


def _token_matches(
    candidate: str,
    configured: str | None,
) -> bool:
    expected = configured or ""
    bounded_candidate = candidate if len(candidate) <= 4096 else ""

    return bool(configured) and hmac.compare_digest(
        bounded_candidate,
        expected,
    )


def _first_header(
    headers: list[tuple[bytes, bytes]],
    name: bytes,
) -> str | None:
    normalized = name.lower()

    for header_name, value in headers:
        if header_name.lower() == normalized:
            try:
                return value.decode("latin-1")
            except UnicodeDecodeError:
                return None

    return None


def _host_without_port(
    value: str,
) -> str:
    normalized = value.strip()

    if normalized.startswith("["):
        closing = normalized.find("]")

        if closing >= 0:
            return normalized[: closing + 1].lower()

    if normalized.count(":") == 1:
        host, _separator, _port = normalized.partition(":")
        return host.lower()

    return normalized.lower()


async def _send_error(
    send: Callable[
        [dict[str, Any]],
        Awaitable[None],
    ],
    *,
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    retryable: bool = False,
    extra_headers: tuple[
        tuple[bytes, bytes],
        ...,
    ] = (),
) -> None:
    payload = json.dumps(
        {
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
                "retryable": retryable,
                "details": None,
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    headers = [
        (
            b"content-type",
            b"application/json",
        ),
        (
            b"content-length",
            str(len(payload)).encode("ascii"),
        ),
        (
            b"x-request-id",
            request_id.encode("ascii"),
        ),
        *_SECURITY_HEADERS,
        *extra_headers,
    ]

    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": headers,
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": payload,
            "more_body": False,
        }
    )


__all__ = [
    "ApiRequestGuardMiddleware",
    "RequestBodyLimitExceeded",
    "bearer_token_from_headers",
    "normalize_request_id",
]
