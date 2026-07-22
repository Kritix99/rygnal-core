"""Local FastAPI service for Rygnal Core."""

from __future__ import annotations

import hmac
import ipaddress
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from rygnal.api_security import (
    ApiRequestGuardMiddleware,
    bearer_token_from_headers,
    normalize_request_id,
)
from rygnal.approval_queue import (
    APPROVAL_QUEUE_DB_PATH_ENV,
    ApprovalDeniedError,
    ApprovalNotFoundError,
    ApprovalStateConflictError,
    InMemoryApprovalQueue,
    SQLiteApprovalQueue,
)
from rygnal.approval_service import (
    ApprovalArtifactBindingError,
    ApprovalArtifactService,
    ApprovalOperationError,
    ApprovalOperationStateError,
)
from rygnal.audit_logger import AuditLogger
from rygnal.audit_query import AuditQuery, AuditQueryError, query_audit_events
from rygnal.models import ApprovalRequest, ApprovalStatus, AuditEvent, PolicyDecision, ToolRequest
from rygnal.patch_approval import write_patch_approval_decision_audit_event
from rygnal.policy_engine import PolicyEngine, load_default_policy_engine
from rygnal.risk_engine import RiskAssessment, RiskEngine
from rygnal.runtime_config import (
    RuntimeConfigV1,
    load_runtime_config,
)

REDACTED_VALUE = "[REDACTED]"
OPERATOR_TOKEN_ENV = "RYGNAL_OPERATOR_TOKEN"
SECRET_KEYWORDS = {
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "bearer",
    "client_secret",
    "credential",
    "key",
    "password",
    "private_key",
    "secret",
    "token",
}
SECRET_VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9._-]{8,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
)
INTERNAL_PATH_PATTERN = re.compile(r"(/workspaces/|/home/|/tmp/|[A-Za-z]:\\)")


class ApprovalDecisionRequest(BaseModel):
    """Request body for approval queue approve/reject actions."""

    decided_by: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class ArtifactApplyRequest(BaseModel):
    """Request to apply a previously approved patch artifact."""

    target_repo_path: str = Field(
        min_length=1,
        max_length=4096,
    )


class _EmptyAuditSource:
    """Read-only empty audit source used when API has no configured audit logger."""

    def read_events(self) -> list[AuditEvent]:
        return []


class EvaluateRequest(BaseModel):
    """Request body for local policy/risk evaluation."""

    tool_name: str
    action: str | None = None
    target: str | None = None
    input: Any | None = None
    user_id: str = "api_user"
    agent_id: str = "api_agent"
    environment: str = "local"
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_tool_request(self) -> ToolRequest:
        """Convert API payload to ToolRequest."""
        return ToolRequest(
            tool_name=self.tool_name,
            action=self.action,
            target=self.target,
            input=self.input,
            user_id=self.user_id,
            agent_id=self.agent_id,
            environment=self.environment,
            metadata=self.metadata,
        )


def _query_audit_events_response(
    *,
    request: Request,
    audit_query: AuditQuery,
    verify_integrity: bool,
    active_audit_logger: AuditLogger | None,
) -> Any:
    source = active_audit_logger if active_audit_logger is not None else _EmptyAuditSource()

    try:
        result = query_audit_events(
            source,
            audit_query,
            verify_integrity=verify_integrity,
        )
    except AuditQueryError as exc:
        return api_error_response(
            request=request,
            status_code=400,
            code="audit_query_error",
            message=redact_text(str(exc)),
            retryable=False,
            details=None,
        )

    return redact_for_api(result.to_dict())


def create_app(
    *,
    policy_engine: PolicyEngine | None = None,
    risk_engine: RiskEngine | None = None,
    audit_logger: AuditLogger | None = None,
    approval_queue: InMemoryApprovalQueue | None = None,
    approval_queue_db_path: str | Path | None = None,
    approval_service: ApprovalArtifactService | None = None,
    operator_token: str | None = None,
    runtime_config: RuntimeConfigV1 | None = None,
    readiness_probe: Callable[[], bool] | None = None,
) -> FastAPI:
    """Create the local Rygnal FastAPI app."""
    active_approval_service = approval_service
    active_runtime_config = (
        runtime_config
        if runtime_config is not None
        else load_runtime_config(
            environ=os.environ,
            allow_implicit_development=True,
        )
    )
    active_operator_token = (
        operator_token
        if operator_token is not None
        else active_runtime_config.api.operator_token_value()
    )
    app = FastAPI(
        title="Rygnal Core Local API",
        version="0.1.0",
        description="Local API for evaluating AI-agent tool actions.",
        docs_url=("/docs" if active_runtime_config.api.docs_enabled else None),
        redoc_url=("/redoc" if active_runtime_config.api.docs_enabled else None),
        openapi_url=("/openapi.json" if active_runtime_config.api.docs_enabled else None),
    )
    app.add_middleware(
        ApiRequestGuardMiddleware,
        config=active_runtime_config.api,
        token=active_operator_token,
    )

    active_policy_engine = policy_engine or load_default_policy_engine()
    active_risk_engine = risk_engine or RiskEngine()
    active_audit_logger = audit_logger
    configured_approval_queue_db_path = approval_queue_db_path
    if configured_approval_queue_db_path is None:
        configured_approval_queue_db_path = os.environ.get(APPROVAL_QUEUE_DB_PATH_ENV) or None

    if approval_queue is not None:
        active_approval_queue = approval_queue
    elif configured_approval_queue_db_path is not None:
        active_approval_queue = SQLiteApprovalQueue(configured_approval_queue_db_path)
    else:
        active_approval_queue = InMemoryApprovalQueue()

    @app.middleware("http")
    async def attach_request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.request_id = getattr(
            request.state,
            "request_id",
            None,
        ) or normalize_request_id(request.headers.get("X-Request-ID"))

        try:
            response = await call_next(request)
        except Exception:
            return api_error_response(
                request=request,
                status_code=500,
                code="internal_server_error",
                message="Internal server error.",
                retryable=True,
                details=None,
            )

        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return api_error_response(
            request=request,
            status_code=422,
            code="validation_error",
            message="Request validation failed.",
            retryable=False,
            details={"errors": exc.errors()},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        return api_error_response(
            request=request,
            status_code=exc.status_code,
            code="http_error",
            message=safe_http_message(exc),
            retryable=False,
            details=None,
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        del exc
        return api_error_response(
            request=request,
            status_code=500,
            code="internal_server_error",
            message="Internal server error.",
            retryable=True,
            details=None,
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "rygnal-core"}

    @app.get("/ready", response_model=None)
    def ready() -> JSONResponse:
        try:
            is_ready = readiness_probe() if readiness_probe is not None else True
        except Exception:
            is_ready = False

        return JSONResponse(
            status_code=200 if is_ready else 503,
            content={
                "status": ("ready" if is_ready else "not_ready"),
                "service": "rygnal-core",
            },
        )

    @app.get("/v1/audit/events", response_model=None)
    def audit_events(
        request: Request,
        event_id: str | None = None,
        trace_id: str | None = None,
        decision: str | None = None,
        tool_name: str | None = None,
        action: str | None = None,
        severity: str | None = None,
        policy_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = Query(default=100, ge=0),
        offset: int = Query(default=0, ge=0),
        newest_first: bool = False,
        verify_integrity: bool = False,
    ) -> Any:
        audit_query = AuditQuery(
            event_id=event_id,
            trace_id=trace_id,
            decision=decision,
            tool_name=tool_name,
            action=action,
            severity=severity,
            policy_id=policy_id,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
            newest_first=newest_first,
        )

        return _query_audit_events_response(
            request=request,
            audit_query=audit_query,
            verify_integrity=verify_integrity,
            active_audit_logger=active_audit_logger,
        )

    @app.get("/v1/audit/events/{event_id}", response_model=None)
    def audit_event_by_id(
        request: Request,
        event_id: str,
        verify_integrity: bool = False,
    ) -> Any:
        result = _query_audit_events_response(
            request=request,
            audit_query=AuditQuery(event_id=event_id, limit=1),
            verify_integrity=verify_integrity,
            active_audit_logger=active_audit_logger,
        )

        if isinstance(result, JSONResponse):
            return result

        if result.get("returned_count") == 0:
            return api_error_response(
                request=request,
                status_code=404,
                code="audit_event_not_found",
                message="Audit event not found.",
                retryable=False,
                details={"event_id": redact_text(event_id)},
            )

        return {"event": result["events"][0], "integrity_verified": result["integrity_verified"]}

    @app.post("/v1/approvals", status_code=201, response_model=None)
    def create_approval(payload: ApprovalRequest) -> dict[str, Any]:
        approval_request = active_approval_queue.submit(payload)
        queued = active_approval_queue.get(approval_request.approval_id)
        return {"approval": redact_for_api(queued.to_dict())}

    @app.get("/v1/approvals", response_model=None)
    def list_approvals(
        status: ApprovalStatus | None = None,
        limit: int = Query(default=100, ge=1),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        bounded_limit = min(
            limit,
            active_runtime_config.api.max_page_size,
        )
        all_approvals = tuple(item.to_dict() for item in active_approval_queue.list(status=status))
        approvals = all_approvals[offset : offset + bounded_limit]

        return {
            "approvals": redact_for_api(approvals),
            "returned_count": len(approvals),
            "limit": bounded_limit,
            "offset": offset,
        }

    @app.get("/v1/approvals/{approval_id}", response_model=None)
    def get_approval(request: Request, approval_id: str) -> Any:
        try:
            queued = active_approval_queue.get(approval_id)
        except ApprovalNotFoundError as exc:
            return api_error_response(
                request=request,
                status_code=404,
                code="approval_not_found",
                message=redact_text(str(exc)),
                retryable=False,
                details=None,
            )

        return {"approval": redact_for_api(queued.to_dict())}

    @app.post("/v1/approvals/{approval_id}/approve", response_model=None)
    def approve_approval(
        request: Request,
        approval_id: str,
        payload: ApprovalDecisionRequest,
    ) -> Any:
        return _decide_approval(
            request=request,
            approval_id=approval_id,
            decided_by=payload.decided_by,
            reason=payload.reason,
            approve=True,
            approval_queue=active_approval_queue,
            audit_logger=active_audit_logger,
        )

    @app.post("/v1/approvals/{approval_id}/reject", response_model=None)
    def reject_approval(
        request: Request,
        approval_id: str,
        payload: ApprovalDecisionRequest,
    ) -> Any:
        return _decide_approval(
            request=request,
            approval_id=approval_id,
            decided_by=payload.decided_by,
            reason=payload.reason,
            approve=False,
            approval_queue=active_approval_queue,
            audit_logger=active_audit_logger,
        )

    @app.get(
        "/v1/patch-approvals",
        response_model=None,
    )
    def list_patch_approvals(
        status: ApprovalStatus | None = None,
        limit: int = Query(default=100, ge=1),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        service = require_patch_operation_service(active_approval_service)

        try:
            all_views = service.list(status=status)
        except Exception as exc:
            raise_patch_operation_http_error(exc)

        bounded_limit = min(
            limit,
            active_runtime_config.api.max_page_size,
        )
        views = all_views[offset : offset + bounded_limit]

        return {
            "approvals": tuple(view.to_dict() for view in views),
            "returned_count": len(views),
            "limit": bounded_limit,
            "offset": offset,
        }

    @app.get(
        "/v1/patch-approvals/{approval_id}",
        response_model=None,
    )
    def inspect_patch_approval(
        approval_id: str,
    ) -> dict[str, Any]:
        service = require_patch_operation_service(active_approval_service)

        try:
            return service.inspect_approval(approval_id).to_dict()
        except Exception as exc:
            raise_patch_operation_http_error(exc)

    @app.post(
        "/v1/patch-approvals/{approval_id}/approve",
        response_model=None,
    )
    def approve_patch_approval(
        approval_id: str,
        body: ApprovalDecisionRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_patch_operator(
            request,
            operator_token=active_operator_token,
        )
        service = require_patch_operation_service(active_approval_service)

        try:
            return service.approve(
                approval_id,
                decided_by=body.decided_by,
                reason=body.reason,
            ).to_dict()
        except Exception as exc:
            raise_patch_operation_http_error(exc)

    @app.post(
        "/v1/patch-approvals/{approval_id}/reject",
        response_model=None,
    )
    def reject_patch_approval(
        approval_id: str,
        body: ApprovalDecisionRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_patch_operator(
            request,
            operator_token=active_operator_token,
        )
        service = require_patch_operation_service(active_approval_service)

        try:
            return service.reject(
                approval_id,
                decided_by=body.decided_by,
                reason=body.reason,
            ).to_dict()
        except Exception as exc:
            raise_patch_operation_http_error(exc)

    @app.get(
        "/v1/patch-artifacts/{artifact_id}",
        response_model=None,
    )
    def inspect_patch_artifact(
        artifact_id: str,
    ) -> dict[str, Any]:
        service = require_patch_operation_service(active_approval_service)

        try:
            return service.inspect_artifact(artifact_id).to_dict()
        except Exception as exc:
            raise_patch_operation_http_error(exc)

    @app.post(
        "/v1/patch-artifacts/{artifact_id}/apply",
        response_model=None,
    )
    def apply_patch_artifact(
        artifact_id: str,
        body: ArtifactApplyRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_patch_operator(
            request,
            operator_token=active_operator_token,
        )
        service = require_patch_operation_service(active_approval_service)

        try:
            result = service.apply_artifact(
                artifact_id,
                Path(body.target_repo_path),
            )
        except Exception as exc:
            raise_patch_operation_http_error(exc)

        summary = getattr(
            result,
            "audit_summary",
            None,
        )

        if callable(summary):
            summary = summary()

        return {
            "artifact_id": artifact_id,
            "applied": bool(getattr(result, "applied", False)),
            "result": redact_for_api(summary),
        }

    @app.post("/v1/evaluate")
    def evaluate(payload: EvaluateRequest) -> dict[str, Any]:
        request = payload.to_tool_request()
        risk_assessment: RiskAssessment = active_risk_engine.assess(request)
        policy_decision: PolicyDecision = active_policy_engine.evaluate(
            request,
            risk_assessment=risk_assessment,
        )

        audit_event: AuditEvent | None = None
        if active_audit_logger is not None:
            audit_event = active_audit_logger.log_decision(
                request=request,
                policy_decision=policy_decision,
                metadata={
                    "source": "local_fastapi",
                    "risk": risk_assessment.model_dump(mode="json"),
                },
            )

        return redact_for_api(
            {
                "request": request.model_dump(mode="json"),
                "risk_assessment": risk_assessment.model_dump(mode="json"),
                "policy_decision": policy_decision.model_dump(mode="json"),
                "audit_event": audit_event.model_dump(mode="json") if audit_event else None,
            }
        )

    app.state.rygnal_runtime_config = active_runtime_config
    app.state.rygnal_ready_probe = readiness_probe

    return app


def _decide_approval(
    *,
    request: Request,
    approval_id: str,
    decided_by: str,
    reason: str,
    approve: bool,
    approval_queue: InMemoryApprovalQueue,
    audit_logger: AuditLogger | None,
) -> Any:
    try:
        queued = (
            approval_queue.approve(
                approval_id,
                decided_by=decided_by,
                reason=reason,
            )
            if approve
            else approval_queue.reject(
                approval_id,
                decided_by=decided_by,
                reason=reason,
            )
        )
    except ApprovalNotFoundError as exc:
        return api_error_response(
            request=request,
            status_code=404,
            code="approval_not_found",
            message=redact_text(str(exc)),
            retryable=False,
            details=None,
        )
    except ApprovalDeniedError as exc:
        return api_error_response(
            request=request,
            status_code=403,
            code="approval_denied",
            message=redact_text(str(exc)),
            retryable=False,
            details=None,
        )
    except ApprovalStateConflictError as exc:
        return api_error_response(
            request=request,
            status_code=409,
            code="approval_state_conflict",
            message=redact_text(str(exc)),
            retryable=False,
            details=None,
        )

    audit_event = None
    if audit_logger is not None and queued.decision is not None:
        audit_event = write_patch_approval_decision_audit_event(
            audit_logger,
            queued.request,
            queued.decision,
        )

    return {
        "approval": redact_for_api(queued.to_dict()),
        "approval_decision": redact_for_api(
            queued.decision.model_dump(mode="json") if queued.decision is not None else None
        ),
        "audit_event": redact_for_api(
            audit_event.model_dump(mode="json") if audit_event is not None else None
        ),
    }


def require_patch_operation_service(
    service: ApprovalArtifactService | None,
) -> ApprovalArtifactService:
    """Return the configured operation service or fail safely."""
    if service is None:
        raise HTTPException(
            status_code=503,
            detail=("Durable patch operations are unavailable for this application instance."),
        )

    return service


def require_patch_operator(
    request: Request,
    *,
    operator_token: str | None,
) -> None:
    """Require the configured operator credential."""
    if operator_token:
        candidate = request.headers.get(
            "x-rygnal-operator-token",
            "",
        )

        if not candidate:
            candidate = bearer_token_from_headers(request.headers)

        if not hmac.compare_digest(
            candidate,
            operator_token,
        ):
            raise HTTPException(
                status_code=403,
                detail="Operator authentication failed.",
            )

        return

    client = request.client
    host = client.host if client is not None else ""

    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"

    if not loopback:
        raise HTTPException(
            status_code=403,
            detail=("Patch mutation endpoints require authenticated or loopback access."),
        )


def raise_patch_operation_http_error(
    exc: Exception,
) -> None:
    """Map operational failures to safe HTTP responses."""
    if isinstance(exc, ApprovalNotFoundError):
        status_code = 404
    elif isinstance(
        exc,
        ApprovalArtifactBindingError,
    ):
        status_code = 404 if str(exc).startswith("No approval") else 409
    elif isinstance(
        exc,
        ApprovalOperationStateError,
    ):
        status_code = 409
    elif isinstance(exc, ApprovalOperationError):
        status_code = 400
    else:
        status_code = 500

    message = str(exc) if status_code < 500 else "Patch operation failed safely."

    raise HTTPException(
        status_code=status_code,
        detail=message,
    ) from exc


def api_error_response(
    *,
    request: Request,
    status_code: int,
    code: str,
    message: str,
    retryable: bool,
    details: Mapping[str, Any] | None,
) -> JSONResponse:
    """Return a stable, redacted API error response."""
    request_id = getattr(request.state, "request_id", None) or f"req_{uuid4().hex}"

    payload = {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
            "retryable": retryable,
            "details": redact_for_api(details) if details is not None else None,
        }
    }

    return JSONResponse(
        status_code=status_code,
        content=payload,
        headers={"X-Request-ID": request_id},
    )


def safe_http_message(exc: StarletteHTTPException) -> str:
    """Return safe HTTP error text without echoing arbitrary internals."""
    if isinstance(exc, HTTPException) and isinstance(exc.detail, str):
        return redact_text(exc.detail)

    if exc.status_code == 404:
        return "Not found."

    return "HTTP error."


def redact_for_api(value: Any) -> Any:
    """Redact secret-like material before returning local API JSON."""
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if is_sensitive_key(key_text):
                redacted[key_text] = REDACTED_VALUE
            else:
                redacted[key_text] = redact_for_api(item)
        return redacted

    if isinstance(value, list | tuple):
        return [redact_for_api(item) for item in value]

    if isinstance(value, str):
        return redact_text(value)

    return value


def redact_text(value: str) -> str:
    """Redact secret-like strings and local filesystem paths."""
    redacted = value

    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub(REDACTED_VALUE, redacted)

    if INTERNAL_PATH_PATTERN.search(redacted):
        return REDACTED_VALUE

    return redacted


def is_sensitive_key(key: str) -> bool:
    """Return true for common credential-bearing key names."""
    normalized = key.lower().replace("-", "_")
    return any(keyword in normalized for keyword in SECRET_KEYWORDS)
