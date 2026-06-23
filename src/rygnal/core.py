"""Public Rygnal SDK convenience wrapper."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rygnal.approval import ApprovalWorkflow
from rygnal.audit_logger import AuditLogger
from rygnal.interceptor import RygnalInterceptor
from rygnal.models import RuntimeMode, ToolRequest
from rygnal.policy_engine import PolicyEngine, load_default_policy_engine
from rygnal.risk_engine import RiskEngine
from rygnal.tool_executor import ToolExecutor, ToolHandler


class Rygnal:
    """High-level SDK wrapper for Rygnal Core.

    This class gives developers a simple entry point without requiring them to
    manually wire the policy engine, risk engine, audit logger, and tool executor.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        audit_logger: AuditLogger | None = None,
        tool_executor: ToolExecutor | None = None,
        risk_engine: RiskEngine | None = None,
        approval_workflow: ApprovalWorkflow | None = None,
        runtime_mode: RuntimeMode | str = RuntimeMode.ENFORCE,
        audit_log_path: str | Path = "logs/audit_log.jsonl",
    ) -> None:
        self.runtime_mode = RuntimeMode(runtime_mode)
        self.policy_engine = policy_engine or load_default_policy_engine(self.runtime_mode)
        self.audit_logger = audit_logger or AuditLogger(audit_log_path)
        self.tool_executor = tool_executor or ToolExecutor()
        self.risk_engine = risk_engine or RiskEngine()
        self.approval_workflow = approval_workflow

        self.interceptor = RygnalInterceptor(
            policy_engine=self.policy_engine,
            audit_logger=self.audit_logger,
            tool_executor=self.tool_executor,
            risk_engine=self.risk_engine,
            approval_workflow=self.approval_workflow,
            runtime_mode=self.runtime_mode,
        )

    @classmethod
    def from_defaults(
        cls,
        runtime_mode: RuntimeMode | str = RuntimeMode.ENFORCE,
        audit_log_path: str | Path = "logs/audit_log.jsonl",
    ) -> Rygnal:
        """Create Rygnal with default policy, risk, audit, and execution components."""
        return cls(runtime_mode=runtime_mode, audit_log_path=audit_log_path)

    def register_tool(self, tool_name: str, handler: ToolHandler) -> None:
        """Register a trusted tool handler."""
        self.tool_executor.register(tool_name, handler)

    def intercept(self, request: ToolRequest) -> Any:
        """Intercept a tool request."""
        return self.interceptor.intercept(request)

    def handle(self, request: ToolRequest) -> Any:
        """Alias for intercept."""
        return self.intercept(request)
