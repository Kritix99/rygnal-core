# Known Limitations

Rygnal Core is intentionally scoped as a local-first safety and containment kernel.

## Not Production-Ready Yet

Rygnal Core should not be presented as an enterprise-grade production runtime security layer yet. It is designed as a local prototype and architecture foundation.

## AI-Agent Integration Status

Rygnal Core includes adapter wrappers and examples to integrate with popular AI agent frameworks:

- **OpenAI Tool Calling**: Integrated via [openai_tool_calling_adapter.py](file:///Users/bicky/Desktop/rygnal-core/examples/openai_tool_calling_adapter.py).
- **LangChain**: Integrated via [langchain_tool_wrapper.py](file:///Users/bicky/Desktop/rygnal-core/examples/langchain_tool_wrapper.py).
- **MCP (Model Context Protocol)**: Integrated via [mcp_tool_call_adapter.py](file:///Users/bicky/Desktop/rygnal-core/examples/mcp_tool_call_adapter.py).

Direct, out-of-the-box integration with other production orchestration frameworks (e.g., AutoGen, CrewAI) is not yet supported.

## Approval Workflow Status

A local approval workflow is fully supported, including:
- **Durable Approval Queue**: Supported via [InMemoryApprovalQueue](file:///Users/bicky/Desktop/rygnal-core/src/rygnal/approval_queue.py#L65) and [SQLiteApprovalQueue](file:///Users/bicky/Desktop/rygnal-core/src/rygnal/approval_queue.py#L160) configurations.
- **REST API Endpoints**: Exposed via `/v1/approvals` endpoints in [api.py](file:///Users/bicky/Desktop/rygnal-core/src/rygnal/api.py).
- **Role-Based Approvals**: Configured via [roles.yaml](file:///Users/bicky/Desktop/rygnal-core/policies/roles.yaml) and evaluated by the [ApprovalAuthorizationEngine](file:///Users/bicky/Desktop/rygnal-core/src/rygnal/approval_authorization.py).
- **Self-Approval Protection**: Requesters are blocked from approving their own actions.

Missing/Planned:
- Frontend user interface (Approval UI Dashboard)
- Notification system (e.g., Slack/Email triggers)
- Sophisticated timeout logic for distributed multi-user approval environments

## Policy Engine Status

The Policy Engine supports:
- **Prioritized Rules**: Policy rules are sorted by a `priority` field and evaluated sequentially (precedence-based decisions).
- **Policy Versioning**: Policies specify a schema-validated version (e.g., `policy.v2`).
- **Richer Match Conditions**: Evaluation supports metadata matching, input scanning, and risk thresholds.

Limitations:
- No OPA/Rego support yet
- No complex contextual logic (e.g., temporal or multi-stage state conditions)
- No organization-level policy management

## Risk Engine Status

The Risk Engine leverages both high-performance Rust safety primitives and PyO3 native extensions (e.g. AST parsing, path safety checks) alongside subjective risk evaluations (survival ratios, ownership multipliers).

Limitations:
- Static secret pattern matching (limited regex patterns)
- Gaps in dynamic threat intelligence
- No agent behavior history tracking

## Tool Adapters are Local/Sandboxed

Current adapters are controlled local adapters. They are not full production adapters.

## External API Adapter is Dry-Run

External send does not perform real network transmission. This is intentional for safety.

## SaaS and Dashboard Status

A full SaaS layer remains out of scope for the current local-first CLI/Core release.
- **Audit Queries**: Supported via the local FastAPI service query endpoints.
- **No SaaS Frontend UI**: Missing a visual dashboard, policy editor, user authentication (SSO/Identity providers), team management, or billing features.

## Summary

Rygnal Core is useful for architecture validation, local demos, and core runtime development. It is not yet a complete enterprise product.

