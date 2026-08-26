# Known Limitations

Rygnal Core is intentionally scoped as a local-first safety and governance architecture foundation.

## Not production-ready

Rygnal Core must not be presented as an enterprise-grade production runtime security layer. The project contains substantial policy, risk, approval, audit, recovery, CLI, and Rust safety-kernel work, but several product and containment boundaries remain incomplete.

## No production containment backend

The current command backend implementation supports only explicit `unsafe_local` execution. A configured container backend may be detected, but it is not implemented as an executable guarded-command backend and does not provide verified containment.

A disposable Git workspace protects the trusted working tree from direct mutation during review, but it is not an OS-level sandbox. Process-group cleanup is lifecycle management, not a security boundary.

Track the unresolved containment decision in [issue #274](https://github.com/Rygnal/rygnal-core/issues/274).

## AI-agent integration status

Rygnal Core provides local adapter examples:

- [OpenAI tool-calling adapter](../examples/openai_tool_calling_adapter.py)
- [LangChain tool wrapper](../examples/langchain_tool_wrapper.py)
- [MCP tool-call adapter](../examples/mcp_tool_call_adapter.py)

These are controlled examples, not a production, provider-neutral interception gateway. The first real agent-agnostic AI Reviewer pipeline is tracked in [issue #370](https://github.com/Rygnal/rygnal-core/issues/370).

## Approval workflow status

Implemented local components include:

- [In-memory and SQLite approval queues](../src/rygnal/approval_queue.py)
- [Approval API endpoints](../src/rygnal/api.py)
- [Role-based authorization](../src/rygnal/approval_authorization.py)
- [Role policy](../policies/roles.yaml)
- Self-approval protection
- Patch digest and baseline binding
- Durable patch artifacts and recovery reconciliation

The Go local approval flow is not yet fully connected to the shared Python approval queue. This remaining contract is tracked in [issue #333](https://github.com/Rygnal/rygnal-core/issues/333).

Still missing:

- Frontend approval dashboard
- Notification delivery
- Distributed multi-user approval coordination
- Enterprise identity and SSO

## UI/TUI status

The Go CLI and terminal approval components exist, but a canonical user-experience proposal covering event mapping, privacy defaults, risk presentation, and the minimum first TUI milestone remains open in [issue #348](https://github.com/Rygnal/rygnal-core/issues/348).

## Policy-engine limitations

The policy engine supports prioritized rules, schema validation, metadata conditions, input matching, and risk thresholds.

It does not currently provide:

- OPA/Rego support
- Organization-level policy distribution
- Rich temporal or distributed policy state
- Central policy administration

## Risk-engine limitations

The risk system combines Python orchestration with Rust/PyO3 safety primitives, including path checks and Tree-Sitter-based semantic analysis.

Remaining limitations include:

- Static secret-pattern coverage
- Limited dynamic threat intelligence
- No production agent behavior-history service
- Fallback telemetry and operational observability gaps tracked in [issue #298](https://github.com/Rygnal/rygnal-core/issues/298)

## Local service and SaaS scope

The local FastAPI service exposes approval and audit operations. Rygnal Core does not include a SaaS control plane, multi-tenancy, billing, enterprise authentication, SIEM integration, or a production web dashboard.

## Current architecture truth

Use [Architecture Status and Issue Evidence](architecture-status.md) for implementation evidence and [Architecture Roadmap](architecture-roadmap.md) for active sequencing.

Rygnal Core is useful for architecture validation, local experimentation, and continued development. It is not yet a complete production security product.
