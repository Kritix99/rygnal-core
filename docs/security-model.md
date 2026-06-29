# Security Model

## Security Goal

Rygnal Core protects tool execution boundaries for AI-agent actions.

## Core Safety Principles

- Never execute arbitrary agent-generated code directly
- Execute only registered tools
- Block known unsafe actions
- Require approval for sensitive actions
- Simulate risky external sends
- Redact secrets before logging
- Restrict file access to sandbox
- Use shell command allowlists
- Block local/private network destinations
- Keep audit logs tamper-evident

## Main Security Controls

### Policy Enforcement

Policy engine decides:

- allow
- block
- simulate
- require approval

### Risk Scoring

Risk engine assigns:

- risk score
- risk level
- reasons
- signals

### Approval

Approval-required actions do not execute automatically.

### Audit Logging

Every decision is logged with:

- event ID
- trace ID
- policy decision
- risk metadata
- approval metadata
- reason
- hash-chain integrity

### Tool Safety

Current tool safety includes:

- sandboxed file paths
- path traversal protection
- shell allowlist
- shell metacharacter blocking
- HTTP allowlist checks
- dry-run external sending

## Current Security Limitations

- No real production identity provider (IdP) integration
- No frontend dashboard/visual approval UI (a local HTTP API is supported for queue management and role checks)
- No direct out-of-the-box integration with production agent orchestration frameworks (integrated via example adapter wrappers for OpenAI, LangChain, and MCP)
- No advanced adversarial detection yet
- No enterprise policy backend yet

