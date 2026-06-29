# Rygnal Core Architecture

## Overview

Rygnal Core is designed as a runtime control layer for AI-agent tool actions. The codebase is organized as a three-language monorepo:

- **Go (CLI and TUI)**: Manages CLI commands, process containment, terminal approval prompt UX, and routes tool-interception requests.
- **Python (Engine and Orchestration)**: Handles policy evaluation, risk analysis, local HTTP API services, database audit logs, and approval queue workflows.
- **Rust (Safety Kernel)**: Provides high-performance, deterministic primitives (AST parsing via Tree-Sitter, path safety, and criticality assessment) exported as a Python extension via PyO3.

The core architecture is modular so each part can evolve independently.

## Runtime Flow

```
ToolRequest
→ RygnalInterceptor
→ RiskEngine
→ PolicyEngine
→ ApprovalWorkflow
→ AuditLogger
→ ToolExecutor
→ InterceptorResult
```

## Main Components

### ToolRequest

Represents the action an AI agent wants to perform.

Examples:

- read a file
- delete a file
- run shell command
- send data externally
- write a file

### RygnalInterceptor

The main runtime control point.

It receives the tool request and coordinates:

- risk scoring
- policy decision
- approval workflow
- audit logging
- safe execution

### RiskEngine

Scores how risky a tool request is.

Current output includes:

- risk score
- risk level
- reasons
- signals

### PolicyEngine

Applies policy rules and returns a decision.

Current decisions:

- `allow`
- `block`
- `simulate`
- `require_approval`

### ApprovalWorkflow

Handles actions that require human approval.

Current safe default:

- reject approval-required actions if no approval resolver is configured

### AuditLogger

Writes structured JSONL audit events.

Current audit features:

- event ID
- trace ID
- timestamp
- decision
- reason
- risk metadata
- approval metadata
- sensitive data redaction
- hash-chain integrity

### ToolExecutor

Executes only registered tools.

Rygnal does not execute arbitrary agent-generated code directly.

### Scenario Runner

Runs controlled local workflows to prove the runtime behavior.

## Current Architecture Status

This architecture is strong for a local MVP, but it is not yet a full enterprise runtime platform.
