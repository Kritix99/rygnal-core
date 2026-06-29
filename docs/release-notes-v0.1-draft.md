# Rygnal Core v0.1 Release Notes Draft

## Release

`v0.1-core-mvp`

## Summary

Rygnal Core v0.1 is the first local-first core MVP for runtime security and governance of AI-agent tool actions.

It provides a tested core runtime flow for intercepting tool requests, scoring risk, applying policy, logging decisions, and safely allowing, blocking, simulating, or requiring approval.

## Highlights

- Runtime interceptor for AI-agent tool requests
- Deterministic risk scoring
- YAML-based policy decisions
- Tamper-evident audit logging
- Sensitive data redaction
- Approval workflow foundation
- Runtime modes: observe, simulate, enforce
- Real scenario runner
- Human-readable CLI output
- Security hardening for file, shell, HTTP, and audit paths
- Docker-based reproducibility
- CI validation

## What This Release Is

This is a local-first core runtime MVP.

It is intended for:

- architecture validation
- internal engineering review
- local demos
- security workflow testing
- future SDK and agent integration foundation

## What This Release Is Not

This is not:

- a full SaaS product
- a production enterprise deployment
- a web dashboard
- a cloud-hosted service
- a direct, out-of-the-box real AI-agent framework integration or proxy gateway (integrated via example adapter wrappers for OpenAI, LangChain, and MCP under `examples/`)



## Validation

Before release, run:

```bash
make validate
docker compose build
docker compose run --rm rygnal pytest -q
docker compose run --rm rygnal python -m demo.run_demo
```
