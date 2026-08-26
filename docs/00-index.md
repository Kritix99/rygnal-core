# Rygnal Documentation Index

Rygnal is a runtime security and governance control layer for AI-agent tool actions.

This index separates docs by purpose so contributors can quickly find current product truth versus engineering design notes and historical material.

## Canonical Product Docs

These are user-facing and actively maintained.

- README.md
- getting-started.md
- architecture.md
- architecture-status.md
- architecture-roadmap.md
- security-model.md
- known-limitations.md
- v0.1-scope.md
- release-readiness-v0.1.md
- release-notes-v0.1-draft.md
- tool-side-effects.md
- 38-v02-roadmap.md

## Internal Engineering and Design Docs

These are technical implementation/design notes. They are useful for contributors but are not product-facing promises.

- 08-audit-log-schema.md
- 09-risk-engine.md
- 10-real-scenario-runner.md
- 11-approval-workflow.md
- 12-runtime-modes.md
- 13-cli-output.md
- 14-security-hardening.md
- 16-sdk-boundary.md
- 17-cli-approval-workflow.md
- 18-adversarial-scenarios.md
- 19-risk-engine-limitations.md
- 20-langchain-integration.md
- 21-openai-tool-calling-integration.md
- 22-mcp-tool-call-adapter.md
- 23-policy-engine-v2-research.md (current policy v2 direction)
- 24-policy-engine-v2-schema.md
- 25-policy-explain-cli-audit.md
- 26-rygnal-cli-v1.md
- 27-risk-engine-v2-design.md
- 28-risk-engine-v2-foundation.md
- 29-policy-risk-bridge.md
- 30-richer-policy-match-fields.md
- 31-policy-test-fixtures.md
- 32-sqlite-audit-storage.md
- 33-local-fastapi-service.md
- 34-approval-queue-api-design.md
- 35-role-based-approval-design.md
- 36-policy-bundles-research.md
- 37-audit-viewer-dashboard-plan.md
- 39-optional-live-openai-demo.md
- 40-live-mcp-client-server.md

## Historical and Archive Docs

These are kept for context/history and should not be treated as current direction.

- 01-research-before-building.md
- 02-tools-and-tech-stack.md
- 03-production-architecture.md
- 04-low-cost-production-plan.md
- 05-mvp-demo-plan.md
- 15-policy-engine-v2-research.md (historical; superseded by 23-policy-engine-v2-research.md)
- archive-early-planning.md

## Test-Locked Documentation

Many docs are validated by tests in `tests/test_*docs.py`. If a file is removed or renamed, update the related tests in the same change.
