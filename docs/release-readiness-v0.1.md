# Release Readiness v0.1

## What v0.1 Must Prove

Rygnal Core should prove this workflow:

```
Tool request
→ Risk assessment
→ Policy decision
→ Approval workflow if needed
→ Audit logging
→ Safe execution or block
→ Clear CLI output
```

## Required Validation Commands

Run these before release:

```
ruff format src tests demo
ruff check src tests demo
pytest -q
bandit -r src demo -c pyproject.toml
pip-audit -r requirements-dev.txt
python -m demo.run_demo
```

## Docker Validation

Run these before release:

```
docker compose build
docker compose run --rm rygnal pytest -q
docker compose run --rm rygnal python -m demo.run_demo
```

## Required Checks

- Main branch is up to date

- All feature PRs are merged

- CI is green

- Ruff format passes

- Ruff lint passes

- Pytest passes

- Bandit passes

- pip-audit passes

- Demo runner works

- Docker build works

- Docker test works

- Docker demo works

- README is reviewed

- Architecture docs are reviewed

- Security docs are reviewed

- Known limitations are documented

- Release notes are ready

## Included in v0.1

- Policy Engine v1

- Risk Engine v1

- Audit Logger v1

- Interceptor v1

- Approval Workflow v1

- Runtime Modes v1

- Real Scenario Runner v1

- CLI Output v1

- Security Hardening v1

- Docker setup

- CI/CD checks

- Documentation foundation

## Not Included in v0.1

- SaaS dashboard
- Web UI
- Cloud-hosted auth/identity provider integration
- Billing
- Multi-tenant cloud workspaces
- Cloud deployment / Kubernetes
- Direct out-of-the-box integration with production agent orchestration frameworks (integrated via example adapter wrappers for OpenAI, LangChain, and MCP)
- Enterprise SSO
- SIEM integration

## Known Limitations

- Scenario runner uses controlled local workflows.
- No direct out-of-the-box integration with production agent orchestration frameworks (integrated via example adapter wrappers for OpenAI, LangChain, and MCP).
- Approval workflow is a local HTTP API / CLI workflow (no frontend visual dashboard UI yet).
- Policy engine is simple YAML-based logic (but supports priority sorting and schema validation).
- Risk engine is deterministic and rules-based.
- External API adapter is dry-run only.
- Tool adapters are local/sandbox-oriented.
- Not enterprise production-ready yet.

