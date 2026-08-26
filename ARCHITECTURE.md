# Rygnal Architecture

Rygnal is a Go/Python/Rust monorepo. Each language has a clear ownership boundary so the repository can evolve without duplicating safety logic or breaking CI.

## Repository ownership

### Go: CLI and terminal UX

Paths:

- `cmd/`
- `internal/`

Go owns the user-facing command-line interface, terminal approval UX, command routing, and process-level interaction with the Python engine.

Go must not duplicate the core safety, policy, risk, approval, or audit logic owned by Python. When Go needs engine decisions, it should call the Python engine through the defined engine API/client contract.

### Python: engine and orchestration

Paths:

- `src/rygnal/`
- `tests/`
- `demo/`
- `examples/`
- `policies/`
- `schemas/`

Python owns the core Rygnal engine:

- guarded runner orchestration
- policy evaluation
- risk classification
- approval workflow
- audit logging and audit queries
- workspace and patch handling
- Python-side adapters around the Rust safety kernel

Python remains the source of truth for guarded execution decisions.

### Rust: deterministic safety kernel

Path:

- `rust-kernel/`

Rust owns deterministic, high-performance safety primitives used by the Python engine:

- path safety checks
- path sensitivity classification
- subjective risk scoring helpers
- Tree-Sitter AST analysis
- semantic criticality evaluation

Rust exposes these capabilities through the PyO3/native extension boundary. Python must handle Rust unavailability safely and fall back where appropriate.

## CI ownership

The monorepo CI must validate all active language zones:

- Go: format, vet, test, build
- Rust: format, clippy, test, Python extension build
- Python: ruff, pytest, bandit, pip-audit, demo

No PR should be considered ready if it breaks any active language lane.

## Local validation

Use the root Makefile validation lanes:

- `make validate-go`
- `make validate-rust`
- `make validate-python`
- `make validate`

`make validate` is the full monorepo validation command.

## Boundary rules

- Do not place Python engine logic inside Go packages.
- Do not place CLI UX logic inside the Python engine unless it is legacy compatibility code.
- Do not put policy, risk, or approval decisions inside Rust.
- Do not duplicate safety decisions across languages.
- Do not commit generated artifacts such as Python wheels, Rust target output, Go binaries, dist output, or build output.
- Keep language-specific build outputs ignored by Git.

## Current layout

- `cmd/` — Go CLI entrypoints
- `internal/` — Go internal packages
- `src/rygnal/` — Python engine package
- `tests/` — Python test suite
- `rust-kernel/` — Rust/PyO3 safety kernel
- `docs/` — documentation
- `examples/` — example integrations
- `demo/` — local demo runner
- `policies/` — policy fixtures and defaults
- `schemas/` — JSON/schema contracts
- `.github/workflows/` — CI definitions

## Roadmap note

This layout supports the active Rygnal architecture:

- Go owns CLI/TUI surfaces.
- Python owns orchestration and guarded engine decisions.
- Rust owns deterministic safety primitives.
