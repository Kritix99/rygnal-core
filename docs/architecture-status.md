# Architecture Status and Issue Evidence

Status date: 2026-08-26

This document records the implemented architecture and the evidence required before closing architecture issues. An issue is closure-ready only when every acceptance criterion is supported by merged code, tests, or canonical documentation.

## Status vocabulary

- **Closure-ready**: merged evidence satisfies the issue's stated architectural scope.
- **Partial**: meaningful implementation exists, but at least one acceptance criterion remains open or conflicts with current architecture.
- **Open**: the principal deliverable is not implemented.
- **Superseded**: the intended direction changed and must be explicitly documented before closure.

## Closure-ready architecture issues

### #271 — Go CLI, Python engine, Rust safety-kernel architecture

Evidence:

- [ARCHITECTURE.md](../ARCHITECTURE.md) defines language ownership and prohibits duplicated safety decisions.
- [PR #279](https://github.com/Rygnal/rygnal-core/pull/279) added the headless NDJSON engine contract.
- [PR #280](https://github.com/Rygnal/rygnal-core/pull/280) added the Go-to-Python CLI bridge.
- [PRs #281–#295](https://github.com/Rygnal/rygnal-core/pulls?q=is%3Apr+281..295) established the Rust/PyO3 boundary and semantic criticality path.
- [PR #306](https://github.com/Rygnal/rygnal-core/pull/306) formalized monorepo validation boundaries.
- Current layout follows the documented Go/Python/Rust ownership model.

Recommendation: close #271 after this evidence document is merged.

### #273 — Rust Tree-Sitter Criticality Index

Evidence:

- [PR #283](https://github.com/Rygnal/rygnal-core/pull/283) added Tree-Sitter AST analysis.
- [PRs #284 and #285](https://github.com/Rygnal/rygnal-core/pulls?q=is%3Apr+284..285) added the criticality matrix.
- [PR #294](https://github.com/Rygnal/rygnal-core/pull/294) added the Rust Criticality Index.
- [PR #295](https://github.com/Rygnal/rygnal-core/pull/295) added the Python criticality adapter.
- Rust tests and Python integration/parity tests are present under `rust-kernel/` and `tests/test_rust_kernel_*.py`.
- Python falls back safely when native analysis is unavailable.

Recommendation: close #273 after confirming the current CI lane passes on the merged baseline.

### #275 — Official Go CLI foundation

Evidence:

- [PR #280](https://github.com/Rygnal/rygnal-core/pull/280) implemented the Go CLI bridge.
- `cmd/rygnal/`, `internal/cli/`, and `internal/engineclient/` implement the product-facing CLI boundary.
- Go delegates guarded execution to the Python NDJSON engine and does not own risk or policy decisions.
- Human and structured output paths are implemented and covered by Go tests.

Recommendation: close #275 after current Go validation passes.

### #277 — Rust safety-kernel foundation with PyO3

Evidence:

- [PR #281](https://github.com/Rygnal/rygnal-core/pull/281) established the Rust/Python tracer-bullet boundary.
- [PR #282](https://github.com/Rygnal/rygnal-core/pull/282) added the safe JSON boundary.
- [PR #293](https://github.com/Rygnal/rygnal-core/pull/293) added the path-safety foundation.
- `rust-kernel/Cargo.toml` builds a PyO3 `cdylib`.
- `src/rygnal/rust_kernel.py` provides the Python adapter and fallback behavior.
- Native and fallback behavior are covered by Rust and Python tests.

Recommendation: close #277 after current Rust and Python validation passes.

### #278 — Go/Python/Rust monorepo transition

Evidence:

- [PR #306](https://github.com/Rygnal/rygnal-core/pull/306) formalized monorepo ownership and validation.
- Current repository layout separates Go CLI, Python engine, Rust kernel, tests, documentation, policies, and schemas.
- [ARCHITECTURE.md](../ARCHITECTURE.md) documents ownership and validation boundaries.
- The root Makefile exposes Go, Rust, Python, and aggregate validation lanes.

Recommendation: close #278 after `make validate` passes on the documentation PR.

## Provisional issues requiring acceptance review

### #308 — Global fail-closed policy and process isolation

Implemented evidence:

- [PR #318](https://github.com/Rygnal/rygnal-core/pull/318) added guarded command process-group supervision.
- [PR #328](https://github.com/Rygnal/rygnal-core/pull/328) added global fail-closed interceptor behavior.
- Signal cleanup and fail-closed tests exist.

Why it should not be closed automatically:

- Process groups are explicitly not a containment boundary.
- The issue body combines several architectural concerns beyond its title.
- PR #375 removed Linux containment support, changing assumptions used by parts of the issue.

Required next step: create a criterion-by-criterion checklist against the current post-#375 architecture, then close completed portions or split remaining work into focused issues.

### #309 — Resource exhaustion, AST denial of service, and concurrency corruption

Implemented evidence:

- [PR #325](https://github.com/Rygnal/rygnal-core/pull/325) bounded Tree-Sitter analysis.
- [PR #326](https://github.com/Rygnal/rygnal-core/pull/326) bounded policy-regex resource usage.
- [PR #327](https://github.com/Rygnal/rygnal-core/pull/327) added guarded-run concurrency control.

Why it should not be closed automatically:

- The issue spans multiple resource and concurrency boundaries.
- Repository-level CI concurrency and fallback telemetry remain separately tracked in #298.
- Closure requires verification that all limits and corruption scenarios named in #309 have regression coverage.

Required next step: audit every acceptance criterion against merged tests and explicitly separate any remaining operational telemetry work from #298.

## Related partial or open architecture work

- #274: production containment direction is unresolved after Linux support removal.
- #276: Go approval UX exists, but shared approval identity propagation remains incomplete through #333.
- #298: CI concurrency and fallback telemetry require completion evidence.
- #310: operational-security epic remains open while child requirements remain incomplete.
- #333, #348, and #370: sequenced in [Architecture Roadmap](architecture-roadmap.md).

## Closure procedure

Before closing an issue:

1. Confirm the implementation PR is merged into `Rygnal/rygnal-core:main`.
2. Map every acceptance criterion to a file, test, PR, or canonical document.
3. Run the relevant validation lanes.
4. Add a final issue comment containing the evidence matrix.
5. Close as completed only when no criterion remains.
6. Use “not planned” or “superseded” only with an explicit architecture decision and replacement link.
