# Contributing to Rygnal Core

Thank you for contributing to Rygnal Core.

Rygnal is safety-sensitive infrastructure. Contributions must prioritize correctness, fail-closed behavior, auditability, and test evidence over feature speed.

## Architecture boundaries

Follow the ownership boundaries in [ARCHITECTURE.md](ARCHITECTURE.md):

- Go owns the official CLI, terminal UX, and engine-client boundary.
- Python owns orchestration, guarded execution, policy, risk, approval, and audit behavior.
- Rust owns deterministic safety primitives exposed through PyO3.
- Do not duplicate security decisions across languages.

## Development setup

Requirements:

- Python 3.11 or newer
- Go version declared by `go.mod`
- Rust stable toolchain
- Git

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e . -r requirements-dev.txt
```

Build the Rust extension when testing the native Python boundary:

```bash
cd rust-kernel
maturin develop
cd ..
```

## Validation

Run the complete validation suite before requesting review:

```bash
make validate
```

The language-specific lanes are:

```bash
make validate-go
make validate-rust
make validate-python
```

Documentation-only changes should still verify links, terminology, issue references, and any documentation tests affected by the change.

## Branch and pull-request workflow

1. Create a focused branch from the latest `main`.
2. Keep each pull request limited to one architectural or maintenance objective.
3. Do not push feature work directly to `main`.
4. Explain what changed, why it changed, and how it was validated.
5. Link the governing issue and describe which acceptance criteria are satisfied.
6. Request review before merge.
7. Close an issue only after merged evidence satisfies every acceptance criterion.

## Security requirements

- Never commit credentials, tokens, private keys, `.env` files, local databases, audit logs, generated artifacts, or raw sensitive patches.
- Preserve fail-closed behavior at security boundaries.
- Do not describe Git worktrees or process groups as OS-level containment.
- Treat `unsafe_local` as an explicit development/testing mode.
- Add regression tests for security-sensitive behavior changes.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Commit guidance

Use clear, scoped commit messages such as:

```text
docs: reconcile architecture roadmap
fix(approval): reject mismatched patch digest
test(risk): cover critical path fallback
```

Do not rewrite shared history or alter existing contributor attribution to change ownership appearance.

## Review expectations

Reviewers should verify:

- The change respects language ownership boundaries.
- Security claims match implemented behavior.
- Failure modes remain explicit and fail closed.
- Approval and audit evidence remain bound to the correct request, patch, and baseline.
- Tests and documentation support the claimed completion state.
- An issue marked complete has merged, traceable evidence for all acceptance criteria.

## Documentation

Canonical product truth belongs in the README, architecture, security model, known limitations, architecture status, and roadmap documents. Research notes must not be presented as implemented guarantees.

See:

- [Documentation index](docs/00-index.md)
- [Architecture status and issue evidence](docs/architecture-status.md)
- [Architecture roadmap](docs/architecture-roadmap.md)
- [Known limitations](docs/known-limitations.md)
