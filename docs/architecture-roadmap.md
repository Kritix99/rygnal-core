# Architecture Roadmap

Status date: 2026-08-26

This roadmap focuses on the remaining core-design work represented by #333, #348, and #370. It does not treat unfinished work as an implemented product guarantee.

## Architectural priorities

### 1. Complete the shared approval contract — #333

Goal: make the Go CLI and Python engine operate on the same approval identity and durable decision state.

Required sequence:

1. Preserve the Python-provided `approval_id` in Go local review state.
2. Bind decisions to `run_id`, `approval_id`, `patch_sha256`, and `baseline_commit_sha`.
3. Define one provider-neutral Go client contract for the shared approval service.
4. Preserve offline/local `decision.json` behavior without reporting remote success when synchronization fails.
5. Fail clearly on missing IDs, digest mismatch, baseline mismatch, or shared-service failure.
6. Add cross-language contract and regression tests.
7. Document the authoritative source of approval state.

Exit criteria:

- Go approve/reject can update the shared approval request when configured.
- Offline mode remains backward-compatible.
- A local decision cannot be confused with a successfully synchronized shared decision.
- Tests cover all acceptance criteria in #333.

Dependency role: this contract should be stable before richer approval UI work is implemented.

### 2. Publish the first UI/TUI design contract — #348

Goal: define the user-facing trust boundary before expanding terminal or dashboard features.

Research deliverable:

- Recommended first interface
- Safe, risky, blocked, failed, and degraded user journeys
- Engine-event to UI-state mapping
- Risk and patch-summary presentation
- Approval actions and default rejection behavior
- Privacy defaults for paths, commands, output, environment data, and patch content
- Accessibility and keyboard interaction requirements
- Minimal first implementation milestone
- Explicit non-goals

Architecture rule: the UI renders engine facts and collects decisions; it must not duplicate Python safety logic.

Exit criteria:

- The proposal answers every acceptance question in #348.
- Event names are checked against the current NDJSON engine contract.
- The proposal accounts for the shared approval identity from #333.
- Follow-up implementation issues are created only after the design is accepted.

### 3. Validate the agent-agnostic AI Reviewer pipeline — #370

Goal: prove a provider-neutral semantic reviewer can compare human intent, agent intent, tool activity, and proposed repository changes.

Architecture phases:

#### Phase A — contracts

- Define a canonical immutable `SafetyContext` schema.
- Define a strictly typed reviewer response.
- Define schema versioning, size limits, redaction, hashing, and provenance fields.
- Separate deterministic engine evidence from probabilistic reviewer conclusions.

#### Phase B — adapter boundary

- Define an agent-agnostic event-emitter interface.
- Capture only observable reasoning summaries and plans; do not assume private chain-of-thought access.
- Normalize tool calls, shell commands, file operations, and patches.
- Keep provider-specific logic outside the core review model.

#### Phase C — reviewer integration

- Run the reviewer with read-only capabilities.
- Enforce structured output parsing and fail-closed handling for malformed responses.
- Record model identity, prompt/schema version, latency, token usage, and confidence.
- Combine reviewer output with deterministic policy without allowing probabilistic output to bypass critical deterministic blocks.

#### Phase D — real validation

- Execute non-trivial tasks against real disposable repositories.
- Measure payload fidelity, latency, false positives, false negatives, and decision stability.
- Document limitations and reproducibility.
- Do not use synthetic payloads as the primary completion evidence.

Exit criteria:

- Every acceptance criterion in #370 has real-run evidence.
- The core schema has no hard dependency on one model provider or coding agent.
- Deterministic safety remains authoritative for critical blocks.
- Reviewer uncertainty and failure modes are explicit and auditable.

## Dependency order

```text
#333 shared approval contract
    → #348 UI/TUI trust-boundary proposal
    → approval UI implementation issues

#370 reviewer contracts
    → adapter implementation
    → real repository validation
    → later reviewer-driven UI integration
```

#333 and #370 may proceed in parallel because they operate on different contracts. UI approval implementation should wait for #333, while semantic-review UI integration should wait for #370's schemas.

## Documentation rules

- Update [Architecture Status and Issue Evidence](architecture-status.md) when a milestone is merged.
- Keep [Known Limitations](known-limitations.md) aligned with executable behavior.
- Do not call research or planned architecture “implemented.”
- Link each closure recommendation to merged PRs and validation evidence.
