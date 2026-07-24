# Shared approval authority

Rygnal's Go CLI preserves local/offline review artifacts while optionally
synchronizing approval and rejection decisions with the canonical Python
patch-approval authority.

This is backend integration only. It does not define or implement a terminal
prompt, TUI, dashboard, styling, or other UI/UX behavior.

## Configuration

Configure the Python approval API:

```text
RYGNAL_APPROVAL_API_URL=http://127.0.0.1:8787
```

When the API requires authentication, configure:

```text
RYGNAL_OPERATOR_TOKEN=<operator token>
```

Plain HTTP is accepted only for loopback hosts. A remote API must use HTTPS
and requires an operator token. Redirects are rejected so credentials cannot
be forwarded to a different origin.

## Decision flow

1. The Python guarded runner returns a patch-bound `approval_id`.
2. Go preserves the approval identity, patch digest, and baseline in its local
   review summary.
3. `rygnal approve` or `rygnal reject` validates the local binding.
4. When `RYGNAL_APPROVAL_API_URL` is configured, Go inspects the authoritative
   Python approval and verifies its approval ID, patch digest, and baseline.
5. Go submits the terminal decision to the Python patch-approval endpoint.
6. Only after authoritative synchronization succeeds does Go persist the
   local decision and append its local audit mirror.

If no shared API is configured, the existing offline/local workflow remains
available. A configured shared API that fails or returns mismatched evidence
causes the command to fail without writing a local success decision.

## Local decision receipts

New records use `rygnal.local_decision.v2` and bind:

- run ID
- approval ID
- patch SHA-256
- baseline commit SHA
- decision status, actor, reason, and timestamp
- engine protocol version
- Rygnal version
- decision authority and synchronization state
- deterministic receipt SHA-256

Version 1 records remain readable for backward compatibility. Version 2
records are rejected when their bound fields or receipt digest are altered.

The Python approval service remains the authoritative source when shared
synchronization is configured. The local JSONL file is a compatibility and
inspection mirror, not a substitute for the Python durable audit store.
