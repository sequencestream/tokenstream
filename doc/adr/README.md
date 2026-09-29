# Architecture Decision Records

This directory records the forks Tokenstream already took. Each record is a choice among real alternatives, not a procedure and not a bug write-up.

The [architecture document](../architecture.md) states the rules that are in force now. Module designs under [`modules/`](../modules/) show how those rules work, including edge cases learned later. An ADR explains why the rule exists and what was rejected.

A new architectural fork gets an ADR before the architecture document changes. A repair that only enforces an existing decision belongs in the relevant module design, and at most a sentence in that ADR's consequences.

| ID | Status | Decision |
| --- | --- | --- |
| [0001](./0001-transparent-proxy-core.md) | Accepted | Transparent proxy core; client-owned fallback |
| [0002](./0002-dual-planes-in-one-process.md) | Accepted | Dual planes in one process |
| [0003](./0003-explicit-route-allowlist.md) | Accepted | Explicit route allowlist as an architectural change |
| [0004](./0004-request-local-immutable-snapshots.md) | Accepted | Request-local immutable snapshots; no credential cache |
| [0005](./0005-best-effort-metadata-logging.md) | Accepted | Best-effort metadata logging |
| [0006](./0006-fail-closed-resource-bounds.md) | Accepted | Fail-closed resource bounds |
| [0007](./0007-upstream-websocket-handshake-first.md) | Accepted | Upstream WebSocket handshake before downstream upgrade |
| [0008](./0008-secret-and-credential-model.md) | Accepted | Encrypted upstream keys and hashed gateway secrets |
| [0009](./0009-same-origin-administration.md) | Accepted | Same-origin administration; no shared caching of control-plane JSON |
| [0010](./0010-dual-storage-and-cursor-lists.md) | Accepted | Dual storage with cursor lists; logs pin providers |
| [0011](./0011-defaulted-local-settings.md) | Accepted | Defaulted local settings with an operator overlay |
| [0012](./0012-account-sessions-and-two-roles.md) | Accepted | Account sessions and two fixed roles in the control plane |
| [0013](./0013-account-owned-data-plane-credentials.md) | Accepted | Data-plane credentials identify an account, not a provider |
| [0014](./0014-migrating-provider-issued-credentials.md) | Accepted | Converting provider-issued credentials to account-owned credentials |

## Template

```markdown
# NNNN. Title

- Status: Accepted
- Date: YYYY-MM-DD

## Context

The problem and the alternatives that were actually on the table.

## Decision

The choice, in force.

## Consequences

What became easier, what became harder, and which later invariants tightened the decision without replacing it.
```
