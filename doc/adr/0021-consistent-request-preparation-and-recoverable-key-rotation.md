# 0021. Consistent request preparation and recoverable online key rotation

- Status: Accepted
- Date: 2026-11-01

## Context

An immutable request context assembled from independent reads can mix configurations that never
coexisted. Independently bounded queries do not establish a total lookup deadline or reserve every
read against administration traffic. Lifecycle completion in both transport and request orchestration
can count one exchange twice. Bounded payload preparation also requires a time bound.

Online master-key replacement crosses database, runtime, and external secret persistence. Sequential
replacement cannot make those resources atomic. Removing online rotation would remove an existing
capability; one transaction over all providers would hold resources for an unbounded configuration.

## Decision

Data-plane configuration resolution uses one short consistent database view, one authentication
connection reservation, and one total lookup deadline. The connection is released before hashing.
The read view is the configuration visibility point: writes committed before it are visible; writes
concurrent with preparation may affect the next exchange. Existing provider-selection behavior stays
unchanged. Authentication never holds a database transaction during hashing or forwarding.

An exchange has one lifecycle owner. Preparation failures and admission refusals remain distinct from
admitted exchanges. Internal failure classifications stay closed and typed. The owner records metrics
directly and attempts sideband publication independently; metrics do not depend on queue delivery.
HTTP alias preparation uses the existing stream idle deadline and a total preparation deadline of the
same duration, under global connection capacity. It consumes no rate allowance before validation.
WebSocket adaptation remains after the handshake. The frozen adapter context is separate from the
transport snapshot; forwarding receives no alias configuration. Transport and system TLS trust
configuration are constructed before traffic is served, rather than reloaded during a handshake.

Online master-key rotation uses at most two distinguishable data-key generations. Before switching
the write generation, a private, atomically replaced and durably flushed recovery record persists both
keys outside the database. New requests can decrypt both while bounded batches migrate records.
Concurrent secret writes and rotations are coordinated. Before switching generations, a bounded
storage barrier settles earlier database writes, including driver work whose request was cancelled; ordinary traffic keeps running. A failed or
interrupted migration is resumed before listeners bind, and retrying the same rotation is idempotent.

The recovery record is bound to its database identity (excluding PostgreSQL connection credentials
and TLS options, while retaining namespace options) and accepts only the configured active or
previous key. An unrelated configured key fails closed. A stale external key may recover the first
rotation using the previous generation; it must be updated to the active key before another rotation
can retire that previous generation. This bounded acknowledgement avoids indefinite key history or
silently ignoring external configuration. Local-secret deployments update the ordinary secret file
after migration and can rotate again. The recovery record remains authoritative for its two
generations while it exists; it never admits an unrelated external secret.

Old generation retirement waits for in-progress secret readers and writers; admitted streams already
own plaintext snapshots and are unaffected. Secret state never enters request events, diagnostics,
metrics, or the business database. Recovery must fail before binding if its record cannot be read,
validated, or migrated. In-memory-only configurations cannot claim durable rotation and must refuse
it before any ciphertext changes.

## Consequences

- No credential cache or generic pipeline framework is introduced.
- SQLite and PostgreSQL must establish equivalent read-view semantics explicitly.
- Key rotation gains a small, durable recovery protocol and bounded coordination state.
- Keeping online rotation requires fault-injection and concurrent-write tests, not just cipher tests.
- This tightens [0004](./0004-request-local-immutable-snapshots.md),
  [0006](./0006-fail-closed-resource-bounds.md), and
  [0011](./0011-defaulted-local-settings.md) without adding routing or scheduling behavior.
