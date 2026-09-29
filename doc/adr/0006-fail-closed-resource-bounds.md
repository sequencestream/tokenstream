# 0006. Fail-closed resource bounds

- Status: Accepted
- Date: 2026-09-29

## Context

A transparent streaming gateway holds long-lived connections. If any queue, buffer, pool, or hash computation can grow without a bound, memory and file descriptors follow connection duration. If overload is absorbed by queueing, latency becomes unbounded and hashing or database work on new requests can starve connections that are already streaming.

The alternatives were to queue admissions, to share one hashing and database budget across both planes, to retry failed exchanges onto idle connections, and to treat hashing or lookup timeouts as internal errors.

## Decision

Every accumulator has an explicit bound, and exhaustion fails closed with a sanitized gateway error rather than queueing. Admission never queues. Password hashing uses non-queueing, independent data-plane and control-plane budgets under a process-wide ceiling. Authentication lookups may reserve pooled database connections. Database operations have explicit deadlines. Idle HTTP connections to an origin are capped and expire after an explicit deadline; a failed or cancelled exchange is never replayed onto another connection. SIGINT and SIGTERM are the same stop request: drain connections, then flush logs, each for a bounded period.

The bounds policy is in the [architecture document](../architecture.md). Process, authentication, and proxy designs apply it.

## Consequences

- A full admission limit or exhausted hashing or lookup capacity returns `503` with `resource_exhausted`, not `internal_error`.
- Exhausting one plane's hashing budget does not borrow the other plane's slots. A cancelled caller keeps occupying a hashing slot until the computation finishes.
- Raised hashing budgets must not substitute for default-configuration load results. Idle reuse may cut upstream accepts; it must not mix snapshots or retry.
- Forced cancellation after the drain period leaves unfinished WebSocket records incomplete and does not invent a close event ([ADR 0005](./0005-best-effort-metadata-logging.md)).
