# 0005. Best-effort metadata logging

- Status: Accepted
- Date: 2026-09-29

## Context

Operators need to see that a request started and whether it completed, without storing application payloads. Logging can be synchronous on the proxy path, buffered without a bound, or emitted through a bounded non-blocking queue that is allowed to drop.

Synchronous writes would make database latency part of every stream. An unbounded buffer would grow with connection duration and load. A strictly durable log would have to block or retry in the proxy task when the database is slow or when a start row races with provider deletion.

## Decision

Logging is best-effort, metadata-only, and must never block proxy traffic. Proxy tasks only attempt a non-blocking start or completion emit. A full or closed queue drops the event and increments a dropped-event metric. Request and response payloads are never stored. An absent end time means no completion event was persisted; it does not prove that a connection is still active. Close times are never synthesized after a crash or forced shutdown.

The current contract is in the [architecture document](../architecture.md). Queue, batch, and isolation behavior is in the [logging design](../modules/logging.md).

## Consequences

- Completeness is not guaranteed. The administration page must label rows with no end time as incomplete, not as still active.
- Retryable batch failures may discard the remaining batch after a bounded retry. Permanent event errors, such as a start record that loses a race with provider deletion, are isolated with bounded splits so they cannot roll back the rest of the batch; those isolated events still count as dropped.
- Metrics stay aggregated and must not carry key IDs, URLs with query strings, or other high-cardinality secrets.
