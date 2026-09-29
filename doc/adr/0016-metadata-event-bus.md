# 0016. A sideband metadata event bus with per-subscriber bounded queues

- Status: Accepted
- Date: 2026-09-30

## Context

The proxy reports what happened to a request through exactly one queue, owned by the request-log
writer. Every future consumer of the same fact — token statistics, tracing, billing, alerts, plugin
hooks — would otherwise mean another edit inside the proxy core, which is the outcome
[ADR 0001](./0001-transparent-proxy-core.md) exists to prevent and the transparency rule in the
[architecture document](../architecture.md) binds.

The emit discipline already in force ([ADR 0005](./0005-best-effort-metadata-logging.md)) says a full
queue drops the event and increments a counter, and that the proxy never waits. That discipline was
written when there was one consumer, so a full queue read as a single fact about the process. With
several consumers that reading is wrong: a full queue is a fact about one consumer, and a process-wide
drop count cannot say which consumer fell behind.

Three shapes were genuinely available.

A single shared queue drained by one worker that then dispatches to consumers keeps one bound but
makes every consumer wait behind the slowest one and behind every storage operation the fastest one
performs. A consumer that is down becomes a head-of-line block for all of them.

An atomic broadcast, in which an event either reaches every consumer or none, gives a consistent view
at the cost of exactly that coupling: one saturated consumer would suppress the others, and a consumer
with a bounded queue would have to bound the whole system.

A synchronous callback into each consumer keeps the code short and puts consumer latency into the
forwarding path, which [ADR 0005](./0005-best-effort-metadata-logging.md) forbids outright.

What the proxy has at each reporting point is a closed set of transport facts: a request identity, the
account, credential, and provider it resolved to, the protocol and transport type, the normalized path,
an upstream status or handshake outcome, an elapsed time, and a result drawn from the failure-category
set the gateway already reports. No payload, header value, credential plaintext, or query string is
available at any of those points, and a consumer that needs one of those is not a consumer of
lifecycle metadata at all.

## Decision

The proxy reports to a bus. The bus fans out to a fixed set of subscribers, each owning its own bounded
queue, its own worker, and its own drop counter.

The event set is closed and has three points: admitted, upstream observed, and finished. The set is
not extensible at the call site, so the vocabulary of results cannot grow with traffic, and a result
can be compared against a metric or a sanitized error without translation. A cancellation or disconnect
reason travels in that same closed category set rather than as a free-form string.

Fan-out is per subscriber and is not atomic across subscribers. A subscriber that is full, closed, or
whose worker has stopped drops that event for itself, counts it under its own name, and the others
still receive the event. This is the whole point: a slow consumer must be able to exist without
becoming a reason a request fails or a reason another consumer misses a fact.

Emission stays what [ADR 0005](./0005-best-effort-metadata-logging.md) made it. A proxy task attempts
a non-blocking hand-off instead of waiting, and the outcome of that attempt cannot change a proxy
result. The emit path therefore reads a fixed collection of bounded channels and allocates nothing.

The subscriber set is fixed before either listener binds, and a bus handed to a proxy task is sealed by
construction: only a builder that is still being composed may attach a subscriber. The bus holds no
unbounded state. The subscriber count is fixed and each queue is bounded by an explicit capacity, and
subscriber names are a compiled closed set so exposition cardinality cannot grow with the number of
subscribers a deployment happens to attach.

A subscriber's worker owns every failure decision and never reports one to a proxy task. It drains by
size or by interval, retries a transient failure a bounded number of times, then discards the rest of
that batch, and isolates a permanently unwritable event with bounded splits so one bad event cannot roll
back its neighbours. A dropped or aborted worker counts whatever was still queued for it, so a queue
depth never claims work is pending after the worker is gone.

The request-log writer becomes the first subscriber, and its projection from events to stored rows is
unchanged in meaning. Metrics for queue depth and dropped events become per-subscriber, because a
process-wide figure cannot attribute a loss.

## Consequences

- A consumer that does not exist yet needs no change to the proxy core, which is what makes token
  statistics, billing, and alerts adapters rather than core features.
- Completeness was never guaranteed and is now guaranteed per consumer rather than per process: a
  saturated subscriber is a loss of that subscriber's fidelity, never a loss of availability.
- Because fan-out clones the event for each subscriber, the number of subscribers multiplies the cost
  of one emit. The fixed and small subscriber set is what keeps that bounded, and attaching a
  subscriber is a deliberate composition-time act rather than a runtime one.
- The event set is closed, so a genuinely new fact is an architectural change, not a field addition.
  That is the intended friction.
- A subscriber whose worker has stopped receives nothing further, so a consumer that is restarted is a
  composition-root concern rather than a bus concern.
- A capability that needs to read a payload — usage counting, for instance — is not a new event variant.
  It is a separate adapter outside the proxy core, and this decision does not make room for it.
