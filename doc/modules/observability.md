# Observability

## Purpose

Give an operator the minimum statistical surface that can raise an alert today and feed a breaker or a
scheduler later, without reading a payload and without letting the surface grow with traffic.

## Design

The exposition is a fixed set of series ([ADR 0017](../adr/0017-cardinality-bounded-observability.md)).
Its size is a property of the build, not of a deployment's traffic, because every series is enumerated
from a compiled closed set. Nothing is configured at runtime: an operator cannot add a label, a series,
or a bucket boundary, and therefore cannot make a percentile mean something different in a second
deployment.

Two dimensions label the series, and both are facts the gateway already decides before contacting an
upstream. **Transport type** is HTTP or WebSocket and comes from the route allowlist. **Result
classification** has exactly four members: success, gateway failure, upstream failure, and client
cancellation.

That classification is a total function over the fine failure-category set a request record and a
gateway error already use, and is deliberately not the same set. The fine set is right for one row
describing one exchange, where exactness is free. It is wrong for a metric, where the label is repeated
across a time series and must be readable at a glance. The coarse set is what a threshold is written
against; the fine set is what an investigation reads. Because the mapping is total, a rate over a coarse
label is well defined and no failure can fall through unclassified.

Protocol type is not a label. Two protocols share each transport, and the coarse result is what an
alert thresholds on; a third dimension would triple the series count to restate a fact the request log
already holds per exchange.

Provider and account identifiers are not labels either. Both are unbounded over a process lifetime, and
one series per provider per transport per result is precisely the explosion a gateway built to hold many
providers cannot afford. This is a deferral, not an omission: when those series are needed the cost is
added series, not a changed meaning, which is what fixing the label set now buys.

## What the exposition contains

| Series | Labels | Fact |
| --- | --- | --- |
| Completed exchanges | transport, result | One increment per exchange, at the point its result is decided |
| Exchange latency | transport, result | One cumulative histogram per series, measured from admission to the terminal point |
| HTTP exchanges in flight | — | Exchanges admitted and not yet finished |
| WebSocket connections in flight | — | Connections admitted and not yet closed |
| Lifecycle events attempted | subscriber | Non-blocking hand-offs the proxy attempted |
| Lifecycle events dropped | subscriber | Copies a subscriber lost to a full, closed, or abandoned queue |
| Admission refusals | layer, reason | Requests a gate refused before they became work |

Pass and fail totals are derived from the completed-exchange counter rather than recorded separately,
because two counters for one fact can disagree, and a disagreement between a total and its parts is
indistinguishable from a bug in either. The fail total is the sum of the gateway-failure and
upstream-failure members, and deliberately excludes client cancellation: a client that hangs up is
neither a success nor a fault of the gateway, and counting it as a failure would put ordinary
disconnects into an error-rate alert and make that alert untrustworthy. A cancellation is still
counted, in its own series.

Refusals name the layer that refused and the reason within it: the global connection gate, then a
provider concurrency bound, a provider rate allowance, a credential concurrency bound, a credential rate
allowance, and a credential long-lived-connection bound. The layer is what an operator needs, because
"the credential rate bound refused four hundred requests" and "the provider concurrency bound refused
four hundred requests" are the same visible symptom and two different fixes.

## Where each fact is recorded

Each fact is recorded at the single point where it is decided, and nowhere else.

A request that a gate refuses produces a refusal and only a refusal. It produces no lifecycle event,
because it never became work the proxy runs, and no result fact, because there is no exchange to
classify. This is what stops a shed request from being counted twice — once as a refusal and once as the
failure of an exchange that never started — and it is why a process shedding load under pressure is
visible rather than merely quiet.

An admitted exchange raises its in-flight gauge, and at the terminal point increments exactly one
completed-exchange counter, records exactly one latency observation, and releases exactly one gauge. The
terminal point is the same point that emits the finished lifecycle event, so a result cannot be recorded
without the event carrying the same classification, and the two cannot drift apart.

## Quantiles from bounded buckets

Latency is recorded into a fixed bucket set per series, cumulatively, so a quantile is a bucket lookup
rather than a stored order statistic. Three properties make the number trustworthy.

The boundaries are fixed at compile time and shared by every series, so two series are always
comparable and a percentile means the same thing in every process. The top bucket is unbounded, so a
slow observation is never discarded for being slow; a quantile that dropped its tail would be worse
than no quantile, because it would look calm. And a quantile over a series with no observation is
undefined, so the exposition reports it as *unknown* rather than as a zero, because a zero latency
percentile is a factually wrong answer to a question that has no answer yet. The quantile series is
declared for every series whether or not it has an observation, so the shape of the exposition stays a
property of the build rather than becoming a function of traffic.

The recorded interval is from admission to the terminal point, which is the whole exchange including the
streamed body rather than only the headers. That is the interval the request log records, so a percentile
and a sampled log row describe the same thing.

## Core flows

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Admission layers
    participant Px as Proxy
    participant B as Event bus
    participant M as Exposition

    C->>A: Request
    alt A gate refuses
        A-->>M: Refusal by layer and reason
        A-->>C: Sanitized gateway error
        Note over B: No event; the request never became work
    else Admitted
        A->>Px: Request with a frozen snapshot
        Px-->>M: In-flight gauge raised
        Px-->>B: Emit admitted
        Px->>Px: Stream to the upstream
        Px-->>B: Emit finished, at the terminal point
        Px-->>M: One result, one latency observation, gauge released
    end
    Note over M: Rendered on the control plane, from closed sets
```

## Invariants

- Every label and every series name is a member of a compiled closed set, so the exposition's size
  cannot grow with traffic, with the number of providers, or with the number of accounts.
- No metric name, label, or value carries a credential plaintext, an account, a provider, a request
  identifier, a path, a host, a query string, or any part of a payload.
- The result classification is a total function over the fine failure-category set, so every failure
  classifies and no classification is free-form.
- An exchange is counted exactly once, at the terminal point, and a refused request is counted as a
  refusal and never as an exchange.
- Recording a fact takes no lock, allocates nothing, and never waits; rendering happens only on the
  control plane.
- The exposition is served to an authenticated administrator only and is served at no data-plane path.
- A quantile is read from bounded cumulative buckets, the top bucket is unbounded, and a quantile with
  no observation is reported as unknown rather than as zero.

## Failures and bounds

- A metric is lost only if the process stops. There is no metric queue, no metric subscriber, and no
  metric write that can fail, so observability adds no failure mode to forwarding and no bound for the
  proxy to hold.
- The exposition is a control-plane response. A very large one is a function of the compiled series set
  and not of traffic, so it does not grow with the process's uptime.
- The subscriber drop counters are best-effort facts about the event bus and are described by the
  [events design](./events.md) and the [logging design](./logging.md); this design only names them as
  series and does not restate their discipline.
- A capability that needs to read a payload — token or usage statistics — is not a new label. It is an
  adapter outside the proxy core.
