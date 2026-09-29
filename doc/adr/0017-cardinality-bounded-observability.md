# 0017. Result classification and a cardinality-bounded exposition

- Status: Accepted
- Date: 2026-09-30

## Context

The exposition exists today and is internal-shaped. It counts active HTTP exchanges and active
WebSocket connections, records one cumulative upstream latency histogram with no transport and no
result dimension, counts failures from three unrelated places, and reports per-subscriber queue depth
and dropped events.

It cannot answer the three questions an alert needs. How fast is the gateway? How often does it fail,
and of what kind? What refused this request? A percentile cannot be recovered from a histogram that is
shared across every transport and every result, because a fast HTTP exchange and a slow WebSocket
session land in the same buckets and the mixture has no single meaning. And a refusal has no
representation at all: a request the process rejected before it became work is invisible, so a gateway
shedding load under an attack looks identical to a gateway that is simply idle.

The architecture document already forbids the obvious cheap answers. The logging constraint says a
metric carries no credential identifiers, no URLs, and no other high-cardinality values, and the
resource-bounds philosophy says the process holds no unbounded state. Both bind this decision, and
neither is a preference.

Four shapes were genuinely available.

Label by provider or account. This is the most operationally useful dimension, and it is the one that
destroys the metric. Both identifiers are unbounded over a process lifetime, and one series per
provider per transport per result is exactly the cardinality explosion a gateway built to hold many
providers cannot afford. It is also the dimension whose value is unproven: no alert has yet been written
against it.

Compute exact percentiles by retaining every observation. This is the only way to get a true P99 rather
than an interpolated one, and it is unbounded memory in the one component whose primary constraint is
that memory must not grow with traffic. A gateway whose memory grows with the number of requests it
has served is a gateway that eventually cannot serve requests.

Keep the histogram as it is and let the alert compute percentiles from it. This is possible in
principle, and it makes the meaning of the exposition depend on the query language of whatever scrapes
it, so two deployments reading the same metric can get two different numbers. It also pushes a
precision decision into configuration, where an operator can choose bucket boundaries that make their
own percentiles look however they like.

Classify coarsely and derive percentiles from fixed cumulative buckets. A histogram per series, with
series identified by transport and a coarse result, and the boundaries fixed at compile time, gives a
bounded and comparable answer to all three questions. It gives up exactness, which is acceptable
because the consumer is a threshold on a trend, not a service-level objective measured to three
significant figures.

## Decision

The exposition is a fixed set of series labelled by at most two dimensions: transport type, and a
coarse result classification with exactly four members — success, gateway failure, upstream failure, and
client cancellation.

The coarse classification is a total function over the fine failure-category set the gateway already
reports, and is deliberately distinct from it. The fine set has thirteen members and is right for a
request record, where one row describes one exchange and exactness is free. It is wrong for a metric,
where the label is repeated across a time series and the operator must read it at a glance. Every fine
category maps to exactly one coarse member, so a rate computed over a coarse label is well defined and
nothing can fall through unclassified.

An exchange is counted once, at the single point where its result is decided, which is also the point
that emits the terminal lifecycle event. A request refused before it became work produces a rejection
fact and no result fact, so a refusal is never counted twice — once as a refusal and once as the
failure of a request that never started.

Rejections name the layer that refused and the reason within that layer. The global connection gate, a
provider concurrency bound, a provider rate allowance, a credential concurrency bound, a credential
rate allowance, and a credential long-lived-connection bound are distinct facts, because "the
credential rate bound refused four hundred requests" and "the provider concurrency bound refused four
hundred requests" are the same symptom and two different fixes.

Percentiles are read as histogram quantiles from cumulative buckets whose boundaries are fixed at
compile time and shared by every series. The highest bucket is unbounded, so an observation is never
discarded for being slow; a quantile that dropped its tail would be worse than no quantile, because it
would look calm. A quantile over an empty series is undefined and is reported as unknown rather than
as a zero, because a zero latency percentile is a factually wrong answer to a question that has no
answer yet. The quantile is declared for every series whether or not that series has an observation, so
declaring it never makes the shape of the exposition a function of traffic.

The exposition is rendered from compiled closed sets, so its size is a property of the build rather
than of a deployment's traffic. Recording a fact is a relaxed atomic increment on a preallocated slot,
so the hot path adds no lock and no allocation, and rendering allocates only in a control-plane call.
The control plane serves the exposition to an authenticated administrator only, and the data plane
serves it at no path at all.

Provider and account dimensions are not included. This is a deliberate deferral and not an oversight,
and it is the reason this decision is worth recording: adding those dimensions later means adding
series to an exposition whose semantics are already fixed, rather than redefining what a series means.
Until an alert actually needs a per-provider breakdown, the cardinality is not paid for.

## Consequences

- The exposition can answer whether latency rose, whether the failure rate rose, and whether the
  process is refusing work, which is the minimum an alert needs and which none of the alternatives
  delivered without an unbounded dimension.
- Percentiles are interpolated within a bucket rather than exact. The boundaries are wide enough to be
  useful for a trend and fixed enough that two processes are comparable.
- A refused request is now visible as a refusal with a reason, so shedding is observable rather than
  inferred from the absence of traffic.
- Every series multiplies by four when a new coarse result member is added, and the set is closed, so
  that is an architectural change rather than something a deployment can turn on.
- The result classification is a second vocabulary beside the fine failure-category set. The mapping
  between them is total and is part of the design rather than an implementation detail, but a reader
  must be told it exists rather than discovering it.
- Per-provider and per-account metrics remain unavailable. When they are needed, the added cost is
  series count, and the discipline this decision fixes is what keeps that cost a decision rather than
  an accident.
- A future capability that needs a payload — token or usage statistics — is not a new label. It is an
  adapter outside the proxy core, as the event bus already anticipated.
