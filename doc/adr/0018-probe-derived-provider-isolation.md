# 0018. Probe-derived provider isolation, and a refusal rather than a reroute

- Status: Accepted
- Date: 2026-09-30

## Context

A provider's availability is currently a manual switch. An operator disables a provider when they
know it is down, and until then every request addressed to a dead origin pays its own connect failure
or its own connect timeout. The gateway learns that an upstream is unavailable only from the traffic
it is already refusing to serve.

The architecture document places circuit breaking and half-open probing in the excluded
application-scheduling layer, so giving a provider a health state is a deliberate scope extension and
not a routine change. The fork that actually matters is therefore not *whether* the gateway probes an
upstream, but what an unhealthy provider does to the traffic addressed to it.

Four shapes were genuinely available.

Do nothing and let each request discover the failure. This is today's behaviour, and it is the one
this decision replaces: the cost is one failed connect or one connect timeout per request, paid by
every caller, for as long as the upstream is down.

Reroute the request to another provider the credential allows. This is the operationally valuable
answer and the one that breaks the resolution contract. A request resolves to exactly one provider
([ADR 0004](./0004-request-local-immutable-snapshots.md)), chosen by the caller through a
non-payload field. Silently answering a request for one origin with a different origin's response is a
correctness change wearing an availability costume: the caller cannot tell which model actually ran,
and neither can a request record.

Retry the same provider. This multiplies load on an upstream that is already failing, and an upstream
that is failing because it is overloaded is made worse by the gateway's reaction to it. It also
requires re-running an exchange, which the proxy constraint already forbids.

Half-open trial traffic: admit a small number of real requests to test recovery. This is genuinely a
scheduling decision, because it decides which requests may cross and in what proportion, and it needs
a comparison against alternatives that this decision does not have. Admitting *probes* achieves the
same recovery detection without that comparison.

## Decision

A provider gains a health state of three members — healthy, isolated, and maintenance — decided from
provider configuration and from probes the gateway originates itself. An isolated provider refuses new
work before any upstream is contacted, and nothing anywhere else decides anything.

The decision is a **refusal, never a reroute**. The existing excluded-scheduling item is reconciled
rather than deleted: probe-derived isolation is admitted, and rerouting, retries, weighted and priority
routing, and latency-based selection stay excluded.

The health state is **persisted**, and a newly created provider starts healthy. The state
is the product of a slow, sampled observation, so the interval between the probe that crossed the
threshold and the next one is a window in which a restart would otherwise discard a verdict the
process had already reached. A stored state makes the refusal survive the restart that most often
follows an incident.

The alternative — recomputing isolation from nothing on every start — was rejected because it makes
recovery cost a full failure threshold after every restart, so a provider that failed twice, crossed
the threshold, and then had its process restarted is trusted again until it fails three more times.
The concern that motivated it, a stored verdict going stale, is real and is answered by the
maintenance window rather than by amnesia: an operator who knows the stored state is no longer
meaningful opens a window, which is explicit and reversible where forgetting is neither.

Maintenance is a **manual state that suppresses probing entirely** and is strictly stronger than
isolation. An operator holding a provider expects no probes, and a probe during a planned upstream
change is both noise to the upstream and a source of false recovery.

Isolation uses **one threshold of consecutive failed probes**, and recovery needs only **a single
successful probe**. Hysteresis between a failure and a recovery threshold was considered and
rejected: it exists to damp a probe result that is ambiguous near the boundary, and the permissive
success criterion has already removed that ambiguity. A recovering upstream is not flickering across a
line — it is either refusing connections or answering, and the first answer is real evidence. A second
threshold would add a stored setting, a validated field, and a way to leave a provider isolated
because its recovery threshold was set higher than anyone remembered, in exchange for damping that is
no longer needed.

A probe is a **bodyless request to an operator-named path** resolved against the provider's own
endpoint origin. It is never a captured business request, never carries a request body, a client
header, or a client credential, and is bounded by the same upstream deadlines as ordinary traffic.

A probe **carries no upstream credential**. Attaching the provider's own encrypted key was considered
and rejected. It would put a secret into a task that runs on a timer rather than on a request, widen
the window in which the secret is resident, and couple the health subsystem to the secret store — all
of it to buy an authentication the success criterion does not need: a refused probe is already a
success, so an authenticated probe and an unauthenticated one report the origin identically. The
accepted cost is that an upstream which is reachable but refusing every request reports healthy. That
is deliberate, because the alternative is a probe that authenticates, and the rule that removes the
need to authenticate is the same rule that would require it.

A probe's **success criterion is the response status and nothing else**, and it is permissive: any
status below 500 means the upstream answered. Only a transport failure, a deadline, or a status at or above 500 is
a failed probe. An upstream that routes an unknown path to a helpful 404 is healthy, and treating that
as a failure would isolate a provider that is serving real traffic perfectly well.

A provider **without a probe path is never probed and can never be isolated**, and holds no probe
registry state at all. The alternative — a default probe path — would mean a provider the operator never
configured for probing could be taken out of service by a probe against a path that was never theirs.

Registry state is **bounded by the number of providers configured for probing**, not by traffic: an
entry is created on first use and dropped when probing stops, exactly as an admission counter is not
created for an unbounded entity. The registry holds opaque provider identifiers and small counters,
never a name, endpoint, key, or secret.

Health state and the maintenance control are **administrator-only**, because maintenance is a
write to which upstreams this gateway trusts and a regular account has no standing to make.

## Consequences

- A dead upstream stops costing every caller a connect timeout within one probe interval, and the
  operator sees why in the administration view and the exposition without reading a single request
  log.
- No client is taught a new failure: an isolated provider is refused with an error class that already
  exists, so the contract a pinned client depends on does not move.
- A request that resolves to an isolated provider fails before any upstream contact, which means the
  refusal costs one credential lookup and no network — the same cost profile as a capacity refusal.
- An exchange already admitted keeps its snapshot and finishes under the state it started in, so
  isolation never cancels a stream that is already producing tokens.
- The health state is persisted, so a restart does not clear an isolation, and a future clustered
  deployment would have several processes each observing health and writing one shared verdict. That
  is recorded here as a later decision rather than pretended away, because this round is explicitly
  single-process.
- An upstream that is reachable but refusing every request reports healthy, because the probe carries
  no credential and any status below 500 counts as an answer. Detecting that condition is a protocol
  question, and reading a response body to answer it is a payload capability this round refuses.
- Probe outcomes and health-state membership appear in the exposition as bounded, low-cardinality
  facts. The per-provider metric dimension stays excluded ([ADR 0017](./0017-cardinality-bounded-observability.md)),
  so an operator learns *that* a provider is isolated from the administration view and *how many* are
  isolated from the exposition, and per-provider rates are still a later decision.
- Rerouting, retries, weighted and priority routing, latency-based selection, and half-open trial
  traffic remain application-layer scheduling and out of scope. They are not blocked by this decision;
  they are refused by it.
