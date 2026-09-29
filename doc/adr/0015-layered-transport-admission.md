# 0015. Layered transport admission, separate from application scheduling

- Status: Accepted
- Date: 2026-09-29

## Context

Admission was a single process-wide semaphore. One provider or one client could occupy every slot, so a
noisy neighbour consumed the whole gateway while unrelated traffic was rejected for a reason that named
neither of them.

Something more than a counter is available as a design and was rejected: probes that decide an
upstream's health and route around an unhealthy one, retries after a failed exchange, weighted or
priority routing between providers, and choosing an upstream by measured latency. Each of those decides
*where* traffic goes. They need failure history, time, and comparison against alternatives, and several
of them re-run an exchange that already failed.

The other alternative was a per-account allowance wider than the credential, which is what billing needs
and what this does not have: there is no usage measurement to divide, and no notion of a period that is
not already the caller's to choose.

What the gateway actually has at the moment a request is admitted is a closed set of connection-level
facts: which credential presented, which account owns it, which single provider it resolved to, and
which transport it will use. Every one of those is already frozen in the request snapshot before any
upstream is contacted.

## Decision

Admission becomes layered, and every layer counts connections or requests. It never reads a payload and
never decides where traffic goes.

Layers exist at two granularities: **provider**, and **credential**. The credential is the unit because it
is the unit that already identifies a caller ([ADR 0013](./0013-account-owned-data-plane-credentials.md));
an account owns credentials, and aggregating above the credential belongs to the billing stage, which has
no measurement to aggregate.

A provider carries a maximum concurrent request count and an optional maximum request rate. A credential
carries a maximum concurrent request count, an optional maximum request rate, and a maximum number of
long-lived WebSocket connections. An unset limit is unbounded, and only the layers that are set apply.

Every limit is decided from the connection-level facts frozen in the request snapshot, so a limit is
part of the same snapshot discipline as the account, the credential, and the selected provider
([ADR 0004](./0014-request-local-immutable-snapshots.md)). Editing a limit affects new work only; a stream
or connection already admitted keeps the limit it was admitted under.

Acquisition never waits. A layer with no capacity rejects immediately, and the existing sanitized gateway
errors carry the refusal, so admission keeps the shed-rather-than-queue discipline of
[ADR 0006](./0006-fail-closed-resource-bounds.md). Limits are configuration with an explicit bound, and
a limit of zero is refused at every layer because it would forbid all traffic rather than bound it.

Counter state is bounded by the number of providers and credentials that carry a limit. A dimension that
carries no limit holds no counter at all, so an unbounded provider cannot grow per-provider state.

## Consequences

- One client can no longer exhaust the gateway for everyone, and one provider can no longer consume
  capacity that belongs to another.
- Rejection reasons stay inside the existing error contract: no new code, status, or envelope appears,
  so no client has to be taught a new failure.
- Layers are evaluated after authentication and route resolution, so a rejected request performs one
  credential lookup and no upstream contact. Admission that ran before authentication would either be
  unattributable or would attribute by an unauthenticated claim.
- A rate limit is a token bucket over a monotonic clock: a burst up to one interval's worth is admitted
  and a sustained rate above the limit is not. It costs no timer task and no allocation per refill.
- Circuit breaking, retries, failover, weighted and priority routing, latency-based selection, monthly
  quotas, and account-wide aggregation all remain application-layer scheduling and out of scope. They
  are not blocked by this decision; they are refused by it.
- Changing a limit is a configuration edit an administrator makes deliberately. There is no adaptive
  or automatic limit anywhere in this decision.
