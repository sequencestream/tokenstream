# 0002. Dual planes in one process

- Status: Accepted
- Date: 2026-09-29

## Context

Proxy traffic and administration have different authentication, failure domains, and performance budgets. They could ship as two processes, as one process with a shared route tree, or as one process with two permanently separate planes.

Two processes would isolate faults and credentials more strongly, at the cost of two deployments, two health surfaces, and split configuration. One shared route tree would be simpler, but administrator sessions and gateway credentials could be confused, and control-plane load could contend with proxy admission on the same middleware.

## Decision

Both planes may ship in one binary. The separation is permanent: separate listeners, separate route trees, separate middleware, and separate authentication that can never be confused.

The data plane authenticates provider-scoped gateway credentials. The control plane authenticates the single administrator. Process composition, shutdown, and reserved budgets are in the [process design](../modules/process.md). Administration behavior is in the [administration design](../modules/administration.md).

## Consequences

- A burst of sign-ins or rotations must not consume data-plane verification capacity; hashing and database budgets are reserved per plane under [ADR 0006](./0006-fail-closed-resource-bounds.md).
- The administration page, when configured, is served from the control-plane listener so it shares an origin with the administration API ([ADR 0009](./0009-same-origin-administration.md)).
- Splitting into two binaries later remains possible without reversing plane isolation. Merging the route trees would reverse this decision.
