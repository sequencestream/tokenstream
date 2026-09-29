# 0004. Request-local immutable snapshots

- Status: Accepted
- Date: 2026-09-29

## Context

After a gateway credential is verified, the process needs the provider endpoint and decrypted upstream key for the life of that request or connection. Those values could come from a shared mutable cache, from a process-wide map updated in place when an administrator edits a provider, or from a request-local snapshot created once after verification.

A cache would hide database latency on the hot path, but it would also serve stale or rotated credentials, need invalidation, and create a second source of truth. Mutating a shared record under an active stream would let a disable, rotation, or endpoint edit change a connection that had already been admitted.

## Decision

Each admitted request or connection looks up the credential it was given, verifies the secret, resolves the account that owns it and the one provider it selects, decrypts the upstream key, and then holds an immutable, request-local snapshot of all four. There is no application-level credential cache. Account status, credential status and expiry, credential rotation, provider edits, provider disabling, and deletion affect new work only.

Snapshot creation is in the [authentication design](../modules/authentication.md). Provider lifecycle is in the [providers design](../modules/providers.md).

## Consequences

- Already admitted HTTP streams and WebSocket connections keep working with the snapshot they received, even if the account is disabled, the credential is rotated, or the provider is later disabled.
- New requests using an old credential fail as soon as the committed rotation is visible.
- Lookup cost and database deadlines sit on every new admission and must fail closed under [ADR 0006](./0006-fail-closed-resource-bounds.md), rather than being absorbed by a cache.
