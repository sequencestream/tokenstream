# 0013. Data-plane credentials identify an account, not a provider

- Status: Accepted
- Date: 2026-09-29

## Context

A gateway credential currently resolves directly to one provider. The credential *is* the upstream
binding, so changing upstreams means issuing a new key, and no request has an owner: a log row names a
provider but not a caller. Anything that needs to distinguish traffic by user — per-user limits, per-user
logs, billing, or a later user-named model alias — has nothing to group by.

The alternatives were to keep the key as the binding and add a user name beside it, to have accounts issue
keys while the key still named a single provider, or to let the credential name a set of providers and
pick one per request.

Picking a provider per request requires a selection input. The only inputs available on a transparent
gateway are the credential, non-payload request fields such as a dedicated header, and the request body.
Reading the body to find a model name would break the transparency principle, so a multi-provider
credential can only be selected by a field the gateway is allowed to look at — and a credential that
silently routes differently depending on a header is surprising to audit.

## Decision

A data-plane credential belongs to an account from creation and identifies that account. It no longer
identifies a provider.

A credential is issued against an ordered set of allowed providers and may name one of them as its
default. Each request still resolves to **exactly one** provider, chosen from:

1. the credential's default binding, and
2. a dedicated non-payload request header, when the credential allows more than one provider.

If neither selects a provider, the request fails closed before any upstream contact. The gateway never
reads the request body to choose a provider; payload transparency is unchanged, and model selection
remains the client's responsibility.

A credential has a lifecycle: it can be created, enabled, disabled, expired, and rotated. Its plaintext
appears only at creation and at rotation, exactly as an upstream key does, and is never recoverable
afterwards.

After authentication succeeds, the request snapshot freezes the account, the credential, and the one
selected provider together. Disabling an account or a credential, changing a role, or editing a binding
affects new work only; a stream or connection that was already admitted keeps the snapshot it holds.

The allowed provider set, the default binding, and the selector are all credential configuration, not
per-request payload. A credential bound to exactly one provider behaves as it did before.

## Consequences

- Every future capability that needs to know "whose traffic is this" reads the account already frozen in
  the snapshot, so none of them requires a second identity model.
- A credential can reach more than one provider, but never more than one at a time, and never by reading
  the body. The set is explicit, reviewable configuration.
- The provider concept stops being an authentication concern. A provider is now purely an upstream
  configuration, and the credential is a routing and attribution concern.
- Losing a create or rotate response still means rotating again; the plaintext cannot be recovered.
- The migration from provider-issued keys is in
  [ADR 0014](./0014-migrating-provider-issued-credentials.md).
