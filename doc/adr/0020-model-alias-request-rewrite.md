# 0020. Resolve an account model alias by rewriting the selected provider's model name

- Status: Accepted
- Date: 2026-10-28

## Context

An account can already store a caller-facing model name and the upstream model name each provider
uses for it ([ADR 0019](./0019-account-owned-model-alias-configuration.md)). That record was inert:
the data plane did not read it, because reading a `model` field inside the proxy would make
application-payload inspection part of the transparent core, and because several targets must not
become a way to choose or fail over among providers.

Callers that keep one model name across providers otherwise have to duplicate each provider's model
name in every client. The alias record already says which upstream name belongs to which provider.
What it did not say is when that name replaces the one in the request.

The alternatives were to leave the substitution to every client, to let the alias choose the
provider, to rewrite the field inside the proxy, or to rewrite it in an adapter that runs only
after the provider is already selected.

Leaving the substitution to clients preserves a proxy that never sees `model`, and it is why the
alias record was stored before it was interpreted. It also makes the stored targets unused by the
only path that can apply them. Letting the alias choose the provider would read the body to make a
routing decision, which the credential's provider selector already refuses to do. Rewriting inside
the proxy would put an application field in the component whose invariant is that it has none.

## Decision

A model alias stays account-owned configuration. Its targets stay a dictionary: one provider, one
opaque upstream model name, with no priority, weight, or fallback meaning.

After a request has resolved to exactly one provider, the gateway freezes that account's alias
names for that provider into the request snapshot. An account with no aliases freezes an empty
table, and the request body and WebSocket messages are not inspected.

When the table is not empty, an adapter outside the proxy core reads only a bounded prefix of the
HTTP body, or a client WebSocket text message, and looks for one top-level JSON string named
`model`:

- The string matches an alias that names this provider: the adapter replaces that string with the
  frozen upstream model name. The rest of the payload is unchanged.
- The string matches an alias that does not name this provider: the request fails before any
  upstream receives it. On a WebSocket the handshake may already have completed, because the model
  arrives in a later message; that message is not forwarded.
- The string matches no alias: the payload is forwarded unchanged, so a caller can still send a
  provider's own model name.
- The field is missing from the bounded prefix, or the body is not a JSON object: the payload is
  forwarded unchanged.
- The field is present but is not one unambiguous string: the request fails before the payload is
  forwarded.

The adapter does not choose a provider, inject a model that was absent, retry, or rewrite the
response. The proxy core still does not read or interpret application payloads. Alias names and
upstream model names do not enter logs, events, or metrics.

An account may store at most a fixed number of aliases, so the frozen table has a fixed maximum
size. A later edit to an alias affects the next request only.

This decision supersedes the part of [ADR 0019](./0019-account-owned-model-alias-configuration.md)
that kept aliases out of the data plane. The ownership, uniqueness, and target rules of that
decision stand.

## Consequences

- One caller-facing name can reach several providers, and each provider sees its own model name.
- Provider selection remains the credential binding and the dedicated selection header.
- Accounts that store no aliases keep the previous byte-transparent path.
- A response still echoes the upstream model name. Rewriting that echo requires a separate decision.
- The proxy core gains no application-payload type. The rewrite adapter is a separate module, and
  the proxy does not depend on it for its forwarding path.
- Authentication does one more bounded read on the snapshot path. An empty result skips the adapter.
- Creating one alias past the account cap fails. The cap is what keeps the snapshot bounded.
