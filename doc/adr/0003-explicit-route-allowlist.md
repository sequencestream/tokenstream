# 0003. Explicit route allowlist

- Status: Accepted
- Date: 2026-09-29

## Context

A multi-provider gateway can accept any path the upstream would accept, can let each provider record carry its own route table, or can fix a small allowlist of provider, method, path, and transport.

Open routing would make the gateway a generic HTTP forwarder and would contact upstreams for unsupported or cross-provider paths. Per-provider route configuration would look flexible, but it would turn path and transport changes into unreviewed runtime edits and would hide cross-provider mistakes until traffic escaped.

## Decision

The gateway runs an explicit allowlist over provider, HTTP method, normalized path, and transport. Every other combination — including a path valid for one provider presented to another — is rejected before any upstream contact. Adding, removing, or changing an allowed route is an architectural change, not a configuration option.

The allowlist itself is in the [architecture document](../architecture.md). How a request is classified is in the [routing design](../modules/routing.md).

## Consequences

- Streaming mode is not a route. SSE is an allowed HTTP response body and content type, never inferred from an application `stream` flag.
- Query strings are not routing input. They are forwarded unchanged and never logged.
- Clients cannot probe arbitrary upstream surfaces through the gateway. Supporting a new path requires changing the architecture document, not toggling a provider setting.
