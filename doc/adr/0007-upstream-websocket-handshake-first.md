# 0007. Upstream WebSocket handshake first

- Status: Accepted
- Date: 2026-09-29

## Context

For Responses WebSocket traffic, the gateway can complete the downstream upgrade first and then dial upstream, or it can dial upstream first and only then accept the downstream upgrade. Completing downstream first would give the client a successful WebSocket whose peer might immediately fail, hiding the upstream HTTP rejection that clients use to fall back to HTTP/SSE.

Accepting any `101` as success would also hide invalid upgrade responses: missing or duplicate accept values, unoffered subprotocols, or negotiated extensions.

## Decision

The upstream WebSocket handshake is established before the downstream upgrade is accepted. An upstream handshake failure — including an invalid `101` — becomes a normal downstream HTTP failure so the client can choose its own fallback. The gateway never reconnects an upstream WebSocket and never creates the fallback request ([ADR 0001](./0001-transparent-proxy-core.md)).

Handshake and relay behavior is in the [proxy design](../modules/proxy.md). Header reconstruction rules are in the [architecture document](../architecture.md).

## Consequences

- An ordinary non-upgrade HTTP rejection from upstream is streamed through unchanged, including its body, so a client can act on that response.
- An invalid `101` is not a successful upgrade: the downstream upgrade is not accepted, the upstream connection is closed, and the client receives a sanitized local failure.
- A later `POST` to the same path is an independent request with its own identity and log record.
- Required upgrade headers are reconstructed; every allowed repeated end-to-end value is retained. Unsupported extensions are rejected.
