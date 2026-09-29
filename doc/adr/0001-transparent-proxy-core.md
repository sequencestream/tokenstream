# 0001. Transparent proxy core

- Status: Accepted
- Date: 2026-09-29

## Context

An AI gateway can sit in front of provider APIs in several ways: inspect and rewrite application payloads, convert WebSocket exchanges into HTTP/SSE, select models, or retry and reshape traffic. Those behaviors couple the gateway to every upstream field and event change, and they steal fallback decisions from the client.

The alternatives on the table were:

1. A protocol-aware adapter that parses bodies, injects defaults, and converts transports.
2. A transparent relay that terminates connections, replaces credentials, and forwards bytes and messages unchanged.
3. A hybrid that stays transparent on HTTP but converts WebSocket to SSE inside the gateway.

## Decision

Tokenstream is a transparent, provider-scoped relay. It never inspects, deserializes, or adapts application payloads. It does not convert WebSocket to HTTP/SSE or the reverse, does not create a fallback request, and does not select models. Ordinary proxy duties — terminating connections, removing hop-by-hop headers, replacing credentials — are not application-protocol conversion.

The current rules live in the [architecture document](../architecture.md). The [proxy](../modules/proxy.md) and [routing](../modules/routing.md) designs apply them.

## Consequences

- Ordinary upstream field and event additions pass through without gateway changes. Path, authentication, and handshake changes still require an architectural change.
- Clients must send a request that is already valid for the selected upstream, including `model`. The gateway will not repair a missing field.
- Fallback after a failed WebSocket handshake is a new, independent HTTP request owned by the client, with its own identity and log record.
- Protocol conversion, retries, caching, and payload-aware features stay outside the proxy core. Folding them in would reverse this decision.
