# Tokenstream Architecture

This document defines the long-term architectural direction of Tokenstream and the core principles, constraints, and policies that bind every change. Milestone specifications and designs apply this architecture to their own scope; they may narrow scope, but they must never relax anything defined here.

## 1. Positioning

Tokenstream is a transparent, provider-scoped AI gateway. It terminates downstream connections, authenticates a gateway credential, resolves exactly one upstream provider, validates the requested route and transport, replaces credentials, and relays HTTP/SSE byte streams and WebSocket messages without interpreting application payloads.

The gateway is infrastructure, not application logic. It does not select models, transform payloads, choose transports, schedule or bill usage, or make fallback decisions.

## 2. Core Principles

1. **Payload transparency**: Never inspect, deserialize, or adapt application payloads. Normal proxy duties — terminating connections, removing hop-by-hop headers, replacing credentials — are not application-protocol conversion. The gateway never reads or injects fields such as `model`, messages, tool calls, or streaming events.
2. **Loose coupling to upstream versions**: Ordinary application field and event additions pass through without gateway changes. Only changes to paths, authentication, or transport handshakes may require configuration or code changes.
3. **Client-owned fallback**: The WebSocket↔HTTP/SSE fallback decision belongs to the client SDK or CLI. The gateway never converts a WebSocket exchange into an HTTP request or vice versa, and never creates the fallback request.
4. **Performance first**: The gateway is fully asynchronous, built with Rust and Tokio, with bounded streaming and backpressure, no garbage collector, and no full-body buffering. It is built for high-concurrency, long-lived connections whose memory use stays bounded regardless of connection duration.
5. **Explicit scope discipline**: Tokenstream provides unified multi-provider access, transparent transport, basic configuration, and basic observability. Scheduling, billing, circuit breaking, rate limiting, retries, caching, load balancing, protocol conversion, and token parsing stay out of scope. Any future capability that conflicts with transparency must be a separate adapter built outside the proxy core, approved explicitly rather than folded into the core.

> **Model-selection boundary**: Model selection and default-model fallback belong to the client or a separate application-layer adapter. The gateway never reads or injects `model`; clients must send a request that is valid for the selected upstream API.

## 3. Non-Negotiable Constraints

- **Proxy**: Never read, inject, or validate application fields. HTTP request and response bodies are streamed with bounded buffers and backpressure, never fully buffered. WebSocket application messages are relayed without deserialization, under configured message and connection bounds. There is no retry, no reconnect, no protocol conversion, and no load balancing. Client cancellation cancels the associated upstream request.
- **Logging**: Logging is best-effort, metadata-only, and must never block proxy traffic. A full log queue drops events and increments a dropped-event metric. Request and response payloads are never stored. Metrics carry no key IDs, URLs with query strings, or other high-cardinality secrets.
- **Bounds**: A global semaphore bounds admitted proxy connections. No component may accumulate without a bound: WebSocket message sizes and outbound queues, HTTP body buffering, database pool size, and log queue capacity are all bounded. Authentication lookup exhaustion fails closed with a sanitized gateway error. Upstream connect, response-header, idle, and shutdown durations are explicit timeouts.

## 4. Security Invariants

- Upstream keys are encrypted at rest with authenticated encryption (AES-256-GCM). Nonce, key version, and ciphertext are stored together. The master key is supplied through an environment secret or secret manager and is never stored in the database.
- Gateway secrets are hashed with a memory-hard password hashing function (Argon2id) and verified with data-independent, constant-time comparison. A secret is returned only at creation or rotation and is never persisted in plaintext.
- `Authorization`, `Proxy-Authorization`, `x-api-key`, cookies, credential values, URL query strings, and application bodies are redacted from logs and error messages.
- APIs never expose ciphertext or password hashes. Provider reads may return non-secret configuration fields and an indication of whether a secret is configured, but never plaintext secrets.
- Decrypted keys live only in short-lived secret wrappers: they are never logged, serialized, rendered by debug output, or returned by an API.

## 5. Route and Transport Policy

- The gateway runs an explicit allowlist over provider, HTTP method, normalized path, and transport. Every other combination — including a path valid for one provider presented to another — is rejected before any upstream contact.
- Path matching uses the normalized path only. The original query string is forwarded unchanged and is never logged.
- Streaming mode is never inferred from application fields such as a JSON `stream` flag. SSE is simply an upstream HTTP response body and content type, streamed transparently.
- For WebSocket routes, the upstream handshake is established before the downstream upgrade is accepted; an upstream handshake failure becomes a normal downstream HTTP failure so the client can choose its own fallback. The gateway never reconnects an upstream WebSocket.

The route allowlist is:

| Provider | Method | Path | Transport |
| --- | --- | --- | --- |
| `openai` | `POST` | `/v1/chat/completions` | HTTP / SSE |
| `openai` | `POST` | `/v1/responses` | HTTP / SSE |
| `openai` | `GET` | `/v1/responses` | WebSocket |
| `anthropic` | `POST` | `/v1/messages` | HTTP / SSE |

Any addition, removal, or change to an allowed route is an architectural change, not a routine implementation change.

## 6. Header Policy

- Remove hop-by-hop headers per RFC connection semantics, including headers nominated by the `Connection` header, and remove `Proxy-Authorization`.
- Require the provider-native downstream credential header (`Authorization: Bearer` for OpenAI, `x-api-key` for Anthropic), replace its gateway key with the upstream key in that same header, and reject duplicate or conflicting credential headers. Set the upstream authority/host from the configured endpoint.
- Replace untrusted inbound forwarding headers with a single value derived from the direct downstream peer, according to one fixed, documented trusted-proxy policy.
- Preserve all other end-to-end headers, including provider version and beta headers.
- Relay upstream response headers after removing hop-by-hop headers, and never rewrite upstream error bodies.
- The same principles govern the WebSocket handshake, except that required upgrade headers are reconstructed by the WebSocket implementation.

## 7. Component Boundaries

- The **data plane** (proxy traffic) and the **control plane** (administration) are logically separate: separate route trees, separate middleware, and separate authentication that can never be confused. They may ship in one binary, but the separation is permanent.
- The proxy core contains no application-payload types. A component that translates application protocols, selects models, or implements fallback is a separate adapter, never an extension of the proxy core.
- Every admitted request or connection holds a request-local, immutable configuration snapshot, created only after credential verification and secret decryption. Provider edits, disabling, key rotation, and deletion affect new work only; they never alter a snapshot held by an active stream or connection.
- Proxy modules depend on snapshot lookup and a non-blocking log sink; they never depend directly on administration handlers. Repository models that contain secrets remain internal, and API responses use separate types so secrets cannot be serialized accidentally.

## 8. Verification Philosophy

Transparency and safety are proven by tests, not assumed:

- HTTP/SSE and WebSocket contract tests demonstrate byte-preserving relay across arbitrary chunk fragmentation, unknown application fields, backpressure, cancellation, and abrupt disconnects.
- Security tests assert redaction, fail-closed behavior, and the absence of secrets from logs and API responses.
- Load tests demonstrate stable memory under the documented concurrency profile for long-lived streams and enforce every queue, buffer, and semaphore bound.
- A version-controlled manifest of pinned client and SDK versions, run against a controllable mock upstream, is the release compatibility gate; external live services are never the CI correctness dependency.

A change is complete only when all applicable layers pass. Milestone designs may add tests, but may not remove or weaken any of these layers.
