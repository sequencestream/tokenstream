# 0009. Same-origin administration

- Status: Accepted
- Date: 2026-09-29

## Context

The administration page needs a session cookie and CSRF protection. Serving the page from a second origin would require cross-site cookie exceptions. Serving only an API would push origin and cookie policy onto whatever hosts the page. Allowing shared caches on JSON responses would let intermediaries or the browser retain session material and one-time gateway credentials.

A role system and general request rate limiting were also possible. They would expand the control plane beyond a single administrator and would duplicate process-level hashing, body, and connection bounds.

## Decision

The administration page and the administration API share one origin. The control-plane listener serves the compiled entry document and its own compiled assets from the process. There is a single administrator account, no role system, and no application-level request rate limiter.

A successful sign-in sets a short-lived, HTTP-only, same-site session cookie, also marked secure on a secure origin. State-changing endpoints require CSRF protection. Every administration API path stays behind session authentication. Control-plane JSON responses, including errors and empty success bodies, forbid shared caching. A page build is not a release substitute for real browser sign-in, session restoration, credential handling, expiry, and sign-out.

The public surfaces are in the [architecture document](../architecture.md). Session and page behavior is in the [administration design](../modules/administration.md).

## Consequences

- Requests to the page are answered before a session exists, because the page must load in order to offer sign-in.
- A plaintext development origin drops only the secure cookie attribute and keeps HTTP-only and same-site restrictions. It may also allow non-HTTPS provider endpoints.
- Hashed page assets may use their own long-lived cache policy. The entry document is not stored, so a replaced binary is picked up on the next navigation.
- Control-plane hashing uses the reserved control-plane budget so sign-ins cannot consume data-plane verification capacity ([ADR 0006](./0006-fail-closed-resource-bounds.md)).
