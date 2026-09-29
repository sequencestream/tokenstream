# AGENTS.md

Entry point for agents and contributors. Defines the rules governing Tokenstream. Long-term architecture and principles live in `doc/architecture.md`; module designs live under `doc/modules/`; architecture decision records live under `doc/adr/`.

## Documentation Independence Principle

> **Core Constraint**: Documentation and source code must remain independent and self-consistent.

- Docs must not reference code files, functions, types, or line numbers.
- Code must not reference docs — no comments pointing to documentation.
- Each artifact stands on its own. When they diverge, reconcile both.
- Doc-to-doc references are allowed.

## Documentation Index

| Document | Path | Description |
| --- | --- | --- |
| Architecture | `doc/architecture.md` | Positioning, principles, constraints, data model, public contracts, and verification |
| Development | `doc/develop.md` | Local build, settings, launch, verification, and GitHub Releases |
| Decisions | `doc/adr/` | Accepted forks among real alternatives |
| Process | `doc/modules/process.md` | Configuration, listeners, and graceful shutdown |
| Authentication | `doc/modules/authentication.md` | Gateway credential verification and snapshots |
| Routing | `doc/modules/routing.md` | Route and transport allowlist decisions |
| Proxy | `doc/modules/proxy.md` | HTTP/SSE streaming and WebSocket relay |
| Providers | `doc/modules/providers.md` | Provider lifecycle and snapshot loading |
| Logging | `doc/modules/logging.md` | Bounded, non-blocking transport-metadata logging |
| Administration | `doc/modules/administration.md` | Control-plane session, APIs, and administration page |

## Architecture Authority

The core principles (payload transparency, loose upstream coupling, client-owned fallback, performance first, explicit scope discipline), the non-negotiable proxy/logging/bounds constraints, the security invariants, and the route and header policies are defined in `doc/architecture.md` and bind every change. Module designs apply those rules within their own boundary and must never relax them; when a document relies on these rules, it references the architecture document rather than redefining them. A new architectural fork is recorded as an ADR under `doc/adr/` before the architecture document changes.

## Working Rules

1. No application-payload types in the proxy core.
2. No out-of-scope features without approval.
3. Verify behavior against `doc/architecture.md`, the relevant module designs under `doc/modules/`, and the relevant ADRs under `doc/adr/`.
4. No doc↔code cross-references; keep docs self-consistent.
5. Prefer editing existing files.

## Verification

Complete only when unit, repository, HTTP/WebSocket contract, security, load, and pinned-client compatibility tests pass. See the architecture document for details.
