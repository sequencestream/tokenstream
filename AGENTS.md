# AGENTS.md

Entry point for agents and contributors. Defines the rules governing Tokenstream. Long-term architecture and principles live in `doc/architecture.md`; milestone implementation detail lives in the MVP documents below.

## Documentation Independence Principle

> **Core Constraint**: Documentation and source code must remain independent and self-consistent.

- Docs must not reference code files, functions, types, or line numbers.
- Code must not reference docs — no comments pointing to documentation.
- Each artifact stands on its own. When they diverge, reconcile both.
- Doc-to-doc references are allowed.

## Documentation Index

| Document | Path | Description |
| --- | --- | --- |
| Architecture | `doc/architecture.md` | Long-term direction, core principles, non-negotiable constraints and policies |
| MVP Spec | `doc/mvp/mvp.md` | MVP scope and acceptance criteria |
| MVP Design | `doc/mvp/design.md` | Module boundaries, APIs, procedures |

## Architecture Authority

The core principles (payload transparency, loose upstream coupling, client-owned fallback, performance first, explicit scope discipline), the non-negotiable proxy/logging/bounds constraints, the security invariants, and the route and header policies are defined in `doc/architecture.md` and bind every change. The MVP documents apply them to the current milestone and must never relax them; when a document relies on these rules, it references the architecture document rather than redefining them.

## Working Rules

1. No application-payload types in the proxy core.
2. No out-of-scope features without approval.
3. Verify behavior against `doc/architecture.md`, `doc/mvp/mvp.md`, and `doc/mvp/design.md`.
4. No doc↔code cross-references; keep docs self-consistent.
5. Prefer editing existing files.

## Verification

Complete only when unit, repository, HTTP/WebSocket contract, security, load, and pinned-client compatibility tests pass. See the design document for details.
