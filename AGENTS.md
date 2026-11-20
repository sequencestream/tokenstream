# AGENTS.md

Rules for agents and contributors working on Tokenstream.

## Design Authority

| Source | Purpose |
| --- | --- |
| `doc/architecture.md` | Principles, constraints, security invariants, public contracts, and verification |
| `doc/modules/` | Module designs and boundaries |
| `doc/adr/` | Accepted architectural decisions |
| `doc/develop.md` | Local development, verification, and releases |

Every change must comply with the architecture, relevant module designs, and ADRs. Module designs must reference architectural rules rather than redefine or relax them. Record new architectural forks in an ADR before changing the architecture document.

## Working Rules

- Keep the architecture simple and elegant; make the smallest change that satisfies the feature and prefer existing files.
- Do not introduce application-payload types into the proxy core.
- Obtain approval before adding out-of-scope features.

## Documentation Independence

- Docs describe architectural concepts, flows, rules, and constraints, not implementation.
- Docs must not reference code files, functions, types, or line numbers; code must not reference docs. Doc-to-doc references are allowed.
- Docs and code must each stand alone and remain self-consistent. Reconcile both when they diverge.

## Feature Completion

After developing each feature:

1. Review the architecture for elegance, extensibility, and maintainability. Fix shortcomings and repeat until the review passes.
2. Run formatting and tests after resolving review findings. Fix all formatting issues and test failures before completion.

Required tests include unit, repository, HTTP/WebSocket contract, security, load, and pinned-client compatibility tests, as defined in `doc/architecture.md`.
