# 0012. Account sessions and two roles in the control plane

- Status: Accepted
- Date: 2026-09-29

## Context

The control plane authenticates one administrator with a single process-wide passphrase. That is enough
when the only writable things are providers and process settings, because one operator owns all of them.
Accounts make that model insufficient: a gateway credential has to belong to someone, per-user limits and
per-user logs need an owner, and later billing needs a subject. The identity of the calling principal has
to exist before any of those can be built, or the whole control-plane surface and the request snapshot are
built twice.

The alternative was to keep the single administrator and add users as a second, parallel concept. That
leaves two notions of "person" in one system: a passphrase that owns configuration, and a label attached
to a key. The label is not a principal, so it cannot be denied access, cannot hold a session, and cannot
be audited.

A general role and permission system was also on the table. It was rejected: the resource kinds are still
only accounts, credentials, providers, and process settings. A permission matrix over four resource
kinds, none of which is a bill, a policy, or an audit trail, would encode today's guesses as tomorrow's
schema and would be redone the moment a fifth resource appears.

## Decision

The control plane authenticates **accounts**, not a process-wide passphrase. An account is a person or
principal with a name, a hashed password, a status, and exactly one of two roles.

Sign-in identifies the account by name and verifies its password. The session it establishes records the
account identity and the role, so every later request in that session acts as that account.

The two roles are fixed and written into the architecture rather than stored as configuration:

- **Administrator** manages accounts and roles, providers, and process settings, and may disable any
  credential.
- **Regular user** manages only its own credentials. It cannot write providers, cannot change process
  settings, cannot create or edit accounts, and cannot read or alter another account's credentials.

The role is a closed set, not a table of permissions. Adding a role is an architectural change with its
own record; it is not a configuration edit. Authorization is decided once per request from the session's
account and role, before the handler runs, so a resource is never accidentally reachable because a
handler forgot a check.

A **bootstrap administrator** is the first account, created from the configured administrator
credentials when no account exists. It is what an existing deployment signs in with after the change, and
it cannot be disabled or demoted, so a deployment can never lock itself out of its own accounts.

Plane separation is unchanged and permanent: a control-plane session never authenticates data-plane
traffic, and a data-plane credential never authenticates a control-plane request.

## Consequences

- Accounts become the common owner for credentials, and later for limits, logs, and billing, so those
  features attach to an existing foreign key instead of inventing one.
- The role vocabulary stays two until a fifth resource kind makes a permission model worth writing.
- The bootstrap administrator is a single point of recovery. Losing it means restoring from the
  configured administrator credentials.
- Every control-plane request now resolves a principal, so authorization failures are a normal outcome
  rather than an exception.
- Sign-in cost is per account, so hashing budgets and their deadlines apply to every control-plane
  verification, exactly as they already applied to the single administrator.
