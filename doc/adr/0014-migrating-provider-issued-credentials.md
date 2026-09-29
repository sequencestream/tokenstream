# 0014. Migrating provider-issued credentials to account-owned credentials

- Status: Accepted
- Date: 2026-09-29

## Context

Credentials issued before [ADR 0013](./0013-account-owned-data-plane-credentials.md) belong to a provider
and resolve straight to it. They have no account. A deployment that upgrades therefore holds credentials
that the new model cannot authenticate, because a credential now has to name an account.

Three strategies were available. The migration could force every operator to re-issue all credentials
immediately, which breaks every running client at the moment of upgrade. It could accept provider-owned
credentials indefinitely as a compatibility path, which keeps the model ambiguous permanently: two
kinds of credential, one ownerless, and no clear end state. Or it could convert the existing credentials
into account-owned credentials in place, preserving the key identifier and hash so every already-deployed
client keeps working.

## Decision

Existing provider-issued credentials are **converted in place**. On migration each one becomes a
credential owned by the bootstrap administrator and bound to its original provider as the default. The
stored key identifier and secret hash are preserved, so a client that already holds the credential
continues to authenticate with no change and no re-issue.

Providers no longer issue credentials. Rotation of a migrated credential is a credential operation, and
the result is an account-owned credential bound to the same provider.

The bootstrap administrator is the owner of every migrated credential, so all traffic keeps resolving
through one principal until an operator distributes new credentials to the accounts that should own it.
The administration API exposes the migrated credentials as ordinary account credentials from that point
on, with no separate compatibility path.

A credential that is presented but is absent from storage fails closed, whether or not it predates the
migration. There is no fallback that trusts a legacy shape.

## Consequences

- An upgrade does not interrupt running clients, and operators migrate ownership gradually by issuing
  new credentials per account.
- The old key identifier and its hash survive the upgrade, so the migration cannot silently invalidate
  traffic the way a forced re-issue would.
- Provider configuration no longer carries credential material at all, so a provider cannot leak a
  credential through its own record.
- The bootstrap administrator is temporarily the owner of all traffic. Until credentials are
  redistributed, per-user limits and per-user logs attribute everything to it, which is honest rather
  than wrong.
- There is no permanent legacy credential type, so the authentication path has exactly one shape.
