# 0019. Account-owned model aliases are inert control-plane configuration

- Status: Accepted
- Date: 2026-10-05

## Context

Accounts and account-owned credentials give every caller a stable owner, but a caller still has no
durable place to name the model it intends to use across providers. Provider bindings answer which
upstreams a credential may reach; they do not say that two provider-specific model names represent
one caller-facing choice.

The alternatives were to leave model names entirely with each client, attach aliases to credentials,
or make an alias an account-owned resource before giving it any data-plane behavior.

Leaving names with clients preserves transparency but forces each client to duplicate configuration.
Attaching aliases to credentials makes the same account repeat them across every credential and turns
credential rotation and access control into model configuration. Resolving an alias immediately from
the request body would make application-payload inspection part of the gateway before the adapter and
scheduling contracts exist.

## Decision

A model alias is account-owned control-plane configuration. Its name is unique within its account and
it contains a bounded, non-empty set of targets. Each target names one existing provider and one opaque
upstream model name; a provider appears at most once in one alias.

Target order is preserved only so a configuration can be read back as it was written. It is not a
priority, weight, fallback order, or scheduling policy.

Administrators manage aliases for any account. A regular account manages only its own aliases. Alias
lists use increasing identifiers and bounded pages, like other administration resources. An account or
provider named by an alias cannot be deleted until the alias is deleted or changed.

The data plane does not read aliases. Authentication snapshots, routing, admission, proxying, events,
logs, and metrics remain unchanged. In particular, the gateway does not read, inject, validate, or
rewrite a `model` field. Connecting this configuration to traffic requires a later, separate adapter
decision.

## Consequences

- Model configuration has the same ownership boundary as credentials without becoming credential
  state.
- Two accounts may use the same alias name without sharing or observing each other's targets.
- A future adapter can resolve a caller-facing name without migrating ownerless configuration.
- Multiple targets can be represented, but this decision creates no rule for choosing among them.
- Provider and account deletion gain another explicit reference that must be removed first.
- The new API is useful for configuration automation, while the administration page can be added later
  without changing the resource contract.
