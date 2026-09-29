# 0008. Secret and credential model

- Status: Accepted
- Date: 2026-09-29

## Context

Each provider needs an upstream API key and a downstream credential that is not that key. Upstream keys could be stored in plaintext, in an external vault only, or encrypted at rest in the database. Downstream credentials could be the upstream key itself, a random bearer with no lookup identifier, or a split identifier-and-secret so verification can look up one row before hashing.

Returning secrets on every read would make the administration API a credential dump. Logging ciphertext or hashes would still leak material into operational sinks.

## Decision

Upstream keys are encrypted at rest with AES-256-GCM. Nonce, key version, and ciphertext are stored together. The master key is supplied through an environment secret, a secret manager, or a generated file in the process data directory, and is never stored in the database.

The external gateway credential is `<key-id>.<secret>`. The identifier is a random, non-secret lookup key. The secret has at least 256 bits of entropy, is hashed with Argon2id, is returned only at creation or rotation, and is never persisted in plaintext. Verification uses data-independent, constant-time comparison.

APIs never expose ciphertext or password hashes. Provider reads may show non-secret configuration and whether a secret is configured. Decrypted keys live only in short-lived snapshot wrappers ([ADR 0004](./0004-request-local-immutable-snapshots.md)).

Security invariants are in the [architecture document](../architecture.md). Issuance and rotation are in the [providers design](../modules/providers.md).

## Consequences

- If a create or rotate response is lost, the secret cannot be recovered; the administrator rotates again.
- Secrets are not accepted from command-line flags. Diagnostic rendering and accidental serialization of decrypted keys are forbidden.
- `Authorization`, `Proxy-Authorization`, `x-api-key`, cookies, credential values, URL query strings, and application bodies are redacted from logs and errors.
