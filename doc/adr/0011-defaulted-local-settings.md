# 0011. Defaulted local settings with an operator overlay

- Status: Accepted
- Date: 2026-09-29

## Context

A first-run binary previously refused to bind until every setting was present in the environment. That blocked a local start. Settings could have stayed environment-only, lived in the provider database, or been discovered from command-line flags.

The master key cannot enter the database ([ADR 0008](./0008-secret-and-credential-model.md)). Secrets also cannot come from process arguments, because process listings may expose them.

Operators still need a way to change the administrator password and the master key after the first sign-in, and to adjust the other process settings from the administration page.

## Decision

Every setting has a compiled default. The process data directory is `~/.tokenstream` unless `TOKENSTREAM_DATA_DIR` is set. SQLite defaults to a file in that directory. Listeners default to loopback ports 3300 and 3301.

A missing master key is generated once and stored as a file in the data directory, never in the database. A missing administrator secret uses a documented default password; its Argon2id hash is stored in the data directory. Environment variables still override files and defaults.

Non-secret operator changes persist as an overlay file in the data directory and are editable from the administration page. The administrator password and master key apply immediately (the master key re-encrypts stored upstream secrets). Listen addresses, the database URL, pooling, hashing budgets, and data-plane bounds take effect on the next start.

## Consequences

- `tokenstream` can start with no Tokenstream-specific environment.
- Changing a listen address or database URL from the page does not rebind the current process.
- The default administrator password is public knowledge; the default listeners are loopback-only, and the page can replace the password after sign-in.
- Secret files in the data directory must remain outside backups that are not access-controlled.
