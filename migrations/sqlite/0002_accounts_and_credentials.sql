-- Accounts own data-plane credentials; credentials select providers by binding.
--
-- A credential issued before accounts existed belongs to a provider rather than
-- an account. Its identifier and hash are staged here, untouched, so the
-- identity bootstrap can adopt them into account-owned credentials in one
-- transaction. Clients that already hold a credential keep working.

CREATE TABLE account (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,
    role              TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    status            TEXT NOT NULL CHECK (status IN ('enabled', 'disabled')),
    is_bootstrap      INTEGER NOT NULL DEFAULT 0 CHECK (is_bootstrap IN (0, 1)),
    created_at        INTEGER NOT NULL
);

-- At most one account may be the bootstrap administrator.
CREATE UNIQUE INDEX account_bootstrap_idx
    ON account (is_bootstrap)
    WHERE is_bootstrap = 1;

CREATE TABLE api_key (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id            INTEGER NOT NULL REFERENCES account(id) ON DELETE RESTRICT,
    name                  TEXT NOT NULL,
    key_id                TEXT NOT NULL UNIQUE,
    secret_hash           TEXT NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('enabled', 'disabled')),
    default_provider_id   INTEGER REFERENCES provider(id) ON DELETE RESTRICT,
    expires_at            INTEGER,
    created_at            INTEGER NOT NULL
);

CREATE INDEX api_key_account_id_idx ON api_key (account_id, id);

CREATE TABLE api_key_provider (
    api_key_id    INTEGER NOT NULL REFERENCES api_key(id) ON DELETE CASCADE,
    provider_id   INTEGER NOT NULL REFERENCES provider(id) ON DELETE RESTRICT,
    position      INTEGER NOT NULL,
    PRIMARY KEY (api_key_id, provider_id)
);

CREATE INDEX api_key_provider_provider_id_idx
    ON api_key_provider (provider_id);

-- Staging for credentials that predate accounts. Cleared once adopted.
--
-- Neither the provider nor the request log is referenced here. Both are
-- rebuilt below, and SQLite refuses to drop a table that another table still
-- references, so a reference from staging would block the rebuild it exists to
-- feed. The staged provider id is a plain column, and provider ids are carried
-- across the rebuild unchanged, so it still identifies the same provider when
-- the rows are adopted.
CREATE TABLE legacy_gateway_key (
    provider_id       INTEGER PRIMARY KEY,
    key_id            TEXT NOT NULL UNIQUE,
    secret_hash       TEXT NOT NULL
);

INSERT INTO legacy_gateway_key (provider_id, key_id, secret_hash)
    SELECT id, gateway_key_id, gateway_api_key_hash
    FROM provider
    WHERE gateway_key_id IS NOT NULL;

-- A provider no longer holds credential columns. SQLite cannot drop a column
-- that carries a UNIQUE constraint, so the table is rebuilt rather than
-- altered, and its rows are carried across unchanged.
--
-- The request log is rebuilt with it, pointing at the replacement table while
-- the original is dropped. SQLite does not defer foreign key checks, so a
-- surviving reference to the old provider would fail the drop outright.
CREATE TABLE provider_rebuilt (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    name                        TEXT NOT NULL UNIQUE,
    protocol_type               TEXT NOT NULL CHECK (protocol_type IN ('openai', 'anthropic')),
    endpoint                    TEXT NOT NULL,
    upstream_api_key_ciphertext TEXT NOT NULL,
    status                      TEXT NOT NULL CHECK (status IN ('enabled', 'disabled')),
    created_at                  INTEGER NOT NULL
);

INSERT INTO provider_rebuilt (
    id, name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at
)
    SELECT id, name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at
    FROM provider;

CREATE TABLE request_log_rebuilt (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id        TEXT NOT NULL UNIQUE,
    provider_id       INTEGER NOT NULL REFERENCES provider_rebuilt(id) ON DELETE RESTRICT,
    protocol_type     TEXT NOT NULL CHECK (protocol_type IN ('openai', 'anthropic')),
    transport_type    TEXT NOT NULL CHECK (transport_type IN ('http', 'websocket')),
    path              TEXT NOT NULL,
    status_code       INTEGER,
    start_time        INTEGER NOT NULL,
    end_time          INTEGER,
    error_msg         TEXT,
    account_id        INTEGER REFERENCES account(id) ON DELETE RESTRICT,
    api_key_id        INTEGER REFERENCES api_key(id) ON DELETE RESTRICT
);

INSERT INTO request_log_rebuilt (
    id, request_id, provider_id, protocol_type, transport_type,
    path, status_code, start_time, end_time, error_msg
)
SELECT
    id, request_id, provider_id, protocol_type, transport_type,
    path, status_code, start_time, end_time, error_msg
FROM request_log;

DROP TABLE request_log;

-- Now that nothing references the old provider, it can be replaced.
DROP TABLE provider;
ALTER TABLE provider_rebuilt RENAME TO provider;

-- The rebuilt log points at the replacement table by name, so the reference
-- follows the provider through the rename above.
ALTER TABLE request_log_rebuilt RENAME TO request_log;

CREATE INDEX request_log_start_time_idx
    ON request_log (start_time, id);

CREATE INDEX request_log_provider_id_idx
    ON request_log (provider_id, id);

CREATE INDEX request_log_account_id_idx ON request_log (account_id, id);
