-- Accounts own data-plane credentials; credentials select providers by binding.
--
-- A credential issued before accounts existed belongs to a provider rather than
-- an account. Its identifier and hash are staged here, untouched, so the
-- identity bootstrap can adopt them into account-owned credentials in one
-- transaction. Clients that already hold a credential keep working.

CREATE TABLE account (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,
    role              TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    status            TEXT NOT NULL CHECK (status IN ('enabled', 'disabled')),
    is_bootstrap      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        BIGINT NOT NULL
);

-- At most one account may be the bootstrap administrator.
CREATE UNIQUE INDEX account_bootstrap_idx
    ON account ((is_bootstrap))
    WHERE is_bootstrap = TRUE;

CREATE TABLE api_key (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id            BIGINT NOT NULL REFERENCES account(id) ON DELETE RESTRICT,
    name                  TEXT NOT NULL,
    key_id                TEXT NOT NULL UNIQUE,
    secret_hash           TEXT NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('enabled', 'disabled')),
    default_provider_id   BIGINT REFERENCES provider(id) ON DELETE RESTRICT,
    expires_at            BIGINT,
    created_at            BIGINT NOT NULL
);

CREATE INDEX api_key_account_id_idx ON api_key (account_id, id);

CREATE TABLE api_key_provider (
    api_key_id    BIGINT NOT NULL REFERENCES api_key(id) ON DELETE CASCADE,
    provider_id   BIGINT NOT NULL REFERENCES provider(id) ON DELETE RESTRICT,
    position      BIGINT NOT NULL,
    PRIMARY KEY (api_key_id, provider_id)
);

CREATE INDEX api_key_provider_provider_id_idx
    ON api_key_provider (provider_id);

-- Staging for credentials that predate accounts. Cleared once adopted.
CREATE TABLE legacy_gateway_key (
    provider_id       BIGINT PRIMARY KEY REFERENCES provider(id) ON DELETE CASCADE,
    key_id            TEXT NOT NULL UNIQUE,
    secret_hash       TEXT NOT NULL
);

INSERT INTO legacy_gateway_key (provider_id, key_id, secret_hash)
    SELECT id, gateway_key_id, gateway_api_key_hash
    FROM provider
    WHERE gateway_key_id IS NOT NULL;

ALTER TABLE provider DROP COLUMN gateway_key_id;
ALTER TABLE provider DROP COLUMN gateway_api_key_hash;

ALTER TABLE request_log ADD COLUMN account_id BIGINT REFERENCES account(id) ON DELETE RESTRICT;
ALTER TABLE request_log ADD COLUMN api_key_id BIGINT REFERENCES api_key(id) ON DELETE RESTRICT;

CREATE INDEX request_log_account_id_idx ON request_log (account_id, id);
