CREATE TABLE ts_model_alias (
    -- Account-owned caller-facing model alias configuration.
    id          INTEGER PRIMARY KEY AUTOINCREMENT, -- Model alias identity.
    account_id  INTEGER NOT NULL REFERENCES ts_account(id) ON DELETE RESTRICT, -- Account that owns the alias.
    name        TEXT NOT NULL, -- Caller-facing name, unique within the account.
    created_at  INTEGER NOT NULL, -- Creation time as Unix microseconds.
    UNIQUE (account_id, name)
);

CREATE INDEX ts_model_alias_account_id_idx ON ts_model_alias (account_id, id);

CREATE TABLE ts_model_alias_target (
    -- Provider-specific model names stored under an alias.
    model_alias_id  INTEGER NOT NULL REFERENCES ts_model_alias(id) ON DELETE CASCADE, -- Alias that owns the target.
    provider_id     INTEGER NOT NULL REFERENCES ts_provider(id) ON DELETE RESTRICT, -- Provider for this upstream model name.
    upstream_model  TEXT NOT NULL, -- Opaque provider-specific model name.
    position        INTEGER NOT NULL, -- Stable presentation order without routing semantics.
    PRIMARY KEY (model_alias_id, provider_id),
    UNIQUE (model_alias_id, position)
);

CREATE INDEX ts_model_alias_target_provider_id_idx ON ts_model_alias_target (provider_id);
