CREATE TABLE ts_model_alias (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id  BIGINT NOT NULL REFERENCES ts_account(id) ON DELETE RESTRICT,
    name        TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    UNIQUE (account_id, name)
);

CREATE INDEX ts_model_alias_account_id_idx ON ts_model_alias (account_id, id);

COMMENT ON TABLE ts_model_alias IS 'Account-owned caller-facing model alias configuration.';
COMMENT ON COLUMN ts_model_alias.id IS 'Model alias identity.';
COMMENT ON COLUMN ts_model_alias.account_id IS 'Account that owns the alias.';
COMMENT ON COLUMN ts_model_alias.name IS 'Caller-facing name, unique within the account.';
COMMENT ON COLUMN ts_model_alias.created_at IS 'Creation time as Unix microseconds.';

CREATE TABLE ts_model_alias_target (
    model_alias_id  BIGINT NOT NULL REFERENCES ts_model_alias(id) ON DELETE CASCADE,
    provider_id     BIGINT NOT NULL REFERENCES ts_provider(id) ON DELETE RESTRICT,
    upstream_model  TEXT NOT NULL,
    position        BIGINT NOT NULL,
    PRIMARY KEY (model_alias_id, provider_id),
    UNIQUE (model_alias_id, position)
);

CREATE INDEX ts_model_alias_target_provider_id_idx ON ts_model_alias_target (provider_id);

COMMENT ON TABLE ts_model_alias_target IS 'Provider-specific model names stored under an alias.';
COMMENT ON COLUMN ts_model_alias_target.model_alias_id IS 'Alias that owns the target.';
COMMENT ON COLUMN ts_model_alias_target.provider_id IS 'Provider for this upstream model name.';
COMMENT ON COLUMN ts_model_alias_target.upstream_model IS 'Opaque provider-specific model name.';
COMMENT ON COLUMN ts_model_alias_target.position IS 'Stable presentation order without routing semantics.';
