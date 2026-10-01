-- Baseline schema. Later numbered files in this directory are incremental
-- upgrades applied in order to databases that already ran this file.

CREATE TABLE ts_account (
    -- Control-plane principal and owner of data-plane credentials.
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- Account identity.
    name              TEXT NOT NULL UNIQUE, -- Unique account name.
    password_hash     TEXT NOT NULL, -- Hash of the control-plane password.
    role              TEXT NOT NULL, -- admin or user.
    status            TEXT NOT NULL, -- enabled or disabled.
    is_bootstrap      BOOLEAN NOT NULL DEFAULT FALSE, -- Whether this is the bootstrap administrator.
    created_at        BIGINT NOT NULL -- Creation time as Unix milliseconds.
);

CREATE UNIQUE INDEX ts_account_bootstrap_idx ON ts_account ((is_bootstrap)) WHERE is_bootstrap = TRUE;

ALTER TABLE ts_account ADD CONSTRAINT ts_account_role_check CHECK (role IN ('admin', 'user'));
ALTER TABLE ts_account ADD CONSTRAINT ts_account_status_check CHECK (status IN ('enabled', 'disabled'));

COMMENT ON TABLE ts_account IS 'Control-plane principal and owner of data-plane credentials.';
COMMENT ON COLUMN ts_account.id IS 'Account identity.';
COMMENT ON COLUMN ts_account.name IS 'Unique account name.';
COMMENT ON COLUMN ts_account.password_hash IS 'Hash of the control-plane password.';
COMMENT ON COLUMN ts_account.role IS 'admin or user.';
COMMENT ON COLUMN ts_account.status IS 'enabled or disabled.';
COMMENT ON COLUMN ts_account.is_bootstrap IS 'Whether this is the bootstrap administrator.';
COMMENT ON COLUMN ts_account.created_at IS 'Creation time as Unix milliseconds.';

CREATE TABLE ts_provider (
    -- Upstream configuration. A provider issues no credentials.
    id                              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- Provider identity.
    name                            TEXT NOT NULL UNIQUE, -- Unique provider name.
    protocol_type                   TEXT NOT NULL, -- openai or anthropic.
    endpoint                        TEXT NOT NULL, -- Upstream origin URL.
    upstream_api_key_ciphertext     TEXT NOT NULL, -- Encrypted upstream credential.
    status                          TEXT NOT NULL, -- enabled or disabled.
    health                          TEXT NOT NULL DEFAULT 'healthy', -- healthy, isolated, or maintenance.
    probe_path                      TEXT, -- Probe path; null when probing is not configured.
    probe_interval_ms               BIGINT, -- Probe interval in milliseconds; null when probing is not configured.
    probe_timeout_ms                BIGINT, -- Probe timeout in milliseconds; null when probing is not configured.
    probe_failure_threshold         BIGINT, -- Consecutive failures before isolation; null when probing is not configured.
    max_concurrent_requests         INTEGER, -- Optional concurrent-request admission bound.
    max_requests_per_second         INTEGER, -- Optional request-rate admission bound.
    created_at                      BIGINT NOT NULL -- Creation time as Unix milliseconds.
);

ALTER TABLE ts_provider ADD CONSTRAINT ts_provider_protocol_type_check CHECK (protocol_type IN ('openai', 'anthropic'));
ALTER TABLE ts_provider ADD CONSTRAINT ts_provider_status_check CHECK (status IN ('enabled', 'disabled'));
ALTER TABLE ts_provider ADD CONSTRAINT ts_provider_health_check CHECK (health IN ('healthy', 'isolated', 'maintenance'));
ALTER TABLE ts_provider ADD CONSTRAINT ts_provider_probe_interval_ms_check CHECK (probe_interval_ms IS NULL OR (probe_interval_ms > 0 AND probe_interval_ms <= 86400000));
ALTER TABLE ts_provider ADD CONSTRAINT ts_provider_probe_timeout_ms_check CHECK (probe_timeout_ms IS NULL OR (probe_timeout_ms > 0 AND probe_timeout_ms <= 86400000));
ALTER TABLE ts_provider ADD CONSTRAINT ts_provider_probe_failure_threshold_check CHECK (probe_failure_threshold IS NULL OR (probe_failure_threshold > 0 AND probe_failure_threshold <= 1000));
ALTER TABLE ts_provider ADD CONSTRAINT ts_provider_max_concurrent_requests_check CHECK (max_concurrent_requests IS NULL OR max_concurrent_requests > 0);
ALTER TABLE ts_provider ADD CONSTRAINT ts_provider_max_requests_per_second_check CHECK (max_requests_per_second IS NULL OR max_requests_per_second > 0);
ALTER TABLE ts_provider ADD CONSTRAINT ts_provider_probe_all_or_none CHECK ((probe_path IS NULL AND probe_interval_ms IS NULL AND probe_timeout_ms IS NULL AND probe_failure_threshold IS NULL) OR (probe_path IS NOT NULL AND probe_interval_ms IS NOT NULL AND probe_timeout_ms IS NOT NULL AND probe_failure_threshold IS NOT NULL));

COMMENT ON TABLE ts_provider IS 'Upstream configuration. A provider issues no credentials.';
COMMENT ON COLUMN ts_provider.id IS 'Provider identity.';
COMMENT ON COLUMN ts_provider.name IS 'Unique provider name.';
COMMENT ON COLUMN ts_provider.protocol_type IS 'openai or anthropic.';
COMMENT ON COLUMN ts_provider.endpoint IS 'Upstream origin URL.';
COMMENT ON COLUMN ts_provider.upstream_api_key_ciphertext IS 'Encrypted upstream credential.';
COMMENT ON COLUMN ts_provider.status IS 'enabled or disabled.';
COMMENT ON COLUMN ts_provider.health IS 'healthy, isolated, or maintenance.';
COMMENT ON COLUMN ts_provider.probe_path IS 'Probe path; null when probing is not configured.';
COMMENT ON COLUMN ts_provider.probe_interval_ms IS 'Probe interval in milliseconds; null when probing is not configured.';
COMMENT ON COLUMN ts_provider.probe_timeout_ms IS 'Probe timeout in milliseconds; null when probing is not configured.';
COMMENT ON COLUMN ts_provider.probe_failure_threshold IS 'Consecutive failures before isolation; null when probing is not configured.';
COMMENT ON COLUMN ts_provider.max_concurrent_requests IS 'Optional concurrent-request admission bound.';
COMMENT ON COLUMN ts_provider.max_requests_per_second IS 'Optional request-rate admission bound.';
COMMENT ON COLUMN ts_provider.created_at IS 'Creation time as Unix milliseconds.';

CREATE TABLE ts_api_key (
    -- Account-owned data-plane credential.
    id                        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- Credential identity.
    account_id                BIGINT NOT NULL REFERENCES ts_account(id) ON DELETE RESTRICT, -- Owning account.
    name                      TEXT NOT NULL, -- Display name.
    key_id                    TEXT NOT NULL UNIQUE, -- Gateway-key lookup identifier.
    secret_hash               TEXT NOT NULL, -- Hash of the gateway secret.
    status                    TEXT NOT NULL, -- enabled or disabled.
    default_provider_id       BIGINT REFERENCES ts_provider(id) ON DELETE RESTRICT, -- Optional default provider binding.
    expires_at                BIGINT, -- Optional expiration as Unix milliseconds.
    max_concurrent_requests   INTEGER, -- Optional concurrent-request admission bound.
    max_requests_per_second   INTEGER, -- Optional request-rate admission bound.
    max_websockets            INTEGER, -- Optional bound on long-lived WebSocket connections.
    created_at                BIGINT NOT NULL -- Creation time as Unix milliseconds.
);

CREATE INDEX ts_api_key_account_id_idx ON ts_api_key (account_id, id);

ALTER TABLE ts_api_key ADD CONSTRAINT ts_api_key_status_check CHECK (status IN ('enabled', 'disabled'));
ALTER TABLE ts_api_key ADD CONSTRAINT ts_api_key_max_concurrent_requests_check CHECK (max_concurrent_requests IS NULL OR max_concurrent_requests > 0);
ALTER TABLE ts_api_key ADD CONSTRAINT ts_api_key_max_requests_per_second_check CHECK (max_requests_per_second IS NULL OR max_requests_per_second > 0);
ALTER TABLE ts_api_key ADD CONSTRAINT ts_api_key_max_websockets_check CHECK (max_websockets IS NULL OR max_websockets > 0);

COMMENT ON TABLE ts_api_key IS 'Account-owned data-plane credential.';
COMMENT ON COLUMN ts_api_key.id IS 'Credential identity.';
COMMENT ON COLUMN ts_api_key.account_id IS 'Owning account.';
COMMENT ON COLUMN ts_api_key.name IS 'Display name.';
COMMENT ON COLUMN ts_api_key.key_id IS 'Gateway-key lookup identifier.';
COMMENT ON COLUMN ts_api_key.secret_hash IS 'Hash of the gateway secret.';
COMMENT ON COLUMN ts_api_key.status IS 'enabled or disabled.';
COMMENT ON COLUMN ts_api_key.default_provider_id IS 'Optional default provider binding.';
COMMENT ON COLUMN ts_api_key.expires_at IS 'Optional expiration as Unix milliseconds.';
COMMENT ON COLUMN ts_api_key.max_concurrent_requests IS 'Optional concurrent-request admission bound.';
COMMENT ON COLUMN ts_api_key.max_requests_per_second IS 'Optional request-rate admission bound.';
COMMENT ON COLUMN ts_api_key.max_websockets IS 'Optional bound on long-lived WebSocket connections.';
COMMENT ON COLUMN ts_api_key.created_at IS 'Creation time as Unix milliseconds.';

CREATE TABLE ts_api_key_provider (
    -- Ordered provider bindings for a credential.
    api_key_id    BIGINT NOT NULL REFERENCES ts_api_key(id) ON DELETE CASCADE, -- Bound credential.
    provider_id   BIGINT NOT NULL REFERENCES ts_provider(id) ON DELETE RESTRICT, -- Bound provider.
    position      BIGINT NOT NULL, -- Order among this credential's bindings.
    PRIMARY KEY (api_key_id, provider_id)
);

CREATE INDEX ts_api_key_provider_provider_id_idx ON ts_api_key_provider (provider_id);

COMMENT ON TABLE ts_api_key_provider IS 'Ordered provider bindings for a credential.';
COMMENT ON COLUMN ts_api_key_provider.api_key_id IS 'Bound credential.';
COMMENT ON COLUMN ts_api_key_provider.provider_id IS 'Bound provider.';
COMMENT ON COLUMN ts_api_key_provider.position IS 'Order among this credential''s bindings.';

CREATE TABLE ts_request_log (
    -- Metadata-only record of one proxy exchange.
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- Request-log identity.
    request_id        TEXT NOT NULL UNIQUE, -- Unique request identifier.
    account_id        BIGINT NOT NULL REFERENCES ts_account(id) ON DELETE RESTRICT, -- Account that owned the credential.
    api_key_id        BIGINT NOT NULL REFERENCES ts_api_key(id) ON DELETE RESTRICT, -- Credential that authenticated the request.
    provider_id       BIGINT NOT NULL REFERENCES ts_provider(id) ON DELETE RESTRICT, -- Provider that the request resolved to.
    protocol_type     TEXT NOT NULL, -- openai or anthropic.
    transport_type    TEXT NOT NULL, -- http or websocket.
    path              TEXT NOT NULL, -- Normalized path without a query string.
    status_code       INTEGER, -- Optional upstream HTTP status or handshake outcome.
    start_time        BIGINT NOT NULL, -- Start time as Unix milliseconds.
    end_time          BIGINT, -- Optional completion time as Unix milliseconds; absent means no completion was persisted.
    error_msg         TEXT -- Optional sanitized error summary.
);

CREATE INDEX ts_request_log_start_time_idx ON ts_request_log (start_time, id);
CREATE INDEX ts_request_log_provider_id_idx ON ts_request_log (provider_id, id);
CREATE INDEX ts_request_log_account_id_idx ON ts_request_log (account_id, id);

ALTER TABLE ts_request_log ADD CONSTRAINT ts_request_log_protocol_type_check CHECK (protocol_type IN ('openai', 'anthropic'));
ALTER TABLE ts_request_log ADD CONSTRAINT ts_request_log_transport_type_check CHECK (transport_type IN ('http', 'websocket'));

COMMENT ON TABLE ts_request_log IS 'Metadata-only record of one proxy exchange.';
COMMENT ON COLUMN ts_request_log.id IS 'Request-log identity.';
COMMENT ON COLUMN ts_request_log.request_id IS 'Unique request identifier.';
COMMENT ON COLUMN ts_request_log.account_id IS 'Account that owned the credential.';
COMMENT ON COLUMN ts_request_log.api_key_id IS 'Credential that authenticated the request.';
COMMENT ON COLUMN ts_request_log.provider_id IS 'Provider that the request resolved to.';
COMMENT ON COLUMN ts_request_log.protocol_type IS 'openai or anthropic.';
COMMENT ON COLUMN ts_request_log.transport_type IS 'http or websocket.';
COMMENT ON COLUMN ts_request_log.path IS 'Normalized path without a query string.';
COMMENT ON COLUMN ts_request_log.status_code IS 'Optional upstream HTTP status or handshake outcome.';
COMMENT ON COLUMN ts_request_log.start_time IS 'Start time as Unix milliseconds.';
COMMENT ON COLUMN ts_request_log.end_time IS 'Optional completion time as Unix milliseconds; absent means no completion was persisted.';
COMMENT ON COLUMN ts_request_log.error_msg IS 'Optional sanitized error summary.';

CREATE TABLE ts_legacy_gateway_key (
    -- Staging for credentials that predate accounts. Empty on a fresh database.
    provider_id       BIGINT PRIMARY KEY REFERENCES ts_provider(id) ON DELETE CASCADE, -- Provider the staged credential belonged to.
    key_id            TEXT NOT NULL UNIQUE, -- Gateway-key lookup identifier to preserve.
    secret_hash       TEXT NOT NULL -- Hash of the gateway secret to preserve.
);

COMMENT ON TABLE ts_legacy_gateway_key IS 'Staging for credentials that predate accounts. Empty on a fresh database.';
COMMENT ON COLUMN ts_legacy_gateway_key.provider_id IS 'Provider the staged credential belonged to.';
COMMENT ON COLUMN ts_legacy_gateway_key.key_id IS 'Gateway-key lookup identifier to preserve.';
COMMENT ON COLUMN ts_legacy_gateway_key.secret_hash IS 'Hash of the gateway secret to preserve.';
