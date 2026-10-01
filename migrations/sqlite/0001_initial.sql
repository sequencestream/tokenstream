-- Baseline schema. Later numbered files in this directory are incremental
-- upgrades applied in order to databases that already ran this file.

CREATE TABLE ts_account (
    -- Control-plane principal and owner of data-plane credentials.
    id                INTEGER PRIMARY KEY AUTOINCREMENT, -- Account identity.
    name              TEXT NOT NULL UNIQUE, -- Unique account name.
    password_hash     TEXT NOT NULL, -- Hash of the control-plane password.
    role              TEXT NOT NULL, -- admin or user.
    status            TEXT NOT NULL, -- enabled or disabled.
    is_bootstrap      INTEGER NOT NULL DEFAULT 0, -- Whether this is the bootstrap administrator.
    created_at        INTEGER NOT NULL, -- Creation time as Unix milliseconds.
    CONSTRAINT ts_account_role_check CHECK (role IN ('admin', 'user')),
    CONSTRAINT ts_account_status_check CHECK (status IN ('enabled', 'disabled')),
    CONSTRAINT ts_account_is_bootstrap_check CHECK (is_bootstrap IN (0, 1))
);

CREATE UNIQUE INDEX ts_account_bootstrap_idx ON ts_account (is_bootstrap) WHERE is_bootstrap = 1;

CREATE TABLE ts_provider (
    -- Upstream configuration. A provider issues no credentials.
    id                              INTEGER PRIMARY KEY AUTOINCREMENT, -- Provider identity.
    name                            TEXT NOT NULL UNIQUE, -- Unique provider name.
    protocol_type                   TEXT NOT NULL, -- openai or anthropic.
    endpoint                        TEXT NOT NULL, -- Upstream origin URL.
    upstream_api_key_ciphertext     TEXT NOT NULL, -- Encrypted upstream credential.
    status                          TEXT NOT NULL, -- enabled or disabled.
    health                          TEXT NOT NULL DEFAULT 'healthy', -- healthy, isolated, or maintenance.
    probe_path                      TEXT, -- Probe path; null when probing is not configured.
    probe_interval_ms               INTEGER, -- Probe interval in milliseconds; null when probing is not configured.
    probe_timeout_ms                INTEGER, -- Probe timeout in milliseconds; null when probing is not configured.
    probe_failure_threshold         INTEGER, -- Consecutive failures before isolation; null when probing is not configured.
    max_concurrent_requests         INTEGER, -- Optional concurrent-request admission bound.
    max_requests_per_second         INTEGER, -- Optional request-rate admission bound.
    created_at                      INTEGER NOT NULL, -- Creation time as Unix milliseconds.
    CONSTRAINT ts_provider_protocol_type_check CHECK (protocol_type IN ('openai', 'anthropic')),
    CONSTRAINT ts_provider_status_check CHECK (status IN ('enabled', 'disabled')),
    CONSTRAINT ts_provider_health_check CHECK (health IN ('healthy', 'isolated', 'maintenance')),
    CONSTRAINT ts_provider_probe_interval_ms_check CHECK (probe_interval_ms IS NULL OR (probe_interval_ms > 0 AND probe_interval_ms <= 86400000)),
    CONSTRAINT ts_provider_probe_timeout_ms_check CHECK (probe_timeout_ms IS NULL OR (probe_timeout_ms > 0 AND probe_timeout_ms <= 86400000)),
    CONSTRAINT ts_provider_probe_failure_threshold_check CHECK (probe_failure_threshold IS NULL OR (probe_failure_threshold > 0 AND probe_failure_threshold <= 1000)),
    CONSTRAINT ts_provider_max_concurrent_requests_check CHECK (max_concurrent_requests IS NULL OR max_concurrent_requests > 0),
    CONSTRAINT ts_provider_max_requests_per_second_check CHECK (max_requests_per_second IS NULL OR max_requests_per_second > 0)
);

CREATE TRIGGER ts_provider_probe_complete_insert
BEFORE INSERT ON ts_provider
WHEN NOT (
    (NEW.probe_path IS NULL
        AND NEW.probe_interval_ms IS NULL
        AND NEW.probe_timeout_ms IS NULL
        AND NEW.probe_failure_threshold IS NULL)
    OR
    (NEW.probe_path IS NOT NULL
        AND NEW.probe_interval_ms IS NOT NULL
        AND NEW.probe_timeout_ms IS NOT NULL
        AND NEW.probe_failure_threshold IS NOT NULL)
)
BEGIN
    SELECT RAISE(ABORT, 'provider probe must be complete');
END;

CREATE TRIGGER ts_provider_probe_complete_update
BEFORE UPDATE OF probe_path, probe_interval_ms, probe_timeout_ms, probe_failure_threshold ON ts_provider
WHEN NOT (
    (NEW.probe_path IS NULL
        AND NEW.probe_interval_ms IS NULL
        AND NEW.probe_timeout_ms IS NULL
        AND NEW.probe_failure_threshold IS NULL)
    OR
    (NEW.probe_path IS NOT NULL
        AND NEW.probe_interval_ms IS NOT NULL
        AND NEW.probe_timeout_ms IS NOT NULL
        AND NEW.probe_failure_threshold IS NOT NULL)
)
BEGIN
    SELECT RAISE(ABORT, 'provider probe must be complete');
END;

CREATE TABLE ts_api_key (
    -- Account-owned data-plane credential.
    id                        INTEGER PRIMARY KEY AUTOINCREMENT, -- Credential identity.
    account_id                INTEGER NOT NULL REFERENCES ts_account(id) ON DELETE RESTRICT, -- Owning account.
    name                      TEXT NOT NULL, -- Display name.
    key_id                    TEXT NOT NULL UNIQUE, -- Gateway-key lookup identifier.
    secret_hash               TEXT NOT NULL, -- Hash of the gateway secret.
    status                    TEXT NOT NULL, -- enabled or disabled.
    default_provider_id       INTEGER REFERENCES ts_provider(id) ON DELETE RESTRICT, -- Optional default provider binding.
    expires_at                INTEGER, -- Optional expiration as Unix milliseconds.
    max_concurrent_requests   INTEGER, -- Optional concurrent-request admission bound.
    max_requests_per_second   INTEGER, -- Optional request-rate admission bound.
    max_websockets            INTEGER, -- Optional bound on long-lived WebSocket connections.
    created_at                INTEGER NOT NULL, -- Creation time as Unix milliseconds.
    CONSTRAINT ts_api_key_status_check CHECK (status IN ('enabled', 'disabled')),
    CONSTRAINT ts_api_key_max_concurrent_requests_check CHECK (max_concurrent_requests IS NULL OR max_concurrent_requests > 0),
    CONSTRAINT ts_api_key_max_requests_per_second_check CHECK (max_requests_per_second IS NULL OR max_requests_per_second > 0),
    CONSTRAINT ts_api_key_max_websockets_check CHECK (max_websockets IS NULL OR max_websockets > 0)
);

CREATE INDEX ts_api_key_account_id_idx ON ts_api_key (account_id, id);

CREATE TABLE ts_api_key_provider (
    -- Ordered provider bindings for a credential.
    api_key_id    INTEGER NOT NULL REFERENCES ts_api_key(id) ON DELETE CASCADE, -- Bound credential.
    provider_id   INTEGER NOT NULL REFERENCES ts_provider(id) ON DELETE RESTRICT, -- Bound provider.
    position      INTEGER NOT NULL, -- Order among this credential's bindings.
    PRIMARY KEY (api_key_id, provider_id)
);

CREATE INDEX ts_api_key_provider_provider_id_idx ON ts_api_key_provider (provider_id);

CREATE TABLE ts_request_log (
    -- Metadata-only record of one proxy exchange.
    id                INTEGER PRIMARY KEY AUTOINCREMENT, -- Request-log identity.
    request_id        TEXT NOT NULL UNIQUE, -- Unique request identifier.
    account_id        INTEGER NOT NULL REFERENCES ts_account(id) ON DELETE RESTRICT, -- Account that owned the credential.
    api_key_id        INTEGER NOT NULL REFERENCES ts_api_key(id) ON DELETE RESTRICT, -- Credential that authenticated the request.
    provider_id       INTEGER NOT NULL REFERENCES ts_provider(id) ON DELETE RESTRICT, -- Provider that the request resolved to.
    protocol_type     TEXT NOT NULL, -- openai or anthropic.
    transport_type    TEXT NOT NULL, -- http or websocket.
    path              TEXT NOT NULL, -- Normalized path without a query string.
    status_code       INTEGER, -- Optional upstream HTTP status or handshake outcome.
    start_time        INTEGER NOT NULL, -- Start time as Unix milliseconds.
    end_time          INTEGER, -- Optional completion time as Unix milliseconds; absent means no completion was persisted.
    error_msg         TEXT, -- Optional sanitized error summary.
    CONSTRAINT ts_request_log_protocol_type_check CHECK (protocol_type IN ('openai', 'anthropic')),
    CONSTRAINT ts_request_log_transport_type_check CHECK (transport_type IN ('http', 'websocket'))
);

CREATE INDEX ts_request_log_start_time_idx ON ts_request_log (start_time, id);
CREATE INDEX ts_request_log_provider_id_idx ON ts_request_log (provider_id, id);
CREATE INDEX ts_request_log_account_id_idx ON ts_request_log (account_id, id);

CREATE TABLE ts_legacy_gateway_key (
    -- Staging for credentials that predate accounts. Empty on a fresh database.
    provider_id       INTEGER PRIMARY KEY, -- Provider the staged credential belonged to.
    key_id            TEXT NOT NULL UNIQUE, -- Gateway-key lookup identifier to preserve.
    secret_hash       TEXT NOT NULL -- Hash of the gateway secret to preserve.
);
