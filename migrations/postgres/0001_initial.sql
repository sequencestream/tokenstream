CREATE TABLE provider (
    id                              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                            TEXT NOT NULL UNIQUE,
    protocol_type                   TEXT NOT NULL CHECK (protocol_type IN ('openai', 'anthropic')),
    endpoint                        TEXT NOT NULL,
    upstream_api_key_ciphertext     TEXT NOT NULL,
    gateway_key_id                  TEXT NOT NULL UNIQUE,
    gateway_api_key_hash            TEXT NOT NULL,
    status                          TEXT NOT NULL CHECK (status IN ('enabled', 'disabled')),
    created_at                      BIGINT NOT NULL
);

CREATE TABLE request_log (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    request_id        TEXT NOT NULL UNIQUE,
    provider_id       BIGINT NOT NULL REFERENCES provider(id) ON DELETE RESTRICT,
    protocol_type     TEXT NOT NULL CHECK (protocol_type IN ('openai', 'anthropic')),
    transport_type    TEXT NOT NULL CHECK (transport_type IN ('http', 'websocket')),
    path              TEXT NOT NULL,
    status_code       INTEGER,
    start_time        BIGINT NOT NULL,
    end_time          BIGINT,
    error_msg         TEXT
);

CREATE INDEX request_log_start_time_idx
    ON request_log (start_time, id);
CREATE INDEX request_log_provider_id_idx
    ON request_log (provider_id, id);
