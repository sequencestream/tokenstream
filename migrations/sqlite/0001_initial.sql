CREATE TABLE provider (
    id                              INTEGER PRIMARY KEY AUTOINCREMENT,
    name                            TEXT NOT NULL UNIQUE,
    protocol_type                   TEXT NOT NULL CHECK (protocol_type IN ('openai', 'anthropic')),
    endpoint                        TEXT NOT NULL,
    upstream_api_key_ciphertext     TEXT NOT NULL,
    gateway_key_id                  TEXT NOT NULL UNIQUE,
    gateway_api_key_hash            TEXT NOT NULL,
    status                          TEXT NOT NULL CHECK (status IN ('enabled', 'disabled')),
    created_at                      INTEGER NOT NULL
);

CREATE TABLE request_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id        TEXT NOT NULL UNIQUE,
    provider_id       INTEGER NOT NULL REFERENCES provider(id) ON DELETE RESTRICT,
    protocol_type     TEXT NOT NULL CHECK (protocol_type IN ('openai', 'anthropic')),
    transport_type    TEXT NOT NULL CHECK (transport_type IN ('http', 'websocket')),
    path              TEXT NOT NULL,
    status_code       INTEGER,
    start_time        INTEGER NOT NULL,
    end_time          INTEGER,
    error_msg         TEXT
);

CREATE INDEX request_log_start_time_idx
    ON request_log (start_time, id);
CREATE INDEX request_log_provider_id_idx
    ON request_log (provider_id, id);
