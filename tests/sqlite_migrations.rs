use std::collections::HashSet;
use std::path::Path;

use sqlx::{Executor, Row, SqlitePool};
use tokenstream::persistence::sqlite::SqliteDatabase;

async fn database(path: &Path, max_connections: usize) -> SqliteDatabase {
    let url = format!("sqlite://{}", path.display());
    SqliteDatabase::connect(&url, max_connections)
        .await
        .expect("connect to SQLite")
}

/// Inserts a provider, which now holds configuration only and issues nothing.
async fn insert_provider(pool: &SqlitePool, name: &str) -> i64 {
    sqlx::query(
        "INSERT INTO ts_provider (
            name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at
         ) VALUES (?, 'openai', 'https://example.com', 'ciphertext', 'enabled', 1)",
    )
    .bind(name)
    .execute(pool)
    .await
    .expect("insert provider")
    .last_insert_rowid()
}

/// Inserts the account and credential a request log is attributed to.
async fn insert_principal(pool: &SqlitePool) -> (i64, i64, i64) {
    let account_id = sqlx::query(
        "INSERT INTO ts_account (name, password_hash, role, status, is_bootstrap, created_at)
         VALUES ('migrated-admin', 'hash', 'admin', 'enabled', 1, 1)",
    )
    .execute(pool)
    .await
    .expect("insert account")
    .last_insert_rowid();
    let api_key_id = sqlx::query(
        "INSERT INTO ts_api_key (
            account_id, name, key_id, secret_hash, status, default_provider_id,
            expires_at, created_at
         ) VALUES (?, 'migrated', 'migrated-key', 'hash', 'enabled', NULL, NULL, 1)",
    )
    .bind(account_id)
    .execute(pool)
    .await
    .expect("insert credential")
    .last_insert_rowid();
    (account_id, api_key_id, api_key_id)
}

/// Inserts a request log attributed to the account and credential above.
async fn insert_request_log(
    pool: &SqlitePool,
    request_id: &str,
    account_id: i64,
    api_key_id: i64,
    provider_id: i64,
) {
    sqlx::query(
        "INSERT INTO ts_request_log (
            request_id, account_id, api_key_id, provider_id,
            protocol_type, transport_type, path, start_time
         ) VALUES (?, ?, ?, ?, 'openai', 'http', '/v1/responses', 1)",
    )
    .bind(request_id)
    .bind(account_id)
    .bind(api_key_id)
    .bind(provider_id)
    .execute(pool)
    .await
    .expect("insert request log");
}

#[tokio::test]
async fn migrations_are_versioned_and_repeatable() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("repeatable.db"), 2).await;

    database.migrate().await.expect("first migration run");
    database.migrate().await.expect("repeated migration run");

    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success = 1 ORDER BY version DESC LIMIT 1",
    )
    .fetch_one(database.pool())
    .await
    .expect("migration version");
    assert_eq!(version, 1);

    let objects: HashSet<String> = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(database.pool())
    .await
    .expect("schema objects")
    .into_iter()
    .map(|row| row.get("name"))
    .collect();
    for expected in [
        "ts_account",
        "ts_api_key",
        "ts_api_key_provider",
        "ts_provider",
        "ts_request_log",
        "ts_legacy_gateway_key",
        "ts_request_log_start_time_idx",
        "ts_request_log_provider_id_idx",
        "ts_request_log_account_id_idx",
    ] {
        assert!(objects.contains(expected), "missing {expected}");
    }
}

#[tokio::test]
async fn schema_records_table_and_column_comments() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("comments.db"), 1).await;
    database.migrate().await.expect("migrations");

    for (table, remark) in [
        (
            "ts_account",
            "Control-plane principal and owner of data-plane credentials.",
        ),
        (
            "ts_provider",
            "Upstream configuration. A provider issues no credentials.",
        ),
        ("ts_api_key", "Account-owned data-plane credential."),
        (
            "ts_api_key_provider",
            "Ordered provider bindings for a credential.",
        ),
        (
            "ts_request_log",
            "Metadata-only record of one proxy exchange.",
        ),
        (
            "ts_legacy_gateway_key",
            "Staging for credentials that predate accounts. Empty on a fresh database.",
        ),
    ] {
        let sql: String =
            sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?")
                .bind(table)
                .fetch_one(database.pool())
                .await
                .expect("table sql");
        assert!(
            sql.contains(remark),
            "{table} is missing its table remark: {sql}"
        );

        let columns = sqlx::query(&format!("PRAGMA table_info({table})"))
            .fetch_all(database.pool())
            .await
            .expect("column info");
        assert!(
            sql.matches("-- ").count() > columns.len(),
            "{table} is missing a remark for every column: {sql}"
        );
    }
}

#[tokio::test]
async fn every_pool_connection_enforces_foreign_keys() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("connections.db"), 4).await;
    database.migrate().await.expect("migrations");

    let mut connections = Vec::new();
    for _ in 0..4 {
        connections.push(database.pool().acquire().await.expect("pool connection"));
    }
    for mut connection in connections {
        let enabled: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut *connection)
            .await
            .expect("foreign key pragma");
        assert_eq!(enabled, 1);
    }
}

#[tokio::test]
async fn schema_rejects_invalid_unique_and_enum_values() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("constraints.db"), 1).await;
    database.migrate().await.expect("migrations");
    let provider_id = insert_provider(database.pool(), "primary").await;
    let (account_id, api_key_id, _) = insert_principal(database.pool()).await;

    for statement in [
        // A provider name is unique.
        "INSERT INTO ts_provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at) VALUES ('primary', 'openai', 'https://example.com', 'ciphertext', 'enabled', 1)",
        // Only the two known protocols and the two known statuses are accepted.
        "INSERT INTO ts_provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at) VALUES ('secondary', 'unknown', 'https://example.com', 'ciphertext', 'enabled', 1)",
        "INSERT INTO ts_provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at) VALUES ('secondary', 'openai', 'https://example.com', 'ciphertext', 'retired', 1)",
        // An account name and a credential key identifier are each unique.
        "INSERT INTO ts_account (name, password_hash, role, status, is_bootstrap, created_at) VALUES ('migrated-admin', 'hash', 'user', 'enabled', 0, 1)",
        "INSERT INTO ts_api_key (account_id, name, key_id, secret_hash, status, default_provider_id, expires_at, created_at) VALUES (1, 'other', 'migrated-key', 'hash', 'enabled', NULL, NULL, 1)",
        // Only the two known roles and statuses are accepted.
        "INSERT INTO ts_account (name, password_hash, role, status, is_bootstrap, created_at) VALUES ('other', 'hash', 'owner', 'enabled', 0, 1)",
        "INSERT INTO ts_account (name, password_hash, role, status, is_bootstrap, created_at) VALUES ('other', 'hash', 'user', 'locked', 0, 1)",
    ] {
        assert!(database.pool().execute(statement).await.is_err());
    }

    let invalid_transport = sqlx::query(
        "INSERT INTO ts_request_log (request_id, account_id, api_key_id, provider_id, protocol_type, transport_type, path, start_time)
         VALUES ('request-invalid', ?, ?, ?, 'openai', 'stream', '/v1/responses', 1)",
    )
    .bind(account_id)
    .bind(api_key_id)
    .bind(provider_id)
    .execute(database.pool())
    .await;
    assert!(invalid_transport.is_err());

    insert_request_log(
        database.pool(),
        "request-1",
        account_id,
        api_key_id,
        provider_id,
    )
    .await;
    for statement in [
        // A request identifier is unique, so a start event is recorded once.
        "INSERT INTO ts_request_log (request_id, account_id, api_key_id, provider_id, protocol_type, transport_type, path, start_time) VALUES ('request-1', 1, 1, 1, 'openai', 'http', '/v1/responses', 1)",
        "INSERT INTO ts_request_log (request_id, account_id, api_key_id, provider_id, protocol_type, transport_type, path, start_time) VALUES ('request-2', 1, 1, 1, 'unknown', 'http', '/v1/responses', 1)",
        // A credential belongs to an account that exists.
        "INSERT INTO ts_request_log (request_id, account_id, api_key_id, provider_id, protocol_type, transport_type, path, start_time) VALUES ('request-3', 999, 999, 1, 'openai', 'http', '/v1/responses', 1)",
        // Every stored request log names an account and a credential.
        "INSERT INTO ts_request_log (request_id, provider_id, protocol_type, transport_type, path, start_time) VALUES ('request-unowned', 1, 'openai', 'http', '/v1/responses', 1)",
    ] {
        assert!(database.pool().execute(statement).await.is_err());
    }
}

#[tokio::test]
async fn referenced_providers_cannot_be_deleted_and_ids_are_not_reused() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("identity.db"), 1).await;
    database.migrate().await.expect("migrations");

    let referenced_id = insert_provider(database.pool(), "referenced").await;
    let (account_id, api_key_id, _) = insert_principal(database.pool()).await;
    insert_request_log(
        database.pool(),
        "request-1",
        account_id,
        api_key_id,
        referenced_id,
    )
    .await;
    assert!(
        sqlx::query("DELETE FROM ts_provider WHERE id = ?")
            .bind(referenced_id)
            .execute(database.pool())
            .await
            .is_err()
    );

    let deleted_id = insert_provider(database.pool(), "deleted").await;
    sqlx::query("DELETE FROM ts_provider WHERE id = ?")
        .bind(deleted_id)
        .execute(database.pool())
        .await
        .expect("delete unreferenced provider");
    let next_id = insert_provider(database.pool(), "next").await;
    assert!(next_id > deleted_id);
}

#[tokio::test]
async fn admission_bounds_default_to_unbounded_and_refuse_zero() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("bounds.db"), 1).await;
    database.migrate().await.expect("migrations");

    // A row written before layered admission existed carries no bound at all,
    // which is unbounded rather than zero.
    let provider_id = insert_provider(database.pool(), "unbounded").await;
    let stored: (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT max_concurrent_requests, max_requests_per_second
         FROM ts_provider WHERE id = ?",
    )
    .bind(provider_id)
    .fetch_one(database.pool())
    .await
    .expect("read provider bounds");
    assert_eq!(stored, (None, None), "an existing row is unbounded");

    let (account_id, _, _) = insert_principal(database.pool()).await;
    let credential_bounds: (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT max_concurrent_requests, max_requests_per_second, max_websockets
         FROM ts_api_key WHERE account_id = ?",
    )
    .bind(account_id)
    .fetch_one(database.pool())
    .await
    .expect("read credential bounds");
    assert_eq!(credential_bounds, (None, None, None));

    // A positive bound is stored; zero is refused by the table itself, because
    // a bound of zero would forbid all traffic rather than bound it.
    sqlx::query(
        "UPDATE ts_provider SET max_concurrent_requests = ?, max_requests_per_second = ?
         WHERE id = ?",
    )
    .bind(4_i64)
    .bind(20_i64)
    .bind(provider_id)
    .execute(database.pool())
    .await
    .expect("store positive bounds");
    assert!(
        sqlx::query("UPDATE ts_provider SET max_concurrent_requests = 0 WHERE id = ?")
            .bind(provider_id)
            .execute(database.pool())
            .await
            .is_err(),
        "a zero provider bound is refused"
    );
    assert!(
        sqlx::query("UPDATE ts_provider SET max_requests_per_second = 0 WHERE id = ?")
            .bind(provider_id)
            .execute(database.pool())
            .await
            .is_err(),
        "a zero provider rate is refused"
    );
    assert!(
        sqlx::query("UPDATE ts_api_key SET max_websockets = 0 WHERE account_id = ?")
            .bind(account_id)
            .execute(database.pool())
            .await
            .is_err(),
        "a zero WebSocket bound is refused"
    );
}

#[tokio::test]
async fn provider_health_is_complete_bounded_and_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("health-constraints.db"), 1).await;
    database.migrate().await.expect("migrations");
    let provider_id = insert_provider(database.pool(), "health-provider").await;

    for statement in [
        "UPDATE ts_provider SET health = 'unknown' WHERE id = ?",
        "UPDATE ts_provider SET probe_path = '/ready' WHERE id = ?",
        "UPDATE ts_provider SET probe_path = '/ready', probe_interval_ms = 86400001, probe_timeout_ms = 1000, probe_failure_threshold = 2 WHERE id = ?",
        "UPDATE ts_provider SET probe_path = '/ready', probe_interval_ms = 1000, probe_timeout_ms = 1000, probe_failure_threshold = 1001 WHERE id = ?",
    ] {
        assert!(
            sqlx::query(statement)
                .bind(provider_id)
                .execute(database.pool())
                .await
                .is_err(),
            "schema accepted invalid health statement: {statement}"
        );
    }
}
