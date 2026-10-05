use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::{PgPool, Row};
use tokenstream::persistence::postgres::PostgresDatabase;

mod support;
use support::require_postgres_url;

fn unique_value(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

/// Inserts a provider, which now holds configuration only and issues nothing.
async fn insert_provider(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO ts_provider (
            name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at
         ) VALUES ($1, 'openai', 'https://example.com', 'ciphertext', 'enabled', 1)
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("insert provider")
}

/// Inserts the account and credential that request logs are attributed to.
///
/// The account is an ordinary one: at most one bootstrap administrator may
/// exist, and the process that connected already created it.
async fn insert_principal(pool: &PgPool, key_id: &str) -> (i64, i64) {
    let account_id: i64 = sqlx::query_scalar(
        "INSERT INTO ts_account (name, password_hash, role, status, is_bootstrap, created_at)
         VALUES ($1, 'hash', 'user', 'enabled', FALSE, 1)
         RETURNING id",
    )
    .bind(unique_value("migrated-admin"))
    .fetch_one(pool)
    .await
    .expect("insert account");
    let api_key_id: i64 = sqlx::query_scalar(
        "INSERT INTO ts_api_key (
            account_id, name, key_id, secret_hash, status, default_provider_id,
            expires_at, created_at
         ) VALUES ($1, 'migrated', $2, 'hash', 'enabled', NULL, NULL, 1)
         RETURNING id",
    )
    .bind(account_id)
    .bind(key_id)
    .fetch_one(pool)
    .await
    .expect("insert credential");
    (account_id, api_key_id)
}

#[tokio::test]
async fn postgres_schema_matches_sqlite_constraints() {
    let url = require_postgres_url("the PostgreSQL migration layer");
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect to PostgreSQL");

    database.migrate().await.expect("first migration run");
    database.migrate().await.expect("repeated migration run");

    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version DESC LIMIT 1",
    )
    .fetch_one(database.pool())
    .await
    .expect("migration version");
    assert_eq!(version, 2);

    let objects: HashSet<String> = sqlx::query(
        "SELECT c.relname AS name
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = current_schema()
           AND c.relkind IN ('r', 'i')",
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
        "ts_model_alias",
        "ts_model_alias_target",
        "ts_model_alias_account_id_idx",
        "ts_model_alias_target_provider_id_idx",
        "ts_request_log_start_time_idx",
        "ts_request_log_provider_id_idx",
        "ts_request_log_account_id_idx",
    ] {
        assert!(objects.contains(expected), "missing {expected}");
    }

    let identity_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND ((table_name = 'ts_provider' AND column_name = 'id')
             OR (table_name = 'ts_request_log' AND column_name = 'id')
             OR (table_name = 'ts_model_alias' AND column_name = 'id'))
           AND data_type = 'bigint'
           AND is_identity = 'YES'",
    )
    .fetch_one(database.pool())
    .await
    .expect("identity column metadata");
    assert_eq!(identity_columns, 3);

    let suffix = unique_value("constraints");
    let primary_name = format!("primary-{suffix}");
    let primary_key = format!("key-1-{suffix}");
    let provider_id = insert_provider(database.pool(), &primary_name).await;

    let duplicate_name = sqlx::query(
        "INSERT INTO ts_provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at)
         VALUES ($1, 'openai', 'https://example.com', 'ciphertext', 'enabled', 1)",
    )
    .bind(&primary_name)
    .execute(database.pool())
    .await;
    assert!(duplicate_name.is_err());

    let (account_id, _api_key_id) = insert_principal(database.pool(), &primary_key).await;

    // A credential identifier is unique across accounts, so the uniqueness the
    // provider used to carry now belongs to the credential.
    let duplicate_key = sqlx::query(
        "INSERT INTO ts_api_key (
            account_id, name, key_id, secret_hash, status, default_provider_id,
            expires_at, created_at
         ) VALUES ($1, 'other', $2, 'hash', 'enabled', NULL, NULL, 1)",
    )
    .bind(account_id)
    .bind(&primary_key)
    .execute(database.pool())
    .await;
    assert!(duplicate_key.is_err());

    for (protocol_type, status) in [("unknown", "enabled"), ("openai", "retired")] {
        let result = sqlx::query(
            "INSERT INTO ts_provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at)
             VALUES ($1, $2, 'https://example.com', 'ciphertext', $3, 1)",
        )
        .bind(unique_value("invalid-provider"))
        .bind(protocol_type)
        .bind(status)
        .execute(database.pool())
        .await;
        assert!(result.is_err());
    }

    let request_id = format!("request-1-{suffix}");
    let (account_id, api_key_id) =
        insert_principal(database.pool(), &unique_value("log-key")).await;
    let invalid_transport = sqlx::query(
        "INSERT INTO ts_request_log (request_id, provider_id, protocol_type, transport_type, path, start_time)
         VALUES ($1, $2, 'openai', 'stream', '/v1/responses', 1)",
    )
    .bind(unique_value("invalid-request"))
    .bind(provider_id)
    .execute(database.pool())
    .await;
    assert!(invalid_transport.is_err());

    let invalid_log_protocol = sqlx::query(
        "INSERT INTO ts_request_log (request_id, provider_id, protocol_type, transport_type, path, start_time)
         VALUES ($1, $2, 'unknown', 'http', '/v1/responses', 1)",
    )
    .bind(unique_value("invalid-protocol-request"))
    .bind(provider_id)
    .execute(database.pool())
    .await;
    assert!(invalid_log_protocol.is_err());

    sqlx::query(
        "INSERT INTO ts_request_log (
            request_id, account_id, api_key_id, provider_id, protocol_type, transport_type, path, start_time
         ) VALUES ($1, $2, $3, $4, 'openai', 'http', '/v1/responses', 1)",
    )
    .bind(&request_id)
    .bind(account_id)
    .bind(api_key_id)
    .bind(provider_id)
    .execute(database.pool())
    .await
    .expect("insert valid request log");

    let duplicate_request = sqlx::query(
        "INSERT INTO ts_request_log (
            request_id, account_id, api_key_id, provider_id, protocol_type, transport_type, path, start_time
         ) VALUES ($1, $2, $3, $4, 'openai', 'http', '/v1/responses', 1)",
    )
    .bind(&request_id)
    .bind(account_id)
    .bind(api_key_id)
    .bind(provider_id)
    .execute(database.pool())
    .await;
    assert!(duplicate_request.is_err());

    let missing_provider = sqlx::query(
        "INSERT INTO ts_request_log (request_id, provider_id, protocol_type, transport_type, path, start_time)
         VALUES ($1, 9223372036854775807, 'openai', 'http', '/v1/responses', 1)",
    )
    .bind(unique_value("missing-provider"))
    .execute(database.pool())
    .await;
    assert!(missing_provider.is_err());

    assert!(
        sqlx::query("DELETE FROM ts_provider WHERE id = $1")
            .bind(provider_id)
            .execute(database.pool())
            .await
            .is_err()
    );

    let deleted_id = insert_provider(database.pool(), &unique_value("deleted")).await;
    sqlx::query("DELETE FROM ts_provider WHERE id = $1")
        .bind(deleted_id)
        .execute(database.pool())
        .await
        .expect("delete unreferenced provider");
    let next_id = insert_provider(database.pool(), &unique_value("next")).await;
    assert!(next_id > deleted_id);
}

#[tokio::test]
async fn postgres_schema_records_table_and_column_comments() {
    let url = require_postgres_url("the PostgreSQL schema comments");
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrations");

    let uncommented_tables: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = current_schema()
           AND c.relkind = 'r'
           AND c.relname LIKE 'ts\\_%' ESCAPE '\\'
           AND obj_description(c.oid) IS NULL
         ORDER BY c.relname",
    )
    .fetch_all(database.pool())
    .await
    .expect("table comments");
    assert!(
        uncommented_tables.is_empty(),
        "tables missing remarks: {uncommented_tables:?}"
    );

    let uncommented_columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname, a.attname
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
         WHERE n.nspname = current_schema()
           AND c.relkind = 'r'
           AND c.relname LIKE 'ts\\_%' ESCAPE '\\'
           AND a.attnum > 0
           AND NOT a.attisdropped
           AND col_description(c.oid, a.attnum) IS NULL
         ORDER BY c.relname, a.attnum",
    )
    .fetch_all(database.pool())
    .await
    .expect("column comments");
    assert!(
        uncommented_columns.is_empty(),
        "columns missing remarks: {uncommented_columns:?}"
    );
}

#[tokio::test]
async fn postgres_admission_bounds_default_to_unbounded_and_refuse_zero() {
    let url = require_postgres_url("the PostgreSQL migration layer");
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrations");

    // A row written before layered admission existed carries no bound at all,
    // which is unbounded rather than zero.
    let provider_id = insert_provider(database.pool(), &unique_value("unbounded")).await;
    let stored: (Option<i32>, Option<i32>) = sqlx::query_as(
        "SELECT max_concurrent_requests, max_requests_per_second
         FROM ts_provider WHERE id = $1",
    )
    .bind(provider_id)
    .fetch_one(database.pool())
    .await
    .expect("read provider bounds");
    assert_eq!(stored, (None, None), "an existing row is unbounded");

    let (account_id, _) = insert_principal(database.pool(), &unique_value("unbounded-key")).await;
    let bounds: (Option<i32>, Option<i32>, Option<i32>) = sqlx::query_as(
        "SELECT max_concurrent_requests, max_requests_per_second, max_websockets
         FROM ts_api_key WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_one(database.pool())
    .await
    .expect("read credential bounds");
    assert_eq!(bounds, (None, None, None));

    // A positive bound is stored; zero is refused by the table itself, because
    // a bound of zero would forbid all traffic rather than bound it.
    sqlx::query(
        "UPDATE ts_provider SET max_concurrent_requests = $1, max_requests_per_second = $2
         WHERE id = $3",
    )
    .bind(4_i32)
    .bind(20_i32)
    .bind(provider_id)
    .execute(database.pool())
    .await
    .expect("store positive bounds");
    for (statement, target) in [
        (
            "UPDATE ts_provider SET max_concurrent_requests = 0 WHERE id = $1",
            provider_id,
        ),
        (
            "UPDATE ts_provider SET max_requests_per_second = 0 WHERE id = $1",
            provider_id,
        ),
        (
            "UPDATE ts_api_key SET max_websockets = 0 WHERE account_id = $1",
            account_id,
        ),
    ] {
        assert!(
            sqlx::query(statement)
                .bind(target)
                .execute(database.pool())
                .await
                .is_err(),
            "expected {statement} to be refused"
        );
    }
}

#[tokio::test]
async fn postgres_provider_health_is_complete_bounded_and_closed() {
    let url = require_postgres_url("the PostgreSQL provider health migration layer");
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrations");
    let provider_id = insert_provider(database.pool(), &unique_value("health-provider")).await;

    for statement in [
        "UPDATE ts_provider SET health = 'unknown' WHERE id = $1",
        "UPDATE ts_provider SET probe_path = '/ready' WHERE id = $1",
        "UPDATE ts_provider SET probe_path = '/ready', probe_interval_ms = 86400001, probe_timeout_ms = 1000, probe_failure_threshold = 2 WHERE id = $1",
        "UPDATE ts_provider SET probe_path = '/ready', probe_interval_ms = 1000, probe_timeout_ms = 1000, probe_failure_threshold = 1001 WHERE id = $1",
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
