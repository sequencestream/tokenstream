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

async fn insert_provider(pool: &SqlitePool, name: &str, key_id: &str) -> i64 {
    sqlx::query(
        "INSERT INTO provider (
            name, protocol_type, endpoint, upstream_api_key_ciphertext,
            gateway_key_id, gateway_api_key_hash, status, created_at
         ) VALUES (?, 'openai', 'https://example.com', 'ciphertext', ?, 'hash', 'enabled', 1)",
    )
    .bind(name)
    .bind(key_id)
    .execute(pool)
    .await
    .expect("insert provider")
    .last_insert_rowid()
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
        "provider",
        "request_log",
        "request_log_start_time_idx",
        "request_log_provider_id_idx",
    ] {
        assert!(objects.contains(expected), "missing {expected}");
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
    let provider_id = insert_provider(database.pool(), "primary", "key-1").await;

    for statement in [
        "INSERT INTO provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, gateway_key_id, gateway_api_key_hash, status, created_at) VALUES ('primary', 'openai', 'https://example.com', 'ciphertext', 'key-2', 'hash', 'enabled', 1)",
        "INSERT INTO provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, gateway_key_id, gateway_api_key_hash, status, created_at) VALUES ('secondary', 'openai', 'https://example.com', 'ciphertext', 'key-1', 'hash', 'enabled', 1)",
        "INSERT INTO provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, gateway_key_id, gateway_api_key_hash, status, created_at) VALUES ('secondary', 'unknown', 'https://example.com', 'ciphertext', 'key-3', 'hash', 'enabled', 1)",
        "INSERT INTO provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, gateway_key_id, gateway_api_key_hash, status, created_at) VALUES ('secondary', 'openai', 'https://example.com', 'ciphertext', 'key-3', 'hash', 'retired', 1)",
    ] {
        assert!(database.pool().execute(statement).await.is_err());
    }

    let invalid_transport = sqlx::query(
        "INSERT INTO request_log (request_id, provider_id, protocol_type, transport_type, path, start_time)
         VALUES ('request-invalid', ?, 'openai', 'stream', '/v1/responses', 1)",
    )
    .bind(provider_id)
    .execute(database.pool())
    .await;
    assert!(invalid_transport.is_err());

    sqlx::query(
        "INSERT INTO request_log (request_id, provider_id, protocol_type, transport_type, path, start_time)
         VALUES ('request-1', ?, 'openai', 'http', '/v1/responses', 1)",
    )
    .bind(provider_id)
    .execute(database.pool())
    .await
    .expect("insert valid request log");
    for statement in [
        "INSERT INTO request_log (request_id, provider_id, protocol_type, transport_type, path, start_time) VALUES ('request-1', 1, 'openai', 'http', '/v1/responses', 1)",
        "INSERT INTO request_log (request_id, provider_id, protocol_type, transport_type, path, start_time) VALUES ('request-2', 1, 'unknown', 'http', '/v1/responses', 1)",
    ] {
        assert!(database.pool().execute(statement).await.is_err());
    }
}

#[tokio::test]
async fn referenced_providers_cannot_be_deleted_and_ids_are_not_reused() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("identity.db"), 1).await;
    database.migrate().await.expect("migrations");

    let referenced_id = insert_provider(database.pool(), "referenced", "key-1").await;
    sqlx::query(
        "INSERT INTO request_log (
            request_id, provider_id, protocol_type, transport_type, path, start_time
         ) VALUES ('request-1', ?, 'openai', 'http', '/v1/responses', 1)",
    )
    .bind(referenced_id)
    .execute(database.pool())
    .await
    .expect("insert request log");
    assert!(
        sqlx::query("DELETE FROM provider WHERE id = ?")
            .bind(referenced_id)
            .execute(database.pool())
            .await
            .is_err()
    );

    let deleted_id = insert_provider(database.pool(), "deleted", "key-2").await;
    sqlx::query("DELETE FROM provider WHERE id = ?")
        .bind(deleted_id)
        .execute(database.pool())
        .await
        .expect("delete unreferenced provider");
    let next_id = insert_provider(database.pool(), "next", "key-3").await;
    assert!(next_id > deleted_id);
}
