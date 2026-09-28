use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use tokenstream::domain::{
    GatewayKeyId, PasswordHash, ProtocolType, ProviderStatus, RequestId, SecretCiphertext,
    TransportType,
};
use tokenstream::persistence::postgres::PostgresDatabase;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{
    Database, DatabaseBackend, NewProvider, ProviderRepository, RepositoryError,
    RequestLogCompleted, RequestLogQuery, RequestLogRepository, RequestLogStarted,
};
use url::Url;

fn unique_value(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn new_provider(prefix: &str, number: usize, created_at: DateTime<Utc>) -> NewProvider {
    NewProvider::new(
        format!("{prefix}-provider-{number}"),
        ProtocolType::OpenAi,
        Url::parse("https://example.com").expect("valid endpoint"),
        SecretCiphertext::new("ciphertext"),
        GatewayKeyId::new(format!("{prefix}-key-{number}")).expect("non-empty key ID"),
        PasswordHash::new("hash"),
        ProviderStatus::Enabled,
        created_at,
    )
}

fn sample_instants() -> [DateTime<Utc>; 3] {
    [
        // One microsecond before the Unix epoch exercises negative signed micros.
        Utc.with_ymd_and_hms(1969, 12, 31, 23, 59, 59)
            .single()
            .expect("valid timestamp")
            + ChronoDuration::microseconds(999_999),
        // Sub-second precision must survive the round trip exactly.
        Utc.with_ymd_and_hms(2001, 9, 9, 1, 46, 40)
            .single()
            .expect("valid timestamp")
            + ChronoDuration::microseconds(555),
        Utc.with_ymd_and_hms(2026, 9, 28, 10, 0, 0)
            .single()
            .expect("valid timestamp")
            + ChronoDuration::microseconds(123_456),
    ]
}

async fn verify_time_round_trip<R>(repository: &R, prefix: &str)
where
    R: ProviderRepository + RequestLogRepository,
{
    for (number, instant) in sample_instants().iter().enumerate() {
        let created = repository
            .create(new_provider(prefix, number, *instant))
            .await
            .expect("create provider");
        assert_eq!(created.created_at(), *instant);

        let key = GatewayKeyId::new(format!("{prefix}-key-{number}")).expect("non-empty key ID");
        let found = repository
            .find_by_key_id(&key)
            .await
            .expect("find provider")
            .expect("provider exists");
        assert_eq!(found.id(), created.id());
        assert_eq!(found.created_at(), *instant);

        let request_id = format!("{prefix}-request-{number}");
        let (start, end) = (*instant, *instant + ChronoDuration::microseconds(789));
        repository
            .insert_started(RequestLogStarted::new(
                RequestId::new(&request_id).expect("non-empty request ID"),
                created.id(),
                ProtocolType::OpenAi,
                TransportType::Http,
                "/v1/responses".to_owned(),
                start,
            ))
            .await
            .expect("insert request log start");
        repository
            .apply_completed(RequestLogCompleted::new(
                RequestId::new(&request_id).expect("non-empty request ID"),
                Some(200),
                end,
                None,
            ))
            .await
            .expect("complete request log");

        let page = repository
            .query(
                RequestLogQuery::new(
                    None,
                    100,
                    Some(created.id()),
                    Some(TransportType::Http),
                    None,
                    None,
                )
                .expect("valid query"),
            )
            .await
            .expect("query request logs");
        let log = page
            .items()
            .iter()
            .find(|log| log.request_id().as_str() == request_id)
            .expect("request log is present");
        assert_eq!(log.start_time(), start);
        assert_eq!(log.end_time(), Some(end));
    }
}

#[tokio::test]
async fn sqlite_storage_times_round_trip() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let url = format!("sqlite://{}", directory.path().join("time.db").display());
    let database = SqliteDatabase::connect(&url, 2)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    verify_time_round_trip(&database, &unique_value("sqlite-time")).await;
}

#[tokio::test]
async fn backend_is_selected_from_the_database_url() {
    assert_eq!(
        DatabaseBackend::from_url("sqlite::memory:"),
        DatabaseBackend::Sqlite
    );
    assert_eq!(
        DatabaseBackend::from_url("sqlite://tokenstream.db"),
        DatabaseBackend::Sqlite
    );
    assert_eq!(
        DatabaseBackend::from_url("postgres://localhost/tokenstream"),
        DatabaseBackend::Postgres
    );
    assert_eq!(
        DatabaseBackend::from_url("postgresql://localhost/tokenstream"),
        DatabaseBackend::Postgres
    );

    let directory = tempfile::tempdir().expect("temporary directory");
    let url = format!("sqlite://{}", directory.path().join("select.db").display());
    assert_eq!(
        Database::connect(&url, 1)
            .await
            .expect("connect to SQLite")
            .backend(),
        DatabaseBackend::Sqlite
    );
}

#[tokio::test]
async fn sqlite_exhausted_pool_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let url = format!(
        "sqlite://{}",
        directory.path().join("exhausted.db").display()
    );
    let database =
        SqliteDatabase::connect_with_acquire_timeout(&url, 1, Duration::from_millis(200))
            .await
            .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");

    let held = database
        .pool()
        .acquire()
        .await
        .expect("hold the only connection");
    let started = Instant::now();
    let result = database
        .find_by_key_id(&GatewayKeyId::new("absent").expect("non-empty key ID"))
        .await;
    assert_eq!(
        result.expect_err("exhausted pool fails closed"),
        RepositoryError::Storage
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    drop(held);
}

#[tokio::test]
async fn postgres_storage_times_round_trip() {
    let Some(url) = std::env::var("TOKENSTREAM_TEST_POSTGRES_URL")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        eprintln!(
            "skipping PostgreSQL storage time test: TOKENSTREAM_TEST_POSTGRES_URL is not set"
        );
        return;
    };
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");
    verify_time_round_trip(&database, &unique_value("postgres-time")).await;
}

#[tokio::test]
async fn postgres_exhausted_pool_fails_closed() {
    let Some(url) = std::env::var("TOKENSTREAM_TEST_POSTGRES_URL")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        eprintln!(
            "skipping PostgreSQL pool exhaustion test: TOKENSTREAM_TEST_POSTGRES_URL is not set"
        );
        return;
    };
    let database =
        PostgresDatabase::connect_with_acquire_timeout(&url, 1, Duration::from_millis(200))
            .await
            .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");

    let held = database
        .pool()
        .acquire()
        .await
        .expect("hold the only connection");
    let started = Instant::now();
    let result = database
        .find_by_key_id(&GatewayKeyId::new("absent").expect("non-empty key ID"))
        .await;
    assert_eq!(
        result.expect_err("exhausted pool fails closed"),
        RepositoryError::Storage
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    drop(held);
}
