use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Duration, TimeZone, Utc};
use tokenstream::domain::{
    GatewayKeyId, PasswordHash, ProtocolType, ProviderId, ProviderStatus, RequestId,
    RequestLogCursor, SecretCiphertext, TransportType,
};
use tokenstream::persistence::postgres::PostgresDatabase;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{
    NewProvider, ProviderRepository, RepositoryError, RequestLogCompleted, RequestLogQuery,
    RequestLogQueryError, RequestLogRepository, RequestLogStarted,
};
use url::Url;

mod support;
use support::require_postgres_url;

fn unique_value(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn new_provider(prefix: &str, number: usize) -> NewProvider {
    NewProvider::new(
        format!("{prefix}-provider-{number}"),
        ProtocolType::OpenAi,
        Url::parse("https://example.com").expect("valid endpoint"),
        SecretCiphertext::new("ciphertext"),
        GatewayKeyId::new(format!("{prefix}-key-{number}")).expect("non-empty key ID"),
        PasswordHash::new("hash"),
        ProviderStatus::Enabled,
        Utc.with_ymd_and_hms(2026, 9, 28, 8, 0, 0)
            .single()
            .expect("valid timestamp"),
    )
}

fn started(
    request_id: &str,
    provider_id: ProviderId,
    protocol_type: ProtocolType,
    transport_type: TransportType,
    path: &str,
    start_time: DateTime<Utc>,
) -> RequestLogStarted {
    RequestLogStarted::new(
        RequestId::new(request_id).expect("non-empty request ID"),
        provider_id,
        protocol_type,
        transport_type,
        path.to_owned(),
        start_time,
    )
}

fn query(
    after_id: Option<RequestLogCursor>,
    limit: usize,
    provider_id: Option<ProviderId>,
    transport_type: Option<TransportType>,
    start_time_gte: Option<DateTime<Utc>>,
    start_time_lt: Option<DateTime<Utc>>,
) -> RequestLogQuery {
    RequestLogQuery::new(
        after_id,
        limit,
        provider_id,
        transport_type,
        start_time_gte,
        start_time_lt,
    )
    .expect("valid request log query")
}

async fn verify_contract<R>(repository: &R, prefix: &str)
where
    R: ProviderRepository + RequestLogRepository,
{
    assert_eq!(
        RequestLogQuery::new(None, 0, None, None, None, None),
        Err(RequestLogQueryError::InvalidLimit)
    );
    assert_eq!(
        RequestLogQuery::new(None, 101, None, None, None, None),
        Err(RequestLogQueryError::InvalidLimit)
    );

    let base = Utc
        .with_ymd_and_hms(2026, 9, 28, 9, 0, 0)
        .single()
        .expect("valid timestamp");
    assert_eq!(
        RequestLogQuery::new(None, 10, None, None, Some(base), Some(base)),
        Err(RequestLogQueryError::InvalidTimeRange)
    );

    let provider = repository
        .create(new_provider(prefix, 0))
        .await
        .expect("create provider");
    let other_provider = repository
        .create(new_provider(prefix, 1))
        .await
        .expect("create other provider");

    let missing_request_id = format!("{prefix}-missing-start");
    repository
        .apply_completed(RequestLogCompleted::new(
            RequestId::new(&missing_request_id).expect("non-empty request ID"),
            Some(502),
            base,
            Some("not inserted".to_owned()),
        ))
        .await
        .expect("completion without start is a no-op");
    assert!(
        repository
            .query(query(None, 100, Some(provider.id()), None, None, None))
            .await
            .expect("query empty logs")
            .items()
            .is_empty()
    );

    let missing_provider = ProviderId::try_from(i64::MAX).expect("positive provider ID");
    assert_eq!(
        repository
            .insert_started(started(
                &format!("{prefix}-missing-provider"),
                missing_provider,
                ProtocolType::OpenAi,
                TransportType::Http,
                "/v1/responses",
                base,
            ))
            .await
            .expect_err("foreign key violation is rejected"),
        RepositoryError::NotFound
    );

    let first_request_id = format!("{prefix}-first");
    repository
        .insert_started(started(
            &first_request_id,
            provider.id(),
            ProtocolType::OpenAi,
            TransportType::Http,
            "/v1/responses",
            base,
        ))
        .await
        .expect("insert first start");
    assert_eq!(
        repository
            .insert_started(started(
                &first_request_id,
                provider.id(),
                ProtocolType::Anthropic,
                TransportType::WebSocket,
                "/changed",
                base + Duration::seconds(1),
            ))
            .await
            .expect_err("duplicate request ID is rejected"),
        RepositoryError::Conflict
    );

    let incomplete = repository
        .query(query(None, 100, Some(provider.id()), None, None, None))
        .await
        .expect("query incomplete log");
    assert_eq!(incomplete.items().len(), 1);
    assert_eq!(incomplete.items()[0].path(), "/v1/responses");
    assert_eq!(incomplete.items()[0].protocol_type(), ProtocolType::OpenAi);
    assert_eq!(incomplete.items()[0].status_code(), None);
    assert_eq!(incomplete.items()[0].end_time(), None);
    assert_eq!(incomplete.items()[0].error_msg(), None);

    let second_request_id = format!("{prefix}-second");
    repository
        .insert_started(started(
            &second_request_id,
            provider.id(),
            ProtocolType::OpenAi,
            TransportType::WebSocket,
            "/v1/responses",
            base + Duration::seconds(10),
        ))
        .await
        .expect("insert second start");
    repository
        .insert_started(started(
            &format!("{prefix}-other-provider"),
            other_provider.id(),
            ProtocolType::Anthropic,
            TransportType::Http,
            "/v1/messages",
            base + Duration::seconds(20),
        ))
        .await
        .expect("insert other provider start");

    let first_end = base + Duration::seconds(30);
    repository
        .apply_completed(RequestLogCompleted::new(
            RequestId::new(&first_request_id).expect("non-empty request ID"),
            Some(200),
            first_end,
            None,
        ))
        .await
        .expect("complete first log");
    repository
        .apply_completed(RequestLogCompleted::new(
            RequestId::new(&first_request_id).expect("non-empty request ID"),
            Some(500),
            first_end + Duration::seconds(1),
            Some("duplicate completion".to_owned()),
        ))
        .await
        .expect("duplicate completion is idempotent");

    let provider_logs = repository
        .query(query(None, 100, Some(provider.id()), None, None, None))
        .await
        .expect("query provider logs");
    assert_eq!(provider_logs.items().len(), 2);
    assert!(
        provider_logs
            .items()
            .windows(2)
            .all(|pair| pair[0].id() < pair[1].id())
    );
    let completed = &provider_logs.items()[0];
    assert_eq!(completed.request_id().as_str(), first_request_id);
    assert_eq!(completed.status_code(), Some(200));
    assert_eq!(completed.end_time(), Some(first_end));
    assert_eq!(completed.error_msg(), None);

    let websocket_logs = repository
        .query(query(
            None,
            100,
            Some(provider.id()),
            Some(TransportType::WebSocket),
            Some(base + Duration::seconds(10)),
            Some(base + Duration::seconds(20)),
        ))
        .await
        .expect("query filtered logs");
    assert_eq!(websocket_logs.items().len(), 1);
    assert_eq!(
        websocket_logs.items()[0].request_id().as_str(),
        second_request_id
    );

    let first_page = repository
        .query(query(None, 1, Some(provider.id()), None, None, None))
        .await
        .expect("query first page");
    assert_eq!(first_page.items().len(), 1);
    assert!(first_page.has_more());
    let second_page = repository
        .query(query(
            first_page.next_after_id(),
            1,
            Some(provider.id()),
            None,
            None,
            None,
        ))
        .await
        .expect("query second page");
    assert_eq!(second_page.items().len(), 1);
    assert!(!second_page.has_more());
    assert!(second_page.items()[0].id() > first_page.items()[0].id());
}

async fn sqlite_database(path: &Path) -> SqliteDatabase {
    let url = format!("sqlite://{}", path.display());
    let database = SqliteDatabase::connect(&url, 2)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    database
}

#[tokio::test]
async fn sqlite_request_log_repository_satisfies_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("request-logs.db")).await;
    verify_contract(&database, &unique_value("sqlite-request-log-contract")).await;
}

#[tokio::test]
async fn postgres_request_log_repository_satisfies_contract() {
    let url = require_postgres_url("the PostgreSQL request log repository layer");
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");
    verify_contract(&database, &unique_value("postgres-request-log-contract")).await;
}
