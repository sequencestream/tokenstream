//! Compute isolation, reserved database capacity, and execution deadlines.

use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::AUTHORIZATION;
use hyper::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tokenstream::admin::AdminApi;
use tokenstream::auth::{GatewayAuthError, GatewayAuthenticator};
use tokenstream::credentials::{CreateApiKeyRequest, CredentialService};
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier, PasswordWork};
use tokenstream::domain::{
    AccountId, ApiKeyId, ApiKeyStatus, GatewayKeyId, ProtocolType, ProviderStatus, SecretString,
};
use tokenstream::logging::{LogEvent, LogSink, channel};
use tokenstream::persistence::postgres::PostgresDatabase;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{
    ApiKeyRepository, DatabaseBounds, ProviderListRequest, ProviderRepository, RepositoryError,
    RequestLogStarted,
};
use tokenstream::providers::{CreateProviderRequest, ProviderService};
use tokenstream::telemetry::{Metrics, ProxyFailureCategory};
use tokio::sync::oneshot;

mod support;
use support::{bootstrap_account, require_postgres_url};

static POSTGRES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const MASTER_KEY: [u8; 32] = [0x5c; 32];
const UPSTREAM_KEY: &str = "sk-upstream-secret-value";
const ADMIN_NAME: &str = "admin";
const ADMIN_PASSWORD: &str = "correct horse battery staple";

fn short_bounds(max_connections: usize, auth_connections: usize) -> DatabaseBounds {
    DatabaseBounds {
        max_connections,
        auth_connections,
        acquire_timeout: Duration::from_millis(200),
        auth_timeout: Duration::from_millis(200),
        admin_timeout: Duration::from_millis(200),
        log_timeout: Duration::from_millis(200),
    }
}

async fn sqlite(path: &std::path::Path, bounds: DatabaseBounds) -> SqliteDatabase {
    let url = format!("sqlite://{}", path.display());
    let database = SqliteDatabase::connect_with_bounds(&url, bounds)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    database
}

fn create_request(name: &str) -> CreateProviderRequest {
    CreateProviderRequest::new(
        name.to_owned(),
        ProtocolType::OpenAi,
        "https://api.openai.example/v1".to_owned(),
        SecretString::new(UPSTREAM_KEY),
        ProviderStatus::Enabled,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn control_plane_hashing_cannot_consume_data_plane_slots() {
    let data = PasswordWork::new(1);
    let control = PasswordWork::new(1);
    let (started, ready) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let occupying = control.clone();
    let task = tokio::spawn(async move {
        occupying
            .run(move || {
                started.send(()).unwrap();
                blocked.recv().unwrap();
            })
            .await
    });
    ready.await.unwrap();
    assert!(
        control.run(|| ()).await.is_err(),
        "control plane budget is isolated"
    );
    assert_eq!(
        data.run(|| 7)
            .await
            .expect("data plane keeps its own slots"),
        7
    );
    release.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn exhausted_password_work_fails_closed_as_busy() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite(
        &directory.path().join("busy.db"),
        DatabaseBounds::for_tests(2),
    )
    .await;
    let service = ProviderService::new(database.clone(), AesGcmCipher::new(&MASTER_KEY), false);
    let created = service
        .create(create_request("primary"))
        .await
        .expect("create provider");
    let accounts = CredentialService::new(database.clone(), Argon2GatewaySecretVerifier::new());
    let account = bootstrap_account(&accounts).await;
    let issued = accounts
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "busy".to_owned(),
            vec![created.id()],
            Some(created.id()),
            None,
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect("issue a credential");
    let work = PasswordWork::new(1);
    let authenticator = GatewayAuthenticator::new(
        database,
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
    )
    .with_password_work(work.clone());

    let (started, ready) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let occupying = work.clone();
    let task = tokio::spawn(async move {
        occupying
            .run(move || {
                started.send(()).unwrap();
                blocked.recv().unwrap();
            })
            .await
    });
    ready.await.unwrap();

    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", issued.credential().render())
            .parse()
            .expect("valid header"),
    );
    assert_eq!(
        authenticator
            .authenticate(&headers)
            .await
            .expect_err("compute exhaustion fails closed"),
        GatewayAuthError::Busy
    );
    release.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn administrator_sign_in_reports_resource_exhausted_without_internal_error() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite(
        &directory.path().join("admin-busy.db"),
        DatabaseBounds::for_tests(2),
    )
    .await;
    let salt = SaltString::encode_b64(b"admin-budget-salt").expect("valid salt");
    let hash = Argon2::default()
        .hash_password(ADMIN_PASSWORD.as_bytes(), &salt)
        .expect("hash password")
        .to_string();
    let metrics = Metrics::default();
    let work = PasswordWork::new(1);
    let api = AdminApi::new(
        database,
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
        false,
        hash,
    )
    .with_password_work(work.clone())
    .with_metrics(metrics.clone());
    api.ensure_bootstrap_account(ADMIN_NAME, ADMIN_PASSWORD)
        .await
        .expect("create the bootstrap account");

    let (started, ready) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let occupying = work;
    let task = tokio::spawn(async move {
        occupying
            .run(move || {
                started.send(()).unwrap();
                blocked.recv().unwrap();
            })
            .await
    });
    ready.await.unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/admin/api/session")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&json!({ "name": ADMIN_NAME, "password": ADMIN_PASSWORD }))
                .expect("JSON"),
        )))
        .expect("request");
    let response = api.handle(request, Metrics::default()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("JSON envelope");
    assert_eq!(body["error"]["code"], "resource_exhausted");
    assert_eq!(
        metrics.failure_count(ProxyFailureCategory::ResourceExhausted),
        1
    );
    assert!(
        !serde_json::to_string(&body)
            .expect("render")
            .contains(ADMIN_PASSWORD)
    );
    release.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn sqlite_reserved_auth_connections_survive_shared_pool_exhaustion() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite(&directory.path().join("reserved.db"), short_bounds(3, 1)).await;
    let held = (
        database.pool().acquire().await.expect("shared slot 1"),
        database.pool().acquire().await.expect("shared slot 2"),
    );
    let started = Instant::now();
    ApiKeyRepository::find_by_key_id(&database, &GatewayKeyId::new("absent").expect("key"))
        .await
        .expect("auth lookup uses reserved capacity");
    assert!(started.elapsed() < Duration::from_millis(500));
    let list =
        ProviderRepository::list(&database, ProviderListRequest::new(None, 10).expect("page"))
            .await;
    assert_eq!(
        list.expect_err("shared pool is exhausted"),
        RepositoryError::Timeout
    );
    drop(held);
    ProviderRepository::list(&database, ProviderListRequest::new(None, 10).expect("page"))
        .await
        .expect("shared pool recovers");
}

#[tokio::test]
async fn sqlite_write_lock_wait_fails_within_the_deadline_and_pool_recovers() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite(&directory.path().join("lock.db"), short_bounds(2, 2)).await;
    let mut held = database.pool().acquire().await.expect("hold a connection");
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *held)
        .await
        .expect("reserved lock");
    let started = Instant::now();
    let service = ProviderService::new(database.clone(), AesGcmCipher::new(&MASTER_KEY), false);
    let result = service.create(create_request("blocked")).await;
    assert_eq!(
        result.expect_err("write lock wait fails closed"),
        tokenstream::providers::ProviderServiceError::Busy
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    sqlx::query("ROLLBACK")
        .execute(&mut *held)
        .await
        .expect("release lock");
    drop(held);
    service
        .create(create_request("after-lock"))
        .await
        .expect("pool is usable after the timed-out write");
}

#[tokio::test]
async fn sqlite_log_batch_deadline_does_not_block_a_later_write() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite(&directory.path().join("log-timeout.db"), short_bounds(2, 2)).await;
    let service = ProviderService::new(database.clone(), AesGcmCipher::new(&MASTER_KEY), false);
    service
        .create(create_request("logged"))
        .await
        .expect("create provider");

    let mut held = database.pool().acquire().await.expect("hold a connection");
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut *held)
        .await
        .expect("exclusive lock");
    let (sink, worker): (LogSink, _) = channel(
        std::sync::Arc::new(tokenstream::persistence::Database::Sqlite(database.clone())),
        4,
        1,
        Duration::from_millis(10),
    );
    let worker = tokio::spawn(worker.run());
    let started = Instant::now();
    assert_eq!(
        sink.try_emit(LogEvent::Started(RequestLogStarted::new(
            tokenstream::domain::RequestId::new("req-log-timeout").expect("id"),
            AccountId::try_from(1).expect("account"),
            ApiKeyId::try_from(1).expect("credential"),
            tokenstream::domain::ProviderId::try_from(1).expect("provider"),
            ProtocolType::OpenAi,
            tokenstream::domain::TransportType::Http,
            "/v1/responses".to_owned(),
            chrono::Utc::now(),
        ))),
        tokenstream::logging::EmitResult::Enqueued
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while sink.queued_events() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("log worker gives up within the batch deadline");
    assert!(started.elapsed() < Duration::from_secs(3));
    sqlx::query("ROLLBACK")
        .execute(&mut *held)
        .await
        .expect("release lock");
    drop(held);
    drop(sink);
    worker.await.expect("worker exits");
}

#[tokio::test]
async fn postgres_lock_wait_and_sleep_fail_within_deadlines() {
    let _guard = POSTGRES.lock().await;
    let url = require_postgres_url("database execution deadlines");
    let database = PostgresDatabase::connect_with_bounds(&url, short_bounds(2, 2))
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");

    let mut held = database.pool().acquire().await.expect("hold a connection");
    sqlx::query("BEGIN")
        .execute(&mut *held)
        .await
        .expect("begin");
    sqlx::query("LOCK TABLE provider IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *held)
        .await
        .expect("lock table");
    let started = Instant::now();
    let result = ProviderRepository::find_by_id(
        &database,
        tokenstream::domain::ProviderId::try_from(1).expect("positive provider ID"),
    )
    .await;
    assert_eq!(
        result.expect_err("lock wait fails closed"),
        RepositoryError::Timeout
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    sqlx::query("ROLLBACK")
        .execute(&mut *held)
        .await
        .expect("release lock");
    drop(held);

    let started = Instant::now();
    let stalled = tokio::time::timeout(
        Duration::from_millis(200),
        sqlx::query("SELECT pg_sleep(5)").execute(database.pool()),
    )
    .await;
    assert!(
        stalled.is_err() || stalled.unwrap().is_err(),
        "execution stall is cancelled"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    ApiKeyRepository::find_by_key_id(&database, &GatewayKeyId::new("absent").expect("key"))
        .await
        .expect("pool is usable after a cancelled stall");
}

#[tokio::test]
async fn postgres_reserved_auth_connections_survive_shared_pool_exhaustion() {
    let _guard = POSTGRES.lock().await;
    let url = require_postgres_url("reserved authentication database capacity");
    let database = PostgresDatabase::connect_with_bounds(&url, short_bounds(3, 1))
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");
    let held = (
        database.pool().acquire().await.expect("shared slot 1"),
        database.pool().acquire().await.expect("shared slot 2"),
    );
    ApiKeyRepository::find_by_key_id(&database, &GatewayKeyId::new("absent").expect("key"))
        .await
        .expect("auth lookup uses reserved capacity");
    assert_eq!(
        ProviderRepository::list(&database, ProviderListRequest::new(None, 10).expect("page"),)
            .await
            .expect_err("shared pool is exhausted"),
        RepositoryError::Timeout
    );
    drop(held);
}

#[tokio::test]
async fn cancelled_authentication_keeps_compute_until_hashing_finishes() {
    let work = PasswordWork::new(1);
    let (started, ready) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let occupying = work.clone();
    let task = tokio::spawn(async move {
        occupying
            .run(move || {
                started.send(()).unwrap();
                blocked.recv().unwrap();
            })
            .await
    });
    ready.await.unwrap();
    task.abort();
    let _ = task.await;
    assert!(
        work.run(|| ()).await.is_err(),
        "a cancelled caller does not free a running hash"
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while work.run(|| ()).await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("capacity returns after the hash finishes");
}
