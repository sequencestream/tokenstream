use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{TimeZone, Utc};
use tokenstream::domain::{
    AccountId, ApiKeyId, ProtocolType, ProviderId, ProviderStatus, RequestId, SecretCiphertext,
    TransportType,
};
use tokenstream::events::{Admitted, EmitResult, Finished, LifecycleEvent, UpstreamObserved};
use tokenstream::logging::{LogEvent, LogStore, channel_with_metrics};
use tokenstream::persistence::postgres::PostgresDatabase;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{
    Database, NewProvider, ProviderRepository, RepositoryError, RequestLogQuery,
    RequestLogRepository,
};
use tokenstream::telemetry::{Metrics, SubscriberName};
use tokio::sync::Mutex;
use url::Url;

mod support;
use support::{ensure_bootstrap, require_postgres_url};

#[derive(Default)]
struct RecordingStore {
    failures_remaining: AtomicUsize,
    attempts: AtomicUsize,
    batches: Mutex<Vec<Vec<LogEvent>>>,
    poison_request_ids: Vec<String>,
    conflict_request_ids: Vec<String>,
}

impl RecordingStore {
    fn with_poison(ids: &[&str]) -> Self {
        Self {
            poison_request_ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            ..Self::default()
        }
    }

    fn with_conflicts(ids: &[&str]) -> Self {
        Self {
            conflict_request_ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            ..Self::default()
        }
    }
}

impl LogStore for RecordingStore {
    async fn write_batch(&self, events: &[LogEvent]) -> Result<(), RepositoryError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self
            .failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(RepositoryError::Storage);
        }
        if events
            .iter()
            .any(|event| started_id_in(event, &self.poison_request_ids))
        {
            return Err(RepositoryError::NotFound);
        }
        if events
            .iter()
            .any(|event| started_id_in(event, &self.conflict_request_ids))
        {
            return Err(RepositoryError::Conflict);
        }
        self.batches.lock().await.push(events.to_vec());
        Ok(())
    }
}

fn started_id_in(event: &LogEvent, ids: &[String]) -> bool {
    match event {
        LogEvent::Started(event) => ids.iter().any(|id| event.request_id().as_str() == id),
        LogEvent::Completed(_) => false,
    }
}

fn persisted_started_ids(batches: &[Vec<LogEvent>]) -> Vec<String> {
    batches
        .iter()
        .flatten()
        .filter_map(|event| match event {
            LogEvent::Started(event) => Some(event.request_id().as_str().to_owned()),
            LogEvent::Completed(_) => None,
        })
        .collect()
}

/// The admitted point, which is what produces a start row.
fn started(request_id: &str) -> LifecycleEvent {
    started_for(request_id, ProviderId::try_from(1).expect("provider ID"))
}

fn started_for(request_id: &str, provider_id: ProviderId) -> LifecycleEvent {
    started_for_account(
        request_id,
        AccountId::try_from(1).expect("account ID"),
        test_api_key_id(),
        provider_id,
    )
}

/// The credential a synthetic event is attributed to when no real one exists.
fn test_api_key_id() -> ApiKeyId {
    ApiKeyId::try_from(1).expect("positive credential ID")
}

fn started_for_account(
    request_id: &str,
    account_id: AccountId,
    api_key_id: ApiKeyId,
    provider_id: ProviderId,
) -> LifecycleEvent {
    LifecycleEvent::Admitted(Admitted {
        request_id: RequestId::new(request_id).expect("request ID"),
        account_id,
        api_key_id,
        provider_id,
        protocol_type: ProtocolType::OpenAi,
        transport_type: TransportType::Http,
        path: "/v1/responses".to_owned(),
        observed_at: Utc::now(),
    })
}

/// The finished point, which is what produces the completion update.
fn completed(request_id: &str, status: u16) -> LifecycleEvent {
    LifecycleEvent::Finished(Finished {
        request_id: RequestId::new(request_id).expect("request ID"),
        status_code: Some(status),
        transport_type: TransportType::Http,
        outcome: None,
        elapsed: Duration::from_millis(1),
        finished_at: Utc::now(),
    })
}

/// The upstream-observed point, which produces no row of its own because the
/// terminal event owns the one optional status a record carries.
fn observed(request_id: &str, status: u16) -> LifecycleEvent {
    LifecycleEvent::UpstreamObserved(UpstreamObserved {
        request_id: RequestId::new(request_id).expect("request ID"),
        status_code: Some(status),
        observed_at: Utc::now(),
    })
}

fn queued(metrics: &Metrics) -> usize {
    metrics.subscriber(SubscriberName::RequestLog).queue_depth
}

fn dropped(metrics: &Metrics) -> u64 {
    metrics
        .subscriber(SubscriberName::RequestLog)
        .dropped_events
}

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
        ProviderStatus::Enabled,
        Utc.with_ymd_and_hms(2026, 9, 28, 8, 0, 0)
            .single()
            .expect("valid timestamp"),
    )
}

#[test]
fn a_full_or_abandoned_queue_drops_immediately_and_counts_the_event() {
    let store = Arc::new(RecordingStore::default());
    let metrics = Metrics::default();
    let (bus, writer) = channel_with_metrics(store, 1, 1, Duration::from_secs(1), metrics.clone());

    assert_eq!(bus.emit(started("request-1")), EmitResult::Enqueued);
    assert_eq!(bus.emit(started("request-2")), EmitResult::PartiallyDropped);
    assert_eq!(queued(&metrics), 1);
    assert_eq!(dropped(&metrics), 1);

    // An abandoned worker is a full queue forever: the subscriber owns the
    // receiver, so nothing drains it and every later copy is lost here.
    drop(writer);
    assert_eq!(bus.emit(started("request-3")), EmitResult::PartiallyDropped);
    assert_eq!(bus.emit(started("request-4")), EmitResult::PartiallyDropped);
}

#[tokio::test]
async fn worker_flushes_by_size_and_retries_only_inside_the_background_task() {
    let store = Arc::new(RecordingStore {
        failures_remaining: AtomicUsize::new(2),
        ..RecordingStore::default()
    });
    let metrics = Metrics::default();
    let (bus, writer) = channel_with_metrics(
        Arc::clone(&store),
        4,
        2,
        Duration::from_secs(5),
        metrics.clone(),
    );
    let worker = tokio::spawn(writer.run());

    assert_eq!(bus.emit(started("request-1")), EmitResult::Enqueued);
    assert_eq!(bus.emit(started("request-2")), EmitResult::Enqueued);

    tokio::time::timeout(Duration::from_secs(1), async {
        while store.batches.lock().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("batch persisted after bounded retry");
    assert_eq!(store.attempts.load(Ordering::SeqCst), 3);
    assert_eq!(store.batches.lock().await[0].len(), 2);
    assert_eq!(queued(&metrics), 0);

    drop(bus);
    worker.await.expect("worker exits after the bus closes");
}

#[tokio::test]
async fn worker_flushes_a_partial_batch_on_the_interval() {
    let store = Arc::new(RecordingStore::default());
    let metrics = Metrics::default();
    let (bus, writer) = channel_with_metrics(
        Arc::clone(&store),
        4,
        4,
        Duration::from_millis(20),
        metrics.clone(),
    );
    let worker = tokio::spawn(writer.run());
    assert_eq!(bus.emit(started("request-1")), EmitResult::Enqueued);

    tokio::time::timeout(Duration::from_secs(1), async {
        while store.batches.lock().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("interval flushes partial batch");
    assert_eq!(store.batches.lock().await[0].len(), 1);

    drop(bus);
    worker.await.expect("worker exits after the bus closes");
}

#[tokio::test]
async fn exhausted_retries_drop_the_batch_without_blocking_producers() {
    let store = Arc::new(RecordingStore {
        failures_remaining: AtomicUsize::new(10),
        ..RecordingStore::default()
    });
    let metrics = Metrics::default();
    let (bus, writer) = channel_with_metrics(
        Arc::clone(&store),
        2,
        1,
        Duration::from_secs(1),
        metrics.clone(),
    );
    let worker = tokio::spawn(writer.run());
    assert_eq!(bus.emit(started("request-1")), EmitResult::Enqueued);

    tokio::time::timeout(Duration::from_secs(1), async {
        while queued(&metrics) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed batch is discarded after bounded retry");
    assert_eq!(store.attempts.load(Ordering::SeqCst), 3);
    assert_eq!(dropped(&metrics), 1);

    drop(bus);
    worker.await.expect("worker exits after the bus closes");
}

#[tokio::test]
async fn a_single_permanent_failure_is_dropped_without_retrying() {
    let store = Arc::new(RecordingStore::with_poison(&["poison"]));
    let metrics = Metrics::default();
    let (bus, writer) = channel_with_metrics(
        Arc::clone(&store),
        2,
        1,
        Duration::from_secs(1),
        metrics.clone(),
    );
    let worker = tokio::spawn(writer.run());
    assert_eq!(bus.emit(started("poison")), EmitResult::Enqueued);

    tokio::time::timeout(Duration::from_secs(1), async {
        while queued(&metrics) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("permanent event is isolated");
    assert_eq!(store.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(dropped(&metrics), 1);
    assert!(store.batches.lock().await.is_empty());

    drop(bus);
    worker.await.expect("worker exits after the bus closes");
}

#[tokio::test]
async fn worker_isolates_a_permanent_event_and_keeps_the_rest() {
    let store = Arc::new(RecordingStore::with_poison(&["poison"]));
    let metrics = Metrics::default();
    let (bus, writer) = channel_with_metrics(
        Arc::clone(&store),
        8,
        4,
        Duration::from_secs(5),
        metrics.clone(),
    );
    let worker = tokio::spawn(writer.run());

    assert_eq!(bus.emit(started("poison")), EmitResult::Enqueued);
    assert_eq!(bus.emit(started("good-1")), EmitResult::Enqueued);
    assert_eq!(bus.emit(started("good-2")), EmitResult::Enqueued);
    assert_eq!(bus.emit(completed("good-1", 200)), EmitResult::Enqueued);

    drop(bus);
    worker.await.expect("worker exits after the bus closes");

    assert_eq!(dropped(&metrics), 1);
    assert_eq!(queued(&metrics), 0);
    assert!(store.attempts.load(Ordering::SeqCst) <= 7);
    let persisted = persisted_started_ids(&store.batches.lock().await);
    assert_eq!(persisted, ["good-1", "good-2"]);
    let completion_kept = store.batches.lock().await.iter().flatten().any(|event| {
        matches!(
            event,
            LogEvent::Completed(completed)
                if completed.request_id().as_str() == "good-1"
                    && completed.status_code() == Some(200)
        )
    });
    assert!(completion_kept);
}

#[tokio::test]
async fn the_upstream_observed_point_persists_no_row_of_its_own() {
    let store = Arc::new(RecordingStore::default());
    let metrics = Metrics::default();
    let (bus, writer) = channel_with_metrics(
        Arc::clone(&store),
        8,
        3,
        Duration::from_secs(5),
        metrics.clone(),
    );
    let worker = tokio::spawn(writer.run());

    // A stored record has exactly one optional status and the terminal event
    // owns it, so the upstream-observed point carries a fact the writer skips
    // rather than a row of its own.
    assert_eq!(bus.emit(observed("request-1", 200)), EmitResult::Enqueued);
    assert_eq!(bus.emit(started("request-1")), EmitResult::Enqueued);
    assert_eq!(bus.emit(observed("request-1", 200)), EmitResult::Enqueued);
    assert_eq!(bus.emit(completed("request-1", 200)), EmitResult::Enqueued);

    drop(bus);
    worker.await.expect("worker exits after the bus closes");

    let batches = store.batches.lock().await;
    let writes: Vec<&LogEvent> = batches.iter().flatten().collect();
    assert_eq!(
        writes.len(),
        2,
        "only the admitted and finished points persist"
    );
    assert!(
        matches!(writes[0], LogEvent::Started(started) if started.request_id().as_str() == "request-1")
    );
    assert!(
        matches!(writes[1], LogEvent::Completed(completed) if completed.status_code() == Some(200))
    );
    assert_eq!(dropped(&metrics), 0);
    assert_eq!(queued(&metrics), 0);
}

#[tokio::test]
async fn worker_isolates_a_duplicate_start_and_keeps_later_events() {
    let store = Arc::new(RecordingStore::with_conflicts(&["dup"]));
    let metrics = Metrics::default();
    let (bus, writer) = channel_with_metrics(
        Arc::clone(&store),
        8,
        3,
        Duration::from_secs(5),
        metrics.clone(),
    );
    let worker = tokio::spawn(writer.run());

    assert_eq!(bus.emit(started("dup")), EmitResult::Enqueued);
    assert_eq!(bus.emit(started("later")), EmitResult::Enqueued);
    assert_eq!(bus.emit(completed("later", 200)), EmitResult::Enqueued);

    drop(bus);
    worker.await.expect("worker exits after the bus closes");

    assert_eq!(dropped(&metrics), 1);
    let persisted = persisted_started_ids(&store.batches.lock().await);
    assert_eq!(persisted, ["later"]);
}

async fn sqlite_database(path: &Path) -> Database {
    let url = format!("sqlite://{}", path.display());
    let database = SqliteDatabase::connect(&url, 2)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    Database::Sqlite(database)
}

async fn verify_deleted_provider_start_does_not_poison_the_batch(database: Database, prefix: &str) {
    let removable = ProviderRepository::create(&database, new_provider(prefix, 0))
        .await
        .expect("create removable provider");
    let kept = ProviderRepository::create(&database, new_provider(prefix, 1))
        .await
        .expect("create kept provider");
    let account = ensure_bootstrap(&database).await;
    // A stored log names the credential that presented the request, so the
    // events are attributed to one that exists and is bound to the provider.
    let api_key_id = support::stored_api_key(&database, &account, kept.id()).await;
    let store = Arc::new(database);
    let metrics = Metrics::default();
    let (bus, writer) = channel_with_metrics(
        Arc::clone(&store),
        8,
        8,
        Duration::from_secs(30),
        metrics.clone(),
    );
    let worker = tokio::spawn(writer.run());

    let orphan_id = format!("{prefix}-orphan");
    let kept_id = format!("{prefix}-kept");
    assert_eq!(
        bus.emit(started_for_account(
            &orphan_id,
            account.id(),
            api_key_id,
            removable.id(),
        )),
        EmitResult::Enqueued
    );
    ProviderRepository::delete(store.as_ref(), removable.id())
        .await
        .expect("delete succeeds while the start event is still queued");
    assert_eq!(
        bus.emit(started_for_account(
            &kept_id,
            account.id(),
            api_key_id,
            kept.id(),
        )),
        EmitResult::Enqueued
    );
    assert_eq!(bus.emit(completed(&kept_id, 200)), EmitResult::Enqueued);
    assert_eq!(bus.emit(completed(&kept_id, 500)), EmitResult::Enqueued);

    drop(bus);
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .expect("worker finishes isolation")
        .expect("worker join");

    assert_eq!(dropped(&metrics), 1);
    assert_eq!(queued(&metrics), 0);

    let kept_logs = store
        .as_ref()
        .query(
            RequestLogQuery::new(
                None,
                100,
                Some(account.id()),
                Some(kept.id()),
                None,
                None,
                None,
            )
            .expect("valid request log query"),
        )
        .await
        .expect("query kept logs");
    assert_eq!(kept_logs.items().len(), 1);
    assert_eq!(kept_logs.items()[0].request_id().as_str(), kept_id);
    assert_eq!(kept_logs.items()[0].status_code(), Some(200));
    assert!(kept_logs.items()[0].end_time().is_some());

    let orphan_logs = store
        .as_ref()
        .query(
            RequestLogQuery::new(
                None,
                100,
                Some(account.id()),
                Some(removable.id()),
                None,
                None,
                None,
            )
            .expect("valid request log query"),
        )
        .await
        .expect("query orphan logs");
    assert!(orphan_logs.items().is_empty());
}

#[tokio::test]
async fn sqlite_deleted_provider_start_does_not_poison_the_batch() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("log-isolation.db")).await;
    verify_deleted_provider_start_does_not_poison_the_batch(
        database,
        &unique_value("sqlite-log-isolation"),
    )
    .await;
}

#[tokio::test]
async fn postgres_deleted_provider_start_does_not_poison_the_batch() {
    let url = require_postgres_url("log-batch isolation of a deleted-provider start event");
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");
    verify_deleted_provider_start_does_not_poison_the_batch(
        Database::Postgres(database),
        &unique_value("postgres-log-isolation"),
    )
    .await;
}
