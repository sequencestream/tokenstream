use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use chrono::Utc;
use tokenstream::domain::{ProtocolType, ProviderId, RequestId, TransportType};
use tokenstream::logging::{EmitResult, LogEvent, LogStore, channel};
use tokenstream::persistence::{RepositoryError, RequestLogStarted};
use tokio::sync::Mutex;

#[derive(Default)]
struct RecordingStore {
    failures_remaining: AtomicUsize,
    attempts: AtomicUsize,
    batches: Mutex<Vec<Vec<LogEvent>>>,
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
        self.batches.lock().await.push(events.to_vec());
        Ok(())
    }
}

fn started(request_id: &str) -> LogEvent {
    LogEvent::Started(RequestLogStarted::new(
        RequestId::new(request_id).expect("request ID"),
        ProviderId::try_from(1).expect("provider ID"),
        ProtocolType::OpenAi,
        TransportType::Http,
        "/v1/responses".to_owned(),
        Utc::now(),
    ))
}

#[test]
fn a_full_or_closed_queue_drops_immediately_and_counts_the_event() {
    let store = Arc::new(RecordingStore::default());
    let (sink, worker) = channel(store, 1, 1, Duration::from_secs(1));

    assert_eq!(sink.try_emit(started("request-1")), EmitResult::Enqueued);
    assert_eq!(sink.try_emit(started("request-2")), EmitResult::DroppedFull);
    assert_eq!(sink.queued_events(), 1);
    assert_eq!(sink.dropped_events(), 1);

    drop(worker);
    assert_eq!(
        sink.try_emit(started("request-3")),
        EmitResult::DroppedClosed
    );
    assert_eq!(sink.queued_events(), 0);
    assert_eq!(sink.dropped_events(), 3);
}

#[tokio::test]
async fn worker_flushes_by_size_and_retries_only_inside_the_background_task() {
    let store = Arc::new(RecordingStore {
        failures_remaining: AtomicUsize::new(2),
        ..RecordingStore::default()
    });
    let (sink, worker) = channel(Arc::clone(&store), 4, 2, Duration::from_secs(5));
    let worker = tokio::spawn(worker.run());

    assert_eq!(sink.try_emit(started("request-1")), EmitResult::Enqueued);
    assert_eq!(sink.try_emit(started("request-2")), EmitResult::Enqueued);

    tokio::time::timeout(Duration::from_secs(1), async {
        while store.batches.lock().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("batch persisted after bounded retry");
    assert_eq!(store.attempts.load(Ordering::SeqCst), 3);
    assert_eq!(store.batches.lock().await[0].len(), 2);
    assert_eq!(sink.queued_events(), 0);

    drop(sink);
    worker.await.expect("worker exits after sender closes");
}

#[tokio::test]
async fn worker_flushes_a_partial_batch_on_the_interval() {
    let store = Arc::new(RecordingStore::default());
    let (sink, worker) = channel(Arc::clone(&store), 4, 4, Duration::from_millis(20));
    let worker = tokio::spawn(worker.run());
    assert_eq!(sink.try_emit(started("request-1")), EmitResult::Enqueued);

    tokio::time::timeout(Duration::from_secs(1), async {
        while store.batches.lock().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("interval flushes partial batch");
    assert_eq!(store.batches.lock().await[0].len(), 1);

    drop(sink);
    worker.await.expect("worker exits after sender closes");
}

#[tokio::test]
async fn exhausted_retries_drop_the_batch_without_blocking_producers() {
    let store = Arc::new(RecordingStore {
        failures_remaining: AtomicUsize::new(10),
        ..RecordingStore::default()
    });
    let (sink, worker) = channel(Arc::clone(&store), 2, 1, Duration::from_secs(1));
    let worker = tokio::spawn(worker.run());
    assert_eq!(sink.try_emit(started("request-1")), EmitResult::Enqueued);

    tokio::time::timeout(Duration::from_secs(1), async {
        while sink.queued_events() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed batch is discarded after bounded retry");
    assert_eq!(store.attempts.load(Ordering::SeqCst), 3);
    assert_eq!(sink.dropped_events(), 1);

    drop(sink);
    worker.await.expect("worker exits after sender closes");
}
