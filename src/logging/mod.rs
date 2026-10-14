//! Request-log storage, implemented as one subscriber on the event bus.
//!
//! This module owns the durable side only: how a dequeued slice of lifecycle
//! events becomes request-log rows. The bus, the emit path, the queue bounds,
//! the bounded retry, and the isolation of an unwritable event live in
//! [`crate::events`].
//!
//! Events contain transport metadata only. A payload is never stored.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::events::{
    BusBuilder, EventBus, LifecycleEvent, Subscriber, SubscriberOutcome, SubscriberReadiness,
    SubscriberStore,
};
use crate::persistence::{Database, RepositoryError, RequestLogCompleted, RequestLogStarted};
use crate::telemetry::{Metrics, SubscriberName};

const WARNING_INTERVAL: Duration = Duration::from_secs(1);

/// One metadata-only lifecycle event as the storage layer sees it.
pub use crate::persistence::RequestLogWrite as LogEvent;

/// Storage boundary used only by the background worker.
pub trait LogStore: Send + Sync + 'static {
    fn write_batch(
        &self,
        events: &[LogEvent],
    ) -> impl std::future::Future<Output = Result<(), RepositoryError>> + Send;
}

impl LogStore for Database {
    async fn write_batch(&self, events: &[LogEvent]) -> Result<(), RepositoryError> {
        match self {
            Database::Sqlite(database) => database.write_log_batch(events).await,
            Database::Postgres(database) => database.write_log_batch(events).await,
        }
    }
}

/// Attaches the request-log writer to a new bus and returns the sealed bus plus
/// the writer's receiver-owning half.
///
/// This is the composition-time call. The bus handed to the gateway is sealed
/// by construction, so no subscriber can be added once the process is serving.
pub fn channel<S>(
    store: Arc<S>,
    capacity: usize,
    batch_size: usize,
    batch_interval: Duration,
) -> (EventBus, LogWriter<S>)
where
    S: LogStore,
{
    channel_with_metrics(
        store,
        capacity,
        batch_size,
        batch_interval,
        Metrics::default(),
    )
}

pub fn channel_with_metrics<S>(
    store: Arc<S>,
    capacity: usize,
    batch_size: usize,
    batch_interval: Duration,
    metrics: Metrics,
) -> (EventBus, LogWriter<S>)
where
    S: LogStore,
{
    let (events, subscriber) = BusBuilder::new().attach(
        SubscriberName::RequestLog,
        RequestLogStore { store },
        capacity,
        batch_size,
        batch_interval,
        metrics,
    );
    (events, LogWriter { subscriber })
}

/// The store the bus sees.
///
/// It is handed lifecycle events, not storage events, so projecting them onto
/// rows is this subscriber's own business, and a projection that produces no row
/// is a skip rather than a failure: a skipped event is not a lost event, because
/// the fact it carries is owned by another event in the same batch.
struct RequestLogStore<S> {
    store: Arc<S>,
}

impl<S> SubscriberStore for RequestLogStore<S>
where
    S: LogStore,
{
    fn readiness(&self) -> SubscriberReadiness {
        SubscriberReadiness::Ready
    }

    async fn consume_batch(&self, events: &[LifecycleEvent]) -> SubscriberOutcome {
        let projected: Vec<LogEvent> = events.iter().filter_map(project_event).collect();
        if projected.is_empty() {
            return SubscriberOutcome::Handled;
        }
        match self.store.write_batch(&projected).await {
            Ok(()) => SubscriberOutcome::Handled,
            Err(error) if is_permanent_log_failure(&error) => {
                warn_rate_limited();
                SubscriberOutcome::Permanent
            }
            Err(_) => {
                warn_rate_limited();
                SubscriberOutcome::Transient
            }
        }
    }
}

/// Projects one lifecycle event onto the storage record it produces.
///
/// A stored record has exactly one optional status, and the terminal event owns
/// it, so the upstream-observed point produces no row of its own. It is still
/// emitted, because a subscriber other than this one may want the earlier fact.
fn project_event(event: &LifecycleEvent) -> Option<LogEvent> {
    match event {
        LifecycleEvent::Admitted(admitted) => Some(LogEvent::Started(RequestLogStarted::new(
            admitted.request_id.clone(),
            admitted.account_id,
            admitted.api_key_id,
            admitted.provider_id,
            admitted.protocol_type,
            admitted.transport_type,
            admitted.path.clone(),
            admitted.observed_at,
        ))),
        LifecycleEvent::Finished(finished) => Some(LogEvent::Completed(RequestLogCompleted::new(
            finished.request_id.clone(),
            finished.status_code,
            finished.finished_at,
            finished.outcome.map(|outcome| outcome.as_str().to_owned()),
        ))),
        LifecycleEvent::UpstreamObserved(_) => None,
    }
}

fn is_permanent_log_failure(error: &RepositoryError) -> bool {
    matches!(error, RepositoryError::NotFound | RepositoryError::Conflict)
}

fn warn_rate_limited() {
    use std::sync::Mutex;
    use std::sync::OnceLock;
    static LAST_WARNING: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
    let cell = LAST_WARNING.get_or_init(|| Mutex::new(None));
    let Ok(mut last) = cell.lock() else {
        return;
    };
    let now = Instant::now();
    if last.is_none_or(|previous| now.duration_since(previous) >= WARNING_INTERVAL) {
        tracing::warn!(
            target: "tokenstream::logging",
            event = "request_log_batch_failed",
            message = "A request-log batch write failed; retry and isolation are bounded.",
            subscriber = "request_log",
        );
        *last = Some(now);
    }
}

/// Owns the receiver and performs size-or-time based batch flushing.
pub struct LogWriter<S> {
    subscriber: Subscriber<RequestLogStore<S>>,
}

impl<S> LogWriter<S>
where
    S: LogStore,
{
    /// Runs until the bus is dropped, then handles the final partial batch.
    pub async fn run(self) {
        self.subscriber.run().await;
    }

    /// Depth of this subscriber's own queue, not a process-wide figure.
    pub fn queued_events(&self) -> usize {
        self.subscriber.queued_events()
    }

    /// Events this subscriber lost to a full queue or an aborted worker.
    pub fn dropped_events(&self) -> u64 {
        self.subscriber.dropped_events()
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn request_log_warning_is_structured_and_rate_limited() {
        let output = crate::diagnostics::capture_for_test(|| {
            warn_rate_limited();
            warn_rate_limited();
        });
        assert_eq!(output.lines().count(), 1);
        let event: serde_json::Value =
            serde_json::from_str(output.trim()).expect("request-log diagnostic");
        assert_eq!(event["fields"]["event"], "request_log_batch_failed");
        assert_eq!(event["fields"]["subscriber"], "request_log");
    }
}
