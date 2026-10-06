//! Request-log storage, implemented as one subscriber on the event bus.
//!
//! This module owns the durable side only: how a dequeued slice of lifecycle
//! events becomes request-log rows. The bus, the emit path, the queue bounds,
//! the bounded retry, and the isolation of an unwritable event live in
//! [`crate::events`]. The emit discipline this writer inherits is
//! ADR 0005; the fan-out it sits on is ADR 0016.
//!
//! Events contain transport metadata only. A payload is never stored.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use chrono::Utc;
use hyper::body::{Body, Frame, SizeHint};
use hyper::{Response, StatusCode};

use crate::domain::{ProviderSnapshot, RequestId};
use crate::events::{
    Admitted, BusBuilder, EventBus, Finished, LifecycleEvent, Subscriber, SubscriberOutcome,
    SubscriberReadiness, SubscriberStore, UpstreamObserved,
};
use crate::persistence::{Database, RepositoryError, RequestLogCompleted, RequestLogStarted};
use crate::routing::ResolvedRoute;
use crate::telemetry::{
    ActiveRequestGuard, ExchangeOutcome, Metrics, ProxyFailureCategory, SubscriberName,
};

const WARNING_INTERVAL: Duration = Duration::from_secs(1);

/// One metadata-only lifecycle event as the storage layer sees it.
#[derive(Clone, Debug)]
pub enum LogEvent {
    Started(RequestLogStarted),
    Completed(RequestLogCompleted),
}

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

/// One request or connection lifecycle whose completion is emitted at most once.
pub struct RequestLogLifecycle {
    bus: EventBus,
    metrics: Metrics,
    request_id: Option<RequestId>,
    transport: Option<crate::domain::TransportType>,
    started: Instant,
    active: Option<ActiveRequestGuard>,
}

impl RequestLogLifecycle {
    pub fn start(
        bus: EventBus,
        metrics: Metrics,
        request_id: RequestId,
        snapshot: &ProviderSnapshot,
        route: &ResolvedRoute,
    ) -> Self {
        let transport = route.transport();
        // The admitted point is emitted here, after every admission layer has
        // granted, so a rejected request never produces one.
        let _ = bus.emit(LifecycleEvent::Admitted(Admitted {
            request_id: request_id.clone(),
            account_id: snapshot.account_id(),
            api_key_id: snapshot.api_key_id(),
            provider_id: snapshot.id(),
            protocol_type: snapshot.protocol_type(),
            transport_type: transport,
            path: route.path().to_owned(),
            observed_at: Utc::now(),
        }));
        Self {
            bus,
            metrics,
            request_id: Some(request_id),
            transport: Some(transport),
            started: Instant::now(),
            active: None,
        }
    }

    pub fn observe_http(mut self) -> Self {
        self.active = Some(self.metrics.start_http());
        self
    }

    pub fn observe_websocket(mut self) -> Self {
        self.active = Some(self.metrics.start_websocket());
        self
    }

    /// Emits the upstream-observed point, which is the moment an upstream
    /// status or a handshake outcome arrived.
    pub fn observe_upstream(&mut self, status: Option<StatusCode>) {
        let Some(request_id) = self.request_id.clone() else {
            return;
        };
        let _ = self
            .bus
            .emit(LifecycleEvent::UpstreamObserved(UpstreamObserved {
                request_id,
                status_code: status.map(|status| status.as_u16()),
                observed_at: Utc::now(),
            }));
    }

    /// Emits the finished point, at most once for this lifecycle.
    ///
    /// The elapsed time is measured from admission, so it covers the whole
    /// exchange including the streamed body rather than only the headers.
    pub fn complete(&mut self, status: Option<StatusCode>, error: Option<&'static str>) {
        let (Some(request_id), Some(transport)) = (self.request_id.take(), self.transport.take())
        else {
            return;
        };
        let outcome = error.and_then(failure_category);
        let elapsed = self.started.elapsed();
        let _ = self.bus.emit(LifecycleEvent::Finished(Finished {
            request_id,
            status_code: status.map(|status| status.as_u16()),
            transport_type: transport,
            outcome,
            elapsed,
            finished_at: Utc::now(),
        }));
        // The operational result is recorded here, at the same point and from
        // the same member that the terminal event carries, so a metric and a
        // request record cannot drift apart. An exchange with no upstream
        // response and no gateway-originated failure is a success: nothing went
        // wrong, and the status is not a label this process may read.
        let recorded = match outcome {
            Some(category) => {
                self.metrics.record_failure(category);
                ExchangeOutcome::failure(transport, category)
            }
            None => ExchangeOutcome::success(transport),
        };
        self.metrics.record_exchange(recorded, elapsed);
        self.active.take();
    }
}

fn failure_category(error: &str) -> Option<ProxyFailureCategory> {
    Some(match error {
        "invalid_gateway_credential" => ProxyFailureCategory::InvalidGatewayCredential,
        "provider_disabled" => ProxyFailureCategory::ProviderDisabled,
        "account_disabled" => ProxyFailureCategory::AccountDisabled,
        "key_expired" => ProxyFailureCategory::KeyExpired,
        "no_provider_selected" => ProxyFailureCategory::NoProviderSelected,
        "unsupported_route" => ProxyFailureCategory::UnsupportedRoute,
        "invalid_upgrade" => ProxyFailureCategory::InvalidUpgrade,
        "upstream_connect_failed" => ProxyFailureCategory::UpstreamConnectFailed,
        "upstream_timeout" | "idle_timeout" => ProxyFailureCategory::UpstreamTimeout,
        "connection_limit_reached" => ProxyFailureCategory::ConnectionLimitReached,
        "resource_exhausted" => ProxyFailureCategory::ResourceExhausted,
        "internal_error" => ProxyFailureCategory::InternalError,
        "stream_failed" => ProxyFailureCategory::StreamFailed,
        "downstream_cancelled" => ProxyFailureCategory::DownstreamCancelled,
        "message_too_large" => ProxyFailureCategory::MessageTooLarge,
        "relay_failed" => ProxyFailureCategory::RelayFailed,
        _ => return None,
    })
}

/// Response-body observer that completes an HTTP lifecycle on EOF, failure, or cancellation.
pub struct LoggedBody<B> {
    inner: Option<B>,
    lifecycle: RequestLogLifecycle,
    status: StatusCode,
    finished: bool,
}

impl<B> LoggedBody<B>
where
    B: Body,
{
    pub fn new(inner: B, lifecycle: RequestLogLifecycle, status: StatusCode) -> Self {
        let finished = inner.is_end_stream();
        let mut body = Self {
            inner: Some(inner),
            lifecycle,
            status,
            finished: false,
        };
        if finished {
            body.finish(None);
        }
        body
    }

    fn finish(&mut self, error: Option<&'static str>) {
        if !self.finished {
            self.finished = true;
            drop(self.inner.take());
            self.lifecycle.complete(Some(self.status), error);
        }
    }
}

impl<B> Body for LoggedBody<B>
where
    B: Body + Unpin,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(inner).poll_frame(context) {
            Poll::Ready(None) => {
                this.finish(None);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                this.finish(Some("stream_failed"));
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(Some(Ok(frame))) => {
                if this.inner.as_ref().is_some_and(Body::is_end_stream) {
                    this.finish(None);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.as_ref().map(Body::size_hint).unwrap_or_else(|| {
            let mut hint = SizeHint::new();
            hint.set_exact(0);
            hint
        })
    }
}

impl<B> Drop for LoggedBody<B> {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            drop(self.inner.take());
            self.lifecycle
                .complete(Some(self.status), Some("downstream_cancelled"));
        }
    }
}

pub fn observe_response<B>(
    response: Response<B>,
    lifecycle: RequestLogLifecycle,
) -> Response<LoggedBody<B>>
where
    B: Body,
{
    let status = response.status();
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, LoggedBody::new(body, lifecycle, status))
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
