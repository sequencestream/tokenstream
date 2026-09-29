//! Best-effort request lifecycle logging outside the proxy hot path.
//!
//! Proxy tasks only attempt a bounded channel send. A full or closed channel
//! drops the event and increments a counter; database work and retries remain
//! confined to the background worker. Events contain transport metadata only.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use chrono::Utc;
use hyper::body::{Body, Frame, SizeHint};
use hyper::{Response, StatusCode};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::domain::{ProviderSnapshot, RequestId};
use crate::persistence::{Database, RepositoryError, RequestLogCompleted, RequestLogStarted};
use crate::routing::ResolvedRoute;
use crate::telemetry::{ActiveRequestGuard, Metrics, ProxyFailureCategory};

const MAX_WRITE_ATTEMPTS: usize = 3;
const RETRY_DELAY: Duration = Duration::from_millis(10);
const WARNING_INTERVAL: Duration = Duration::from_secs(1);

/// One metadata-only lifecycle event.
#[derive(Clone, Debug)]
pub enum LogEvent {
    Started(RequestLogStarted),
    Completed(RequestLogCompleted),
}

/// Result of a non-blocking log emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmitResult {
    Enqueued,
    DroppedFull,
    DroppedClosed,
}

/// Cloneable, bounded, non-blocking event producer used by proxy tasks.
#[derive(Clone, Debug)]
pub struct LogSink {
    sender: mpsc::Sender<LogEvent>,
    metrics: Metrics,
}

impl LogSink {
    /// Attempts to enqueue without waiting for capacity or database I/O.
    pub fn try_emit(&self, event: LogEvent) -> EmitResult {
        self.metrics.enqueue_log_event();
        match self.sender.try_send(event) {
            Ok(()) => EmitResult::Enqueued,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.remove_log_events(1);
                self.metrics.drop_log_events(1);
                EmitResult::DroppedFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.metrics.remove_log_events(1);
                self.metrics.drop_log_events(1);
                EmitResult::DroppedClosed
            }
        }
    }

    pub fn queued_events(&self) -> usize {
        self.metrics.log_queue_depth()
    }

    pub fn dropped_events(&self) -> u64 {
        self.metrics.dropped_log_events()
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
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

/// Owns the receiver and performs size-or-time based batch flushing.
pub struct LogWorker<S> {
    receiver: mpsc::Receiver<LogEvent>,
    store: Arc<S>,
    metrics: Metrics,
    batch_size: usize,
    batch_interval: Duration,
}

impl<S> Drop for LogWorker<S> {
    fn drop(&mut self) {
        let mut discarded = 0;
        while self.receiver.try_recv().is_ok() {
            discarded += 1;
        }
        if discarded > 0 {
            self.metrics.remove_log_events(discarded);
            self.metrics.drop_log_events(discarded as u64);
        }
    }
}

/// Creates the proxy-side sink and its single background worker.
pub fn channel<S>(
    store: Arc<S>,
    capacity: usize,
    batch_size: usize,
    batch_interval: Duration,
) -> (LogSink, LogWorker<S>)
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
) -> (LogSink, LogWorker<S>)
where
    S: LogStore,
{
    assert!(capacity > 0, "log queue capacity must be positive");
    assert!(batch_size > 0, "log batch size must be positive");
    assert!(batch_size <= capacity, "log batch size must fit the queue");
    assert!(
        !batch_interval.is_zero(),
        "log batch interval must be positive"
    );
    let (sender, receiver) = mpsc::channel(capacity);
    (
        LogSink {
            sender,
            metrics: metrics.clone(),
        },
        LogWorker {
            receiver,
            store,
            metrics,
            batch_size,
            batch_interval,
        },
    )
}

impl<S> LogWorker<S>
where
    S: LogStore,
{
    /// Runs until every sender is dropped, then flushes the final partial batch.
    pub async fn run(mut self) {
        let mut batch = Vec::with_capacity(self.batch_size);
        let mut last_warning = None;
        while let Some(first) = self.receiver.recv().await {
            batch.push(first);
            let deadline = tokio::time::sleep(self.batch_interval);
            tokio::pin!(deadline);
            while batch.len() < self.batch_size {
                tokio::select! {
                    event = self.receiver.recv() => match event {
                        Some(event) => batch.push(event),
                        None => break,
                    },
                    () = &mut deadline => break,
                }
            }

            let persisted = self.write_with_retry(&batch, &mut last_warning).await;
            if !persisted {
                self.metrics.drop_log_events(batch.len() as u64);
            }
            self.metrics.remove_log_events(batch.len());
            batch.clear();
        }
    }

    async fn write_with_retry(
        &self,
        batch: &[LogEvent],
        last_warning: &mut Option<Instant>,
    ) -> bool {
        for attempt in 1..=MAX_WRITE_ATTEMPTS {
            match self.store.write_batch(batch).await {
                Ok(()) => return true,
                Err(_) if attempt < MAX_WRITE_ATTEMPTS => {
                    warn_rate_limited(last_warning);
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(_) => {
                    warn_rate_limited(last_warning);
                    return false;
                }
            }
        }
        false
    }
}

fn warn_rate_limited(last_warning: &mut Option<Instant>) {
    let now = Instant::now();
    if last_warning.is_none_or(|previous| now.duration_since(previous) >= WARNING_INTERVAL) {
        eprintln!("Tokenstream request-log batch write failed; retry is bounded");
        *last_warning = Some(now);
    }
}

/// One request/connection lifecycle whose completion is emitted at most once.
pub struct RequestLogLifecycle {
    sink: LogSink,
    request_id: Option<RequestId>,
    active: Option<ActiveRequestGuard>,
}

impl RequestLogLifecycle {
    pub fn start(
        sink: LogSink,
        request_id: RequestId,
        snapshot: &ProviderSnapshot,
        route: &ResolvedRoute,
    ) -> Self {
        let _ = sink.try_emit(LogEvent::Started(RequestLogStarted::new(
            request_id.clone(),
            snapshot.id(),
            snapshot.protocol_type(),
            route.transport(),
            route.path().to_owned(),
            Utc::now(),
        )));
        Self {
            sink,
            request_id: Some(request_id),
            active: None,
        }
    }

    pub fn observe_http(mut self) -> Self {
        self.active = Some(self.sink.metrics.start_http());
        self
    }

    pub fn observe_websocket(mut self) -> Self {
        self.active = Some(self.sink.metrics.start_websocket());
        self
    }

    pub fn complete(&mut self, status: Option<StatusCode>, error: Option<&'static str>) {
        let Some(request_id) = self.request_id.take() else {
            return;
        };
        let _ = self
            .sink
            .try_emit(LogEvent::Completed(RequestLogCompleted::new(
                request_id,
                status.map(|status| status.as_u16()),
                Utc::now(),
                error.map(str::to_owned),
            )));
        if let Some(category) = error.and_then(failure_category) {
            self.sink.metrics.record_failure(category);
        }
        self.active.take();
    }
}

fn failure_category(error: &str) -> Option<ProxyFailureCategory> {
    Some(match error {
        "invalid_gateway_credential" => ProxyFailureCategory::InvalidGatewayCredential,
        "provider_disabled" => ProxyFailureCategory::ProviderDisabled,
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
