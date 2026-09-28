//! Best-effort request lifecycle logging outside the proxy hot path.
//!
//! Proxy tasks only attempt a bounded channel send. A full or closed channel
//! drops the event and increments a counter; database work and retries remain
//! confined to the background worker. Events contain transport metadata only.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

#[derive(Debug, Default)]
struct Counters {
    queued: AtomicUsize,
    dropped: AtomicU64,
}

/// Cloneable, bounded, non-blocking event producer used by proxy tasks.
#[derive(Clone, Debug)]
pub struct LogSink {
    sender: mpsc::Sender<LogEvent>,
    counters: Arc<Counters>,
}

impl LogSink {
    /// Attempts to enqueue without waiting for capacity or database I/O.
    pub fn try_emit(&self, event: LogEvent) -> EmitResult {
        self.counters.queued.fetch_add(1, Ordering::AcqRel);
        match self.sender.try_send(event) {
            Ok(()) => EmitResult::Enqueued,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.counters.queued.fetch_sub(1, Ordering::AcqRel);
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                EmitResult::DroppedFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.counters.queued.fetch_sub(1, Ordering::AcqRel);
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                EmitResult::DroppedClosed
            }
        }
    }

    pub fn queued_events(&self) -> usize {
        self.counters.queued.load(Ordering::Acquire)
    }

    pub fn dropped_events(&self) -> u64 {
        self.counters.dropped.load(Ordering::Relaxed)
    }
}

/// Storage boundary used only by the background worker.
#[allow(async_fn_in_trait)]
pub trait LogStore: Send + Sync + 'static {
    async fn write_batch(&self, events: &[LogEvent]) -> Result<(), RepositoryError>;
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
    counters: Arc<Counters>,
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
            self.counters.queued.fetch_sub(discarded, Ordering::AcqRel);
            self.counters
                .dropped
                .fetch_add(discarded as u64, Ordering::Relaxed);
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
    assert!(capacity > 0, "log queue capacity must be positive");
    assert!(batch_size > 0, "log batch size must be positive");
    assert!(batch_size <= capacity, "log batch size must fit the queue");
    assert!(
        !batch_interval.is_zero(),
        "log batch interval must be positive"
    );
    let (sender, receiver) = mpsc::channel(capacity);
    let counters = Arc::new(Counters::default());
    (
        LogSink {
            sender,
            counters: Arc::clone(&counters),
        },
        LogWorker {
            receiver,
            store,
            counters,
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
                self.counters
                    .dropped
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
            }
            self.counters
                .queued
                .fetch_sub(batch.len(), Ordering::AcqRel);
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
        }
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
    }
}

/// Response-body observer that completes an HTTP lifecycle on EOF, failure, or cancellation.
pub struct LoggedBody<B> {
    inner: B,
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
            inner,
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
        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Ready(None) => {
                this.finish(None);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                this.finish(Some("stream_failed"));
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for LoggedBody<B> {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
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
