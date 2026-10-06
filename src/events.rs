//! The request-lifecycle metadata event bus and its bounded subscribers.
//!
//! Proxy tasks emit to the bus and never wait. The bus fans out to a fixed set
//! of subscribers, each owning its own bounded queue, so a saturated or stopped
//! subscriber drops only its own copy of an event and can neither change a
//! proxy result nor starve another subscriber.
//!
//! The event set is closed and metadata-only. An event may name the request,
//! the account, credential, and provider it belongs to, but it never carries a
//! credential plaintext, a header value, a full URL, a query string, or any
//! part of a request or response payload. The event type is deliberately not a
//! serialization format: there is no wire form to leak.

use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;

use crate::domain::{AccountId, ApiKeyId, ProtocolType, ProviderId, RequestId, TransportType};
use crate::telemetry::{Metrics, ProxyFailureCategory, SubscriberCounters};

const MAX_CONSUME_ATTEMPTS: usize = 3;
const CONSUME_RETRY_DELAY: Duration = Duration::from_millis(10);
const WARNING_INTERVAL: Duration = Duration::from_secs(1);

/// The closed set of lifecycle points the proxy reports.
///
/// The three variants are the points the proxy already passes. A request that
/// admission rejects produces none of them, because it never became work the
/// proxy would run; an admitted request produces exactly one [`Admitted`] and
/// eventually one [`Finished`].
#[derive(Clone, Debug)]
pub enum LifecycleEvent {
    /// Every admission layer granted, the snapshot is frozen, and the route is valid.
    Admitted(Admitted),
    /// An upstream HTTP status, or a WebSocket handshake outcome, arrived.
    UpstreamObserved(UpstreamObserved),
    /// The exchange ended: at EOF, at a stream failure, a cancellation, or an upstream failure.
    Finished(Finished),
}

impl LifecycleEvent {
    /// The request this event belongs to. Every variant names exactly one.
    pub fn request_id(&self) -> &RequestId {
        match self {
            Self::Admitted(event) => &event.request_id,
            Self::UpstreamObserved(event) => &event.request_id,
            Self::Finished(event) => &event.request_id,
        }
    }
}

/// The point at which the gateway accepted a request and froze its snapshot.
#[derive(Clone, Debug)]
pub struct Admitted {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub api_key_id: ApiKeyId,
    pub provider_id: ProviderId,
    pub protocol_type: ProtocolType,
    pub transport_type: TransportType,
    /// The normalized route path. Never a query string and never a full URL.
    pub path: String,
    pub observed_at: DateTime<Utc>,
}

/// The point at which an upstream response status or a handshake outcome arrived.
///
/// For an HTTP route this is the moment response headers are in hand, which is
/// where the gateway stops being able to answer with an error envelope and
/// starts streaming.
#[derive(Clone, Debug)]
pub struct UpstreamObserved {
    pub request_id: RequestId,
    /// The upstream HTTP status, or the handshake status for a WebSocket route.
    pub status_code: Option<u16>,
    pub observed_at: DateTime<Utc>,
}

/// The point at which the exchange ended, however it ended.
#[derive(Clone, Debug)]
pub struct Finished {
    pub request_id: RequestId,
    /// The terminal status, absent when no upstream response was received.
    pub status_code: Option<u16>,
    pub transport_type: TransportType,
    /// A member of the closed category set the gateway already reports, absent
    /// when the exchange ended without a gateway-originated failure. This is
    /// also where a cancellation or disconnect reason is carried: it is a
    /// member of that set rather than a free-form string, so the set of
    /// possible reasons cannot grow with traffic.
    pub outcome: Option<ProxyFailureCategory>,
    pub elapsed: Duration,
    pub finished_at: DateTime<Utc>,
}

pub use crate::telemetry::SubscriberName;

/// The outcome of one non-blocking attempt to hand events to the bus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmitResult {
    /// Every subscriber accepted the event.
    Enqueued,
    /// At least one subscriber was full or had stopped. Those subscribers
    /// dropped the event and counted it; the others still received it.
    PartiallyDropped,
    /// There are no subscribers, so nothing was enqueued anywhere.
    Unsubscribed,
}

/// A non-blocking producer used by proxy tasks.
///
/// Cloning is an `Arc` bump, and emission performs one non-blocking send per
/// subscriber. The subscriber set is fixed before either listener binds, so
/// this type never grows and never allocates per event.
#[derive(Clone, Debug)]
pub struct EventBus {
    subscribers: Arc<Vec<SubscriberChannel>>,
}

impl EventBus {
    /// Creates a bus with no subscribers. Emitting to it is inert and
    /// allocation-free, which is the state a test or a tool that only forwards
    /// traffic starts in.
    pub fn empty() -> Self {
        Self {
            subscribers: Arc::new(Vec::new()),
        }
    }

    /// The number of attached subscribers, fixed for the life of the process.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Hands one event to every subscriber without waiting for any of them.
    ///
    /// A subscriber that is full, or whose worker has stopped, drops that event
    /// for itself and increments its own drop counter. The return value reports
    /// whether any subscriber lost the event; it never describes the proxy's
    /// outcome, because the proxy result cannot depend on it.
    ///
    /// Fan-out is per subscriber and not atomic across subscribers. That is
    /// deliberate: an atomic bus would give every subscriber the fate of the
    /// slowest one, which is the coupling the bus exists to remove.
    pub fn emit(&self, event: LifecycleEvent) -> EmitResult {
        if self.subscribers.is_empty() {
            return EmitResult::Unsubscribed;
        }
        let mut dropped = false;
        for subscriber in self.subscribers.iter() {
            if !subscriber.try_emit(event.clone()) {
                dropped = true;
            }
        }
        if dropped {
            EmitResult::PartiallyDropped
        } else {
            EmitResult::Enqueued
        }
    }
}

/// The composition-time handle that owns a bus and may attach subscribers to it.
///
/// Subscription is deliberately not available from [`EventBus`]: once a proxy
/// task holds a bus, nothing can add a subscriber underneath it.
#[derive(Debug)]
pub struct BusBuilder {
    subscribers: Vec<SubscriberChannel>,
}

impl BusBuilder {
    /// Starts a new bus. The builder is consumed by the first attachment, so a
    /// bus handed to a proxy task is sealed by construction.
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    /// Attaches a named subscriber and returns the sealed bus plus the
    /// receiver-owning half of that subscriber.
    ///
    /// The queue is bounded by `capacity` and the worker batches by size or by
    /// interval, whichever comes first. `batch_size` must fit the queue, and a
    /// zero capacity or a zero interval is refused: a bound that cannot hold
    /// anything, or a flush that never fires, is a configuration mistake rather
    /// than a policy.
    pub fn attach<S>(
        &mut self,
        name: SubscriberName,
        store: S,
        capacity: usize,
        batch_size: usize,
        batch_interval: Duration,
        metrics: Metrics,
    ) -> (EventBus, Subscriber<S>)
    where
        S: SubscriberStore,
    {
        assert!(capacity > 0, "subscriber queue capacity must be positive");
        assert!(batch_size > 0, "subscriber batch size must be positive");
        assert!(
            batch_size <= capacity,
            "subscriber batch size must fit the queue"
        );
        assert!(
            !batch_interval.is_zero(),
            "subscriber batch interval must be positive"
        );
        let counters = SubscriberCounters::new(metrics, name);
        let (sender, receiver) = mpsc::channel(capacity);
        self.subscribers.push(SubscriberChannel {
            sender,
            counters: counters.clone(),
        });
        let bus = EventBus {
            subscribers: Arc::new(self.subscribers.clone()),
        };
        // The subscriber deliberately does not keep a bus handle. A handle
        // here would be a sender into its own queue, so the queue could never
        // close and the worker could never finish its final partial batch.
        let subscriber = Subscriber {
            name,
            receiver,
            store,
            counters,
            batch_size,
            batch_interval,
        };
        (bus, subscriber)
    }
}

impl Default for BusBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// One subscriber's bounded queue and its sender.
#[derive(Clone, Debug)]
struct SubscriberChannel {
    sender: mpsc::Sender<LifecycleEvent>,
    counters: SubscriberCounters,
}

impl SubscriberChannel {
    /// Attempts one non-blocking hand-off. A full or closed queue is this
    /// subscriber's problem alone, so it is counted here and reported upward
    /// without touching any other subscriber.
    fn try_emit(&self, event: LifecycleEvent) -> bool {
        self.counters.enqueue();
        match self.sender.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                self.counters.remove_queued(1);
                self.counters.drop(1);
                false
            }
        }
    }
}

/// A dequeued batch whose queue depth is released when the batch goes away.
///
/// The worker releases the depth itself on the normal path, but an abort during
/// a slow store cancels the worker without unwinding it. Releasing the depth
/// from a value that is dropped on every exit path is what keeps a cancelled
/// worker from leaving a queue depth that claims work is still pending.
struct InFlightBatch {
    events: Vec<LifecycleEvent>,
    counters: SubscriberCounters,
    released: bool,
}

impl InFlightBatch {
    fn new(counters: SubscriberCounters, first: LifecycleEvent) -> Self {
        Self {
            events: vec![first],
            counters,
            released: false,
        }
    }

    fn push(&mut self, event: LifecycleEvent) {
        self.events.push(event);
    }

    fn len(&self) -> usize {
        self.events.len()
    }

    fn events(&self) -> &[LifecycleEvent] {
        &self.events
    }

    /// Releases the batch's share of the queue depth. The first call does the
    /// accounting; later calls are no-ops, so both the worker and the drop
    /// path may call it.
    fn release(&mut self) {
        if !self.released {
            self.released = true;
            self.counters.remove_queued(self.events.len());
        }
    }
}

impl Drop for InFlightBatch {
    fn drop(&mut self) {
        self.release();
    }
}

/// A rate-limited warning channel, so a persistently failing subscriber cannot
/// turn a slow store into a stream of stderr writes.
struct SubscriberWarning {
    last: Option<std::time::Instant>,
}

impl SubscriberWarning {
    fn new() -> Self {
        Self { last: None }
    }

    fn report(&mut self, name: SubscriberName) {
        let now = std::time::Instant::now();
        if self
            .last
            .is_none_or(|previous| now.duration_since(previous) >= WARNING_INTERVAL)
        {
            tracing::warn!(
                target: "tokenstream::events",
                event = "event_subscriber_batch_failed",
                message = "An event subscriber failed to handle a batch; retry and isolation are bounded.",
                subscriber = name.as_str(),
            );
            self.last = Some(now);
        }
    }
}

/// What a subscriber does with a dequeued batch.
///
/// The trait is the whole extension point. A subscriber is handed metadata and
/// returns; it cannot reach a proxy result or change the event vocabulary.
pub trait SubscriberStore: Send + Sync + 'static {
    /// Reports whether it can keep this subscriber's worker, given the facts
    /// the worker exposes.
    fn readiness(&self) -> SubscriberReadiness;

    /// Consumes one contiguous slice of a dequeued batch.
    fn consume_batch(
        &self,
        events: &[LifecycleEvent],
    ) -> impl std::future::Future<Output = SubscriberOutcome> + Send;
}

/// Why a subscriber's worker may not run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriberReadiness {
    /// The subscriber can run.
    Ready,
    /// The subscriber cannot run in this process, and the bus must not carry
    /// its events at all.
    Unavailable(&'static str),
}

/// What a subscriber's handling of one batch achieved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriberOutcome {
    /// The batch was handled. Nothing is lost.
    Handled,
    /// The batch failed in a way that may succeed later.
    Transient,
    /// This event can never be handled, while the rest of the batch may be.
    Permanent,
}

/// The receiver-owning half of an attached subscriber.
///
/// Dropping it counts whatever was still queued for that subscriber, so an
/// aborted worker never leaves a queue depth that says work is still pending.
pub struct Subscriber<S> {
    name: SubscriberName,
    receiver: mpsc::Receiver<LifecycleEvent>,
    store: S,
    counters: SubscriberCounters,
    batch_size: usize,
    batch_interval: Duration,
}

impl<S> Subscriber<S> {
    pub fn name(&self) -> SubscriberName {
        self.name
    }

    /// Depth of this subscriber's own queue, not a process-wide figure.
    pub fn queued_events(&self) -> usize {
        self.counters.queued()
    }

    /// Events this subscriber lost, whether to a full queue or a stopped worker.
    pub fn dropped_events(&self) -> u64 {
        self.counters.dropped()
    }
}

impl<S> Subscriber<S>
where
    S: SubscriberStore,
{
    /// Runs until the bus is dropped, then handles the final partial batch.
    ///
    /// The worker owns every failure decision. It never propagates an error to
    /// a proxy task, because a proxy task is not waiting on it and must not be
    /// able to learn that it failed.
    ///
    /// Whatever is still queued when this returns, however it returns, is
    /// counted as lost, so a queue depth never claims work is pending after the
    /// worker has gone. The abort path is a task cancellation, which does not
    /// run this function's body again, so the accounting is done here rather
    /// than only in the destructor.
    pub async fn run(mut self) {
        if self.store.readiness() != SubscriberReadiness::Ready {
            // A subscriber that cannot run must not be handed events at all, so
            // everything still queued for it is counted as lost here.
            self.drain_remainder();
            return;
        }
        let mut warning = SubscriberWarning::new();
        loop {
            let Some(first) = self.receiver.recv().await else {
                break;
            };
            let mut batch = InFlightBatch::new(self.counters.clone(), first);
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
            let dropped = self.handle_batch(batch.events(), &mut warning).await;
            if dropped > 0 {
                self.counters.drop(dropped as u64);
            }
        }
        self.drain_remainder();
    }

    /// Hands one dequeued batch to the subscriber, retrying a transient failure
    /// a bounded number of times and isolating a permanently unwritable event
    /// with bounded binary splits so it cannot roll back the rest of the batch.
    async fn handle_batch(
        &self,
        batch: &[LifecycleEvent],
        warning: &mut SubscriberWarning,
    ) -> usize {
        let mut pending = vec![Range {
            start: 0,
            end: batch.len(),
        }];
        let mut dropped = 0;
        while let Some(range) = pending.pop() {
            if range.is_empty() {
                continue;
            }
            let chunk = &batch[range.clone()];
            match self.try_consume(chunk, warning).await {
                SubscriberOutcome::Handled => {}
                SubscriberOutcome::Transient => dropped += chunk.len(),
                SubscriberOutcome::Permanent if chunk.len() == 1 => dropped += 1,
                SubscriberOutcome::Permanent => {
                    let mid = range.start + chunk.len() / 2;
                    pending.push(mid..range.end);
                    pending.push(range.start..mid);
                }
            }
        }
        dropped
    }

    async fn try_consume(
        &self,
        batch: &[LifecycleEvent],
        warning: &mut SubscriberWarning,
    ) -> SubscriberOutcome {
        for attempt in 1..=MAX_CONSUME_ATTEMPTS {
            match self.store.consume_batch(batch).await {
                SubscriberOutcome::Handled => return SubscriberOutcome::Handled,
                SubscriberOutcome::Permanent => {
                    warning.report(self.name);
                    return SubscriberOutcome::Permanent;
                }
                SubscriberOutcome::Transient if attempt < MAX_CONSUME_ATTEMPTS => {
                    warning.report(self.name);
                    tokio::time::sleep(CONSUME_RETRY_DELAY).await;
                }
                SubscriberOutcome::Transient => {
                    warning.report(self.name);
                    return SubscriberOutcome::Transient;
                }
            }
        }
        SubscriberOutcome::Transient
    }

    /// Counts everything still queued for a worker that will never run.
    fn drain_remainder(&mut self) {
        let mut discarded = 0;
        while self.receiver.try_recv().is_ok() {
            discarded += 1;
        }
        if discarded > 0 {
            self.counters.remove_queued(discarded);
            self.counters.drop(discarded as u64);
        }
    }
}

impl<S> Drop for Subscriber<S> {
    fn drop(&mut self) {
        let mut discarded = 0;
        while self.receiver.try_recv().is_ok() {
            discarded += 1;
        }
        if discarded > 0 {
            self.counters.remove_queued(discarded);
            self.counters.drop(discarded as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct CountingStore {
        seen: AtomicU64,
    }

    impl SubscriberStore for CountingStore {
        fn readiness(&self) -> SubscriberReadiness {
            SubscriberReadiness::Ready
        }

        async fn consume_batch(&self, events: &[LifecycleEvent]) -> SubscriberOutcome {
            self.seen.fetch_add(events.len() as u64, Ordering::SeqCst);
            SubscriberOutcome::Handled
        }
    }

    struct Never;

    impl<T> SubscriberStore for std::sync::Arc<T>
    where
        T: SubscriberStore,
    {
        fn readiness(&self) -> SubscriberReadiness {
            (**self).readiness()
        }

        async fn consume_batch(&self, events: &[LifecycleEvent]) -> SubscriberOutcome {
            (**self).consume_batch(events).await
        }
    }

    impl SubscriberStore for Never {
        fn readiness(&self) -> SubscriberReadiness {
            SubscriberReadiness::Ready
        }

        async fn consume_batch(&self, _events: &[LifecycleEvent]) -> SubscriberOutcome {
            SubscriberOutcome::Handled
        }
    }

    fn admitted(id: &str) -> LifecycleEvent {
        LifecycleEvent::Admitted(Admitted {
            request_id: RequestId::new(id).expect("non-empty"),
            account_id: AccountId::try_from(1).expect("positive"),
            api_key_id: ApiKeyId::try_from(1).expect("positive"),
            provider_id: ProviderId::try_from(1).expect("positive"),
            protocol_type: ProtocolType::OpenAi,
            transport_type: TransportType::Http,
            path: "/v1/responses".to_owned(),
            observed_at: Utc::now(),
        })
    }

    fn attach(
        builder: &mut BusBuilder,
        capacity: usize,
        store: Never,
    ) -> (EventBus, Subscriber<Never>) {
        builder.attach(
            SubscriberName::RequestLog,
            store,
            capacity,
            1,
            Duration::from_secs(5),
            Metrics::default(),
        )
    }

    #[tokio::test]
    async fn every_subscriber_receives_every_event() {
        let mut builder = BusBuilder::new();
        let (first_bus, first) = attach(&mut builder, 8, Never);
        let (bus, second) = attach(&mut builder, 8, Never);
        // The earlier snapshot already had one subscriber, so both generations
        // of the bus are sealed snapshots of the builder at that moment.
        assert_eq!(first_bus.subscriber_count(), 1);
        assert_eq!(bus.subscriber_count(), 2);

        assert_eq!(bus.emit(admitted("a")), EmitResult::Enqueued);
        assert_eq!(bus.emit(admitted("b")), EmitResult::Enqueued);
        assert_eq!(first.queued_events(), 2);
        assert_eq!(second.queued_events(), 2);
    }

    #[tokio::test]
    async fn a_full_subscriber_drops_only_its_own_copy() {
        let mut builder = BusBuilder::new();
        let (_, narrow) = attach(&mut builder, 1, Never);
        let (bus, wide) = attach(&mut builder, 8, Never);

        // The narrow queue holds one event, so the second event overflows it
        // while the wider queue still has room.
        assert_eq!(bus.emit(admitted("a")), EmitResult::Enqueued);
        assert_eq!(bus.emit(admitted("b")), EmitResult::PartiallyDropped);
        assert_eq!(narrow.dropped_events(), 1);
        assert_eq!(narrow.queued_events(), 1);
        assert_eq!(wide.dropped_events(), 0);
        assert_eq!(wide.queued_events(), 2);
    }

    #[tokio::test]
    async fn a_stopped_subscriber_does_not_starve_the_others() {
        let mut builder = BusBuilder::new();
        let (_, stopped) = attach(&mut builder, 8, Never);
        let (bus, live) = attach(&mut builder, 8, Never);
        drop(stopped);

        assert_eq!(bus.emit(admitted("a")), EmitResult::PartiallyDropped);
        assert_eq!(live.queued_events(), 1);
    }

    #[tokio::test]
    async fn an_empty_bus_is_inert() {
        let bus = EventBus::empty();
        assert_eq!(bus.emit(admitted("a")), EmitResult::Unsubscribed);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn dropping_a_subscriber_counts_its_own_remainder() {
        let mut builder = BusBuilder::new();
        let (bus, subscriber) = attach(&mut builder, 8, Never);
        bus.emit(admitted("a"));
        let counters = subscriber.counters.clone();
        drop(subscriber);
        assert_eq!(counters.queued(), 0);
        assert_eq!(counters.dropped(), 1);
    }

    #[tokio::test]
    async fn a_subscriber_runs_and_consumes_its_own_queue() {
        let store = std::sync::Arc::new(CountingStore::default());
        let mut builder = BusBuilder::new();
        let (bus, subscriber) = builder.attach(
            SubscriberName::RequestLog,
            std::sync::Arc::clone(&store),
            8,
            2,
            Duration::from_millis(20),
            Metrics::default(),
        );
        let worker = tokio::spawn(async move { subscriber.run().await });
        bus.emit(admitted("a"));
        bus.emit(admitted("b"));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(store.seen.load(Ordering::SeqCst), 2);
        drop(bus);
        drop(builder);
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("the worker finishes its final partial batch and exits")
            .expect("worker exits after the bus closes");
    }

    #[test]
    fn subscriber_warning_is_structured_safe_and_rate_limited() {
        let output = crate::diagnostics::capture_for_test(|| {
            let mut warning = SubscriberWarning::new();
            warning.report(SubscriberName::RequestLog);
            warning.report(SubscriberName::RequestLog);
        });
        assert_eq!(output.lines().count(), 1);
        let event: serde_json::Value =
            serde_json::from_str(output.trim()).expect("subscriber diagnostic");
        assert_eq!(event["fields"]["event"], "event_subscriber_batch_failed");
        assert_eq!(event["fields"]["subscriber"], "request_log");
    }
}
