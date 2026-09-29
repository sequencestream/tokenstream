//! Bounded-cardinality operational metrics for the proxy lifecycle.
//!
//! Every label is selected from a closed enum. Request identifiers, provider
//! identifiers, paths, query strings, headers, and payload values can never be
//! attached to these metrics.

use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

const LATENCY_BUCKETS_SECONDS: [f64; 8] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0, 5.0];
const FAILURE_CATEGORY_COUNT: usize = 13;
const SUBSCRIBER_COUNT: usize = 1;

/// The closed set of event subscribers that can appear in the exposition.
///
/// Every name is compiled in rather than configured, so exposition cardinality
/// cannot grow with the number of subscribers a deployment happens to attach,
/// and a name is never derived from a request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SubscriberName {
    /// The subscriber that persists request-log rows.
    RequestLog,
}

impl SubscriberName {
    const ALL: [Self; SUBSCRIBER_COUNT] = [Self::RequestLog];

    fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestLog => "request_log",
        }
    }
}

impl std::fmt::Display for SubscriberName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyFailureCategory {
    InvalidGatewayCredential,
    ProviderDisabled,
    UnsupportedRoute,
    InvalidUpgrade,
    UpstreamConnectFailed,
    UpstreamTimeout,
    ConnectionLimitReached,
    ResourceExhausted,
    InternalError,
    StreamFailed,
    DownstreamCancelled,
    MessageTooLarge,
    RelayFailed,
}

impl ProxyFailureCategory {
    const ALL: [Self; FAILURE_CATEGORY_COUNT] = [
        Self::InvalidGatewayCredential,
        Self::ProviderDisabled,
        Self::UnsupportedRoute,
        Self::InvalidUpgrade,
        Self::UpstreamConnectFailed,
        Self::UpstreamTimeout,
        Self::ConnectionLimitReached,
        Self::ResourceExhausted,
        Self::InternalError,
        Self::StreamFailed,
        Self::DownstreamCancelled,
        Self::MessageTooLarge,
        Self::RelayFailed,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidGatewayCredential => "invalid_gateway_credential",
            Self::ProviderDisabled => "provider_disabled",
            Self::UnsupportedRoute => "unsupported_route",
            Self::InvalidUpgrade => "invalid_upgrade",
            Self::UpstreamConnectFailed => "upstream_connect_failed",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::ConnectionLimitReached => "connection_limit_reached",
            Self::ResourceExhausted => "resource_exhausted",
            Self::InternalError => "internal_error",
            Self::StreamFailed => "stream_failed",
            Self::DownstreamCancelled => "downstream_cancelled",
            Self::MessageTooLarge => "message_too_large",
            Self::RelayFailed => "relay_failed",
        }
    }
}

#[derive(Debug)]
struct Inner {
    active_http: AtomicUsize,
    active_websockets: AtomicUsize,
    latency_buckets: [AtomicU64; LATENCY_BUCKETS_SECONDS.len()],
    latency_count: AtomicU64,
    latency_micros: AtomicU64,
    failures: [AtomicU64; FAILURE_CATEGORY_COUNT],
    subscriber_queue_depth: [AtomicUsize; SUBSCRIBER_COUNT],
    subscriber_dropped: [AtomicU64; SUBSCRIBER_COUNT],
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            active_http: AtomicUsize::new(0),
            active_websockets: AtomicUsize::new(0),
            latency_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            latency_count: AtomicU64::new(0),
            latency_micros: AtomicU64::new(0),
            failures: std::array::from_fn(|_| AtomicU64::new(0)),
            subscriber_queue_depth: std::array::from_fn(|_| AtomicUsize::new(0)),
            subscriber_dropped: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Metrics {
    inner: Arc<Inner>,
}

impl Metrics {
    pub fn start_http(&self) -> ActiveRequestGuard {
        self.inner.active_http.fetch_add(1, Ordering::AcqRel);
        ActiveRequestGuard {
            metrics: self.clone(),
            transport: ActiveTransport::Http,
        }
    }

    pub fn start_websocket(&self) -> ActiveRequestGuard {
        self.inner.active_websockets.fetch_add(1, Ordering::AcqRel);
        ActiveRequestGuard {
            metrics: self.clone(),
            transport: ActiveTransport::WebSocket,
        }
    }

    pub fn observe_upstream_latency(&self, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        self.inner.latency_count.fetch_add(1, Ordering::Relaxed);
        self.inner
            .latency_micros
            .fetch_add(micros, Ordering::Relaxed);
        let seconds = elapsed.as_secs_f64();
        for (index, boundary) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
            if seconds <= *boundary {
                self.inner.latency_buckets[index].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_failure(&self, category: ProxyFailureCategory) {
        self.inner.failures[category.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn active_http(&self) -> usize {
        self.inner.active_http.load(Ordering::Acquire)
    }

    pub fn active_websockets(&self) -> usize {
        self.inner.active_websockets.load(Ordering::Acquire)
    }

    pub fn failure_count(&self, category: ProxyFailureCategory) -> u64 {
        self.inner.failures[category.index()].load(Ordering::Relaxed)
    }

    /// The per-subscriber queue depth and drop counters, by subscriber name.
    pub fn subscriber(&self, name: SubscriberName) -> SubscriberView {
        SubscriberView {
            queue_depth: self.inner.subscriber_queue_depth[name.index()].load(Ordering::Acquire),
            dropped_events: self.inner.subscriber_dropped[name.index()].load(Ordering::Relaxed),
        }
    }

    /// Renders a Prometheus text exposition containing only fixed metric names
    /// and fixed failure-category labels.
    pub fn render(&self) -> String {
        let mut output = String::new();
        writeln!(output, "# TYPE tokenstream_active_http_requests gauge").unwrap();
        writeln!(
            output,
            "tokenstream_active_http_requests {}",
            self.active_http()
        )
        .unwrap();
        writeln!(output, "# TYPE tokenstream_active_websockets gauge").unwrap();
        writeln!(
            output,
            "tokenstream_active_websockets {}",
            self.active_websockets()
        )
        .unwrap();
        writeln!(
            output,
            "# TYPE tokenstream_upstream_latency_seconds histogram"
        )
        .unwrap();
        for (index, boundary) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
            writeln!(
                output,
                "tokenstream_upstream_latency_seconds_bucket{{le=\"{boundary}\"}} {}",
                self.inner.latency_buckets[index].load(Ordering::Relaxed)
            )
            .unwrap();
        }
        let count = self.inner.latency_count.load(Ordering::Relaxed);
        writeln!(
            output,
            "tokenstream_upstream_latency_seconds_bucket{{le=\"+Inf\"}} {count}"
        )
        .unwrap();
        writeln!(output, "tokenstream_upstream_latency_seconds_count {count}").unwrap();
        let sum = self.inner.latency_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        writeln!(output, "tokenstream_upstream_latency_seconds_sum {sum}").unwrap();
        writeln!(output, "# TYPE tokenstream_proxy_failures_total counter").unwrap();
        for category in ProxyFailureCategory::ALL {
            writeln!(
                output,
                "tokenstream_proxy_failures_total{{category=\"{}\"}} {}",
                category.as_str(),
                self.failure_count(category)
            )
            .unwrap();
        }
        writeln!(
            output,
            "# TYPE tokenstream_event_subscriber_queue_depth gauge"
        )
        .unwrap();
        for name in SubscriberName::ALL {
            writeln!(
                output,
                "tokenstream_event_subscriber_queue_depth{{subscriber=\"{}\"}} {}",
                name.as_str(),
                self.subscriber(name).queue_depth
            )
            .unwrap();
        }
        writeln!(
            output,
            "# TYPE tokenstream_event_subscriber_events_dropped_total counter"
        )
        .unwrap();
        for name in SubscriberName::ALL {
            writeln!(
                output,
                "tokenstream_event_subscriber_events_dropped_total{{subscriber=\"{}\"}} {}",
                name.as_str(),
                self.subscriber(name).dropped_events
            )
            .unwrap();
        }
        output
    }
}

/// A read-only view of one subscriber's queue state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriberView {
    pub queue_depth: usize,
    pub dropped_events: u64,
}

/// One subscriber's own queue depth and drop counters.
///
/// The counters are per subscriber rather than global so a lagging consumer is
/// distinguishable from a healthy one: a process-wide drop count cannot say
/// which consumer fell behind.
#[derive(Clone, Debug)]
pub struct SubscriberCounters {
    metrics: Metrics,
    name: SubscriberName,
}

impl SubscriberCounters {
    pub fn new(metrics: Metrics, name: SubscriberName) -> Self {
        Self { metrics, name }
    }

    pub fn enqueue(&self) {
        self.metrics.inner.subscriber_queue_depth[self.name.index()].fetch_add(1, Ordering::AcqRel);
    }

    pub fn remove_queued(&self, count: usize) {
        self.metrics.inner.subscriber_queue_depth[self.name.index()]
            .fetch_sub(count, Ordering::AcqRel);
    }

    pub fn drop(&self, count: u64) {
        self.metrics.inner.subscriber_dropped[self.name.index()]
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn queued(&self) -> usize {
        self.metrics.subscriber(self.name).queue_depth
    }

    pub fn dropped(&self) -> u64 {
        self.metrics.subscriber(self.name).dropped_events
    }
}

#[derive(Debug)]
enum ActiveTransport {
    Http,
    WebSocket,
}

#[derive(Debug)]
pub struct ActiveRequestGuard {
    metrics: Metrics,
    transport: ActiveTransport,
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        let counter = match self.transport {
            ActiveTransport::Http => &self.metrics.inner.active_http,
            ActiveTransport::WebSocket => &self.metrics.inner.active_websockets,
        };
        counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_guards_cover_the_whole_transport_lifetime() {
        let metrics = Metrics::default();
        let http = metrics.start_http();
        let websocket = metrics.start_websocket();
        assert_eq!(metrics.active_http(), 1);
        assert_eq!(metrics.active_websockets(), 1);

        drop(http);
        assert_eq!(metrics.active_http(), 0);
        assert_eq!(metrics.active_websockets(), 1);
        drop(websocket);
        assert_eq!(metrics.active_websockets(), 0);
    }

    #[test]
    fn subscriber_counters_are_independent_of_the_process_wide_drop_count() {
        let metrics = Metrics::default();
        let request_log = SubscriberCounters::new(metrics.clone(), SubscriberName::RequestLog);
        request_log.enqueue();
        request_log.enqueue();
        request_log.remove_queued(1);
        request_log.drop(1);

        let rendered = metrics.render();
        assert!(
            rendered
                .contains("tokenstream_event_subscriber_queue_depth{subscriber=\"request_log\"} 1"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "tokenstream_event_subscriber_events_dropped_total{subscriber=\"request_log\"} 1"
            ),
            "{rendered}"
        );
        // The superseded process-wide pair is gone: a drop is only ever
        // reported against the subscriber that lost it.
        assert!(
            !rendered.contains("tokenstream_log_queue_depth"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("tokenstream_log_events_dropped_total"),
            "{rendered}"
        );
    }

    #[test]
    fn subscriber_names_are_a_closed_set() {
        let names: Vec<&str> = SubscriberName::ALL
            .iter()
            .map(|name| name.as_str())
            .collect();
        assert_eq!(names, ["request_log"]);
    }

    #[test]
    fn exposition_uses_only_closed_safe_labels() {
        let metrics = Metrics::default();
        metrics.observe_upstream_latency(Duration::from_millis(12));
        metrics.record_failure(ProxyFailureCategory::UpstreamTimeout);
        let rendered = metrics.render();

        assert!(rendered.contains("tokenstream_upstream_latency_seconds_count 1"));
        assert!(
            rendered.contains("tokenstream_proxy_failures_total{category=\"upstream_timeout\"} 1")
        );
        for forbidden in ["key-id", "?secret=", "authorization", "/v1/responses"] {
            assert!(!rendered.contains(forbidden));
        }
    }
}
