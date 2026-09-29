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
    log_queue_depth: AtomicUsize,
    dropped_log_events: AtomicU64,
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
            log_queue_depth: AtomicUsize::new(0),
            dropped_log_events: AtomicU64::new(0),
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

    pub(crate) fn enqueue_log_event(&self) {
        self.inner.log_queue_depth.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn remove_log_events(&self, count: usize) {
        self.inner
            .log_queue_depth
            .fetch_sub(count, Ordering::AcqRel);
    }

    pub(crate) fn drop_log_events(&self, count: u64) {
        self.inner
            .dropped_log_events
            .fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn drop_all_queued_log_events(&self) {
        let queued = self.inner.log_queue_depth.swap(0, Ordering::AcqRel);
        self.drop_log_events(queued as u64);
    }

    pub fn active_http(&self) -> usize {
        self.inner.active_http.load(Ordering::Acquire)
    }

    pub fn active_websockets(&self) -> usize {
        self.inner.active_websockets.load(Ordering::Acquire)
    }

    pub fn log_queue_depth(&self) -> usize {
        self.inner.log_queue_depth.load(Ordering::Acquire)
    }

    pub fn dropped_log_events(&self) -> u64 {
        self.inner.dropped_log_events.load(Ordering::Relaxed)
    }

    pub fn failure_count(&self, category: ProxyFailureCategory) -> u64 {
        self.inner.failures[category.index()].load(Ordering::Relaxed)
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
        writeln!(output, "# TYPE tokenstream_log_queue_depth gauge").unwrap();
        writeln!(
            output,
            "tokenstream_log_queue_depth {}",
            self.log_queue_depth()
        )
        .unwrap();
        writeln!(
            output,
            "# TYPE tokenstream_log_events_dropped_total counter"
        )
        .unwrap();
        writeln!(
            output,
            "tokenstream_log_events_dropped_total {}",
            self.dropped_log_events()
        )
        .unwrap();
        output
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
