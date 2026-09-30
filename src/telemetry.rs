//! The bounded operational exposition for the proxy lifecycle.
//!
//! Every series is enumerated from a closed set compiled into the process, so
//! the size of the exposition is a property of this build rather than of a
//! deployment's traffic. Request identifiers, account identifiers, provider
//! identifiers, paths, query strings, headers, and payload values can never be
//! attached to these metrics, and no label is derived from a request.
//!
//! Series are labelled by at most two dimensions: the transport a request
//! resolved to, and a coarse result classification. The classification is a
//! total function over the fine failure-category set the gateway already
//! reports, so a metric and a request record can never disagree about how an
//! exchange ended, and nothing can fall through unclassified.
//!
//! Recording a fact is a relaxed atomic increment on a preallocated slot. It
//! takes no lock, allocates nothing, and never waits, so observability adds no
//! cost and no failure mode to the forwarding path. Rendering happens only on
//! the control plane.

use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crate::domain::{ProviderHealthState, TransportType};

const LATENCY_BUCKETS_SECONDS: [f64; 10] =
    [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];
const FAILURE_CATEGORY_COUNT: usize = 17;
const SUBSCRIBER_COUNT: usize = 1;
const TRANSPORT_COUNT: usize = 2;
const RESULT_COUNT: usize = 4;
const REJECTION_LAYER_COUNT: usize = 6;
const REJECTION_REASON_COUNT: usize = 2;
const HEALTH_STATE_COUNT: usize = 3;
const PROBE_OUTCOME_COUNT: usize = 3;

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

/// The closed set of layers that can refuse a request before it becomes work.
///
/// The layer is the fact an operator acts on: the same visible symptom of a
/// refused request has a different fix depending on which gate was full.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RejectionLayer {
    /// The process-wide connection gate.
    GlobalGate,
    /// A provider's bound on concurrent requests.
    ProviderConcurrency,
    /// A provider's request-rate allowance.
    ProviderRate,
    /// A credential's bound on concurrent requests.
    CredentialConcurrency,
    /// A credential's request-rate allowance.
    CredentialRate,
    /// A credential's bound on long-lived WebSocket connections.
    CredentialWebSockets,
}

impl RejectionLayer {
    const ALL: [Self; REJECTION_LAYER_COUNT] = [
        Self::GlobalGate,
        Self::ProviderConcurrency,
        Self::ProviderRate,
        Self::CredentialConcurrency,
        Self::CredentialRate,
        Self::CredentialWebSockets,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GlobalGate => "global_gate",
            Self::ProviderConcurrency => "provider_concurrency",
            Self::ProviderRate => "provider_rate",
            Self::CredentialConcurrency => "credential_concurrency",
            Self::CredentialRate => "credential_rate",
            Self::CredentialWebSockets => "credential_websockets",
        }
    }
}

/// Why a layer refused work.
///
/// A layer refuses either because it had no free concurrency slot or because
/// its rate allowance was exhausted. Both are refusals, so both are counted
/// here and reported as the same sanitized gateway errors the client already
/// receives.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RejectionReason {
    /// No free concurrency slot remained.
    Concurrency,
    /// The rate allowance for this interval was exhausted.
    Rate,
}

impl RejectionReason {
    const ALL: [Self; REJECTION_REASON_COUNT] = [Self::Concurrency, Self::Rate];

    const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Concurrency => "concurrency",
            Self::Rate => "rate",
        }
    }
}

/// The coarse result classification a completed exchange is counted under.
///
/// This is deliberately a smaller set than [`ProxyFailureCategory`]. The fine
/// set is right for one record describing one exchange, where exactness is
/// free; it is wrong for a series repeated across time, where the label has to
/// be read at a glance. The mapping between them is total, so a rate over a
/// coarse member is well defined and no failure is unclassified.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResultClass {
    /// The exchange completed and an upstream response was relayed.
    Success,
    /// The gateway refused or failed the exchange before an upstream response.
    GatewayFailure,
    /// The upstream connection, handshake, or stream failed or timed out.
    UpstreamFailure,
    /// The downstream client went away before the exchange ended.
    ClientCancellation,
}

impl ResultClass {
    const ALL: [Self; RESULT_COUNT] = [
        Self::Success,
        Self::GatewayFailure,
        Self::UpstreamFailure,
        Self::ClientCancellation,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::GatewayFailure => "gateway_failure",
            Self::UpstreamFailure => "upstream_failure",
            Self::ClientCancellation => "client_cancellation",
        }
    }
}

impl TransportType {
    const ALL: [Self; TRANSPORT_COUNT] = [Self::Http, Self::WebSocket];

    const fn index(self) -> usize {
        match self {
            Self::Http => 0,
            Self::WebSocket => 1,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::WebSocket => "websocket",
        }
    }
}

/// A transition the health state machine performed.
///
/// The pair is the whole label, and both members come from the closed state set,
/// so the transition series is a fixed shape no matter how many providers exist
/// or how often they move. A provider identifier is deliberately not a label: it
/// is unbounded over a process lifetime, and the fact an operator alerts on is
/// "a provider was isolated", not "provider 41 was isolated".
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HealthTransition {
    pub from: ProviderHealthState,
    pub to: ProviderHealthState,
}

impl HealthTransition {
    /// Every transition the state machine can perform, compiled in.
    ///
    /// Declaring all of them is what keeps the exposition's size a property of
    /// the build: a deployment that has never isolated anything still renders
    /// the same series, so a rate over one of them is always well defined.
    pub const ALL: [Self; HEALTH_TRANSITION_COUNT] = [
        Self {
            from: ProviderHealthState::Healthy,
            to: ProviderHealthState::Isolated,
        },
        Self {
            from: ProviderHealthState::Isolated,
            to: ProviderHealthState::Healthy,
        },
        Self {
            from: ProviderHealthState::Healthy,
            to: ProviderHealthState::Maintenance,
        },
        Self {
            from: ProviderHealthState::Maintenance,
            to: ProviderHealthState::Healthy,
        },
        Self {
            from: ProviderHealthState::Isolated,
            to: ProviderHealthState::Maintenance,
        },
        Self {
            from: ProviderHealthState::Maintenance,
            to: ProviderHealthState::Isolated,
        },
        Self {
            from: ProviderHealthState::Healthy,
            to: ProviderHealthState::Healthy,
        },
        Self {
            from: ProviderHealthState::Isolated,
            to: ProviderHealthState::Isolated,
        },
        Self {
            from: ProviderHealthState::Maintenance,
            to: ProviderHealthState::Maintenance,
        },
    ];

    fn index(self) -> usize {
        self.from as usize * HEALTH_STATE_COUNT + self.to as usize
    }

    /// The Prometheus label value for this transition.
    ///
    /// The two state names are joined into one label so the series is a single
    /// fixed name rather than a cross product the exposition has to enumerate.
    pub fn as_str(self) -> String {
        format!(
            "{}->{}",
            health_state_name(self.from),
            health_state_name(self.to)
        )
    }
}

/// The outcome of one provider health probe.
///
/// Three members, all decided by the probe's own transport result, and none of
/// them carrying the upstream's response text. Keeping the two failures apart is
/// what lets an operator tell "the origin is answering with errors" from "the
/// origin is not answering", which are different faults with different fixes, and
/// it costs no dimension because all three are counted rather than labelled per
/// provider.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProbeOutcomeLabel {
    /// The origin answered with a status below 500.
    Reachable,
    /// The origin answered with a status at or above 500.
    Failing,
    /// The probe never reached a response.
    Unreachable,
}

impl ProbeOutcomeLabel {
    const ALL: [Self; PROBE_OUTCOME_COUNT] = [Self::Reachable, Self::Failing, Self::Unreachable];

    const fn index(self) -> usize {
        self as usize
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Failing => "failing",
            Self::Unreachable => "unreachable",
        }
    }
}

/// The stored-independent name of a health state, used in the exposition.
const fn health_state_name(health: ProviderHealthState) -> &'static str {
    match health {
        ProviderHealthState::Healthy => "healthy",
        ProviderHealthState::Isolated => "isolated",
        ProviderHealthState::Maintenance => "maintenance",
    }
}

/// The number of slots the transition counters hold.
///
/// One slot per ordered pair of states, including the self-pairs the state
/// machine never performs. The spare slots cost three counters and buy a slot
/// index that is the pair itself, so `index` needs no table and a new state
/// cannot silently renumber the ones already recorded.
const HEALTH_TRANSITION_COUNT: usize = HEALTH_STATE_COUNT * HEALTH_STATE_COUNT;

/// The fine result category a request record and a gateway error use.
///
/// This set is closed, so the number of possible results cannot grow with
/// traffic, and a result can be compared with a metric or a sanitized error
/// without translation. It is also the source the coarse classification is
/// derived from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyFailureCategory {
    InvalidGatewayCredential,
    ProviderDisabled,
    ProviderUnhealthy,
    AccountDisabled,
    KeyExpired,
    NoProviderSelected,
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
        Self::ProviderUnhealthy,
        Self::AccountDisabled,
        Self::KeyExpired,
        Self::NoProviderSelected,
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
            Self::ProviderUnhealthy => "provider_unhealthy",
            Self::AccountDisabled => "account_disabled",
            Self::KeyExpired => "key_expired",
            Self::NoProviderSelected => "no_provider_selected",
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

    /// The coarse member this category is counted under in the exposition.
    ///
    /// The function is total over the closed set, so there is no failure that
    /// classifies as nothing, and it never returns a value derived from the
    /// request.
    pub const fn result_class(self) -> ResultClass {
        match self {
            // A client that left is not a gateway fault and not an upstream
            // fault; counting it as either would put a normal disconnect into
            // an error-rate alert.
            Self::DownstreamCancelled => ResultClass::ClientCancellation,
            Self::UpstreamConnectFailed
            | Self::UpstreamTimeout
            | Self::StreamFailed
            | Self::MessageTooLarge
            | Self::RelayFailed => ResultClass::UpstreamFailure,
            Self::InvalidGatewayCredential
            | Self::ProviderDisabled
            | Self::ProviderUnhealthy
            | Self::AccountDisabled
            | Self::KeyExpired
            | Self::NoProviderSelected
            | Self::UnsupportedRoute
            | Self::InvalidUpgrade
            | Self::ConnectionLimitReached
            | Self::ResourceExhausted
            | Self::InternalError => ResultClass::GatewayFailure,
        }
    }
}

/// One completed exchange: how it ended, and how long it took.
///
/// Recorded at the single point where an exchange's result is decided, which is
/// also the point that emits the terminal lifecycle event. Recording it here
/// and there together is what stops a metric and a request record from drifting
/// apart.
#[derive(Clone, Copy, Debug)]
pub struct ExchangeOutcome {
    transport: TransportType,
    result: ResultClass,
}

impl ExchangeOutcome {
    /// A successful exchange on the given transport.
    pub fn success(transport: TransportType) -> Self {
        Self {
            transport,
            result: ResultClass::Success,
        }
    }

    /// A failed exchange on the given transport, classified from the closed
    /// category set so the caller cannot invent a label.
    pub fn failure(transport: TransportType, category: ProxyFailureCategory) -> Self {
        Self {
            transport,
            result: category.result_class(),
        }
    }

    const fn series(self) -> usize {
        self.transport.index() * RESULT_COUNT + self.result.index()
    }
}

#[derive(Debug)]
struct Inner {
    active_http: AtomicUsize,
    active_websockets: AtomicUsize,
    exchanges: [AtomicU64; TRANSPORT_COUNT * RESULT_COUNT],
    latency_buckets: [[AtomicU64; LATENCY_BUCKETS_SECONDS.len()]; TRANSPORT_COUNT * RESULT_COUNT],
    latency_count: [AtomicU64; TRANSPORT_COUNT * RESULT_COUNT],
    latency_micros: [AtomicU64; TRANSPORT_COUNT * RESULT_COUNT],
    failures: [AtomicU64; FAILURE_CATEGORY_COUNT],
    rejections: [[AtomicU64; REJECTION_REASON_COUNT]; REJECTION_LAYER_COUNT],
    subscriber_queue_depth: [AtomicUsize; SUBSCRIBER_COUNT],
    subscriber_attempted: [AtomicU64; SUBSCRIBER_COUNT],
    subscriber_dropped: [AtomicU64; SUBSCRIBER_COUNT],
    health_transitions: [AtomicU64; HEALTH_TRANSITION_COUNT],
    probe_outcomes: [AtomicU64; PROBE_OUTCOME_COUNT],
    health_refusals: AtomicU64,
    providers_by_state: [AtomicU64; HEALTH_STATE_COUNT],
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            active_http: AtomicUsize::new(0),
            active_websockets: AtomicUsize::new(0),
            exchanges: std::array::from_fn(|_| AtomicU64::new(0)),
            latency_buckets: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            latency_count: std::array::from_fn(|_| AtomicU64::new(0)),
            latency_micros: std::array::from_fn(|_| AtomicU64::new(0)),
            failures: std::array::from_fn(|_| AtomicU64::new(0)),
            rejections: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            subscriber_queue_depth: std::array::from_fn(|_| AtomicUsize::new(0)),
            subscriber_attempted: std::array::from_fn(|_| AtomicU64::new(0)),
            subscriber_dropped: std::array::from_fn(|_| AtomicU64::new(0)),
            health_transitions: std::array::from_fn(|_| AtomicU64::new(0)),
            probe_outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            health_refusals: AtomicU64::new(0),
            providers_by_state: std::array::from_fn(|_| AtomicU64::new(0)),
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

    /// Records one completed exchange: its coarse result and the elapsed time
    /// from admission to the terminal point.
    ///
    /// The elapsed time is the whole exchange including a streamed body, which
    /// is the same interval a request record stores, so a percentile and a
    /// sampled log row describe the same thing.
    pub fn record_exchange(&self, outcome: ExchangeOutcome, elapsed: Duration) {
        let series = outcome.series();
        self.inner.exchanges[series].fetch_add(1, Ordering::Relaxed);
        let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        self.inner.latency_count[series].fetch_add(1, Ordering::Relaxed);
        self.inner.latency_micros[series].fetch_add(micros, Ordering::Relaxed);
        let seconds = elapsed.as_secs_f64();
        for (index, boundary) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
            if seconds <= *boundary {
                self.inner.latency_buckets[series][index].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Records one failure in the fine category set, which the terminal
    /// lifecycle point uses as its own result classification.
    pub fn record_failure(&self, category: ProxyFailureCategory) {
        self.inner.failures[category.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Records one request a gate refused before it became work.
    ///
    /// A refusal is not an exchange: it produces no result fact and no latency
    /// observation, so a shed request is never also counted as the failure of an
    /// exchange that never started.
    pub fn record_rejection(&self, layer: RejectionLayer, reason: RejectionReason) {
        self.inner.rejections[layer.index()][reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Records one health state transition.
    ///
    /// Recorded where the transition is decided, which is the same conditional
    /// write that changed storage, so a count and a stored state cannot drift.
    pub fn record_health_transition(&self, transition: HealthTransition) {
        self.inner.health_transitions[transition.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Records one probe outcome.
    ///
    /// Recorded by the probe itself, at the point its own response or failure was
    /// decided, because that is the only place the outcome exists. A probe is not
    /// a client request, so it produces no lifecycle event and no completed
    /// exchange: it is a control-plane observation, not work the proxy ran.
    pub fn record_probe(&self, outcome: ProbeOutcomeLabel) {
        self.inner.probe_outcomes[outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Probe outcomes of one kind since the process started.
    pub fn probe_outcome_count(&self, outcome: ProbeOutcomeLabel) -> u64 {
        self.inner.probe_outcomes[outcome.index()].load(Ordering::Relaxed)
    }

    /// Records a request refused because its provider was not serving.
    ///
    /// Counted as a refusal rather than as a completed exchange, because no
    /// exchange started: counting it as a failure would overstate the error rate
    /// of a gateway that is correctly protecting an upstream.
    pub fn record_health_refusal(&self) {
        self.inner.health_refusals.fetch_add(1, Ordering::Relaxed);
    }

    /// Requests refused because their provider was not serving.
    pub fn health_refusal_count(&self) -> u64 {
        self.inner.health_refusals.load(Ordering::Relaxed)
    }

    /// Replaces the count of providers in one health state.
    ///
    /// Set rather than incremented, because the count of providers in a state is a
    /// property of the current configuration and not a running total. The discovery
    /// tick writes all three, so the three always sum to the number of providers
    /// that carry a probe.
    pub fn set_providers_in_state(&self, state: ProviderHealthState, count: u64) {
        self.inner.providers_by_state[state as usize].store(count, Ordering::Relaxed);
    }

    /// The count of providers currently in one health state.
    pub fn provider_state_count(&self, state: ProviderHealthState) -> u64 {
        self.inner.providers_by_state[state as usize].load(Ordering::Relaxed)
    }

    /// Health transitions of one kind since the process started.
    pub fn health_transition_count(&self, transition: HealthTransition) -> u64 {
        self.inner.health_transitions[transition.index()].load(Ordering::Relaxed)
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

    /// Completed exchanges in one series.
    pub fn exchange_count(&self, transport: TransportType, result: ResultClass) -> u64 {
        self.inner.exchanges[transport.index() * RESULT_COUNT + result.index()]
            .load(Ordering::Relaxed)
    }

    /// Completed exchanges in one transport, summed over every result.
    pub fn exchange_count_for_transport(&self, transport: TransportType) -> u64 {
        ResultClass::ALL
            .iter()
            .map(|result| self.exchange_count(transport, *result))
            .sum()
    }

    /// Completed exchanges in one result, summed over every transport.
    pub fn exchange_count_for_result(&self, result: ResultClass) -> u64 {
        TransportType::ALL
            .iter()
            .map(|transport| self.exchange_count(*transport, result))
            .sum()
    }

    /// Requests one layer refused for one reason.
    pub fn rejection_count(&self, layer: RejectionLayer, reason: RejectionReason) -> u64 {
        self.inner.rejections[layer.index()][reason.index()].load(Ordering::Relaxed)
    }

    /// The per-subscriber queue depth, hand-off attempts, and drop counters, by
    /// subscriber name.
    pub fn subscriber(&self, name: SubscriberName) -> SubscriberView {
        SubscriberView {
            queue_depth: self.inner.subscriber_queue_depth[name.index()].load(Ordering::Acquire),
            attempted_events: self.inner.subscriber_attempted[name.index()].load(Ordering::Relaxed),
            dropped_events: self.inner.subscriber_dropped[name.index()].load(Ordering::Relaxed),
        }
    }

    /// Renders a Prometheus text exposition containing only fixed metric names
    /// and fixed label values.
    ///
    /// Every series is emitted, including those with no observation, so a
    /// scraper sees a stable set of names and a rate over a series that has not
    /// been used yet is a defined zero rather than a missing series.
    pub fn render(&self) -> String {
        let mut output = String::new();
        self.render_exchanges(&mut output);
        self.render_latency(&mut output);
        self.render_gauges(&mut output);
        self.render_failures(&mut output);
        self.render_rejections(&mut output);
        self.render_health(&mut output);
        self.render_subscribers(&mut output);
        output
    }

    fn render_exchanges(&self, output: &mut String) {
        writeln!(output, "# TYPE tokenstream_exchanges_total counter").unwrap();
        for transport in TransportType::ALL {
            for result in ResultClass::ALL {
                writeln!(
                    output,
                    "tokenstream_exchanges_total{{transport=\"{}\",result=\"{}\"}} {}",
                    transport.as_str(),
                    result.as_str(),
                    self.exchange_count(transport, result)
                )
                .unwrap();
            }
        }
        // Pass and fail are derived rather than separately recorded: two
        // counters for one fact can disagree, and a disagreement between a
        // total and its parts is indistinguishable from a bug in either.
        writeln!(output, "# TYPE tokenstream_exchanges_pass_total counter").unwrap();
        for transport in TransportType::ALL {
            writeln!(
                output,
                "tokenstream_exchanges_pass_total{{transport=\"{}\"}} {}",
                transport.as_str(),
                self.exchange_count(transport, ResultClass::Success)
            )
            .unwrap();
        }
        writeln!(output, "# TYPE tokenstream_exchanges_fail_total counter").unwrap();
        for transport in TransportType::ALL {
            // A client that hung up is neither a success nor a failure of the
            // gateway, so it is excluded here rather than folded into the error
            // total. Counting it as a failure would put ordinary disconnects
            // into an error-rate alert and make the alert untrustworthy, which
            // is worse than having one more series to read.
            let failed = [ResultClass::GatewayFailure, ResultClass::UpstreamFailure]
                .into_iter()
                .map(|result| self.exchange_count(transport, result))
                .sum::<u64>();
            writeln!(
                output,
                "tokenstream_exchanges_fail_total{{transport=\"{}\"}} {failed}",
                transport.as_str()
            )
            .unwrap();
        }
    }

    /// Renders the per-series latency histogram and the quantiles read from it.
    ///
    /// The quantile is a separate series from the histogram rather than an
    /// extra line of it, because a quantile summarizes the buckets and is not
    /// itself an observation. It is declared for every series whether or not
    /// that series has an observation, so the shape of the exposition is a
    /// property of the build and never of traffic. A quantile with no
    /// observation is reported as `NaN` rather than zero, because a zero
    /// latency percentile would be a factually wrong answer to a question that
    /// has no answer yet.
    fn render_latency(&self, output: &mut String) {
        writeln!(
            output,
            "# TYPE tokenstream_exchange_duration_seconds histogram"
        )
        .unwrap();
        for transport in TransportType::ALL {
            for result in ResultClass::ALL {
                let series = transport.index() * RESULT_COUNT + result.index();
                let label = format!(
                    "{{transport=\"{}\",result=\"{}\"}}",
                    transport.as_str(),
                    result.as_str()
                );
                for (index, boundary) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
                    writeln!(
                        output,
                        "tokenstream_exchange_duration_seconds_bucket{{transport=\"{}\",result=\"{}\",le=\"{boundary}\"}} {count}",
                        transport.as_str(),
                        result.as_str(),
                        count = self.inner.latency_buckets[series][index].load(Ordering::Relaxed),
                    )
                    .unwrap();
                }
                let count = self.inner.latency_count[series].load(Ordering::Relaxed);
                writeln!(
                    output,
                    "tokenstream_exchange_duration_seconds_bucket{{transport=\"{}\",result=\"{}\",le=\"+Inf\"}} {count}",
                    transport.as_str(),
                    result.as_str(),
                )
                .unwrap();
                writeln!(
                    output,
                    "tokenstream_exchange_duration_seconds_count{label} {count}"
                )
                .unwrap();
                let sum =
                    self.inner.latency_micros[series].load(Ordering::Relaxed) as f64 / 1_000_000.0;
                writeln!(
                    output,
                    "tokenstream_exchange_duration_seconds_sum{label} {sum}"
                )
                .unwrap();
            }
        }
        writeln!(
            output,
            "# TYPE tokenstream_exchange_duration_quantile_seconds summary"
        )
        .unwrap();
        for transport in TransportType::ALL {
            for result in ResultClass::ALL {
                let series = transport.index() * RESULT_COUNT + result.index();
                for quantile in QUANTILES {
                    let value = match self.quantile_boundary(series, quantile) {
                        Some(boundary) => boundary.to_string(),
                        None => "NaN".to_owned(),
                    };
                    writeln!(
                        output,
                        "tokenstream_exchange_duration_quantile_seconds{{transport=\"{}\",result=\"{}\",quantile=\"{quantile}\"}} {value}",
                        transport.as_str(),
                        result.as_str(),
                    )
                    .unwrap();
                }
            }
        }
    }

    /// The bucket boundary a quantile falls in, or `None` when the series has
    /// no observation at all.
    ///
    /// The buckets are cumulative, so the quantile is the first boundary whose
    /// count reaches the requested rank. The returned value is that boundary
    /// rather than an interpolation, because an interpolation between two
    /// compile-time boundaries would imply a precision the histogram does not
    /// have.
    fn quantile_boundary(&self, series: usize, quantile: f64) -> Option<f64> {
        let count = self.inner.latency_count[series].load(Ordering::Relaxed);
        if count == 0 {
            return None;
        }
        let rank = (count as f64 * quantile).ceil().max(1.0) as u64;
        for (index, boundary) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
            if self.inner.latency_buckets[series][index].load(Ordering::Relaxed) >= rank {
                return Some(*boundary);
            }
        }
        // The top bucket is unbounded, so this is only reachable when the
        // series changed between reading the count and reading the buckets.
        LATENCY_BUCKETS_SECONDS.last().copied()
    }

    fn render_gauges(&self, output: &mut String) {
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
    }

    fn render_failures(&self, output: &mut String) {
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
    }

    fn render_health(&self, output: &mut String) {
        writeln!(
            output,
            "# TYPE tokenstream_provider_health_transitions_total counter"
        )
        .unwrap();
        for transition in HealthTransition::ALL {
            writeln!(
                output,
                "tokenstream_provider_health_transitions_total{{transition=\"{}\"}} {}",
                transition.as_str(),
                self.health_transition_count(transition)
            )
            .unwrap();
        }
        writeln!(
            output,
            "# TYPE tokenstream_provider_health_probes_total counter"
        )
        .unwrap();
        for outcome in ProbeOutcomeLabel::ALL {
            writeln!(
                output,
                "tokenstream_provider_health_probes_total{{outcome=\"{}\"}} {}",
                outcome.as_str(),
                self.probe_outcome_count(outcome)
            )
            .unwrap();
        }
        writeln!(
            output,
            "# TYPE tokenstream_provider_health_refusals_total counter"
        )
        .unwrap();
        writeln!(
            output,
            "tokenstream_provider_health_refusals_total {}",
            self.health_refusal_count()
        )
        .unwrap();
        writeln!(output, "# TYPE tokenstream_providers_by_health_state gauge").unwrap();
        for state in [
            ProviderHealthState::Healthy,
            ProviderHealthState::Isolated,
            ProviderHealthState::Maintenance,
        ] {
            writeln!(
                output,
                "tokenstream_providers_by_health_state{{state=\"{}\"}} {}",
                health_state_name(state),
                self.provider_state_count(state)
            )
            .unwrap();
        }
    }

    fn render_rejections(&self, output: &mut String) {
        writeln!(
            output,
            "# TYPE tokenstream_admission_rejections_total counter"
        )
        .unwrap();
        for layer in RejectionLayer::ALL {
            for reason in RejectionReason::ALL {
                writeln!(
                    output,
                    "tokenstream_admission_rejections_total{{layer=\"{}\",reason=\"{}\"}} {}",
                    layer.as_str(),
                    reason.as_str(),
                    self.rejection_count(layer, reason)
                )
                .unwrap();
            }
        }
    }

    fn render_subscribers(&self, output: &mut String) {
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
        // The attempted count is exposed beside the drop count so a drop *rate*
        // is computable. An absolute drop number whose denominator is invisible
        // cannot be alerted on.
        writeln!(
            output,
            "# TYPE tokenstream_event_subscriber_events_total counter"
        )
        .unwrap();
        for name in SubscriberName::ALL {
            writeln!(
                output,
                "tokenstream_event_subscriber_events_total{{subscriber=\"{}\"}} {}",
                name.as_str(),
                self.subscriber(name).attempted_events
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
    }
}

/// The quantiles the exposition reports alongside each histogram.
///
/// The set is fixed, so an operator learns three numbers rather than a
/// configuration, and two processes always publish the same three.
const QUANTILES: [f64; 3] = [0.5, 0.9, 0.99];

/// A read-only view of one subscriber's queue state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriberView {
    pub queue_depth: usize,
    /// Non-blocking hand-offs the proxy attempted for this subscriber.
    pub attempted_events: u64,
    pub dropped_events: u64,
}

/// One subscriber's own queue depth and counters.
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
        self.metrics.inner.subscriber_attempted[self.name.index()].fetch_add(1, Ordering::Relaxed);
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

    pub fn attempted(&self) -> u64 {
        self.metrics.subscriber(self.name).attempted_events
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
    fn the_classification_is_total_and_every_member_is_reachable() {
        // Total: every failure in the closed set classifies, so a rate over a
        // coarse member can never be missing a failure that happened.
        let mut members = std::collections::BTreeSet::new();
        for category in ProxyFailureCategory::ALL {
            members.insert(category.result_class());
        }
        // And no failure member is dead weight: an alert on an unreachable
        // member would be an alert that can never fire. Success is the fourth
        // member and is reached by the absence of a failure, not by one.
        for result in ResultClass::ALL {
            if result != ResultClass::Success {
                assert!(members.contains(&result), "{result:?} is unreachable");
            }
        }
        assert_eq!(members.len(), ResultClass::ALL.len() - 1);
    }

    #[test]
    fn a_cancellation_is_neither_a_gateway_nor_an_upstream_failure() {
        // Counting a normal disconnect as an error would put ordinary client
        // behaviour into an error-rate alert.
        assert_eq!(
            ProxyFailureCategory::DownstreamCancelled.result_class(),
            ResultClass::ClientCancellation
        );
        assert_eq!(
            ProxyFailureCategory::UpstreamTimeout.result_class(),
            ResultClass::UpstreamFailure
        );
        assert_eq!(
            ProxyFailureCategory::InvalidGatewayCredential.result_class(),
            ResultClass::GatewayFailure
        );
    }

    #[test]
    fn every_series_is_present_before_anything_is_recorded() {
        let rendered = Metrics::default().render();
        for transport in TransportType::ALL {
            for result in ResultClass::ALL {
                let series = format!(
                    "tokenstream_exchanges_total{{transport=\"{}\",result=\"{}\"}} 0",
                    transport.as_str(),
                    result.as_str()
                );
                assert!(rendered.contains(&series), "missing {series} in {rendered}");
            }
        }
        for layer in RejectionLayer::ALL {
            for reason in RejectionReason::ALL {
                let series = format!(
                    "tokenstream_admission_rejections_total{{layer=\"{}\",reason=\"{}\"}} 0",
                    layer.as_str(),
                    reason.as_str()
                );
                assert!(rendered.contains(&series), "missing {series} in {rendered}");
            }
        }
    }

    #[test]
    fn a_cancellation_is_excluded_from_the_error_total() {
        // Ordinary client disconnects must not inflate an error rate, or the
        // alert built on that rate is untrustworthy.
        let metrics = Metrics::default();
        metrics.record_exchange(
            ExchangeOutcome::failure(
                TransportType::Http,
                ProxyFailureCategory::DownstreamCancelled,
            ),
            Duration::from_millis(3),
        );
        let rendered = metrics.render();
        assert!(
            rendered.contains("tokenstream_exchanges_fail_total{transport=\"http\"} 0"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "tokenstream_exchanges_total{transport=\"http\",result=\"client_cancellation\"} 1"
            ),
            "the cancellation is still counted, in its own series: {rendered}"
        );
    }

    #[test]
    fn a_refusal_is_counted_as_a_refusal_and_never_as_an_exchange() {
        let metrics = Metrics::default();
        metrics.record_rejection(RejectionLayer::CredentialRate, RejectionReason::Rate);
        assert_eq!(
            metrics.rejection_count(RejectionLayer::CredentialRate, RejectionReason::Rate),
            1
        );
        assert_eq!(
            metrics.exchange_count_for_transport(TransportType::Http),
            0,
            "a refused request never became an exchange"
        );
    }

    #[test]
    fn a_health_refusal_is_neither_an_exchange_nor_a_failure() {
        let metrics = Metrics::default();
        metrics.record_health_refusal();

        assert_eq!(metrics.health_refusal_count(), 1);
        assert_eq!(metrics.exchange_count_for_transport(TransportType::Http), 0);
        assert!(
            metrics
                .render()
                .contains("tokenstream_proxy_failures_total{category=\"provider_unhealthy\"} 0")
        );
    }

    #[test]
    fn refusals_at_different_layers_are_distinguishable() {
        let metrics = Metrics::default();
        metrics.record_rejection(RejectionLayer::GlobalGate, RejectionReason::Concurrency);
        metrics.record_rejection(
            RejectionLayer::ProviderConcurrency,
            RejectionReason::Concurrency,
        );
        metrics.record_rejection(RejectionLayer::ProviderRate, RejectionReason::Rate);
        let rendered = metrics.render();
        assert!(
            rendered.contains(
                "tokenstream_admission_rejections_total{layer=\"global_gate\",reason=\"concurrency\"} 1"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "tokenstream_admission_rejections_total{layer=\"provider_concurrency\",reason=\"concurrency\"} 1"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "tokenstream_admission_rejections_total{layer=\"provider_rate\",reason=\"rate\"} 1"
            ),
            "{rendered}"
        );
    }

    #[test]
    fn one_exchange_is_counted_once_under_its_transport_and_result() {
        let metrics = Metrics::default();
        metrics.record_exchange(
            ExchangeOutcome::success(TransportType::Http),
            Duration::from_millis(40),
        );
        assert_eq!(
            metrics.exchange_count(TransportType::Http, ResultClass::Success),
            1
        );
        assert_eq!(metrics.exchange_count_for_result(ResultClass::Success), 1);
        assert_eq!(
            metrics.exchange_count_for_transport(TransportType::WebSocket),
            0
        );
        assert!(
            metrics
                .render()
                .contains("tokenstream_exchanges_pass_total{transport=\"http\"} 1")
        );
    }

    #[test]
    fn a_quantile_is_read_from_the_cumulative_buckets_over_the_whole_exchange() {
        let metrics = Metrics::default();
        // Ten observations at 10ms and one at 4s: the median lands in the 25ms
        // bucket, the tail lands in the 5s bucket rather than being discarded.
        for _ in 0..10 {
            metrics.record_exchange(
                ExchangeOutcome::success(TransportType::Http),
                Duration::from_millis(10),
            );
        }
        metrics.record_exchange(
            ExchangeOutcome::success(TransportType::Http),
            Duration::from_secs(4),
        );
        let series = TransportType::Http.index() * RESULT_COUNT + ResultClass::Success.index();
        assert_eq!(
            metrics.quantile_boundary(series, 0.5),
            Some(LATENCY_BUCKETS_SECONDS[1]),
            "the median of eleven observations sits where the bulk of them sit"
        );
        assert_eq!(
            metrics.quantile_boundary(series, 0.99),
            Some(LATENCY_BUCKETS_SECONDS[9]),
            "a slow observation is never dropped for being slow"
        );
        assert!(metrics.render().contains(
            "tokenstream_exchange_duration_quantile_seconds{transport=\"http\",result=\"success\",quantile=\"0.5\"} 0.01"
        ));
    }

    #[test]
    fn a_quantile_over_an_empty_series_is_absent_rather_than_zero() {
        // A zero latency percentile would be a factually wrong answer to a
        // question that has no answer yet.
        let rendered = Metrics::default().render();
        assert!(
            rendered.contains(
                "tokenstream_exchange_duration_quantile_seconds{transport=\"http\",result=\"success\",quantile=\"0.5\"} NaN"
            ),
            "a declared series must still be present, reporting no observation: {rendered}"
        );
        assert!(!rendered.contains("quantile=\"0.5\"} 0\n"), "{rendered}");
    }

    #[test]
    fn subscriber_counters_are_independent_and_expose_their_denominator() {
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
                "tokenstream_event_subscriber_events_total{subscriber=\"request_log\"} 2"
            ),
            "the attempted count is the drop rate's denominator: {rendered}"
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
    fn the_exposition_size_is_a_property_of_the_build_and_not_of_traffic() {
        let metrics = Metrics::default();
        let names = |rendered: &str| -> std::collections::BTreeSet<String> {
            rendered
                .lines()
                .filter(|line| !line.starts_with('#'))
                .map(|line| {
                    let series = line.split_once('{').map_or(line, |(name, _)| name);
                    series
                        .rsplit_once(' ')
                        .map_or(series.to_owned(), |(name, _)| name.to_owned())
                })
                .collect()
        };
        let fresh = names(&metrics.render());
        for _ in 0..500 {
            metrics.record_exchange(
                ExchangeOutcome::failure(
                    TransportType::WebSocket,
                    ProxyFailureCategory::RelayFailed,
                ),
                Duration::from_millis(3),
            );
            metrics.record_rejection(RejectionLayer::GlobalGate, RejectionReason::Concurrency);
        }
        assert_eq!(
            names(&metrics.render()),
            fresh,
            "traffic changes values, never the set of series"
        );
    }

    #[test]
    fn exposition_uses_only_closed_safe_labels() {
        let metrics = Metrics::default();
        metrics.record_failure(ProxyFailureCategory::UpstreamTimeout);
        metrics.record_exchange(
            ExchangeOutcome::failure(TransportType::Http, ProxyFailureCategory::UpstreamTimeout),
            Duration::from_millis(12),
        );
        let rendered = metrics.render();

        assert!(rendered.contains("tokenstream_exchange_duration_seconds_count"));
        assert!(
            rendered.contains("tokenstream_proxy_failures_total{category=\"upstream_timeout\"} 1")
        );
        for forbidden in [
            "key-id",
            "provider=",
            "account=",
            "path=",
            "?secret=",
            "authorization",
            "/v1/responses",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "{forbidden} leaked: {rendered}"
            );
        }
    }
}
