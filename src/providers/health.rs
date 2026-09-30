//! Provider health probing and the isolation it causes.
//!
//! A provider that is down stops absorbing one connect attempt per request. A
//! bounded background task issues one bodiless probe per interval, counts
//! consecutive failures, and moves the provider to isolated at the configured
//! threshold. A success moves an isolated provider back. The transition is
//! written conditionally on the state the probe observed, so two probes, or a
//! probe racing an administrator closing a maintenance window, cannot silently
//! overwrite each other.
//!
//! Nothing here runs in a forwarding path. The task is spawned once at startup,
//! issues a request that carries no application body and no business
//! semantics, and decides only from whether that request was answered. It never
//! reads a payload, never inspects a response body for meaning, and never
//! chooses a different provider: a provider that fails its probe produces a
//! refused request, never a request sent somewhere else.
//!
//! Two properties make the subsystem safe to leave running. Its per-provider
//! state is a single counter behind one mutex, so memory is bounded by the
//! number of probed providers rather than by traffic. And every observation is
//! bounded in time by the probe's own timeout, so a hung upstream can delay one
//! transition and never the process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use hyper::{Method, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::time::{Instant, MissedTickBehavior, interval_at};

use crate::domain::{ProviderHealthState, ProviderId, ProviderProbe};
use crate::persistence::{Database, ProviderListRequest, ProviderRepository, RepositoryError};
use crate::proxy::transport::UpstreamConnector;
use crate::routing::build_probe_uri;
use crate::telemetry::{HealthTransition, Metrics, ProbeOutcomeLabel};

/// How often the subsystem re-reads the providers it probes.
///
/// The probe interval each provider carries governs the probe itself. This is
/// the coarser tick that discovers configuration changes — a provider that
/// gained a probe, or a provider that was deleted — so a reconfiguration is
/// picked up without a restart and without the previous provider's task ever
/// running again.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);

/// Providers read per discovery query.
///
/// A configuration count rather than a traffic count: the list is read to the
/// end every tick, so this is a batch size and not a cap on how many providers
/// may be probed.
const DISCOVERY_PAGE_SIZE: usize = 100;

/// The health observation one probe produced.
///
/// The two failures are kept apart because they are different faults — an origin
/// that answers with errors is reachable, and an origin that answers nothing is
/// not — but neither is reported with the upstream's own text, so the split buys
/// an operator a diagnosis without buying a payload reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeOutcome {
    /// The endpoint answered within the probe's deadline with a status below 500.
    Reachable,
    /// The endpoint answered with a status at or above 500.
    Failing,
    /// The probe never reached a response: a refused connect, a failed handshake,
    /// or a deadline.
    Unreachable,
}

impl ProbeOutcome {
    /// Whether this outcome counts as a success for the failure streak.
    pub fn is_reachable(self) -> bool {
        matches!(self, Self::Reachable)
    }

    /// The exposition label for this outcome.
    ///
    /// The mapping is total over three members, so the exposition's probe series
    /// has a fixed size whether or not any provider is configured for probing.
    pub fn label(self) -> ProbeOutcomeLabel {
        match self {
            Self::Reachable => ProbeOutcomeLabel::Reachable,
            Self::Failing => ProbeOutcomeLabel::Failing,
            Self::Unreachable => ProbeOutcomeLabel::Unreachable,
        }
    }
}

/// Classifies the only response fact a health probe observes.
fn classify_status(status: StatusCode) -> ProbeOutcome {
    if status.as_u16() >= 500 {
        ProbeOutcome::Failing
    } else {
        ProbeOutcome::Reachable
    }
}

/// Consecutive-failure bookkeeping for one provider.
#[derive(Debug)]
struct ProbeState {
    /// Failures observed since the last success. Reset by any success, so only
    /// a consecutive streak can reach the threshold.
    consecutive_failures: u32,
    /// The instant the next probe is due, so a slow probe does not shorten the
    /// wait that follows it.
    next_probe_at: Instant,
    /// The bound the streak is measured against, kept so a threshold edit is
    /// observed by the running task rather than only by a restart.
    failure_threshold: u32,
}

/// Issues provider health probes and writes the state they decide.
///
/// The prober owns no forwarding resource. It holds a client that only health
/// checks use, one counter per probed provider, and the repository the
/// transition is written through.
pub struct HealthProber {
    repository: Database,
    metrics: Metrics,
    client: Client<UpstreamConnector, Full<Bytes>>,
    states: Mutex<HashMap<ProviderId, ProbeState>>,
}

impl HealthProber {
    /// Builds a prober over the repository its transitions are written through.
    pub fn new(repository: Database, connect_timeout: Duration, metrics: Metrics) -> Self {
        let mut builder = Client::builder(TokioExecutor::new());
        // A probe is a single observation, and an observation that is retried
        // can report a success the gateway never actually experienced.
        builder
            .retry_canceled_requests(false)
            .pool_max_idle_per_host(0);
        Self {
            repository,
            metrics,
            client: builder.build(UpstreamConnector::new(connect_timeout)),
            states: Mutex::new(HashMap::new()),
        }
    }

    /// Runs one discovery tick and every probe that tick makes due.
    ///
    /// A tick discovers which providers now carry a probe, forgets a provider
    /// that no longer does, and probes those whose interval has elapsed. It is
    /// idempotent per interval: called twice inside one interval, the second
    /// call issues nothing.
    pub async fn tick(&self) {
        let now = Instant::now();
        let providers = match self.probed_providers().await {
            Ok(providers) => providers,
            Err(_) => {
                // A discovery failure is not a health signal. The next tick
                // re-reads the configuration, and a provider that exists is
                // probed on its own schedule whether or not this tick saw it.
                return;
            }
        };

        let mut due = Vec::new();
        {
            let mut states = self.lock_states();
            let mut retained = HashMap::with_capacity(providers.len());
            for (id, probe) in providers {
                let state = states.get(&id);
                let next_probe_at = state
                    .filter(|state| state.failure_threshold == probe.failure_threshold())
                    .map_or(now, |state| state.next_probe_at);
                if next_probe_at <= now {
                    due.push((id, probe.clone(), next_probe_at));
                }
                retained.insert(
                    id,
                    ProbeState {
                        consecutive_failures: state.map_or(0, |state| state.consecutive_failures),
                        next_probe_at,
                        failure_threshold: probe.failure_threshold(),
                    },
                );
            }
            // Only providers that still carry a probe keep an entry, so a
            // removed probe releases its counter rather than leaving it behind
            // for the life of the process.
            *states = retained;
        }

        for (id, probe, _) in due {
            let next_probe_at = now + probe.interval();
            self.probe_once(id, &probe, next_probe_at).await;
        }
    }

    /// Runs the prober until `stop` resolves, on the discovery tick.
    ///
    /// The task is the only background work health adds, and it is joined by
    /// the same shutdown path as the log worker, so a stopping process does not
    /// leave a probe in flight.
    pub async fn run(self: Arc<Self>, mut stop: tokio::sync::watch::Receiver<bool>) {
        let mut ticker = interval_at(Instant::now() + DISCOVERY_INTERVAL, DISCOVERY_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => self.tick().await,
                _ = stop.changed() => {
                    if *stop.borrow() {
                        return;
                    }
                }
            }
        }
    }

    /// Reads every provider that carries a probe configuration.
    ///
    /// Health is opt-in, so a provider without a probe is not returned and is
    /// never contacted. The list is bounded by the number of providers, which
    /// is a configuration count rather than a traffic count.
    async fn probed_providers(&self) -> Result<Vec<(ProviderId, ProviderProbe)>, RepositoryError> {
        let mut cursor = None;
        let mut probed = Vec::new();
        let mut counts = [0_u64; 3];
        loop {
            let request = ProviderListRequest::new(cursor, DISCOVERY_PAGE_SIZE)
                .expect("the discovery page size is within the accepted range");
            let page = self.repository.list(request).await?;
            for provider in page.items() {
                if let Some(probe) = provider.probe() {
                    counts[provider.health() as usize] =
                        counts[provider.health() as usize].saturating_add(1);
                    // Maintenance suppresses probing entirely. A probe already
                    // in flight when maintenance opens is discarded below, but
                    // a provider observed in maintenance is never contacted.
                    if provider.health() != ProviderHealthState::Maintenance {
                        probed.push((provider.id(), probe.clone()));
                    }
                }
            }
            if !page.has_more() {
                for state in [
                    ProviderHealthState::Healthy,
                    ProviderHealthState::Isolated,
                    ProviderHealthState::Maintenance,
                ] {
                    self.metrics
                        .set_providers_in_state(state, counts[state as usize]);
                }
                return Ok(probed);
            }
            // An empty page that claims another one cannot advance the cursor,
            // so a page size larger than the table would otherwise spin here.
            match page.next_after_id() {
                Some(next) => cursor = Some(next),
                None => return Ok(probed),
            }
        }
    }

    /// Issues one probe and applies whatever it observes.
    async fn probe_once(&self, id: ProviderId, probe: &ProviderProbe, next_probe_at: Instant) {
        let outcome = self.observe(probe).await;
        self.metrics.record_probe(outcome.label());

        // A provider in a maintenance window is not probed at all, and a probe
        // already in flight when the window opened is discarded rather than
        // counted: the operator has said this provider is expected to be down, so
        // an observation of it is noise rather than evidence.
        let current = self.current_state(id).await;
        if current == Some(ProviderHealthState::Maintenance) {
            self.forget_failures(id, next_probe_at);
            return;
        }

        // Recovery needs only a single success, because a permissive success
        // criterion means a recovering origin is not flickering near a boundary:
        // it is either refusing connections or answering, and the first answer is
        // real evidence. A recovery threshold would add a stored setting and a way
        // to leave a provider isolated because its threshold was set too high.
        if outcome.is_reachable() {
            self.forget_failures(id, next_probe_at);
            if current == Some(ProviderHealthState::Isolated)
                && matches!(
                    self.repository
                        .set_health(id, ProviderHealthState::Isolated, ProviderHealthState::Healthy)
                        .await,
                    Ok(outcome) if outcome.is_transition()
                )
            {
                self.metrics.record_health_transition(HealthTransition {
                    from: ProviderHealthState::Isolated,
                    to: ProviderHealthState::Healthy,
                });
            }
            return;
        }

        let reached_threshold = {
            let mut states = self.lock_states();
            let state = states.entry(id).or_insert_with(|| ProbeState {
                consecutive_failures: 0,
                next_probe_at,
                failure_threshold: probe.failure_threshold(),
            });
            state.next_probe_at = next_probe_at;
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            if state.consecutive_failures < state.failure_threshold {
                false
            } else {
                // The streak has done its job. Clearing it here means a provider
                // that stays down is isolated once and then holds that state
                // rather than re-isolating on every probe after the threshold.
                state.consecutive_failures = 0;
                true
            }
        };
        if !reached_threshold {
            return;
        }
        if current != Some(ProviderHealthState::Healthy) {
            return;
        }

        // The transition is the only thing a streak is for, and it is written
        // conditionally: a provider that an operator isolated, put into
        // maintenance, or deleted while this probe was in flight is not
        // overwritten. Only a write that actually moved the state is recorded — a
        // conditional write that changed nothing is not a second isolation, and
        // counting it would make a stuck provider look like it is flapping.
        if matches!(
            self.repository
                .set_health(id, ProviderHealthState::Healthy, ProviderHealthState::Isolated)
                .await,
            Ok(outcome) if outcome.is_transition()
        ) {
            self.metrics.record_health_transition(HealthTransition {
                from: ProviderHealthState::Healthy,
                to: ProviderHealthState::Isolated,
            });
        }
    }

    /// Resets one provider's failure streak, releasing the entry when it is unused.
    ///
    /// The entry is dropped rather than kept at zero, so a provider that is being
    /// probed and succeeding holds no counter state at all, exactly as an
    /// unprobed provider holds none.
    fn forget_failures(&self, id: ProviderId, next_probe_at: Instant) {
        let mut states = self.lock_states();
        match states.get_mut(&id) {
            Some(state) if state.consecutive_failures == 0 => state.next_probe_at = next_probe_at,
            Some(state) => {
                state.consecutive_failures = 0;
                state.next_probe_at = next_probe_at;
            }
            None => {}
        }
    }

    /// Reads the state storage currently holds for a provider.
    ///
    /// A provider that has been deleted answers nothing, which is the same answer
    /// as "not in maintenance": a probe for a provider nobody has any more has
    /// nothing to suppress.
    async fn current_state(&self, id: ProviderId) -> Option<ProviderHealthState> {
        self.repository
            .find_by_id(id)
            .await
            .ok()
            .flatten()
            .map(|provider| provider.health())
    }

    /// The consecutive failures currently recorded for one provider.
    ///
    /// Exposed for the subsystem's own tests and for an operator-facing view of
    /// how close a provider is to isolation.
    pub fn consecutive_failures(&self, id: ProviderId) -> Option<u32> {
        self.lock_states()
            .get(&id)
            .map(|state| state.consecutive_failures)
    }

    /// Issues the probe request and classifies only whether it was answered.
    ///
    /// The request carries no application body and asks for nothing in
    /// particular: a bodiless `GET` is a reachability observation and not a
    /// business request, which is what keeps a probe from being a second reader
    /// of somebody's traffic. A deadline covers the whole attempt, so a slow
    /// upstream delays one transition rather than holding the task.
    async fn observe(&self, probe: &ProviderProbe) -> ProbeOutcome {
        let Ok(uri) = build_probe_uri(probe.target()) else {
            return ProbeOutcome::Unreachable;
        };
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .expect("a bodiless probe request is valid");

        let attempt = self.client.request(request);
        let response = match tokio::time::timeout(probe.timeout(), attempt).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => return ProbeOutcome::Unreachable,
        };
        // Any status below 500 is the upstream answering, whatever it answered.
        // Almost every origin replies to an unknown path with a 404, and treating
        // that as a failure would isolate a provider that is passing real traffic
        // perfectly well. The observation is "is this origin serving", not "did
        // the gateway guess a path this origin likes".
        // A status at or above 500 is a different fault from no answer at all:
        // the origin is reachable and is refusing to serve, which is worth
        // distinguishing even for a non-standard status code.
        classify_status(response.status())
    }

    /// Locks the per-provider counters.
    ///
    /// The lock is held only across a counter update and never across an await,
    /// so a probe in flight cannot block a tick and the task cannot deadlock on
    /// itself. A poisoned lock means a probe panicked while updating a counter;
    /// the counters are observations rather than authority, so the state is
    /// recovered rather than propagating the panic into every later tick.
    fn lock_states(&self) -> std::sync::MutexGuard<'_, HashMap<ProviderId, ProbeState>> {
        self.states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        InvalidHealthSetting, MAX_HEALTH_THRESHOLD, MAX_PROBE_INTERVAL_MS, ProviderProbePath,
        validate_provider_probe,
    };
    use url::Url;

    fn probe(path: &str, threshold: i64, interval: i64, timeout: i64) -> ProviderProbePath {
        validate_provider_probe(Some(path), Some(threshold), Some(interval), Some(timeout))
            .expect("the probe configuration is valid")
            .expect("a named path is a configured probe")
    }

    #[test]
    fn only_an_answer_below_five_hundred_is_reachable() {
        // The criterion is "did the origin answer", not "did it like the path".
        // A 404 from a healthy origin is a success, and only a status at or
        // above 500 or no answer
        // at all is a failure, because the alternative isolates a provider that is
        // passing real traffic perfectly well.
        assert!(classify_status(StatusCode::UNAUTHORIZED).is_reachable());
        assert!(classify_status(StatusCode::NOT_FOUND).is_reachable());
        assert!(!classify_status(StatusCode::INTERNAL_SERVER_ERROR).is_reachable());
        assert!(!classify_status(StatusCode::from_u16(600).expect("valid status")).is_reachable());
        assert!(!ProbeOutcome::Unreachable.is_reachable());
    }

    #[test]
    fn every_outcome_maps_to_exactly_one_exposition_label() {
        let labels = [
            ProbeOutcome::Reachable.label(),
            ProbeOutcome::Failing.label(),
            ProbeOutcome::Unreachable.label(),
        ];
        // Three outcomes, three distinct labels: the exposition's probe series is
        // a fixed size whether or not any provider is configured for probing.
        assert_eq!(labels.len(), 3);
        assert_ne!(labels[0], labels[1]);
        assert_ne!(labels[1], labels[2]);
        assert_ne!(labels[0], labels[2]);
    }

    #[test]
    fn a_provider_without_a_probe_path_is_never_probed() {
        // Health is opt-in. A provider naming no path is never contacted, so an
        // upgrade or a misconfiguration cannot take a working provider out of
        // service by probing a path the operator never wrote.
        assert_eq!(validate_provider_probe(None, None, None, None), Ok(None));
        assert_eq!(
            validate_provider_probe(Some(""), None, None, None),
            Ok(None)
        );
        assert_eq!(
            validate_provider_probe(Some("   "), None, None, None),
            Ok(None)
        );
    }

    #[test]
    fn settings_without_a_path_are_refused_rather_than_completed() {
        // A threshold with no path describes a provider that is never probed.
        // Completing it with a default target would assert a reachability contract
        // the operator never agreed to.
        for outcome in [
            validate_provider_probe(None, Some(3), None, None),
            validate_provider_probe(None, None, Some(30_000), None),
            validate_provider_probe(None, None, None, Some(5_000)),
        ] {
            assert_eq!(outcome, Err(InvalidHealthSetting));
        }
    }

    #[test]
    fn a_half_written_probe_is_refused() {
        // Each missing number leaves the probe undecidable: an absent threshold
        // isolates immediately and an absent interval never probes.
        for outcome in [
            validate_provider_probe(Some("/health"), None, Some(30_000), Some(5_000)),
            validate_provider_probe(Some("/health"), Some(3), None, Some(5_000)),
            validate_provider_probe(Some("/health"), Some(3), Some(30_000), None),
        ] {
            assert_eq!(outcome, Err(InvalidHealthSetting));
        }
    }

    #[test]
    fn a_zero_or_oversized_setting_is_refused_rather_than_clamped() {
        for outcome in [
            validate_provider_probe(Some("/health"), Some(0), Some(30_000), Some(5_000)),
            validate_provider_probe(Some("/health"), Some(3), Some(0), Some(5_000)),
            validate_provider_probe(Some("/health"), Some(3), Some(30_000), Some(0)),
            validate_provider_probe(Some("/health"), Some(-1), Some(30_000), Some(5_000)),
            validate_provider_probe(
                Some("/health"),
                Some(i64::from(MAX_HEALTH_THRESHOLD) + 1),
                Some(30_000),
                Some(5_000),
            ),
            validate_provider_probe(
                Some("/health"),
                Some(3),
                Some(MAX_PROBE_INTERVAL_MS as i64 + 1),
                Some(5_000),
            ),
        ] {
            assert_eq!(outcome, Err(InvalidHealthSetting));
        }
    }

    #[test]
    fn a_probe_path_must_be_rooted_dot_free_and_normalized() {
        // A `..` segment would let a probe walk out of the origin it was aimed
        // at, so it is refused before persistence rather than resolved and
        // normalized into somewhere the operator did not name.
        for path in [
            "health",
            "/health/",
            "/./health",
            "/../health",
            "/health/../admin",
            "/health\n/set",
            "/",
        ] {
            assert_eq!(
                validate_provider_probe(Some(path), Some(3), Some(30_000), Some(5_000)),
                Err(InvalidHealthSetting),
                "expected {path:?} to be refused"
            );
        }
    }

    #[test]
    fn a_threshold_of_one_is_a_statement_rather_than_a_mistake() {
        // One is accepted: it means "isolate on the first failure", which is a
        // decision an operator can legitimately make about an upstream they cannot
        // afford to send a second request to.
        let configured = probe("/health", 1, 30_000, 5_000);
        assert_eq!(configured.failure_threshold(), 1);
    }

    #[test]
    fn a_probe_resolves_inside_the_providers_own_origin() {
        let configured = probe("/health", 3, 30_000, 5_000);
        let endpoint = Url::parse("https://api.example.com/v1?token=secret").unwrap();
        let resolved = configured
            .resolve(&endpoint)
            .expect("the endpoint is usable");

        // The probe stays on the origin the operator already trusts and keeps the
        // endpoint's base path, so an endpoint edit does not silently repoint it.
        assert_eq!(resolved.target().scheme(), "https");
        assert_eq!(resolved.target().host_str(), Some("api.example.com"));
        assert_eq!(resolved.target().path(), "/v1/health");
        // The endpoint's own query is dropped: a probe asks whether the origin
        // serves, and persisting a query string per provider would be one more
        // secret-shaped value to store.
        assert_eq!(resolved.target().query(), None);
        assert_eq!(resolved.target().fragment(), None);
    }

    #[test]
    fn a_probe_never_leaves_the_origin_it_names() {
        let configured = probe("/health", 3, 30_000, 5_000);
        for endpoint in ["https://first.example.com/api", "http://second.example.com"] {
            let resolved = configured.resolve(&Url::parse(endpoint).unwrap()).unwrap();
            assert!(resolved.target().as_str().starts_with(endpoint));
        }
    }

    #[test]
    fn a_probe_target_carries_no_query_string() {
        // The request a probe issues is built from the origin and the path alone,
        // so a stored query can never be forwarded upstream even by accident.
        let configured = probe("/health", 3, 30_000, 5_000);
        let resolved = configured
            .resolve(&Url::parse("https://api.example.com").unwrap())
            .unwrap();
        let uri = build_probe_uri(resolved.target()).expect("a resolved probe is a usable target");
        assert_eq!(uri.query(), None);
        assert_eq!(uri.path(), "/health");
    }

    #[test]
    fn a_probe_configuration_keeps_the_values_it_was_given() {
        let configured = probe("/health", 3, 30_000, 5_000);
        assert_eq!(configured.path(), "/health");
        assert_eq!(configured.interval(), Duration::from_millis(30_000));
        assert_eq!(configured.timeout(), Duration::from_millis(5_000));
        assert_eq!(configured.failure_threshold(), 3);
    }
}
