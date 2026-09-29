//! Per-provider and per-credential admission layers.
//!
//! The global gate bounds the process as a whole. This module adds the layers
//! below it that bound one provider and one caller, so neither a noisy upstream
//! nor a single client can consume capacity that belongs to everyone else.
//!
//! Every layer here counts. It decides only from connection-level facts — which
//! provider a request resolved to, which credential it presented, which transport
//! it will use — and never reads a payload, never probes an upstream, and never
//! chooses a different one. Whether a request may *start* is an admission
//! question; where it should *go* is application-layer scheduling, which this
//! module deliberately does not answer.
//!
//! Acquisition never waits. A layer with no capacity rejects immediately and
//! releases everything already acquired at an outer layer, so overload sheds
//! load instead of growing an unbounded backlog. The limits themselves travel in
//! the request snapshot, so an edit applies to new work only and cannot reach a
//! stream or connection that is already admitted.
//!
//! A dimension that carries no bound holds no counter at all: an unbounded
//! entity is never entered in the registry. A gate whose holders have all
//! finished is dropped again, so counter state is bounded by the number of
//! limited entities rather than by traffic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::domain::{ApiKeyId, CredentialAdmission, ProviderAdmission, ProviderId};
use crate::proxy::error::GatewayError;

/// Why a layered admission layer refused work.
///
/// Both variants report through the existing sanitized gateway error contract, so
/// layered admission never teaches a client a new failure shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayerRejection {
    /// A concurrency layer had no free slot.
    Concurrency,
    /// A rate layer had no remaining allowance.
    Rate,
}

impl LayerRejection {
    /// The gateway error this refusal is reported as.
    ///
    /// A full concurrency bound is the same condition as a full connection
    /// limit, and an exhausted rate allowance is the same condition as exhausted
    /// capacity, so both reuse codes and statuses that already exist.
    pub fn error(self) -> GatewayError {
        match self {
            Self::Concurrency => GatewayError::ConnectionLimitReached,
            Self::Rate => GatewayError::ResourceExhausted,
        }
    }
}

/// A token bucket over a monotonic clock.
///
/// A burst of up to one interval's worth of work is admitted and a sustained rate
/// above the bound is not. Tokens refill continuously rather than on a timer, so
/// the bucket costs no background task and no allocation per refill: the count is
/// recomputed from the elapsed time whenever it is consulted.
#[derive(Debug)]
struct RateBucket {
    /// Allowance granted per second, and the capacity of one interval's burst.
    capacity: f64,
    /// Tokens currently available.
    tokens: f64,
    /// The instant `tokens` was last true.
    last_refill: Instant,
}

impl RateBucket {
    /// A bucket that starts full, so a fresh limit admits its first burst.
    fn new(per_second: u32) -> Self {
        let capacity = f64::from(per_second);
        Self {
            capacity,
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Takes one token if one is available, and never waits for one.
    ///
    /// A long idle period refills at most one interval's worth, so a bucket that
    /// was untouched for an hour cannot bank an hour of requests.
    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.capacity).min(self.capacity);
        self.last_refill = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// The counted layers of one entity.
///
/// A gate exists only when at least one dimension is bounded, so an unbounded
/// provider or credential is never entered in the registry at all.
#[derive(Debug)]
struct Gate {
    /// The bounds this gate was built for, so a later edit to the same entity
    /// is recognized as a different bound and rebuilds the gate.
    bounds: Bounds,
    /// Bounded concurrent work, when the dimension is limited.
    concurrency: Option<Arc<Semaphore>>,
    /// Bounded work rate, when the dimension is limited.
    rate: Option<Mutex<RateBucket>>,
    /// Bounded long-lived connections, when the dimension is limited.
    websockets: Option<Arc<Semaphore>>,
}

/// The complete set of bounds a gate counts.
///
/// A gate serves exactly one set of bounds. Comparing this is what lets a
/// limit edit reach work that starts after it without disturbing the slots a
/// request admitted before it is already holding: the holder keeps its permit,
/// and the next request gets a gate built from the new bounds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Bounds {
    concurrency: Option<u32>,
    rate: Option<u32>,
    websockets: Option<u32>,
}

impl Gate {
    /// Builds the gate for a bounded entity.
    fn new(
        max_concurrent_requests: Option<u32>,
        max_requests_per_second: Option<u32>,
        max_websockets: Option<u32>,
    ) -> Option<Self> {
        if max_concurrent_requests.is_none()
            && max_requests_per_second.is_none()
            && max_websockets.is_none()
        {
            return None;
        }
        Some(Self {
            bounds: Bounds {
                concurrency: max_concurrent_requests,
                rate: max_requests_per_second,
                websockets: max_websockets,
            },
            concurrency: max_concurrent_requests
                .map(|bound| Arc::new(Semaphore::new(bound as usize))),
            rate: max_requests_per_second.map(|bound| Mutex::new(RateBucket::new(bound))),
            websockets: max_websockets.map(|bound| Arc::new(Semaphore::new(bound as usize))),
        })
    }

    /// Whether this gate already counts the given bounds.
    fn matches(&self, bounds: Bounds) -> bool {
        self.bounds == bounds
    }

    fn concurrency(&self) -> Option<Arc<Semaphore>> {
        self.concurrency.clone()
    }

    fn websockets(&self) -> Option<Arc<Semaphore>> {
        self.websockets.clone()
    }

    fn rate(&self) -> Option<&Mutex<RateBucket>> {
        self.rate.as_ref()
    }
}

/// A bounded store of per-entity gates.
///
/// An entry is created on first use for a limited entity and dropped once it is
/// no longer limited and holds nothing, so the map is bounded by the number of
/// limited providers and credentials rather than by traffic.
#[derive(Debug)]
struct GateRegistry<K: Eq + std::hash::Hash> {
    gates: Mutex<HashMap<K, Arc<Gate>>>,
}

impl<K: Eq + std::hash::Hash> Default for GateRegistry<K> {
    fn default() -> Self {
        Self {
            gates: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Eq + std::hash::Hash + Copy> GateRegistry<K> {
    /// Returns the gate for `key`, building it from `bounds` on first use or
    /// whenever the bounds have changed since it was built.
    ///
    /// A request presents the bounds frozen in its snapshot, so a request
    /// admitted under the old bounds keeps the gate it is already using: the
    /// registry only replaces its own reference, and a holder keeps its permit
    /// through the gate it holds. Work that starts afterwards sees the new
    /// bounds.
    ///
    /// The rebuild happens while the registry is locked, so two concurrent
    /// first requests for the same entity and bounds cannot create two gates and
    /// each end up seeing half the traffic.
    fn gate(&self, key: K, bounds: Bounds) -> Option<Arc<Gate>> {
        if bounds == Bounds::default() {
            // An entity that carries no bound needs no counter state at all,
            // and any state it left behind is released now.
            self.forget(key);
            return None;
        }
        let mut gates = self.gates.lock().expect("gate registry lock");
        if let Some(gate) = gates.get(&key)
            && gate.matches(bounds)
        {
            return Some(Arc::clone(gate));
        }
        let gate = Arc::new(Gate::new(
            bounds.concurrency,
            bounds.rate,
            bounds.websockets,
        )?);
        gates.insert(key, Arc::clone(&gate));
        Some(gate)
    }

    /// The number of entities currently holding counter state, for a caller
    /// that observes whether that state stays bounded.
    fn len(&self) -> usize {
        self.gates.lock().expect("gate registry lock").len()
    }

    fn forget(&self, key: K) {
        self.gates.lock().expect("gate registry lock").remove(&key);
    }
}

/// The layered admission registry for one process.
///
/// Every clone shares one registry, so a limit applies to the whole process
/// rather than to one listener or one connection task. It holds only opaque
/// provider and credential identifiers and the counters derived from them: no
/// credential, no secret, no request value, and no path. It is never exposed on
/// the control plane or in metrics.
#[derive(Clone, Debug, Default)]
pub struct LayeredAdmission {
    providers: Arc<GateRegistry<ProviderId>>,
    credentials: Arc<GateRegistry<ApiKeyId>>,
}

impl LayeredAdmission {
    /// An empty registry, in which every layer is unbounded.
    pub fn new() -> Self {
        Self::default()
    }

    /// The layers that apply to the provider a request resolved to.
    pub fn provider_layers(
        &self,
        provider_id: ProviderId,
        admission: ProviderAdmission,
    ) -> ProviderLayers {
        ProviderLayers {
            gate: self.providers.gate(
                provider_id,
                Bounds {
                    concurrency: admission.max_concurrent_requests().get(),
                    rate: admission.max_requests_per_second().get(),
                    websockets: None,
                },
            ),
        }
    }

    /// How many providers and credentials currently hold counter state.
    ///
    /// The count is what keeps the registry bounded: an entity with no bound is
    /// never entered, and an entity whose bound is lifted is dropped again, so
    /// this never grows with traffic.
    pub fn tracked_entities(&self) -> usize {
        self.providers.len() + self.credentials.len()
    }

    /// The layers that apply to the credential that presented the request.
    pub fn credential_layers(
        &self,
        api_key_id: ApiKeyId,
        admission: CredentialAdmission,
    ) -> CredentialLayers<'_> {
        CredentialLayers {
            registry: &self.credentials,
            key: api_key_id,
            gate: self.credentials.gate(
                api_key_id,
                Bounds {
                    concurrency: admission.max_concurrent_requests().get(),
                    rate: admission.max_requests_per_second().get(),
                    websockets: admission.max_websockets().get(),
                },
            ),
        }
    }
}

/// The layers that apply to one provider.
#[derive(Debug)]
pub struct ProviderLayers {
    gate: Option<Arc<Gate>>,
}

impl ProviderLayers {
    /// Takes a provider concurrency slot, or refuses immediately.
    pub fn acquire_concurrency(&self) -> Result<Option<LayerPermit>, LayerRejection> {
        let Some(slots) = self.gate.as_ref().and_then(|gate| gate.concurrency()) else {
            return Ok(None);
        };
        match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => Ok(Some(LayerPermit { _permit: permit })),
            Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
                Err(LayerRejection::Concurrency)
            }
        }
    }

    /// Consumes one unit of the provider's rate allowance, or refuses
    /// immediately.
    pub fn acquire_rate(&self) -> Result<(), LayerRejection> {
        let Some(bucket) = self.gate.as_ref().and_then(|gate| gate.rate()) else {
            return Ok(());
        };
        if bucket
            .lock()
            .expect("rate bucket lock")
            .take(Instant::now())
        {
            Ok(())
        } else {
            Err(LayerRejection::Rate)
        }
    }
}

/// The layers that apply to one credential.
#[derive(Debug)]
pub struct CredentialLayers<'a> {
    registry: &'a GateRegistry<ApiKeyId>,
    key: ApiKeyId,
    gate: Option<Arc<Gate>>,
}

impl CredentialLayers<'_> {
    /// Takes a credential concurrency slot, or refuses immediately.
    pub fn acquire_concurrency(&self) -> Result<Option<LayerPermit>, LayerRejection> {
        let Some(slots) = self.gate.as_ref().and_then(|gate| gate.concurrency()) else {
            return Ok(None);
        };
        match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => Ok(Some(LayerPermit { _permit: permit })),
            Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
                Err(LayerRejection::Concurrency)
            }
        }
    }

    /// Consumes one unit of the credential's rate allowance, or refuses
    /// immediately.
    pub fn acquire_rate(&self) -> Result<(), LayerRejection> {
        let Some(bucket) = self.gate.as_ref().and_then(|gate| gate.rate()) else {
            return Ok(());
        };
        if bucket
            .lock()
            .expect("rate bucket lock")
            .take(Instant::now())
        {
            Ok(())
        } else {
            Err(LayerRejection::Rate)
        }
    }

    /// Takes one of the credential's long-lived WebSocket connection slots, or
    /// refuses immediately.
    ///
    /// The slot is held for the connection's whole lifetime, so a client cannot
    /// exceed its bound by opening sockets faster than they close.
    pub fn acquire_websocket(&self) -> Result<Option<LayerPermit>, LayerRejection> {
        let Some(slots) = self.gate.as_ref().and_then(|gate| gate.websockets()) else {
            return Ok(None);
        };
        match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => Ok(Some(LayerPermit { _permit: permit })),
            Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
                Err(LayerRejection::Concurrency)
            }
        }
    }

    /// Releases the registry entry when this credential carries no bound at
    /// all, so a lifted limit hands back its counter state immediately.
    ///
    /// A rejection at a later layer calls this so a request that was refused
    /// does not leave an entry behind for a credential whose only bound is the
    /// one it just failed to take.
    pub fn finish(&self) {
        if self.gate.is_none() {
            self.registry.forget(self.key);
        }
    }
}

/// A held slot in a layered concurrency dimension.
///
/// The slot is released exactly when the permit is dropped, so a finished,
/// cancelled, or panicking exchange cannot leak capacity in the layer that is
/// supposed to be the bound.
#[derive(Debug)]
#[must_use = "the layer slot is released as soon as the permit is dropped"]
pub struct LayerPermit {
    /// Held only so the slot is returned to its layer when this value is
    /// dropped. Nothing reads it, and nothing may.
    _permit: OwnedSemaphorePermit,
}

/// Every slot one admitted request holds across its layers.
///
/// The value is held for the whole HTTP/SSE exchange or the whole WebSocket
/// connection, and releases everything it holds when it is dropped, so a request
/// that fails at a later layer, returns an error, or is cancelled gives back
/// exactly what it took.
#[derive(Debug, Default)]
#[must_use = "layer slots are released as soon as this value is dropped"]
pub struct LayeredSlots {
    // Held only so every slot is returned to its layer when this value is
    // dropped. Nothing reads these, and nothing may.
    #[allow(dead_code)]
    provider_concurrency: Option<LayerPermit>,
    #[allow(dead_code)]
    credential_concurrency: Option<LayerPermit>,
    #[allow(dead_code)]
    credential_websockets: Option<LayerPermit>,
}

impl LayeredSlots {
    /// Records every slot the layers handed out, in acquisition order.
    pub fn new(
        provider_concurrency: Option<LayerPermit>,
        credential_concurrency: Option<LayerPermit>,
        credential_websockets: Option<LayerPermit>,
    ) -> Self {
        Self {
            provider_concurrency,
            credential_concurrency,
            credential_websockets,
        }
    }
}
