//! Global admission control and the explicit resource bounds of the data plane.
//!
//! Every resource the proxy can accumulate is bounded before traffic is served:
//! the number of concurrently admitted proxy requests, the in-memory HTTP body
//! buffer, and the WebSocket frame, message, and outbound-queue limits. The
//! bounds travel together in one [`ProxyLimits`] value so a pipeline cannot be
//! assembled without deciding each limit, and they are derived from the startup
//! configuration that was validated before either plane bound its socket.
//!
//! Admission itself is a single global semaphore. Acquisition is
//! non-blocking: a request that arrives while every slot is taken is rejected
//! immediately as [`GatewayError::ConnectionLimitReached`] instead of being
//! queued, so overload sheds load rather than growing an unbounded backlog. The
//! returned [`AdmissionPermit`] releases its slot when it is dropped, so every
//! exit path — completion, cancellation, or panic — returns its capacity.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::config::Config;
use crate::proxy::error::GatewayError;

/// A resource bound that cannot be used as a limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundsError {
    /// A bound was zero, which would forbid all traffic for that resource.
    ZeroBound,
    /// The per-frame WebSocket bound exceeded the per-message bound.
    FrameExceedsMessage,
}

impl fmt::Display for BoundsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroBound => "every resource bound must be greater than zero",
            Self::FrameExceedsMessage => {
                "the WebSocket frame bound must not exceed the message bound"
            }
        };
        formatter.write_str(message)
    }
}

impl Error for BoundsError {}

/// The configured upper bound for every resource the data plane accumulates.
///
/// The value is copyable and immutable, so a request pipeline holds the bounds
/// it was built with without any risk of a later change widening them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyLimits {
    max_connections: usize,
    http_buffer_bytes: usize,
    websocket_max_frame_bytes: usize,
    websocket_max_message_bytes: usize,
    websocket_queue_capacity: usize,
}

impl ProxyLimits {
    /// Validates and bundles the resource bounds.
    pub fn new(
        max_connections: usize,
        http_buffer_bytes: usize,
        websocket_max_frame_bytes: usize,
        websocket_max_message_bytes: usize,
        websocket_queue_capacity: usize,
    ) -> Result<Self, BoundsError> {
        let limits = Self {
            max_connections,
            http_buffer_bytes,
            websocket_max_frame_bytes,
            websocket_max_message_bytes,
            websocket_queue_capacity,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Copies the bounds from the already-validated startup configuration.
    pub fn from_config(config: &Config) -> Self {
        Self::new(
            config.max_proxy_connections(),
            config.http_buffer_bytes(),
            config.websocket_max_frame_bytes(),
            config.websocket_max_message_bytes(),
            config.websocket_queue_capacity(),
        )
        .expect("startup configuration bounds are validated before serving")
    }

    fn validate(&self) -> Result<(), BoundsError> {
        let bounds = [
            self.max_connections,
            self.http_buffer_bytes,
            self.websocket_max_frame_bytes,
            self.websocket_max_message_bytes,
            self.websocket_queue_capacity,
        ];
        if bounds.contains(&0) {
            return Err(BoundsError::ZeroBound);
        }
        if self.websocket_max_frame_bytes > self.websocket_max_message_bytes {
            return Err(BoundsError::FrameExceedsMessage);
        }
        Ok(())
    }

    /// The global bound on concurrently admitted proxy requests.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// The bound on a single in-memory HTTP body buffer.
    pub fn http_buffer_bytes(&self) -> usize {
        self.http_buffer_bytes
    }

    /// The bound on a single inbound WebSocket frame.
    pub fn websocket_max_frame_bytes(&self) -> usize {
        self.websocket_max_frame_bytes
    }

    /// The bound on a single reassembled WebSocket message.
    pub fn websocket_max_message_bytes(&self) -> usize {
        self.websocket_max_message_bytes
    }

    /// The bound on queued outbound WebSocket messages.
    pub fn websocket_queue_capacity(&self) -> usize {
        self.websocket_queue_capacity
    }
}

/// A global, non-blocking admission gate for proxy requests.
///
/// Every clone shares one semaphore, so the bound is process-wide rather than
/// per connection, per plane, or per listener.
#[derive(Clone, Debug)]
pub struct AdmissionControl {
    slots: Arc<Semaphore>,
    limits: ProxyLimits,
}

impl AdmissionControl {
    /// Builds the control from validated resource bounds.
    pub fn new(limits: ProxyLimits) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(limits.max_connections())),
            limits,
        }
    }

    /// The resource bounds the control was built from.
    pub fn limits(&self) -> &ProxyLimits {
        &self.limits
    }

    /// The total number of proxy slots.
    pub fn capacity(&self) -> usize {
        self.limits.max_connections()
    }

    /// The number of slots that are currently taken.
    pub fn in_flight(&self) -> usize {
        self.capacity() - self.available()
    }

    /// The number of slots that are free right now.
    pub fn available(&self) -> usize {
        self.slots.available_permits()
    }

    /// Admits one proxy request, or reports the limit immediately.
    ///
    /// The call never waits and never queues: with no free slot it returns
    /// [`GatewayError::ConnectionLimitReached`], which renders as a sanitized
    /// `503`, so an overloaded gateway sheds load instead of accumulating it.
    pub fn try_admit(&self) -> Result<AdmissionPermit, GatewayError> {
        match Arc::clone(&self.slots).try_acquire_owned() {
            Ok(permit) => Ok(AdmissionPermit { _permit: permit }),
            Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
                Err(GatewayError::ConnectionLimitReached)
            }
        }
    }
}

/// A held admission slot.
///
/// The slot is released exactly when the permit is dropped, so a finished,
/// cancelled, or panicking request cannot leak capacity.
#[derive(Debug)]
#[must_use = "the admission slot is released as soon as the permit is dropped"]
pub struct AdmissionPermit {
    _permit: OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_connections: usize) -> ProxyLimits {
        ProxyLimits::new(max_connections, 65_536, 1_048_576, 8_388_608, 32).expect("valid bounds")
    }

    #[test]
    fn bounds_reject_zero_and_a_frame_wider_than_its_message() {
        assert_eq!(
            ProxyLimits::new(0, 65_536, 1_048_576, 8_388_608, 32),
            Err(BoundsError::ZeroBound)
        );
        assert_eq!(
            ProxyLimits::new(1, 0, 1_048_576, 8_388_608, 32),
            Err(BoundsError::ZeroBound)
        );
        assert_eq!(
            ProxyLimits::new(1, 65_536, 8_388_609, 8_388_608, 32),
            Err(BoundsError::FrameExceedsMessage)
        );
        assert!(ProxyLimits::new(1, 65_536, 8_388_608, 8_388_608, 32).is_ok());
    }

    #[test]
    fn bounds_errors_have_stable_sanitized_messages() {
        assert_eq!(
            BoundsError::ZeroBound.to_string(),
            "every resource bound must be greater than zero"
        );
        assert_eq!(
            BoundsError::FrameExceedsMessage.to_string(),
            "the WebSocket frame bound must not exceed the message bound"
        );
    }

    #[test]
    fn admission_sheds_load_without_queueing() {
        let control = AdmissionControl::new(limits(2));

        assert_eq!(control.capacity(), 2);
        assert_eq!(control.available(), 2);
        assert_eq!(control.in_flight(), 0);

        let first = control.try_admit().expect("first slot");
        let second = control.try_admit().expect("second slot");
        assert_eq!(control.in_flight(), 2);
        assert_eq!(control.available(), 0);

        let rejected = control.try_admit().expect_err("the bound is full");
        assert_eq!(rejected, GatewayError::ConnectionLimitReached);
        assert_eq!(rejected.status(), hyper::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(control.in_flight(), 2, "a rejected request takes no slot");

        drop(first);
        assert_eq!(control.in_flight(), 1);
        let third = control.try_admit().expect("a freed slot is reusable");
        assert_eq!(control.in_flight(), 2);

        drop(second);
        drop(third);
        assert_eq!(control.in_flight(), 0);
        assert_eq!(control.available(), 2);
    }

    #[test]
    fn clones_share_one_global_gate() {
        let control = AdmissionControl::new(limits(1));
        let clone = control.clone();

        let _held = clone.try_admit().expect("the shared slot");
        assert_eq!(control.available(), 0);
        assert_eq!(
            control.try_admit().expect_err("the shared bound is full"),
            GatewayError::ConnectionLimitReached
        );
    }

    #[test]
    fn a_permit_is_released_even_when_its_scope_panics() {
        let control = AdmissionControl::new(limits(1));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = control.try_admit().expect("the only slot");
            panic!("simulated request failure");
        }));

        assert!(outcome.is_err(), "the scope panicked");
        assert_eq!(control.in_flight(), 0, "the slot survived the panic");
        assert!(control.try_admit().is_ok(), "capacity is fully recovered");
    }

    #[test]
    fn every_limit_is_carried_with_the_control() {
        let control = AdmissionControl::new(limits(7));
        let limits = control.limits();

        assert_eq!(limits.max_connections(), 7);
        assert_eq!(limits.http_buffer_bytes(), 65_536);
        assert_eq!(limits.websocket_max_frame_bytes(), 1_048_576);
        assert_eq!(limits.websocket_max_message_bytes(), 8_388_608);
        assert_eq!(limits.websocket_queue_capacity(), 32);
    }
}
