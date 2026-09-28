//! Data-plane proxy pipelines.
//!
//! The proxy core relays provider traffic without interpreting application
//! payloads. Modules here operate on the connection envelope only: the request
//! target, hop-by-hop and forwarding header policy, credential replacement, and
//! bounding. Header policy lives in [`headers`] so both the HTTP and the
//! WebSocket handshake share one implementation.
//!
//! Local failures are rendered through [`error`], which fixes the code,
//! status, and sanitized message for every class of gateway-originated error.
//! Admission and the per-process resource bounds live in [`admission`], which
//! sheds load at the configured limit instead of queueing it.

pub mod admission;
pub mod error;
pub mod headers;
