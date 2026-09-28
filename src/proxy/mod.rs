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

pub mod error;
pub mod headers;
