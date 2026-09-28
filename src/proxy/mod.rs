//! Data-plane proxy pipelines.
//!
//! The proxy core relays provider traffic without interpreting application
//! payloads. Modules here operate on the connection envelope only: the request
//! target, hop-by-hop and forwarding header policy, credential replacement, and
//! bounding. Header policy lives in [`headers`] so both the HTTP and the
//! WebSocket handshake share one implementation.

pub mod headers;
