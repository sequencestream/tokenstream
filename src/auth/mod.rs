//! Authentication for the independent service planes.
//!
//! The module currently exposes data-plane gateway authentication: it turns a
//! provider-native request credential into an immutable, request-local provider
//! snapshot. Administration-plane authentication is added separately so the two
//! planes never share credential handling.

mod gateway;

pub use gateway::{GatewayAuthError, GatewayAuthenticator};
