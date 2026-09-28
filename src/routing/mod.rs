//! Data-plane route and transport validation.
//!
//! The router decides from the resolved provider type, the request method, the
//! normalized path, and the standard WebSocket upgrade headers alone. It never
//! reads the request body or any application field, performs no I/O, and holds
//! no state, so every unsupported or invalid combination is rejected before an
//! upstream can be contacted.
//!
//! The allowlist is fixed: widening it is an architectural change rather than a
//! configuration option. A path that is valid for one provider is not accepted
//! for another, and a WebSocket upgrade is accepted only on the one route that
//! supports it.

use std::error::Error;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use hyper::header::HeaderMap;
use hyper::{Method, StatusCode};

use crate::domain::{ProtocolType, TransportType};

pub mod target;

pub use target::{TargetError, build_upstream_uri};

/// OpenAI Chat Completions path, served over HTTP including SSE.
pub const OPENAI_CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
/// OpenAI Responses path, served over HTTP including SSE and over WebSocket when upgraded.
pub const OPENAI_RESPONSES_PATH: &str = "/v1/responses";
/// Anthropic Messages path, served over HTTP including SSE.
pub const ANTHROPIC_MESSAGES_PATH: &str = "/v1/messages";

const CONNECTION_HEADER: &str = "connection";
const UPGRADE_HEADER: &str = "upgrade";
const SEC_WEBSOCKET_KEY_HEADER: &str = "sec-websocket-key";
const SEC_WEBSOCKET_VERSION_HEADER: &str = "sec-websocket-version";

/// Token that must appear in the `Connection` header of an upgrade request.
const UPGRADE_TOKEN: &str = "upgrade";
/// Token that must appear in the `Upgrade` header of a WebSocket upgrade request.
const WEBSOCKET_TOKEN: &str = "websocket";
/// The only WebSocket protocol version the gateway accepts.
const WEBSOCKET_VERSION: &str = "13";
/// Required entropy of the `Sec-WebSocket-Key` nonce.
const WEBSOCKET_KEY_BYTES: usize = 16;

/// One entry of the fixed data-plane allowlist.
struct RouteRule {
    protocol_type: ProtocolType,
    method: Method,
    path: &'static str,
    transport: TransportType,
}

/// Every supported provider/method/path/transport combination and nothing else.
///
/// The WebSocket route is not listed here because it additionally requires a
/// valid upgrade request; it is matched separately.
const ROUTE_ALLOWLIST: &[RouteRule] = &[
    RouteRule {
        protocol_type: ProtocolType::OpenAi,
        method: Method::POST,
        path: OPENAI_CHAT_COMPLETIONS_PATH,
        transport: TransportType::Http,
    },
    RouteRule {
        protocol_type: ProtocolType::OpenAi,
        method: Method::POST,
        path: OPENAI_RESPONSES_PATH,
        transport: TransportType::Http,
    },
    RouteRule {
        protocol_type: ProtocolType::Anthropic,
        method: Method::POST,
        path: ANTHROPIC_MESSAGES_PATH,
        transport: TransportType::Http,
    },
];

/// The only route that accepts a WebSocket upgrade.
const WEBSOCKET_ROUTE: RouteRule = RouteRule {
    protocol_type: ProtocolType::OpenAi,
    method: Method::GET,
    path: OPENAI_RESPONSES_PATH,
    transport: TransportType::WebSocket,
};

/// A rejected data-plane route or upgrade.
///
/// Each variant maps to one stable gateway error code and status and carries no
/// request value, so a rejection is safe to surface or log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    /// The provider cannot serve the requested method, path, or transport.
    UnsupportedRoute,
    /// The request carried upgrade headers that do not form the one supported upgrade.
    InvalidUpgrade,
}

impl RouteError {
    /// Stable gateway error code reported for this rejection.
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedRoute => "unsupported_route",
            Self::InvalidUpgrade => "invalid_upgrade",
        }
    }

    /// HTTP status reported for this rejection.
    pub fn status(self) -> StatusCode {
        match self {
            Self::UnsupportedRoute => StatusCode::NOT_FOUND,
            Self::InvalidUpgrade => StatusCode::BAD_REQUEST,
        }
    }
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedRoute => "the requested route is not available for this provider",
            Self::InvalidUpgrade => "the requested WebSocket upgrade is not valid",
        };
        formatter.write_str(message)
    }
}

impl Error for RouteError {}

/// A route that passed validation.
///
/// The path is the normalized path used for the match, without a query string,
/// so it is safe to use when building the upstream request target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRoute {
    transport: TransportType,
    path: String,
}

impl ResolvedRoute {
    /// The transport the proxy must use for this request.
    pub fn transport(&self) -> TransportType {
        self.transport
    }

    /// The normalized request path, without a query string.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Rejection reason for a request path that cannot be normalized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathNormalizationError {
    /// The path is empty or is not an absolute origin-form path.
    NotAbsolute,
    /// The path contains an ASCII control character.
    ControlCharacter,
    /// Removing dot segments would leave the root.
    EscapesRoot,
}

impl fmt::Display for PathNormalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NotAbsolute => "path must be an absolute origin-form path",
            Self::ControlCharacter => "path must not contain control characters",
            Self::EscapesRoot => "path must not escape the root",
        };
        formatter.write_str(message)
    }
}

impl Error for PathNormalizationError {}

/// Resolves the transport for one data-plane request.
///
/// `path` is the origin-form request path without a query string. The decision
/// uses only `protocol_type`, `method`, the normalized path, and the standard
/// upgrade headers, and the returned path is that normalized form. The function
/// performs no I/O and never inspects the request body, so a rejection here
/// always precedes upstream contact.
pub fn resolve_route(
    protocol_type: ProtocolType,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> Result<ResolvedRoute, RouteError> {
    let normalized = normalize_path(path).map_err(|_| RouteError::UnsupportedRoute)?;

    if is_upgrade_attempt(headers) {
        return resolve_upgrade(protocol_type, method, normalized, headers);
    }

    let matched = ROUTE_ALLOWLIST.iter().find(|rule| {
        rule.protocol_type == protocol_type && rule.method == *method && rule.path == normalized
    });
    match matched {
        Some(rule) => Ok(ResolvedRoute {
            transport: rule.transport,
            path: normalized,
        }),
        None => Err(RouteError::UnsupportedRoute),
    }
}

/// Validates an upgrade attempt against the single WebSocket route.
///
/// An upgrade attempt is rejected as an invalid upgrade whenever its headers are
/// not a well-formed WebSocket handshake or the provider, method, or path is not
/// the one route that supports WebSocket.
fn resolve_upgrade(
    protocol_type: ProtocolType,
    method: &Method,
    normalized: String,
    headers: &HeaderMap,
) -> Result<ResolvedRoute, RouteError> {
    if !is_websocket_upgrade(headers) {
        return Err(RouteError::InvalidUpgrade);
    }
    if protocol_type != WEBSOCKET_ROUTE.protocol_type
        || WEBSOCKET_ROUTE.method != *method
        || WEBSOCKET_ROUTE.path != normalized
    {
        return Err(RouteError::InvalidUpgrade);
    }
    Ok(ResolvedRoute {
        transport: WEBSOCKET_ROUTE.transport,
        path: normalized,
    })
}

/// Canonicalizes a request path for allowlist matching.
///
/// The result has no query string and no `.` or `..` segments. Percent-encoded
/// octets are left untouched, so an encoded form never collapses into an
/// allowed path; a path that would escape the root is rejected instead of being
/// clamped or rewritten.
pub fn normalize_path(path: &str) -> Result<String, PathNormalizationError> {
    if !path.starts_with('/') {
        return Err(PathNormalizationError::NotAbsolute);
    }
    if path.chars().any(char::is_control) {
        return Err(PathNormalizationError::ControlCharacter);
    }

    let mut segments: Vec<&str> = Vec::new();
    let mut remainder = path.split('/');
    remainder.next();
    for segment in remainder {
        match segment {
            "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err(PathNormalizationError::EscapesRoot);
                }
            }
            other => segments.push(other),
        }
    }

    let mut normalized = String::with_capacity(path.len());
    for segment in segments {
        normalized.push('/');
        normalized.push_str(segment);
    }
    Ok(normalized)
}

/// Reports whether the request asks for a protocol upgrade at all.
///
/// Any sign of an upgrade — the `Connection: upgrade` token or the presence of
/// an `Upgrade` header — is treated as an attempt, so a malformed attempt is
/// rejected as an invalid upgrade rather than silently handled as plain HTTP.
fn is_upgrade_attempt(headers: &HeaderMap) -> bool {
    has_token(headers, CONNECTION_HEADER, UPGRADE_TOKEN) || headers.contains_key(UPGRADE_HEADER)
}

/// Reports whether the headers form a well-formed WebSocket handshake.
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    has_token(headers, CONNECTION_HEADER, UPGRADE_TOKEN)
        && has_token(headers, UPGRADE_HEADER, WEBSOCKET_TOKEN)
        && header_equals(headers, SEC_WEBSOCKET_VERSION_HEADER, WEBSOCKET_VERSION)
        && is_websocket_key(headers)
}

/// Reports whether any value of `name` carries the comma-separated `token`.
fn has_token(headers: &HeaderMap, name: &str, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|rendered| {
            rendered
                .split(',')
                .any(|candidate| candidate.trim().eq_ignore_ascii_case(token))
        })
    })
}

/// Reports whether `name` appears exactly once with the trimmed value `expected`.
fn header_equals(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .is_ok_and(|rendered| rendered.trim() == expected),
        _ => false,
    }
}

/// Reports whether the request carries one nonce of the required length.
fn is_websocket_key(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(SEC_WEBSOCKET_KEY_HEADER).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return false;
    };
    let Ok(rendered) = value.to_str() else {
        return false;
    };
    let rendered = rendered.trim();
    let decoded = STANDARD
        .decode(rendered)
        .or_else(|_| STANDARD_NO_PAD.decode(rendered));
    matches!(decoded, Ok(bytes) if bytes.len() == WEBSOCKET_KEY_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn upgrade_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION_HEADER, HeaderValue::from_static("Upgrade"));
        headers.insert(UPGRADE_HEADER, HeaderValue::from_static("websocket"));
        headers.insert(
            SEC_WEBSOCKET_VERSION_HEADER,
            HeaderValue::from_static(WEBSOCKET_VERSION),
        );
        headers.insert(
            SEC_WEBSOCKET_KEY_HEADER,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers
    }

    fn resolve(
        protocol_type: ProtocolType,
        method: Method,
        path: &str,
    ) -> Result<ResolvedRoute, RouteError> {
        resolve_route(protocol_type, &method, path, &HeaderMap::new())
    }

    #[test]
    fn allowlist_covers_exactly_the_supported_http_routes() {
        for (protocol_type, method, path) in [
            (
                ProtocolType::OpenAi,
                Method::POST,
                OPENAI_CHAT_COMPLETIONS_PATH,
            ),
            (ProtocolType::OpenAi, Method::POST, OPENAI_RESPONSES_PATH),
            (
                ProtocolType::Anthropic,
                Method::POST,
                ANTHROPIC_MESSAGES_PATH,
            ),
        ] {
            let route = resolve(protocol_type, method, path).expect("allowed HTTP route");
            assert_eq!(route.transport(), TransportType::Http);
            assert_eq!(route.path(), path);
        }
    }

    #[test]
    fn only_the_responses_route_accepts_a_valid_websocket_upgrade() {
        let route = resolve_route(
            ProtocolType::OpenAi,
            &Method::GET,
            OPENAI_RESPONSES_PATH,
            &upgrade_headers(),
        )
        .expect("responses WebSocket upgrade");
        assert_eq!(route.transport(), TransportType::WebSocket);
        assert_eq!(route.path(), OPENAI_RESPONSES_PATH);
    }

    #[test]
    fn a_websocket_route_without_upgrade_headers_is_an_unsupported_route() {
        assert_eq!(
            resolve(ProtocolType::OpenAi, Method::GET, OPENAI_RESPONSES_PATH),
            Err(RouteError::UnsupportedRoute)
        );
    }

    #[test]
    fn dot_segments_are_normalized_before_matching() {
        assert_eq!(
            normalize_path("/v1/./responses").expect("normalized path"),
            OPENAI_RESPONSES_PATH
        );
        assert_eq!(
            normalize_path("/v1/child/../responses").expect("normalized path"),
            OPENAI_RESPONSES_PATH
        );
        assert_eq!(
            resolve(ProtocolType::OpenAi, Method::POST, "/v1/./responses")
                .expect("normalized route matches")
                .transport(),
            TransportType::Http
        );
    }

    #[test]
    fn unsafe_paths_are_rejected_instead_of_rewritten() {
        for (path, expected) in [
            ("", PathNormalizationError::NotAbsolute),
            ("v1/responses", PathNormalizationError::NotAbsolute),
            ("/../v1/responses", PathNormalizationError::EscapesRoot),
            ("/v1/responses\n", PathNormalizationError::ControlCharacter),
        ] {
            assert_eq!(
                normalize_path(path),
                Err(expected),
                "expected {path:?} to be rejected"
            );
            assert_eq!(
                resolve(ProtocolType::OpenAi, Method::POST, path),
                Err(RouteError::UnsupportedRoute),
                "expected {path:?} to be rejected before matching"
            );
        }

        for encoded in ["/v1/%2E%2E/responses", "/v1//responses", "/v1/responses/"] {
            assert_ne!(
                normalize_path(encoded).expect("normalizable path"),
                OPENAI_RESPONSES_PATH,
                "expected {encoded:?} not to collapse into the allowed path"
            );
        }
    }

    #[test]
    fn every_other_path_is_rejected() {
        for path in [
            ANTHROPIC_MESSAGES_PATH,
            "/v1/embeddings",
            "/v1/chat/completions/extra",
            "/v1/responses?stream=true",
            "/",
        ] {
            assert_eq!(
                resolve(ProtocolType::OpenAi, Method::POST, path),
                Err(RouteError::UnsupportedRoute),
                "expected {path:?} to be rejected"
            );
        }
    }

    #[test]
    fn wrong_methods_and_cross_provider_paths_are_rejected() {
        for (method, path) in [
            (Method::GET, OPENAI_CHAT_COMPLETIONS_PATH),
            (Method::PUT, OPENAI_CHAT_COMPLETIONS_PATH),
            (Method::POST, ANTHROPIC_MESSAGES_PATH),
        ] {
            assert_eq!(
                resolve(ProtocolType::OpenAi, method, path),
                Err(RouteError::UnsupportedRoute)
            );
        }
        assert_eq!(
            resolve(ProtocolType::Anthropic, Method::GET, OPENAI_RESPONSES_PATH),
            Err(RouteError::UnsupportedRoute)
        );
    }

    #[test]
    fn malformed_upgrade_attempts_are_invalid_upgrades() {
        let mut missing_version = upgrade_headers();
        missing_version.remove(SEC_WEBSOCKET_VERSION_HEADER);
        let mut wrong_version = upgrade_headers();
        wrong_version.insert(SEC_WEBSOCKET_VERSION_HEADER, HeaderValue::from_static("8"));
        let mut short_key = upgrade_headers();
        short_key.insert(
            SEC_WEBSOCKET_KEY_HEADER,
            HeaderValue::from_static("c2hvcnQ="),
        );
        let mut duplicate_key = upgrade_headers();
        duplicate_key.append(
            SEC_WEBSOCKET_KEY_HEADER,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        let mut wrong_protocol = upgrade_headers();
        wrong_protocol.insert(UPGRADE_HEADER, HeaderValue::from_static("h2c"));

        let mut connection_only = HeaderMap::new();
        connection_only.insert(CONNECTION_HEADER, HeaderValue::from_static("upgrade"));
        let mut upgrade_only = HeaderMap::new();
        upgrade_only.insert(UPGRADE_HEADER, HeaderValue::from_static("websocket"));

        for headers in [
            missing_version,
            wrong_version,
            short_key,
            duplicate_key,
            wrong_protocol,
            connection_only,
            upgrade_only,
        ] {
            assert_eq!(
                resolve_route(
                    ProtocolType::OpenAi,
                    &Method::GET,
                    OPENAI_RESPONSES_PATH,
                    &headers
                ),
                Err(RouteError::InvalidUpgrade)
            );
        }
    }

    #[test]
    fn a_valid_upgrade_on_any_other_route_is_invalid() {
        for (protocol_type, method, path) in [
            (ProtocolType::Anthropic, Method::GET, OPENAI_RESPONSES_PATH),
            (ProtocolType::OpenAi, Method::POST, OPENAI_RESPONSES_PATH),
            (
                ProtocolType::OpenAi,
                Method::GET,
                OPENAI_CHAT_COMPLETIONS_PATH,
            ),
            (
                ProtocolType::Anthropic,
                Method::POST,
                ANTHROPIC_MESSAGES_PATH,
            ),
        ] {
            assert_eq!(
                resolve_route(protocol_type, &method, path, &upgrade_headers()),
                Err(RouteError::InvalidUpgrade)
            );
        }
    }

    #[test]
    fn route_error_codes_and_statuses_are_stable() {
        assert_eq!(RouteError::UnsupportedRoute.code(), "unsupported_route");
        assert_eq!(RouteError::UnsupportedRoute.status(), StatusCode::NOT_FOUND);
        assert_eq!(RouteError::InvalidUpgrade.code(), "invalid_upgrade");
        assert_eq!(RouteError::InvalidUpgrade.status(), StatusCode::BAD_REQUEST);
    }
}
