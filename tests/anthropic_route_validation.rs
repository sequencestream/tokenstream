//! Anthropic route and transport validation.
//!
//! An `anthropic` provider serves exactly one data-plane route: `POST
//! /v1/messages` over HTTP, which includes SSE responses. The router decides
//! from the provider type, method, normalized path, and upgrade headers alone.
//! It never reads the request body and never infers streaming from a body field
//! or content type, so every rejected combination is refused before an upstream
//! can be contacted.

use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, StatusCode};
use tokenstream::domain::{ProtocolType, TransportType};
use tokenstream::routing::{
    ANTHROPIC_MESSAGES_PATH, OPENAI_CHAT_COMPLETIONS_PATH, OPENAI_RESPONSES_PATH, RouteError,
    resolve_route,
};

/// A complete, standards-compliant WebSocket handshake.
fn websocket_handshake() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("Upgrade"));
    headers.insert("upgrade", HeaderValue::from_static("websocket"));
    headers.insert("sec-websocket-version", HeaderValue::from_static("13"));
    headers.insert(
        "sec-websocket-key",
        HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
    );
    headers
}

fn resolve(method: Method, path: &str) -> Result<TransportType, RouteError> {
    resolve_route(ProtocolType::Anthropic, &method, path, &HeaderMap::new())
        .map(|route| route.transport())
}

#[test]
fn anthropic_allows_only_post_messages_over_http() {
    let route = resolve_route(
        ProtocolType::Anthropic,
        &Method::POST,
        ANTHROPIC_MESSAGES_PATH,
        &HeaderMap::new(),
    )
    .expect("messages route");
    assert_eq!(route.transport(), TransportType::Http);
    assert_eq!(route.path(), ANTHROPIC_MESSAGES_PATH);
}

#[test]
fn anthropic_rejects_every_other_method() {
    for method in [
        Method::GET,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::HEAD,
        Method::OPTIONS,
        Method::TRACE,
        Method::CONNECT,
    ] {
        assert_eq!(
            resolve(method.clone(), ANTHROPIC_MESSAGES_PATH),
            Err(RouteError::UnsupportedRoute),
            "expected {method} {ANTHROPIC_MESSAGES_PATH} to be rejected"
        );
    }
}

#[test]
fn anthropic_rejects_websocket_upgrades() {
    // A well-formed handshake on the messages path is an upgrade attempt the
    // anthropic provider cannot serve, so it is rejected as an invalid upgrade
    // rather than silently handled as a plain HTTP request.
    for method in [Method::GET, Method::POST] {
        assert_eq!(
            resolve_route(
                ProtocolType::Anthropic,
                &method,
                ANTHROPIC_MESSAGES_PATH,
                &websocket_handshake()
            ),
            Err(RouteError::InvalidUpgrade),
            "expected a handshake on {method} {ANTHROPIC_MESSAGES_PATH} to be invalid"
        );
    }

    // Malformed upgrade attempts are still invalid upgrades, never plain HTTP.
    let mut missing_version = websocket_handshake();
    missing_version.remove("sec-websocket-version");
    let mut wrong_protocol = websocket_handshake();
    wrong_protocol.insert("upgrade", HeaderValue::from_static("h2c"));
    let mut connection_only = HeaderMap::new();
    connection_only.insert("connection", HeaderValue::from_static("upgrade"));
    let mut upgrade_only = HeaderMap::new();
    upgrade_only.insert("upgrade", HeaderValue::from_static("websocket"));

    for headers in [
        missing_version,
        wrong_protocol,
        connection_only,
        upgrade_only,
    ] {
        assert_eq!(
            resolve_route(
                ProtocolType::Anthropic,
                &Method::POST,
                ANTHROPIC_MESSAGES_PATH,
                &headers
            ),
            Err(RouteError::InvalidUpgrade)
        );
    }
}

#[test]
fn anthropic_rejects_unserved_paths_including_openai_routes() {
    for path in [
        OPENAI_RESPONSES_PATH,
        OPENAI_CHAT_COMPLETIONS_PATH,
        "/v1/messages/extra",
        "/v1/embeddings",
        "/v1/models",
        "/",
    ] {
        assert_eq!(
            resolve(Method::POST, path),
            Err(RouteError::UnsupportedRoute),
            "expected {path:?} to be rejected for an anthropic provider"
        );
    }

    // The one OpenAI WebSocket route is not available to an anthropic provider.
    assert_eq!(
        resolve_route(
            ProtocolType::Anthropic,
            &Method::GET,
            OPENAI_RESPONSES_PATH,
            &websocket_handshake()
        ),
        Err(RouteError::InvalidUpgrade)
    );
}

#[test]
fn anthropic_matches_the_normalized_path_only() {
    // Dot segments are canonicalized before matching, so equivalent paths match.
    assert_eq!(
        resolve(Method::POST, "/v1/./messages"),
        Ok(TransportType::Http)
    );
    assert_eq!(
        resolve(Method::POST, "/v1/sub/../messages"),
        Ok(TransportType::Http)
    );

    // Percent-encoded, duplicated, trailing, escaping, and relative forms do not
    // collapse into the allowed path and are rejected instead of rewritten.
    for path in [
        "/v1/%2E%2E/messages",
        "/v1//messages",
        "/v1/messages/",
        "/../v1/messages",
        "v1/messages",
        "",
    ] {
        assert_eq!(
            resolve(Method::POST, path),
            Err(RouteError::UnsupportedRoute),
            "expected {path:?} not to match the messages route"
        );
    }
}

#[test]
fn transport_ignores_content_type_and_streaming_hints() {
    // SSE is an upstream HTTP response observed later, not something the router
    // infers from a body field or a content type. Streaming hints therefore do
    // not change the decided transport.
    let mut hinted = HeaderMap::new();
    hinted.insert("content-type", HeaderValue::from_static("application/json"));
    hinted.insert("accept", HeaderValue::from_static("text/event-stream"));
    hinted.insert("stream", HeaderValue::from_static("true"));

    let with_hints = resolve_route(
        ProtocolType::Anthropic,
        &Method::POST,
        ANTHROPIC_MESSAGES_PATH,
        &hinted,
    )
    .expect("messages route");
    let without_hints = resolve_route(
        ProtocolType::Anthropic,
        &Method::POST,
        ANTHROPIC_MESSAGES_PATH,
        &HeaderMap::new(),
    )
    .expect("messages route");

    assert_eq!(with_hints.transport(), TransportType::Http);
    assert_eq!(with_hints, without_hints);
}

#[test]
fn anthropic_rejections_carry_stable_codes_and_statuses() {
    assert_eq!(RouteError::UnsupportedRoute.code(), "unsupported_route");
    assert_eq!(RouteError::UnsupportedRoute.status(), StatusCode::NOT_FOUND);
    assert_eq!(RouteError::InvalidUpgrade.code(), "invalid_upgrade");
    assert_eq!(RouteError::InvalidUpgrade.status(), StatusCode::BAD_REQUEST);
}
