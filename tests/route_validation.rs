//! Data-plane route and upgrade validation.
//!
//! Route resolution is a pure decision over the provider type, method,
//! normalized path, and upgrade headers. It performs no I/O and never reads the
//! request body, so every case asserted here rejects the request before an
//! upstream could be contacted.

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

fn resolve(
    protocol_type: ProtocolType,
    method: Method,
    path: &str,
) -> Result<TransportType, RouteError> {
    resolve_route(protocol_type, &method, path, &HeaderMap::new()).map(|route| route.transport())
}

#[test]
fn openai_allows_only_the_three_supported_routes() {
    assert_eq!(
        resolve(
            ProtocolType::OpenAi,
            Method::POST,
            OPENAI_CHAT_COMPLETIONS_PATH
        ),
        Ok(TransportType::Http)
    );
    assert_eq!(
        resolve(ProtocolType::OpenAi, Method::POST, OPENAI_RESPONSES_PATH),
        Ok(TransportType::Http)
    );

    let route = resolve_route(
        ProtocolType::OpenAi,
        &Method::GET,
        OPENAI_RESPONSES_PATH,
        &websocket_handshake(),
    )
    .expect("upgraded responses route");
    assert_eq!(route.transport(), TransportType::WebSocket);
    assert_eq!(route.path(), OPENAI_RESPONSES_PATH);
}

#[test]
fn openai_wrong_methods_are_rejected() {
    for (method, path) in [
        (Method::GET, OPENAI_CHAT_COMPLETIONS_PATH),
        (Method::PUT, OPENAI_RESPONSES_PATH),
        (Method::DELETE, OPENAI_RESPONSES_PATH),
        (Method::GET, OPENAI_RESPONSES_PATH),
    ] {
        assert_eq!(
            resolve(ProtocolType::OpenAi, method, path),
            Err(RouteError::UnsupportedRoute),
            "expected {path:?} without an upgrade to be rejected"
        );
    }
}

#[test]
fn openai_invalid_upgrades_are_rejected() {
    let mut missing_version = websocket_handshake();
    missing_version.remove("sec-websocket-version");
    let mut wrong_protocol = websocket_handshake();
    wrong_protocol.insert("upgrade", HeaderValue::from_static("h2c"));
    let mut short_key = websocket_handshake();
    short_key.insert("sec-websocket-key", HeaderValue::from_static("c2hvcnQ="));
    let mut connection_only = HeaderMap::new();
    connection_only.insert("connection", HeaderValue::from_static("upgrade"));

    for headers in [missing_version, wrong_protocol, short_key, connection_only] {
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

    for (method, path) in [
        (Method::POST, OPENAI_RESPONSES_PATH),
        (Method::GET, OPENAI_CHAT_COMPLETIONS_PATH),
    ] {
        assert_eq!(
            resolve_route(ProtocolType::OpenAi, &method, path, &websocket_handshake()),
            Err(RouteError::InvalidUpgrade),
            "expected a handshake on {path:?} to be an invalid upgrade"
        );
    }
}

#[test]
fn openai_rejects_other_and_anthropic_paths() {
    for path in [
        ANTHROPIC_MESSAGES_PATH,
        "/v1/embeddings",
        "/v1/models",
        "/v1/responses/extra",
        "/",
    ] {
        assert_eq!(
            resolve(ProtocolType::OpenAi, Method::POST, path),
            Err(RouteError::UnsupportedRoute),
            "expected {path:?} to be rejected for an openai provider"
        );
    }

    assert_eq!(
        resolve(ProtocolType::Anthropic, Method::GET, OPENAI_RESPONSES_PATH),
        Err(RouteError::UnsupportedRoute)
    );
    assert_eq!(
        resolve_route(
            ProtocolType::Anthropic,
            &Method::GET,
            OPENAI_RESPONSES_PATH,
            &websocket_handshake()
        ),
        Err(RouteError::InvalidUpgrade)
    );
    assert_eq!(
        resolve(
            ProtocolType::Anthropic,
            Method::POST,
            ANTHROPIC_MESSAGES_PATH
        ),
        Ok(TransportType::Http)
    );
}

#[test]
fn rejections_carry_stable_codes_and_statuses() {
    assert_eq!(RouteError::UnsupportedRoute.code(), "unsupported_route");
    assert_eq!(RouteError::UnsupportedRoute.status(), StatusCode::NOT_FOUND);
    assert_eq!(RouteError::InvalidUpgrade.code(), "invalid_upgrade");
    assert_eq!(RouteError::InvalidUpgrade.status(), StatusCode::BAD_REQUEST);
}
