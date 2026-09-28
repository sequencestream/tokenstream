//! Bidirectional header policy contract.
//!
//! These tests exercise the pure header transformation used by the data plane.
//! They feed in a provider snapshot and inbound headers, then assert which
//! headers survive to an upstream or a downstream client. No test reads a body
//! or contacts an upstream, so a failure here is a local policy failure.

use std::net::SocketAddr;

use hyper::HeaderMap;
use tokenstream::domain::{ProtocolType, ProviderId, ProviderSnapshot, SecretString};
use tokenstream::proxy::headers::{
    HeaderError, build_downstream_response_headers, build_upstream_request_headers,
};
use url::Url;

fn snapshot(protocol_type: ProtocolType, endpoint: &str, upstream_key: &str) -> ProviderSnapshot {
    ProviderSnapshot::new(
        ProviderId::try_from(1).expect("positive provider ID"),
        protocol_type,
        Url::parse(endpoint).expect("valid endpoint"),
        SecretString::new(upstream_key),
    )
}

fn peer() -> SocketAddr {
    "203.0.113.7:5555".parse().expect("valid socket address")
}

fn openai_inbound() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer gateway.key".parse().expect("header"),
    );
    headers
}

fn anthropic_inbound() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", "gateway.key".parse().expect("header"));
    headers
}

fn text(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .unwrap_or_else(|| panic!("expected header {name:?}"))
        .to_str()
        .expect("text header")
        .to_owned()
}

#[test]
fn openai_replaces_the_credential_and_sets_the_authority() {
    let snapshot = snapshot(
        ProtocolType::OpenAi,
        "https://api.example.com:8443/proxy",
        "up-openai",
    );

    let outbound = build_upstream_request_headers(&snapshot, &openai_inbound(), peer())
        .expect("headers are forwardable");

    assert_eq!(text(&outbound, "authorization"), "Bearer up-openai");
    assert_eq!(text(&outbound, "host"), "api.example.com:8443");
}

#[test]
fn anthropic_replaces_its_native_credential() {
    let snapshot = snapshot(
        ProtocolType::Anthropic,
        "https://api.example.com",
        "up-anthropic",
    );

    let outbound = build_upstream_request_headers(&snapshot, &anthropic_inbound(), peer())
        .expect("headers are forwardable");

    assert_eq!(text(&outbound, "x-api-key"), "up-anthropic");
    assert!(!outbound.contains_key("authorization"));
    assert_eq!(text(&outbound, "host"), "api.example.com");
}

#[test]
fn hop_by_hop_and_connection_named_headers_are_dropped() {
    let snapshot = snapshot(ProtocolType::OpenAi, "https://api.example.com", "up-openai");
    let mut inbound = openai_inbound();
    inbound.insert("connection", "keep-alive, x-hop".parse().expect("header"));
    inbound.insert("keep-alive", "timeout=5".parse().expect("header"));
    inbound.insert("proxy-authorization", "Basic abc".parse().expect("header"));
    inbound.insert("te", "trailers".parse().expect("header"));
    inbound.insert("trailer", "x-trailer".parse().expect("header"));
    inbound.insert("transfer-encoding", "chunked".parse().expect("header"));
    inbound.insert("upgrade", "websocket".parse().expect("header"));
    inbound.insert("x-hop", "nominated".parse().expect("header"));

    let outbound = build_upstream_request_headers(&snapshot, &inbound, peer())
        .expect("headers are forwardable");

    for name in [
        "connection",
        "keep-alive",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-hop",
    ] {
        assert!(
            !outbound.contains_key(name),
            "expected {name:?} to be removed"
        );
    }
    assert_eq!(text(&outbound, "authorization"), "Bearer up-openai");
}

#[test]
fn version_and_beta_headers_are_preserved() {
    let snapshot = snapshot(
        ProtocolType::Anthropic,
        "https://api.example.com",
        "up-anthropic",
    );
    let mut inbound = anthropic_inbound();
    inbound.insert("anthropic-version", "2023-06-01".parse().expect("header"));
    inbound.insert(
        "anthropic-beta",
        "tools-2024-04-04".parse().expect("header"),
    );
    inbound.insert("x-custom", "kept".parse().expect("header"));

    let outbound = build_upstream_request_headers(&snapshot, &inbound, peer())
        .expect("headers are forwardable");

    assert_eq!(text(&outbound, "anthropic-version"), "2023-06-01");
    assert_eq!(text(&outbound, "anthropic-beta"), "tools-2024-04-04");
    assert_eq!(text(&outbound, "x-custom"), "kept");
}

#[test]
fn the_forwarding_chain_is_replaced_by_one_peer_value() {
    let snapshot = snapshot(ProtocolType::OpenAi, "https://api.example.com", "up-openai");
    let mut inbound = openai_inbound();
    inbound.insert("forwarded", "for=10.0.0.1".parse().expect("header"));
    inbound.append("x-forwarded-for", "10.0.0.1".parse().expect("header"));
    inbound.append("x-forwarded-for", "10.0.0.2".parse().expect("header"));
    inbound.insert("x-forwarded-host", "spoofed".parse().expect("header"));
    inbound.insert("x-forwarded-port", "1234".parse().expect("header"));
    inbound.insert("x-forwarded-proto", "http".parse().expect("header"));
    inbound.insert("x-real-ip", "10.0.0.3".parse().expect("header"));

    let outbound = build_upstream_request_headers(&snapshot, &inbound, peer())
        .expect("headers are forwardable");

    assert_eq!(
        outbound.get_all("x-forwarded-for").iter().count(),
        1,
        "expected exactly one X-Forwarded-For value"
    );
    assert_eq!(text(&outbound, "x-forwarded-for"), "203.0.113.7");
    for name in [
        "forwarded",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-real-ip",
    ] {
        assert!(
            !outbound.contains_key(name),
            "expected {name:?} to be removed"
        );
    }
}

#[test]
fn duplicate_and_conflicting_credentials_are_rejected() {
    let snapshot = snapshot(ProtocolType::OpenAi, "https://api.example.com", "up-openai");

    let mut duplicated = HeaderMap::new();
    duplicated.append(
        "authorization",
        "Bearer gateway.key".parse().expect("header"),
    );
    duplicated.append(
        "authorization",
        "Bearer gateway.key".parse().expect("header"),
    );
    assert_eq!(
        build_upstream_request_headers(&snapshot, &duplicated, peer()),
        Err(HeaderError::DuplicateCredential)
    );

    let mut conflicting = openai_inbound();
    conflicting.insert("x-api-key", "gateway.key".parse().expect("header"));
    assert_eq!(
        build_upstream_request_headers(&snapshot, &conflicting, peer()),
        Err(HeaderError::ConflictingCredential)
    );

    assert_eq!(
        build_upstream_request_headers(&snapshot, &HeaderMap::new(), peer()),
        Err(HeaderError::MissingCredential)
    );
}

#[test]
fn the_gateway_credential_never_reaches_the_upstream() {
    let snapshot = snapshot(
        ProtocolType::Anthropic,
        "https://api.example.com",
        "up-anthropic",
    );
    let mut inbound = anthropic_inbound();
    inbound.insert("x-custom", "kept".parse().expect("header"));

    let outbound = build_upstream_request_headers(&snapshot, &inbound, peer())
        .expect("headers are forwardable");

    assert!(
        !outbound.iter().any(|(_, value)| value
            .to_str()
            .is_ok_and(|value| value.contains("gateway.key"))),
        "the inbound gateway key must not survive to the upstream"
    );
}

#[test]
fn responses_drop_hop_by_hop_headers() {
    let mut upstream = HeaderMap::new();
    upstream.insert("connection", "close, x-hop".parse().expect("header"));
    upstream.insert("keep-alive", "timeout=5".parse().expect("header"));
    upstream.insert("transfer-encoding", "chunked".parse().expect("header"));
    upstream.insert("proxy-authenticate", "Basic".parse().expect("header"));
    upstream.insert("x-hop", "nominated".parse().expect("header"));
    upstream.insert("content-type", "text/event-stream".parse().expect("header"));
    upstream.insert("x-request-id", "req_123".parse().expect("header"));

    let downstream = build_downstream_response_headers(&upstream);

    for name in [
        "connection",
        "keep-alive",
        "transfer-encoding",
        "proxy-authenticate",
        "x-hop",
    ] {
        assert!(
            !downstream.contains_key(name),
            "expected {name:?} to be removed"
        );
    }
    assert_eq!(text(&downstream, "content-type"), "text/event-stream");
    assert_eq!(text(&downstream, "x-request-id"), "req_123");
}

#[test]
fn rejections_render_without_secret_material() {
    let snapshot = snapshot(
        ProtocolType::OpenAi,
        "https://api.example.com",
        "sup3r-secret\ninjected",
    );

    let error = build_upstream_request_headers(&snapshot, &openai_inbound(), peer())
        .expect_err("a control character cannot be forwarded");

    assert_eq!(error, HeaderError::InvalidUpstreamKey);
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("sup3r-secret"));
    assert!(!rendered.contains("injected"));
    assert!(!rendered.contains("gateway.key"));
}
