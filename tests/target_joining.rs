//! Upstream request-target construction.
//!
//! The join consumes a route that already passed validation and a configured
//! provider endpoint. It reserves the endpoint base-path prefix, forwards the
//! original query string byte for byte, and rejects any path or prefix that is
//! not already rooted and free of dot segments. No test here reads a body or
//! contacts an upstream.

use hyper::Method;
use hyper::header::{HeaderMap, HeaderValue};
use tokenstream::domain::ProtocolType;
use tokenstream::routing::{
    ANTHROPIC_MESSAGES_PATH, OPENAI_CHAT_COMPLETIONS_PATH, OPENAI_RESPONSES_PATH, RouteError,
    TargetError, build_upstream_uri, resolve_route,
};
use url::Url;

fn route(
    protocol_type: ProtocolType,
    method: Method,
    path: &str,
) -> tokenstream::routing::ResolvedRoute {
    resolve_route(protocol_type, &method, path, &HeaderMap::new()).expect("allowed route")
}

fn websocket_route() -> tokenstream::routing::ResolvedRoute {
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("Upgrade"));
    headers.insert("upgrade", HeaderValue::from_static("websocket"));
    headers.insert("sec-websocket-version", HeaderValue::from_static("13"));
    headers.insert(
        "sec-websocket-key",
        HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
    );
    resolve_route(
        ProtocolType::OpenAi,
        &Method::GET,
        OPENAI_RESPONSES_PATH,
        &headers,
    )
    .expect("upgraded responses route")
}

fn endpoint(raw: &str) -> Url {
    Url::parse(raw).expect("valid endpoint URL")
}

fn text(uri: &hyper::Uri) -> String {
    uri.to_string()
}

#[test]
fn an_origin_only_endpoint_uses_the_route_path() {
    let route = route(
        ProtocolType::OpenAi,
        Method::POST,
        OPENAI_CHAT_COMPLETIONS_PATH,
    );
    let uri = build_upstream_uri(&endpoint("https://api.example.com"), &route, None)
        .expect("upstream URI");

    assert_eq!(text(&uri), "https://api.example.com/v1/chat/completions");
}

#[test]
fn a_base_path_prefix_is_preserved() {
    let route = route(ProtocolType::OpenAi, Method::POST, OPENAI_RESPONSES_PATH);
    for raw in [
        "https://api.example.com/proxy",
        "https://api.example.com/proxy/",
    ] {
        let uri = build_upstream_uri(&endpoint(raw), &route, None).expect("upstream URI");
        assert_eq!(
            text(&uri),
            "https://api.example.com/proxy/v1/responses",
            "expected {raw:?} to keep its prefix without doubling a slash"
        );
    }
}

#[test]
fn a_multi_segment_prefix_is_preserved() {
    let route = route(
        ProtocolType::Anthropic,
        Method::POST,
        ANTHROPIC_MESSAGES_PATH,
    );
    let uri = build_upstream_uri(
        &endpoint("https://api.example.com/gateway/anthropic"),
        &route,
        None,
    )
    .expect("upstream URI");

    assert_eq!(
        text(&uri),
        "https://api.example.com/gateway/anthropic/v1/messages"
    );
}

#[test]
fn the_authority_and_non_default_port_are_preserved() {
    let route = route(ProtocolType::OpenAi, Method::POST, OPENAI_RESPONSES_PATH);
    let uri = build_upstream_uri(
        &endpoint("https://api.example.com:8443/proxy"),
        &route,
        None,
    )
    .expect("upstream URI");

    assert_eq!(
        text(&uri),
        "https://api.example.com:8443/proxy/v1/responses"
    );
}

#[test]
fn every_allowed_route_joins_onto_the_prefix() {
    let endpoint = endpoint("https://api.example.com/proxy");
    let cases = [
        (
            route(
                ProtocolType::OpenAi,
                Method::POST,
                OPENAI_CHAT_COMPLETIONS_PATH,
            ),
            "https://api.example.com/proxy/v1/chat/completions",
        ),
        (
            route(ProtocolType::OpenAi, Method::POST, OPENAI_RESPONSES_PATH),
            "https://api.example.com/proxy/v1/responses",
        ),
        (
            websocket_route(),
            "https://api.example.com/proxy/v1/responses",
        ),
        (
            route(
                ProtocolType::Anthropic,
                Method::POST,
                ANTHROPIC_MESSAGES_PATH,
            ),
            "https://api.example.com/proxy/v1/messages",
        ),
    ];

    for (route, expected) in cases {
        let uri = build_upstream_uri(&endpoint, &route, None).expect("upstream URI");
        assert_eq!(text(&uri), expected);
    }
}

#[test]
fn the_query_string_is_forwarded_byte_for_byte() {
    let route = route(ProtocolType::OpenAi, Method::POST, OPENAI_RESPONSES_PATH);
    let endpoint = endpoint("https://api.example.com/proxy");
    for query in [
        "a=%20b&c=+d",
        "x=1&&y=2&",
        "%7E%2F%3D%26",
        "empty=&=value",
        "utf8=%E4%B8%AD%E6%96%87",
        "inner=/v1/responses?nested=1",
    ] {
        let uri = build_upstream_uri(&endpoint, &route, Some(query)).expect("upstream URI");
        assert_eq!(
            uri.query(),
            Some(query),
            "expected the query to round-trip verbatim"
        );
        assert_eq!(
            text(&uri),
            format!("https://api.example.com/proxy/v1/responses?{query}")
        );
    }
}

#[test]
fn a_request_without_a_query_has_no_question_mark() {
    let route = route(ProtocolType::OpenAi, Method::POST, OPENAI_RESPONSES_PATH);
    let uri = build_upstream_uri(&endpoint("https://api.example.com"), &route, None)
        .expect("upstream URI");

    assert_eq!(uri.query(), None);
    assert!(!text(&uri).contains('?'));
}

#[test]
fn dot_segments_are_canonicalized_and_escapes_are_rejected() {
    let endpoint = endpoint("https://api.example.com/proxy");

    let normalized = resolve_route(
        ProtocolType::OpenAi,
        &Method::POST,
        "/v1/../v1/responses",
        &HeaderMap::new(),
    )
    .expect("normalizable route");
    let uri = build_upstream_uri(&endpoint, &normalized, None).expect("upstream URI");
    assert_eq!(text(&uri), "https://api.example.com/proxy/v1/responses");

    assert_eq!(
        resolve_route(
            ProtocolType::OpenAi,
            &Method::POST,
            "/../v1/responses",
            &HeaderMap::new(),
        ),
        Err(RouteError::UnsupportedRoute)
    );
}

#[test]
fn a_failure_does_not_reveal_the_query_string() {
    let route = route(ProtocolType::OpenAi, Method::POST, OPENAI_RESPONSES_PATH);
    let query = "secret=leaked-value";

    for endpoint in [
        endpoint("https://api.example.com?token=1"),
        endpoint("https://user:pass@api.example.com"),
    ] {
        let error =
            build_upstream_uri(&endpoint, &route, Some(query)).expect_err("endpoint is rejected");
        assert_eq!(error, TargetError::InvalidEndpoint);
        assert!(!format!("{error}").contains(query));
        assert!(!format!("{error:?}").contains(query));
    }
}
