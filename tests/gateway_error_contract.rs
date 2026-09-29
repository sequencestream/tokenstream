//! Local gateway error contract.
//!
//! These tests pin the stable code, HTTP status, and sanitized message for every
//! class of gateway-originated failure, and verify that the rendered envelope
//! carries only the fixed error fields plus the internal request ID. Nothing
//! here contacts an upstream, so a failure is always a local contract failure.

use std::collections::BTreeSet;

use tokenstream::auth::GatewayAuthError;
use tokenstream::domain::RequestId;
use tokenstream::proxy::error::{ERROR_CONTENT_TYPE, GatewayError};
use tokenstream::proxy::headers::HeaderError;
use tokenstream::routing::{RouteError, TargetError};

fn request_id(value: &str) -> RequestId {
    RequestId::new(value).expect("non-empty request ID")
}

fn parse(error: GatewayError, id: &str) -> serde_json::Value {
    let body = error.render(&request_id(id));
    serde_json::from_slice(&body).expect("the envelope is valid JSON")
}

#[test]
fn every_error_class_has_a_stable_code_status_and_message() {
    let expected = [
        (GatewayError::InvalidGatewayCredential, 401),
        (GatewayError::ProviderDisabled, 403),
        (GatewayError::UnsupportedRoute, 404),
        (GatewayError::InvalidUpgrade, 400),
        (GatewayError::UpstreamConnectFailed, 502),
        (GatewayError::UpstreamTimeout, 504),
        (GatewayError::ConnectionLimitReached, 503),
        (GatewayError::ResourceExhausted, 503),
        (GatewayError::InternalError, 500),
    ];

    for (error, status) in expected {
        assert_eq!(error.status().as_u16(), status, "status for {error:?}");

        let envelope = parse(error, "req_contract");
        assert_eq!(envelope["error"]["code"], error.code());
        assert_eq!(envelope["error"]["message"], error.message());
        assert_eq!(envelope["error"]["request_id"], "req_contract");
    }

    assert_eq!(ERROR_CONTENT_TYPE, "application/json");
}

#[test]
fn the_code_set_is_exactly_the_documented_data_plane_contract() {
    // There is no variant that carries an upstream status, body, or message, so
    // an upstream response can never be wrapped in a local error.
    let codes: BTreeSet<&'static str> = [
        GatewayError::InvalidGatewayCredential,
        GatewayError::ProviderDisabled,
        GatewayError::UnsupportedRoute,
        GatewayError::InvalidUpgrade,
        GatewayError::UpstreamConnectFailed,
        GatewayError::UpstreamTimeout,
        GatewayError::ConnectionLimitReached,
        GatewayError::ResourceExhausted,
        GatewayError::InternalError,
    ]
    .into_iter()
    .map(GatewayError::code)
    .collect();

    assert_eq!(
        codes,
        BTreeSet::from([
            "invalid_gateway_credential",
            "provider_disabled",
            "unsupported_route",
            "invalid_upgrade",
            "upstream_connect_failed",
            "upstream_timeout",
            "connection_limit_reached",
            "resource_exhausted",
            "internal_error",
        ])
    );
}

#[test]
fn authentication_and_route_failures_classify_into_the_contract() {
    let credential_failures = [
        GatewayAuthError::MissingCredential,
        GatewayAuthError::DuplicateCredential,
        GatewayAuthError::ConflictingCredential,
        GatewayAuthError::MalformedCredential,
        GatewayAuthError::UnknownCredential,
        GatewayAuthError::InvalidCredential,
    ];
    for failure in credential_failures {
        assert_eq!(
            GatewayError::from(failure),
            GatewayError::InvalidGatewayCredential,
            "classification for {failure:?}"
        );
    }

    assert_eq!(
        GatewayError::from(GatewayAuthError::ProviderDisabled),
        GatewayError::ProviderDisabled
    );
    assert_eq!(
        GatewayError::from(GatewayAuthError::Busy),
        GatewayError::ResourceExhausted
    );
    assert_eq!(
        GatewayError::from(GatewayAuthError::Unavailable),
        GatewayError::InternalError
    );

    assert_eq!(
        GatewayError::from(RouteError::UnsupportedRoute),
        GatewayError::UnsupportedRoute
    );
    assert_eq!(
        GatewayError::from(RouteError::InvalidUpgrade),
        GatewayError::InvalidUpgrade
    );

    // A local configuration fault is never surfaced as a client error.
    assert_eq!(
        GatewayError::from(TargetError::InvalidPath),
        GatewayError::InternalError
    );
    assert_eq!(
        GatewayError::from(HeaderError::InvalidUpstreamKey),
        GatewayError::InternalError
    );
}

#[test]
fn hostile_upstream_text_never_reaches_a_local_message() {
    let upstream_text = "upstream leaked model=secret sk-upstream-token\n{\"error\":\"boom\"}";
    let request_id = request_id("req_upstream");

    for error in [
        GatewayError::InvalidGatewayCredential,
        GatewayError::ProviderDisabled,
        GatewayError::UnsupportedRoute,
        GatewayError::InvalidUpgrade,
        GatewayError::UpstreamConnectFailed,
        GatewayError::UpstreamTimeout,
        GatewayError::ConnectionLimitReached,
        GatewayError::ResourceExhausted,
        GatewayError::InternalError,
    ] {
        let body = error.render(&request_id);
        let rendered = String::from_utf8(body.to_vec()).expect("the envelope is UTF-8");

        assert!(
            !rendered.contains(upstream_text),
            "upstream text leaked into {error:?}"
        );
        assert!(
            !rendered.contains("sk-upstream-token"),
            "an upstream secret leaked into {error:?}"
        );
        // The only request-dependent field is the request ID.
        let envelope = parse(error, "req_upstream");
        assert_eq!(envelope["error"]["code"], error.code());
        assert_eq!(envelope["error"]["message"], error.message());
    }
}

#[test]
fn the_request_id_is_the_only_variable_field_and_is_escaped() {
    let error = GatewayError::UnsupportedRoute;

    let first = parse(error, "req_a");
    let second = parse(error, "req_b");

    assert_eq!(first["error"]["code"], second["error"]["code"]);
    assert_eq!(first["error"]["message"], second["error"]["message"]);
    assert_ne!(first["error"]["request_id"], second["error"]["request_id"]);

    let hostile = "req\"}\" , \"injected\": true, \"x\": \"";
    let envelope = parse(error, hostile);
    assert_eq!(envelope["error"]["request_id"], hostile);
    assert_eq!(envelope["error"].as_object().expect("object").len(), 3);
}
