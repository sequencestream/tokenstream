//! Stable, sanitized local error contract for the data plane.
//!
//! Every failure the gateway originates before it has received an upstream
//! response is represented by one [`GatewayError`] variant. A variant fixes
//! three things at compile time: the machine-readable [`code`], the HTTP
//! [`status`], and a human-readable [`message`]. All three are constants, so an
//! error can be rendered or logged without echoing a credential, a query
//! string, an application body, or any upstream text.
//!
//! The contract covers failures that occur before an upstream response is
//! received. Once upstream response headers arrive — including a rejected
//! WebSocket handshake — the gateway forwards that status and body unchanged
//! and never wraps it in this envelope. There is deliberately no variant that
//! carries an upstream status, body, or message, so upstream text cannot enter a
//! local error by construction.
//!
//! [`code`]: GatewayError::code
//! [`status`]: GatewayError::status
//! [`message`]: GatewayError::message

use std::error::Error;
use std::fmt;

use bytes::Bytes;
use hyper::StatusCode;
use serde::Serialize;

use crate::auth::GatewayAuthError;
use crate::domain::RequestId;
use crate::proxy::headers::HeaderError;
use crate::routing::{RouteError, TargetError};
use crate::telemetry::ProxyFailureCategory;

/// Media type of the local error envelope.
pub const ERROR_CONTENT_TYPE: &str = "application/json";

/// A gateway-originated failure that occurs before any upstream response.
///
/// The variants group failures by the class a client can act on. Component
/// errors are mapped onto this set so the same class of failure always produces
/// the same code and status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayError {
    /// A missing, duplicate, conflicting, malformed, unknown, or wrong credential.
    InvalidGatewayCredential,
    /// The credential resolved a provider that is disabled.
    ProviderDisabled,
    /// The account that owns the presented credential is disabled.
    AccountDisabled,
    /// The presented credential carries an expiration that has passed.
    KeyExpired,
    /// The credential selected no provider and carries no default binding.
    NoProviderSelected,
    /// The provider cannot serve the requested method, path, or transport.
    UnsupportedRoute,
    /// The request carried an upgrade that is not the one supported upgrade.
    InvalidUpgrade,
    /// The upstream connection failed before any response was received.
    UpstreamConnectFailed,
    /// The upstream did not answer within the configured timeout.
    UpstreamTimeout,
    /// The admission limit for proxy connections is full.
    ConnectionLimitReached,
    /// Compute or storage capacity for this request is exhausted.
    ResourceExhausted,
    /// A local configuration or processing failure whose detail is withheld.
    InternalError,
}

impl GatewayError {
    /// Stable machine-readable code reported in the local error envelope.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidGatewayCredential => "invalid_gateway_credential",
            Self::ProviderDisabled => "provider_disabled",
            Self::AccountDisabled => "account_disabled",
            Self::KeyExpired => "key_expired",
            Self::NoProviderSelected => "no_provider_selected",
            Self::UnsupportedRoute => "unsupported_route",
            Self::InvalidUpgrade => "invalid_upgrade",
            Self::UpstreamConnectFailed => "upstream_connect_failed",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::ConnectionLimitReached => "connection_limit_reached",
            Self::ResourceExhausted => "resource_exhausted",
            Self::InternalError => "internal_error",
        }
    }

    /// HTTP status reported for this failure class.
    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidGatewayCredential => StatusCode::UNAUTHORIZED,
            Self::ProviderDisabled => StatusCode::FORBIDDEN,
            Self::AccountDisabled => StatusCode::FORBIDDEN,
            Self::KeyExpired => StatusCode::UNAUTHORIZED,
            Self::NoProviderSelected => StatusCode::BAD_REQUEST,
            Self::UnsupportedRoute => StatusCode::NOT_FOUND,
            Self::InvalidUpgrade => StatusCode::BAD_REQUEST,
            Self::UpstreamConnectFailed => StatusCode::BAD_GATEWAY,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::ConnectionLimitReached => StatusCode::SERVICE_UNAVAILABLE,
            Self::ResourceExhausted => StatusCode::SERVICE_UNAVAILABLE,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The fine result category this failure is recorded under.
    ///
    /// The function is total over the closed set, so every gateway-originated
    /// failure is classified and none is counted nowhere. Placing it here rather
    /// than at each call site is what makes totality a property of the error
    /// contract: a new variant cannot be added without a decision about which
    /// category it belongs to, and a partial match at one call site cannot
    /// silently stop counting a failure the exposition already has a series for.
    pub const fn category(self) -> ProxyFailureCategory {
        match self {
            Self::InvalidGatewayCredential => ProxyFailureCategory::InvalidGatewayCredential,
            Self::ProviderDisabled => ProxyFailureCategory::ProviderDisabled,
            Self::AccountDisabled => ProxyFailureCategory::AccountDisabled,
            Self::KeyExpired => ProxyFailureCategory::KeyExpired,
            Self::NoProviderSelected => ProxyFailureCategory::NoProviderSelected,
            Self::UnsupportedRoute => ProxyFailureCategory::UnsupportedRoute,
            Self::InvalidUpgrade => ProxyFailureCategory::InvalidUpgrade,
            Self::UpstreamConnectFailed => ProxyFailureCategory::UpstreamConnectFailed,
            Self::UpstreamTimeout => ProxyFailureCategory::UpstreamTimeout,
            Self::ConnectionLimitReached => ProxyFailureCategory::ConnectionLimitReached,
            Self::ResourceExhausted => ProxyFailureCategory::ResourceExhausted,
            Self::InternalError => ProxyFailureCategory::InternalError,
        }
    }

    /// Constant, sanitized message reported for this failure class.
    ///
    /// The value never depends on the request, a credential, or upstream text.
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidGatewayCredential => "The gateway credential is invalid.",
            Self::ProviderDisabled => "The provider is disabled.",
            Self::AccountDisabled => "The account is disabled.",
            Self::KeyExpired => "The gateway credential has expired.",
            Self::NoProviderSelected => "No provider is selected for this credential.",
            Self::UnsupportedRoute => "The requested route is not available for this provider.",
            Self::InvalidUpgrade => "The requested WebSocket upgrade is not valid.",
            Self::UpstreamConnectFailed => "The upstream connection failed.",
            Self::UpstreamTimeout => "The upstream request timed out.",
            Self::ConnectionLimitReached => "The gateway is at its connection limit.",
            Self::ResourceExhausted => "The gateway has no spare capacity for this request.",
            Self::InternalError => "The gateway encountered an internal error.",
        }
    }

    /// Renders the stable JSON envelope carrying this code, message, and the
    /// internal request ID.
    ///
    /// The request ID is the only caller-supplied value in the result; it is
    /// encoded by the serializer, so no byte of it can break the envelope.
    pub fn render(self, request_id: &RequestId) -> Bytes {
        #[derive(Serialize)]
        struct Envelope<'a> {
            error: Detail<'a>,
        }

        #[derive(Serialize)]
        struct Detail<'a> {
            code: &'static str,
            message: &'static str,
            request_id: &'a str,
        }

        let envelope = Envelope {
            error: Detail {
                code: self.code(),
                message: self.message(),
                request_id: request_id.as_str(),
            },
        };
        let encoded = serde_json::to_vec(&envelope)
            .expect("a fixed error envelope with a text request ID is serializable");
        Bytes::from(encoded)
    }
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for GatewayError {}

impl From<GatewayAuthError> for GatewayError {
    fn from(error: GatewayAuthError) -> Self {
        match error {
            GatewayAuthError::MissingCredential
            | GatewayAuthError::DuplicateCredential
            | GatewayAuthError::ConflictingCredential
            | GatewayAuthError::MalformedCredential
            | GatewayAuthError::UnknownCredential
            | GatewayAuthError::InvalidCredential => Self::InvalidGatewayCredential,
            GatewayAuthError::ProviderDisabled => Self::ProviderDisabled,
            GatewayAuthError::AccountDisabled => Self::AccountDisabled,
            GatewayAuthError::KeyExpired => Self::KeyExpired,
            GatewayAuthError::NoProviderSelected => Self::NoProviderSelected,
            GatewayAuthError::Busy => Self::ResourceExhausted,
            GatewayAuthError::Unavailable => Self::InternalError,
        }
    }
}

impl From<RouteError> for GatewayError {
    fn from(error: RouteError) -> Self {
        match error {
            RouteError::UnsupportedRoute => Self::UnsupportedRoute,
            RouteError::InvalidUpgrade => Self::InvalidUpgrade,
        }
    }
}

impl From<TargetError> for GatewayError {
    fn from(_error: TargetError) -> Self {
        // The route is validated before target construction, so a join failure
        // is a local configuration or processing fault, not client input.
        Self::InternalError
    }
}

impl From<HeaderError> for GatewayError {
    fn from(error: HeaderError) -> Self {
        match error {
            HeaderError::MissingCredential
            | HeaderError::DuplicateCredential
            | HeaderError::ConflictingCredential => Self::InvalidGatewayCredential,
            HeaderError::InvalidUpstreamKey | HeaderError::InvalidUpstreamAuthority => {
                Self::InternalError
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_id(value: &str) -> RequestId {
        RequestId::new(value).expect("non-empty request ID")
    }

    #[test]
    fn every_variant_has_a_distinct_code_and_expected_status() {
        let expected = [
            (GatewayError::InvalidGatewayCredential, 401),
            (GatewayError::ProviderDisabled, 403),
            (GatewayError::AccountDisabled, 403),
            (GatewayError::KeyExpired, 401),
            (GatewayError::NoProviderSelected, 400),
            (GatewayError::UnsupportedRoute, 404),
            (GatewayError::InvalidUpgrade, 400),
            (GatewayError::UpstreamConnectFailed, 502),
            (GatewayError::UpstreamTimeout, 504),
            (GatewayError::ConnectionLimitReached, 503),
            (GatewayError::ResourceExhausted, 503),
            (GatewayError::InternalError, 500),
        ];

        let mut codes = std::collections::BTreeSet::new();
        for (error, status) in expected {
            assert_eq!(error.status().as_u16(), status, "status for {error:?}");
            assert!(!error.code().is_empty());
            assert!(!error.message().is_empty());
            assert!(
                codes.insert(error.code()),
                "duplicate code {:?}",
                error.code()
            );
        }
    }

    #[test]
    fn codes_are_snake_case_tokens() {
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
            assert!(
                error
                    .code()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "code {:?} is not a snake_case token",
                error.code()
            );
        }
    }

    #[test]
    fn credential_errors_classify_as_invalid_gateway_credential() {
        for error in [
            GatewayAuthError::MissingCredential,
            GatewayAuthError::DuplicateCredential,
            GatewayAuthError::ConflictingCredential,
            GatewayAuthError::MalformedCredential,
            GatewayAuthError::UnknownCredential,
            GatewayAuthError::InvalidCredential,
        ] {
            assert_eq!(
                GatewayError::from(error),
                GatewayError::InvalidGatewayCredential,
                "classification for {error:?}"
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
    }

    #[test]
    fn route_errors_keep_their_own_codes() {
        assert_eq!(
            GatewayError::from(RouteError::UnsupportedRoute),
            GatewayError::UnsupportedRoute
        );
        assert_eq!(
            GatewayError::from(RouteError::InvalidUpgrade),
            GatewayError::InvalidUpgrade
        );
    }

    #[test]
    fn configuration_failures_classify_as_internal() {
        assert_eq!(
            GatewayError::from(TargetError::InvalidEndpoint),
            GatewayError::InternalError
        );
        assert_eq!(
            GatewayError::from(TargetError::InvalidQuery),
            GatewayError::InternalError
        );
        assert_eq!(
            GatewayError::from(HeaderError::InvalidUpstreamKey),
            GatewayError::InternalError
        );
        assert_eq!(
            GatewayError::from(HeaderError::InvalidUpstreamAuthority),
            GatewayError::InternalError
        );
        assert_eq!(
            GatewayError::from(HeaderError::MissingCredential),
            GatewayError::InvalidGatewayCredential
        );
    }

    #[test]
    fn render_produces_the_stable_envelope() {
        let body = GatewayError::UnsupportedRoute.render(&request_id("req_01JTEST"));
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");

        assert_eq!(parsed["error"]["code"], "unsupported_route");
        assert_eq!(
            parsed["error"]["message"],
            "The requested route is not available for this provider."
        );
        assert_eq!(parsed["error"]["request_id"], "req_01JTEST");
        assert_eq!(parsed["error"].as_object().expect("object").len(), 3);
    }

    #[test]
    fn render_escapes_a_hostile_request_id_without_adding_fields() {
        let hostile = "req\"}\" , \"injected\": true, \"x\": \"";
        let body = GatewayError::InvalidGatewayCredential.render(&request_id(hostile));
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");

        assert_eq!(parsed["error"]["request_id"], hostile);
        assert_eq!(parsed["error"].as_object().expect("object").len(), 3);
    }
}
