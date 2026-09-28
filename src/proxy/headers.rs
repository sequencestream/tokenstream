//! Bidirectional hop-by-hop, forwarding, and credential header policy.
//!
//! The policy is a pure function of the inbound headers, the request-local
//! provider snapshot, and the direct downstream peer. It never reads a body and
//! performs no I/O, so it is safe to run on the hot path before any upstream
//! contact.
//!
//! Two rules govern every request:
//!
//! - Hop-by-hop headers, headers nominated by `Connection`, and the untrusted
//!   inbound forwarding chain are dropped. The only forwarding information the
//!   gateway adds is a single `X-Forwarded-For` value derived from the direct
//!   downstream peer, so a caller cannot forge a chain the gateway trusts.
//! - The provider-native credential header is replaced in place: the gateway key
//!   never reaches an upstream, and the upstream key never reaches a downstream.
//!   A duplicate native header, or the other provider's native header, is
//!   rejected so two credentials can never both survive to an upstream.
//!
//! Responses travel the other way with the same hop-by-hop discipline: an
//! upstream response is relayed only after its hop-by-hop headers are removed.
//! No error or rendered header produced here carries a credential value.

use std::error::Error;
use std::fmt;
use std::net::SocketAddr;

use hyper::HeaderMap;
use hyper::header::{AUTHORIZATION, CONNECTION, HOST, HeaderName, HeaderValue};
use url::Url;

use crate::domain::{ProtocolType, ProviderSnapshot};

/// Header carrying the gateway credential on Anthropic-native routes.
const ANTHROPIC_CREDENTIAL_HEADER: HeaderName = HeaderName::from_static("x-api-key");
/// Header the gateway sets to the direct downstream peer address.
const FORWARDED_FOR_HEADER: HeaderName = HeaderName::from_static("x-forwarded-for");
/// Authorization scheme token that precedes an OpenAI-native credential.
const BEARER_SCHEME: &str = "Bearer";

/// A rejected header transformation that carries no credential material.
///
/// The variants hold no header value, so an error can be surfaced or logged
/// without echoing a gateway key, an upstream key, or a forwarding chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderError {
    /// No provider-native credential header was supplied.
    MissingCredential,
    /// A provider-native credential header appeared more than once.
    DuplicateCredential,
    /// The credential header does not match the resolved provider protocol.
    ConflictingCredential,
    /// The upstream key cannot be represented as an outbound header value.
    InvalidUpstreamKey,
    /// The configured endpoint cannot produce an upstream authority.
    InvalidUpstreamAuthority,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MissingCredential => "the provider-native credential header is missing",
            Self::DuplicateCredential => "the provider-native credential header is duplicated",
            Self::ConflictingCredential => "the credential header does not match the provider",
            Self::InvalidUpstreamKey => "the upstream credential cannot be forwarded",
            Self::InvalidUpstreamAuthority => "the upstream authority cannot be forwarded",
        };
        formatter.write_str(message)
    }
}

impl Error for HeaderError {}

/// Builds the headers that are forwarded to the configured upstream.
///
/// The result keeps every end-to-end header except the inbound forwarding chain,
/// which is replaced by one `X-Forwarded-For` value for `downstream_peer`. The
/// provider-native credential header is replaced with the snapshot's upstream
/// key, and `Host` is set from the endpoint authority.
///
/// A missing, duplicated, or protocol-mismatched credential header is rejected
/// before any value is produced. Neither the inbound gateway key nor the
/// decrypted upstream key is included in a returned error.
pub fn build_upstream_request_headers(
    snapshot: &ProviderSnapshot,
    inbound: &HeaderMap,
    downstream_peer: SocketAddr,
) -> Result<HeaderMap, HeaderError> {
    require_single_native_credential(snapshot.protocol_type(), inbound)?;

    let nominated = connection_nominated_names(inbound);
    let mut outbound = HeaderMap::new();
    for (name, value) in inbound.iter() {
        if is_hop_by_hop(name) || nominated.contains(name) || is_untrusted_forwarding(name) {
            continue;
        }
        outbound.append(name.clone(), value.clone());
    }

    set_forwarded_for(&mut outbound, downstream_peer);

    match snapshot.protocol_type() {
        ProtocolType::OpenAi => {
            let mut rendered = String::from(BEARER_SCHEME);
            rendered.push(' ');
            rendered.push_str(snapshot.upstream_api_key().expose());
            outbound.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&rendered).map_err(|_| HeaderError::InvalidUpstreamKey)?,
            );
        }
        ProtocolType::Anthropic => {
            outbound.insert(
                ANTHROPIC_CREDENTIAL_HEADER,
                HeaderValue::from_str(snapshot.upstream_api_key().expose())
                    .map_err(|_| HeaderError::InvalidUpstreamKey)?,
            );
        }
    }

    outbound.insert(
        HOST,
        HeaderValue::from_str(&upstream_authority(snapshot.endpoint())?)
            .map_err(|_| HeaderError::InvalidUpstreamAuthority)?,
    );

    Ok(outbound)
}

/// Builds the headers that are relayed to the downstream client.
///
/// Upstream response headers pass through untouched except that hop-by-hop
/// headers and headers nominated by `Connection` are removed. The response body
/// is never inspected, so an upstream error body is relayed as received.
pub fn build_downstream_response_headers(upstream: &HeaderMap) -> HeaderMap {
    let nominated = connection_nominated_names(upstream);
    let mut downstream = HeaderMap::new();
    for (name, value) in upstream.iter() {
        if is_hop_by_hop(name) || nominated.contains(name) {
            continue;
        }
        downstream.append(name.clone(), value.clone());
    }
    downstream
}

/// Requires exactly one credential header, and the one the protocol uses.
///
/// This restates the authentication invariant as a pure precondition so the
/// header builder is safe to call on its own: two native headers can never both
/// reach an upstream, and a credential for the wrong provider is rejected.
fn require_single_native_credential(
    protocol_type: ProtocolType,
    headers: &HeaderMap,
) -> Result<(), HeaderError> {
    let authorization = headers.get_all(AUTHORIZATION).iter().count();
    let api_key = headers.get_all(ANTHROPIC_CREDENTIAL_HEADER).iter().count();

    match (authorization, api_key) {
        (0, 0) => return Err(HeaderError::MissingCredential),
        (count, _) if count > 1 => return Err(HeaderError::DuplicateCredential),
        (_, count) if count > 1 => return Err(HeaderError::DuplicateCredential),
        (1, 1) => return Err(HeaderError::ConflictingCredential),
        _ => {}
    }

    match protocol_type {
        ProtocolType::OpenAi if authorization == 1 => Ok(()),
        ProtocolType::Anthropic if api_key == 1 => Ok(()),
        _ => Err(HeaderError::ConflictingCredential),
    }
}

/// Reports whether `name` is a fixed hop-by-hop header.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Reports whether `name` is part of an untrusted inbound forwarding chain.
fn is_untrusted_forwarding(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-real-ip"
    )
}

/// Collects the header names nominated by every `Connection` header value.
fn connection_nominated_names(headers: &HeaderMap) -> Vec<HeaderName> {
    let mut names = Vec::new();
    for value in headers.get_all(CONNECTION) {
        let Ok(rendered) = value.to_str() else {
            continue;
        };
        for token in rendered.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                names.push(name);
            }
        }
    }
    names
}

/// Sets `X-Forwarded-For` to the single direct downstream peer address.
fn set_forwarded_for(headers: &mut HeaderMap, peer: SocketAddr) {
    let value = HeaderValue::from_str(&peer.ip().to_string())
        .expect("an IP address is always a valid header value");
    headers.insert(FORWARDED_FOR_HEADER, value);
}

/// Returns the `host[:port]` authority of the configured endpoint.
fn upstream_authority(endpoint: &Url) -> Result<String, HeaderError> {
    let host = endpoint
        .host_str()
        .ok_or(HeaderError::InvalidUpstreamAuthority)?;
    Ok(match endpoint.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ProviderId, SecretString};

    fn header(name: &str, value: &str) -> (HeaderName, HeaderValue) {
        (
            HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
            HeaderValue::from_str(value).expect("valid header value"),
        )
    }

    fn snapshot(protocol_type: ProtocolType, endpoint: &str, key: &str) -> ProviderSnapshot {
        ProviderSnapshot::new(
            ProviderId::try_from(1).expect("positive ID"),
            protocol_type,
            Url::parse(endpoint).expect("valid endpoint"),
            SecretString::new(key),
        )
    }

    #[test]
    fn hop_by_hop_membership_is_exact() {
        for name in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(
                is_hop_by_hop(&HeaderName::from_bytes(name.as_bytes()).expect("valid name")),
                "expected {name:?} to be hop-by-hop"
            );
        }
        for name in ["authorization", "content-type", "anthropic-version", "host"] {
            assert!(
                !is_hop_by_hop(&HeaderName::from_bytes(name.as_bytes()).expect("valid name")),
                "expected {name:?} to be end-to-end"
            );
        }
    }

    #[test]
    fn the_authority_keeps_only_a_non_default_port() {
        assert_eq!(
            upstream_authority(&Url::parse("https://api.example.com").expect("valid URL")),
            Ok("api.example.com".to_owned())
        );
        assert_eq!(
            upstream_authority(&Url::parse("https://api.example.com:8443/proxy").expect("URL")),
            Ok("api.example.com:8443".to_owned())
        );
        assert_eq!(
            upstream_authority(&Url::parse("http://api.example.com:80").expect("valid URL")),
            Ok("api.example.com".to_owned())
        );
    }

    #[test]
    fn an_ipv6_authority_keeps_its_brackets() {
        assert_eq!(
            upstream_authority(&Url::parse("http://[::1]:8080").expect("valid URL")),
            Ok("[::1]:8080".to_owned())
        );
    }

    #[test]
    fn connection_named_headers_are_collected_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, X-Hop"));
        headers.append(CONNECTION, HeaderValue::from_static("X-Second"));

        let names = connection_nominated_names(&headers);
        for expected in ["x-hop", "x-second"] {
            assert!(
                names.iter().any(|name| name.as_str() == expected),
                "expected {expected:?} to be nominated"
            );
        }
    }

    #[test]
    fn a_mismatched_protocol_header_is_rejected() {
        let openai = snapshot(ProtocolType::OpenAi, "https://api.example.com", "upstream");
        let mut inbound = HeaderMap::new();
        let (name, value) = header("x-api-key", "gateway-key");
        inbound.insert(name, value);

        assert_eq!(
            build_upstream_request_headers(
                &openai,
                &inbound,
                "203.0.113.7:5555".parse().expect("socket address"),
            ),
            Err(HeaderError::ConflictingCredential)
        );
    }

    #[test]
    fn an_unforwardable_upstream_key_leaks_no_value() {
        let snapshot = snapshot(
            ProtocolType::OpenAi,
            "https://api.example.com",
            "sup3r-secret\ninjected",
        );
        let mut inbound = HeaderMap::new();
        let (name, value) = header("authorization", "Bearer gateway-key");
        inbound.insert(name, value);

        let error = build_upstream_request_headers(
            &snapshot,
            &inbound,
            "203.0.113.7:5555".parse().expect("socket address"),
        )
        .expect_err("a control character cannot be forwarded");

        assert_eq!(error, HeaderError::InvalidUpstreamKey);
        assert!(!format!("{error}").contains("sup3r-secret"));
        assert!(!format!("{error:?}").contains("injected"));
        assert!(!format!("{error}").contains("gateway-key"));
    }
}
