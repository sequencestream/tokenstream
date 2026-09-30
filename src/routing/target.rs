//! Upstream request-target construction.
//!
//! A configured provider endpoint is an origin plus an optional base-path
//! prefix. The proxy joins that prefix with the normalized, validated request
//! path and appends the original query string byte for byte. The join is a pure
//! string operation: it keeps the prefix instead of discarding it, rejects a
//! prefix or path that is not already rooted and free of dot segments, and never
//! re-encodes, reorders, or drops query bytes. A query string is forwarded
//! unchanged and never appears in an error, so it may carry caller values
//! without leaking them.

use std::error::Error;
use std::fmt;

use hyper::Uri;
use url::Url;

use super::{ResolvedRoute, normalize_path};

/// A failure to build an upstream request target.
///
/// The variants carry no endpoint, path, or query value, so a failure can be
/// surfaced or logged without echoing a query string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetError {
    /// The endpoint is not an HTTP(S) origin with an optional base-path prefix.
    InvalidEndpoint,
    /// The endpoint base-path prefix is not a rooted, dot-free path.
    InvalidPrefix,
    /// The validated request path is not a rooted, dot-free normalized path.
    InvalidPath,
    /// The query string is not a raw query value.
    InvalidQuery,
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEndpoint => "the provider endpoint cannot be used as an origin",
            Self::InvalidPrefix => "the provider endpoint base path is not safe to join",
            Self::InvalidPath => "the request path is not safe to join",
            Self::InvalidQuery => "the request query string is not valid",
        };
        formatter.write_str(message)
    }
}

impl Error for TargetError {}

/// Builds the upstream request URI for one proxied request.
///
/// `endpoint` supplies the scheme, authority, and optional base-path prefix;
/// `route` supplies the normalized, validated request path; and `query` is the
/// original query string without its leading `?`, appended verbatim. The caller
/// must not record `query` or the returned URI, because a query string may carry
/// secrets. Every failure returns before a value is produced and mentions no
/// query bytes.
pub fn build_upstream_uri(
    endpoint: &Url,
    route: &ResolvedRoute,
    query: Option<&str>,
) -> Result<Uri, TargetError> {
    let origin = origin(endpoint)?;
    let prefix = base_path_prefix(endpoint.path())?;
    let path = route.path();
    if normalize_path(path).map_err(|_| TargetError::InvalidPath)? != path {
        return Err(TargetError::InvalidPath);
    }

    let mut target = String::with_capacity(
        origin.len() + prefix.len() + path.len() + query.map_or(0, |value| value.len() + 1),
    );
    target.push_str(&origin);
    target.push_str(prefix);
    target.push_str(path);
    if let Some(query) = query {
        validate_query(query)?;
        target.push('?');
        target.push_str(query);
    }

    target.parse().map_err(|_| TargetError::InvalidPath)
}

/// Builds the request URI for one health probe.
///
/// A probe target is a configured URL in its own right rather than an endpoint
/// joined with a validated data-plane path, because it is not a proxied request:
/// there is no route, no snapshot, and no caller behind it. The same origin and
/// prefix rules apply, so a target that could not be a provider endpoint cannot
/// be a probe target either, and no user information, query, or fragment is
/// ever sent. An empty path becomes the origin root.
pub fn build_probe_uri(target: &Url) -> Result<Uri, TargetError> {
    let origin = origin(target)?;
    let prefix = base_path_prefix(target.path())?;
    let mut uri = String::with_capacity(origin.len() + prefix.len());
    uri.push_str(&origin);
    uri.push_str(if prefix.is_empty() { "/" } else { prefix });
    uri.parse().map_err(|_| TargetError::InvalidPath)
}

/// Returns the endpoint origin (`scheme://authority`) with no user information.
fn origin(endpoint: &Url) -> Result<String, TargetError> {
    if !matches!(endpoint.scheme(), "http" | "https")
        || !endpoint.has_host()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(TargetError::InvalidEndpoint);
    }
    Ok(endpoint.origin().ascii_serialization())
}

/// Returns the base-path prefix placed before the request path.
///
/// The result is empty for a root prefix and otherwise begins with `/` and ends
/// with a non-slash, so joining never produces a doubled slash. A prefix that is
/// not rooted, holds a control character, or carries a dot segment is rejected
/// rather than clamped.
fn base_path_prefix(path: &str) -> Result<&str, TargetError> {
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return Err(TargetError::InvalidPrefix);
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(TargetError::InvalidPrefix);
    }
    Ok(path.trim_end_matches('/'))
}

/// Rejects a query string that is not a raw query value.
fn validate_query(query: &str) -> Result<(), TargetError> {
    if query.starts_with('?') || query.chars().any(char::is_control) {
        return Err(TargetError::InvalidQuery);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::TransportType;

    fn route(path: &str) -> ResolvedRoute {
        ResolvedRoute {
            transport: TransportType::Http,
            path: path.to_owned(),
        }
    }

    fn endpoint(raw: &str) -> Url {
        Url::parse(raw).expect("valid endpoint URL")
    }

    #[test]
    fn base_path_prefix_is_empty_only_at_the_root() {
        assert_eq!(base_path_prefix("/"), Ok(""));
        assert_eq!(base_path_prefix("/proxy"), Ok("/proxy"));
        assert_eq!(base_path_prefix("/proxy/"), Ok("/proxy"));
    }

    #[test]
    fn base_path_prefix_rejects_unsafe_paths() {
        for path in ["proxy", "", "/proxy\ninjected"] {
            assert_eq!(
                base_path_prefix(path),
                Err(TargetError::InvalidPrefix),
                "expected {path:?} to be rejected"
            );
        }
        for path in ["/../etc", "/proxy/../../etc", "/./proxy", "/proxy/."] {
            assert_eq!(
                base_path_prefix(path),
                Err(TargetError::InvalidPrefix),
                "expected {path:?} to be rejected"
            );
        }
    }

    #[test]
    fn a_path_that_is_not_normalized_is_rejected() {
        let endpoint = endpoint("https://api.example.com/proxy");
        for path in [
            "/v1/../v1/responses",
            "/../responses",
            "/v1/../../responses",
            "/v1/./responses",
        ] {
            assert_eq!(
                build_upstream_uri(&endpoint, &route(path), None),
                Err(TargetError::InvalidPath),
                "expected {path:?} to be rejected"
            );
        }
    }

    #[test]
    fn endpoints_that_are_not_plain_origins_are_rejected() {
        for raw in [
            "ftp://api.example.com",
            "https://user:pass@api.example.com",
            "https://api.example.com?token=1",
            "https://api.example.com#fragment",
            "mailto:ops@example.com",
        ] {
            assert_eq!(
                build_upstream_uri(&endpoint(raw), &route("/v1/responses"), None),
                Err(TargetError::InvalidEndpoint),
                "expected {raw:?} to be rejected"
            );
        }
    }

    #[test]
    fn malformed_query_values_are_rejected() {
        let endpoint = endpoint("https://api.example.com");
        for query in ["?a=1", "a=b\nc"] {
            assert_eq!(
                build_upstream_uri(&endpoint, &route("/v1/responses"), Some(query)),
                Err(TargetError::InvalidQuery),
                "expected {query:?} to be rejected"
            );
        }
    }
}
