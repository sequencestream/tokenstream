//! Bounded HTTP request streaming to a resolved upstream.
//!
//! Forwarding one request never reads, parses, or buffers the application
//! body. The downstream body is handed to the client unchanged, so payload
//! bytes are copied through under transport backpressure and in-flight memory
//! stays bounded by the client and socket rather than the body length. Only
//! the request target and the envelope headers are rebuilt, and only from the
//! validated route, the immutable snapshot, and the direct downstream peer.
//!
//! Two deadlines bound the boundary. The transport enforces a connect timeout,
//! and the exchange is wrapped in a response-header timeout. A refused or
//! failed connection becomes a sanitized upstream-connection failure and either
//! deadline becomes a sanitized upstream timeout. Because no upstream response
//! has been received at that point, a local error can still be sent downstream.

use std::error::Error as StdError;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use hyper::body::{Body, Incoming};
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use tokio::time::timeout;

use crate::config::Config;
use crate::domain::ProviderSnapshot;
use crate::proxy::error::GatewayError;
use crate::proxy::headers::build_upstream_request_headers;
use crate::routing::{ResolvedRoute, build_upstream_uri};

/// Streams one proxied HTTP request to its provider endpoint.
///
/// The body type is a type parameter so one pipeline accepts both the live
/// downstream body and a test body without buffering either one. The client
/// pools transport connections but holds no credential: every call re-reads the
/// request-local snapshot it is handed.
pub struct HttpProxy<B> {
    client: Client<HttpConnector, B>,
    header_timeout: Duration,
}

impl<B> HttpProxy<B>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    /// Builds a proxy with explicit connect and response-header deadlines.
    pub fn new(connect_timeout: Duration, header_timeout: Duration) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(connect_timeout));
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self {
            client,
            header_timeout,
        }
    }

    /// Builds a proxy from the already-validated startup configuration.
    pub fn from_config(config: &Config) -> Self {
        Self::new(
            config.upstream_connect_timeout(),
            config.upstream_header_timeout(),
        )
    }

    /// Sends `request` upstream and returns the response head with its streaming
    /// body.
    ///
    /// The upstream target is the configured endpoint joined with the validated
    /// route path and the original query string, and the upstream headers are
    /// the rewritten envelope. The body is streamed through untouched.
    ///
    /// A failure here always occurs before any upstream response head, so it is
    /// reported as a stable local error: a refused or failed connection as
    /// [`GatewayError::UpstreamConnectFailed`] and either deadline as
    /// [`GatewayError::UpstreamTimeout`].
    pub async fn forward(
        &self,
        snapshot: &ProviderSnapshot,
        route: &ResolvedRoute,
        query: Option<&str>,
        downstream_peer: SocketAddr,
        request: Request<B>,
    ) -> Result<Response<Incoming>, GatewayError> {
        let uri = build_upstream_uri(snapshot.endpoint(), route, query)?;

        let (parts, body) = request.into_parts();
        let headers = build_upstream_request_headers(snapshot, &parts.headers, downstream_peer)?;

        let mut upstream = Request::builder()
            .method(parts.method)
            .uri(uri)
            .body(body)
            .map_err(|_| GatewayError::InternalError)?;
        *upstream.headers_mut() = headers;

        match timeout(self.header_timeout, self.client.request(upstream)).await {
            Err(_elapsed) => Err(GatewayError::UpstreamTimeout),
            Ok(Err(error)) => Err(classify(&error)),
            Ok(Ok(response)) => Ok(response),
        }
    }
}

impl<B> std::fmt::Debug for HttpProxy<B> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpProxy")
            .field("header_timeout", &self.header_timeout)
            .finish_non_exhaustive()
    }
}

/// Classifies a transport failure that occurred before any upstream response head.
///
/// A deadline reported by the transport is a timeout; every other failure is a
/// connection failure. Neither branch carries upstream text into the result.
fn classify(error: &hyper_util::client::legacy::Error) -> GatewayError {
    if is_timeout(error) {
        GatewayError::UpstreamTimeout
    } else {
        GatewayError::UpstreamConnectFailed
    }
}

/// Reports whether an I/O timeout appears anywhere in an error's source chain.
fn is_timeout(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(source) = current {
        if let Some(io) = source.downcast_ref::<io::Error>()
            && io.kind() == io::ErrorKind::TimedOut
        {
            return true;
        }
        current = source.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_io_timeout_is_recognized_through_a_wrapping_error() {
        assert!(is_timeout(&io::Error::new(
            io::ErrorKind::TimedOut,
            "deadline elapsed"
        )));
        assert!(!is_timeout(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused"
        )));

        #[derive(Debug)]
        struct Wrapper(io::Error);

        impl std::fmt::Display for Wrapper {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("wrapped transport failure")
            }
        }

        impl StdError for Wrapper {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                Some(&self.0)
            }
        }

        assert!(is_timeout(&Wrapper(io::Error::new(
            io::ErrorKind::TimedOut,
            "late"
        ))));
    }
}
