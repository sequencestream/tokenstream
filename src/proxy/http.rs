//! Bounded HTTP request streaming to a resolved upstream.
//!
//! Forwarding one request never reads, parses, or buffers the application
//! body. The downstream body is handed to the client unchanged, so payload
//! bytes are copied through under transport backpressure and in-flight memory
//! stays bounded by the client and socket rather than the body length. Only
//! the request target and the envelope headers are rebuilt, and only from the
//! validated route, the immutable snapshot, and the direct downstream peer.
//!
//! Three deadlines bound the boundary. The transport enforces a connect
//! timeout, the exchange is wrapped in a response-header timeout, and request
//! and response bodies enforce a per-frame idle timeout. A refused or failed
//! connection becomes a sanitized upstream-connection failure and any deadline
//! becomes a sanitized upstream timeout. Before response headers arrive a local
//! error can still be sent downstream; afterward the body stream is terminated.
//!
//! The response travels back the same way through [`relay_response`]: its status
//! and allowed end-to-end headers are forwarded immediately and its body stays a
//! streaming value, so relayed chunks follow the downstream consumer's pace
//! instead of accumulating in the gateway.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::proxy::transport::UpstreamConnector;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::capture_connection;
use hyper_util::rt::TokioExecutor;
use tokio::time::{Instant, Sleep, timeout};

use crate::config::Config;
use crate::domain::{ProviderSnapshot, RequestId};
use crate::logging::{LogSink, LoggedBody, RequestLogLifecycle, observe_response};
use crate::proxy::error::GatewayError;
use crate::proxy::headers::{build_downstream_response_headers, build_upstream_request_headers};
use crate::routing::{ResolvedRoute, build_upstream_uri};
use crate::telemetry::Metrics;

/// Streams one proxied HTTP request to its provider endpoint.
///
/// The body type is a type parameter so one pipeline accepts both the live
/// downstream body and a test body without buffering either one. The client
/// pools transport connections but holds no credential: every call re-reads the
/// request-local snapshot it is handed.
pub struct HttpProxy<B> {
    client: Client<UpstreamConnector, IdleTimeoutBody<B>>,
    header_timeout: Duration,
    idle_timeout: Duration,
    metrics: Metrics,
}

impl<B> HttpProxy<B>
where
    B: Body<Data = bytes::Bytes> + Send + 'static + Unpin,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    /// Builds a proxy with explicit connect, response-header, and stream-idle
    /// deadlines.
    pub fn new(
        connect_timeout: Duration,
        header_timeout: Duration,
        idle_timeout: Duration,
    ) -> Self {
        Self::with_metrics(
            connect_timeout,
            header_timeout,
            idle_timeout,
            Metrics::default(),
        )
    }

    pub fn with_metrics(
        connect_timeout: Duration,
        header_timeout: Duration,
        idle_timeout: Duration,
        metrics: Metrics,
    ) -> Self {
        Self::with_buffer(
            connect_timeout,
            header_timeout,
            idle_timeout,
            metrics,
            65536,
        )
    }

    pub fn with_buffer(
        connect_timeout: Duration,
        header_timeout: Duration,
        idle_timeout: Duration,
        metrics: Metrics,
        buffer_bytes: usize,
    ) -> Self {
        let connector = UpstreamConnector::new(connect_timeout);
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .retry_canceled_requests(false)
            .http1_read_buf_exact_size(buffer_bytes)
            .pool_max_idle_per_host(0);
        let client = builder.build(connector);
        Self {
            client,
            header_timeout,
            idle_timeout,
            metrics,
        }
    }

    /// Builds a proxy from the already-validated startup configuration.
    pub fn from_config(config: &Config) -> Self {
        Self::with_buffer(
            config.upstream_connect_timeout(),
            config.upstream_header_timeout(),
            config.stream_idle_timeout(),
            Metrics::default(),
            config.http_buffer_bytes(),
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
            .body(IdleTimeoutBody::new(body, self.idle_timeout))
            .map_err(|_| GatewayError::InternalError)?;
        *upstream.headers_mut() = headers;

        let started = Instant::now();
        let mut captured = capture_connection(&mut upstream);
        let exchange = self.client.request(upstream);
        tokio::pin!(exchange);
        let result = tokio::select! {
            result = &mut exchange => result.map_err(|error| classify(&error)),
            _ = async { drop(captured.wait_for_connection_metadata().await); } => {
                match timeout(self.header_timeout, &mut exchange).await {
                    Err(_) => Err(GatewayError::UpstreamTimeout),
                    Ok(result) => result.map_err(|error| classify(&error)),
                }
            }
        };
        self.metrics.observe_upstream_latency(started.elapsed());
        result
    }

    /// Converts a received upstream response into the downstream streaming
    /// response governed by this proxy's idle deadline.
    ///
    /// The upstream status and headers have already arrived, so later body
    /// failures cannot be replaced with a gateway error envelope. Instead the
    /// response stream terminates with a sanitized [`HttpBodyError`]. Dropping
    /// the returned response drops the upstream body immediately, which makes
    /// downstream cancellation cancel the associated upstream transfer.
    pub fn relay_response(
        &self,
        upstream: Response<Incoming>,
    ) -> Response<IdleTimeoutBody<Incoming>> {
        relay_response(upstream, self.idle_timeout)
    }

    /// Forwards and observes one HTTP/SSE lifecycle without putting storage I/O
    /// on the request task. The returned body emits completion at EOF, failure,
    /// or downstream cancellation.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_logged(
        &self,
        snapshot: &ProviderSnapshot,
        route: &ResolvedRoute,
        query: Option<&str>,
        downstream_peer: SocketAddr,
        request: Request<B>,
        log_sink: LogSink,
        request_id: RequestId,
    ) -> Result<Response<LoggedBody<IdleTimeoutBody<Incoming>>>, GatewayError> {
        let mut lifecycle =
            RequestLogLifecycle::start(log_sink, request_id, snapshot, route).observe_http();
        match self
            .forward(snapshot, route, query, downstream_peer, request)
            .await
        {
            Ok(upstream) => Ok(observe_response(self.relay_response(upstream), lifecycle)),
            Err(error) => {
                lifecycle.complete(None, Some(error.code()));
                Err(error)
            }
        }
    }
}

/// Relays an upstream response to the downstream client without buffering it.
///
/// The status and HTTP version are preserved, hop-by-hop headers and headers
/// nominated by `Connection` are removed by the shared response policy, and
/// every other end-to-end header is forwarded as received. The body is handed
/// back as the upstream's own streaming body, so one frame crosses the gateway
/// per downstream poll and a slow consumer exerts backpressure on the upstream
/// socket rather than filling an in-memory buffer.
///
/// Nothing here reads the content type, the body, or any application field, so
/// an SSE stream, a JSON document that happens to mention `stream`, and an
/// upstream error body all relay identically.
pub fn relay_response(
    upstream: Response<Incoming>,
    idle_timeout: Duration,
) -> Response<IdleTimeoutBody<Incoming>> {
    let (mut parts, body) = upstream.into_parts();
    parts.headers = build_downstream_response_headers(&parts.headers);
    Response::from_parts(parts, IdleTimeoutBody::new(body, idle_timeout))
}

impl<B> std::fmt::Debug for HttpProxy<B> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpProxy")
            .field("header_timeout", &self.header_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

/// A sanitized failure emitted after downstream response headers have started.
///
/// The error intentionally exposes neither a transport error string nor any
/// upstream data. At this point HTTP permits only terminating the body stream;
/// callers must not synthesize a second response or retry the request.
#[derive(Debug)]
pub enum HttpBodyError {
    /// The HTTP body ended with a transport or framing failure.
    Stream,
    /// No HTTP body frame arrived within the configured idle interval.
    IdleTimeout,
}

impl HttpBodyError {
    /// Reports whether the body was terminated by the stream-idle deadline.
    pub fn is_idle_timeout(&self) -> bool {
        matches!(self, Self::IdleTimeout)
    }
}

impl fmt::Display for HttpBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stream => "the HTTP body stream failed",
            Self::IdleTimeout => "the HTTP body stream timed out",
        })
    }
}

impl StdError for HttpBodyError {}

/// An upstream body that enforces an idle deadline without a background task.
///
/// The timer advances only while the downstream is polling for the next frame.
/// This preserves backpressure: a slow downstream does not cause the gateway to
/// read ahead merely to keep a timer alive. Every received frame resets the
/// deadline. EOF passes through normally; an abnormal EOF is a sanitized body
/// error. Dropping this value drops the upstream body and its transfer state.
#[derive(Debug)]
pub struct IdleTimeoutBody<B> {
    inner: B,
    idle_timeout: Duration,
    deadline: Pin<Box<Sleep>>,
    finished: bool,
}

impl<B> IdleTimeoutBody<B> {
    fn new(inner: B, idle_timeout: Duration) -> Self {
        Self {
            inner,
            idle_timeout,
            deadline: Box::pin(tokio::time::sleep(idle_timeout)),
            finished: false,
        }
    }
}

impl<B> Body for IdleTimeoutBody<B>
where
    B: Body<Data = bytes::Bytes> + Unpin,
{
    type Data = bytes::Bytes;
    type Error = HttpBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }

        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                this.deadline
                    .as_mut()
                    .reset(Instant::now() + this.idle_timeout);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(_error))) => {
                this.finished = true;
                Poll::Ready(Some(Err(HttpBodyError::Stream)))
            }
            Poll::Ready(None) => {
                this.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => match this.deadline.as_mut().poll(context) {
                Poll::Ready(()) => {
                    this.finished = true;
                    Poll::Ready(Some(Err(HttpBodyError::IdleTimeout)))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
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
        if let Some(body) = source.downcast_ref::<HttpBodyError>()
            && body.is_idle_timeout()
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
