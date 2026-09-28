//! Bounded Responses WebSocket handshake and bidirectional relay.
//!
//! The upstream handshake always finishes before the downstream upgrade is
//! accepted, and it runs as an ordinary HTTP/1 exchange rather than as a
//! WebSocket client handshake. That boundary is what makes both outcomes
//! transparent: an upstream rejection stays an ordinary HTTP response whose
//! body is relayed as a live stream under the consumer's pace instead of a
//! buffer of whatever had already been read, while a `101` ends the exchange
//! and hands the untouched stream — together with any bytes the peer sent past
//! the handshake head — to the relay.
//!
//! Transport failures are reduced to the stable local gateway error classes.
//! Once both peers are upgraded, each direction moves one complete library
//! message at a time under read and write idle deadlines. Tungstenite bounds
//! frames, reassembled messages, and its write buffer, so neither fragmented
//! input nor a slow peer can grow memory without limit.

use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::proxy::transport::{UpstreamConnector, UpstreamStream};
use bytes::Bytes;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use http_body_util::Full;
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{CONNECTION, HeaderValue, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Sleep, timeout};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::{client::generate_key, derive_accept_key};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Utf8Bytes};
use tower_service::Service;

use crate::config::Config;
use crate::domain::{ProviderSnapshot, RequestId};
use crate::logging::{LogSink, RequestLogLifecycle};
use crate::proxy::admission::ProxyLimits;
use crate::proxy::error::GatewayError;
use crate::proxy::headers::{build_downstream_response_headers, build_upstream_request_headers};
use crate::routing::{ResolvedRoute, build_upstream_uri};
use crate::telemetry::Metrics;

const WEBSOCKET_VERSION: &str = "13";
const MESSAGE_TOO_LARGE_CODE: u16 = 1009;
const MESSAGE_TOO_LARGE_REASON: &str = "message exceeds configured limit";

pub type RelayFuture = std::pin::Pin<Box<dyn std::future::Future<Output = RelayOutcome> + Send>>;

/// Body of a prepared downstream WebSocket handshake response.
///
/// An accepted upgrade carries no HTTP body; a rejected handshake carries the
/// upstream's own streaming body, so the type is uniform across both outcomes.
pub type HandshakeBody = RejectionBody;

/// Result of preparing a downstream WebSocket handshake.
pub struct Handshake {
    response: Response<HandshakeBody>,
    relay: Option<JoinHandle<RelayOutcome>>,
}

impl Handshake {
    /// HTTP response to return from the downstream request handler.
    pub fn into_response(self) -> Response<HandshakeBody> {
        self.response
    }

    /// Separates the HTTP response from the optional accepted-connection task.
    pub fn into_parts(self) -> (Response<HandshakeBody>, Option<JoinHandle<RelayOutcome>>) {
        (self.response, self.relay)
    }
}

impl fmt::Debug for Handshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Handshake")
            .field("status", &self.response.status())
            .field("has_relay", &self.relay.is_some())
            .finish()
    }
}

/// Sanitized terminal state of a WebSocket relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayOutcome {
    /// A peer sent a normal close message.
    Closed,
    /// A peer exceeded the configured frame or message bound.
    MessageTooLarge,
    /// A read or write made no progress before the idle deadline.
    IdleTimeout,
    /// A transport or protocol error terminated the connection.
    Failed,
}

/// The WebSocket data-plane implementation and its immutable limits.
#[derive(Clone, Debug)]
pub struct WebSocketProxy {
    connect_timeout: Duration,
    header_timeout: Duration,
    idle_timeout: Duration,
    config: WebSocketConfig,
    metrics: Metrics,
}

impl WebSocketProxy {
    /// Creates a proxy from explicit deadlines and validated resource bounds.
    pub fn new(
        connect_timeout: Duration,
        header_timeout: Duration,
        idle_timeout: Duration,
        limits: &ProxyLimits,
    ) -> Self {
        Self::with_metrics(
            connect_timeout,
            header_timeout,
            idle_timeout,
            limits,
            Metrics::default(),
        )
    }

    pub fn with_metrics(
        connect_timeout: Duration,
        header_timeout: Duration,
        idle_timeout: Duration,
        limits: &ProxyLimits,
        metrics: Metrics,
    ) -> Self {
        let frame = limits.websocket_max_frame_bytes();
        let message = limits.websocket_max_message_bytes();
        let queue = limits.websocket_queue_capacity();
        let write_capacity = frame
            .saturating_mul(queue.saturating_add(1))
            .max(frame.saturating_add(1));
        let config = WebSocketConfig::default()
            .read_buffer_size(frame.clamp(1024, 128 * 1024))
            .max_frame_size(Some(frame))
            .max_message_size(Some(message))
            .write_buffer_size(frame)
            .max_write_buffer_size(write_capacity);
        Self {
            connect_timeout,
            header_timeout,
            idle_timeout,
            config,
            metrics,
        }
    }

    /// Creates a proxy from startup configuration that has already been validated.
    pub fn from_config(config: &Config) -> Self {
        let limits = ProxyLimits::from_config(config);
        Self::new(
            config.upstream_connect_timeout(),
            config.upstream_header_timeout(),
            config.stream_idle_timeout(),
            &limits,
        )
    }

    /// Connects upstream first and only then accepts the downstream upgrade.
    ///
    /// An upstream non-101 response is returned unchanged apart from removal of
    /// hop-by-hop headers. A failure without an upstream response is returned as
    /// a sanitized local error for the caller to render with its request ID.
    pub async fn handshake(
        &self,
        snapshot: &ProviderSnapshot,
        route: &ResolvedRoute,
        query: Option<&str>,
        downstream_peer: SocketAddr,
        request: &mut Request<Incoming>,
    ) -> Result<Handshake, GatewayError> {
        let (response, relay) = self
            .prepare(snapshot, route, query, downstream_peer, request)
            .await?;
        Ok(Handshake {
            response,
            relay: relay.map(tokio::spawn),
        })
    }

    /// Prepares a relay owned and polled by the downstream connection supervisor.
    pub async fn prepare(
        &self,
        snapshot: &ProviderSnapshot,
        route: &ResolvedRoute,
        query: Option<&str>,
        downstream_peer: SocketAddr,
        request: &mut Request<Incoming>,
    ) -> Result<(Response<HandshakeBody>, Option<RelayFuture>), GatewayError> {
        let downstream_key = single_header(request.headers(), SEC_WEBSOCKET_KEY)
            .ok_or(GatewayError::InvalidUpgrade)?
            .as_bytes()
            .to_vec();
        let upstream_uri = build_upstream_uri(snapshot.endpoint(), route, query)?;
        let upstream_path = upstream_uri
            .path_and_query()
            .map(|path| path.as_str().to_owned())
            .ok_or(GatewayError::InternalError)?;
        let mut headers =
            build_upstream_request_headers(snapshot, request.headers(), downstream_peer)?;
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            "sec-websocket-version",
            HeaderValue::from_static(WEBSOCKET_VERSION),
        );
        // The downstream key must not reach the upstream. The gateway performs
        // its own client handshake toward the upstream, so the two peers'
        // handshake values are independent and the accept values differ.
        headers.remove(SEC_WEBSOCKET_KEY);
        headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_str(&generate_key()).map_err(|_| GatewayError::InternalError)?,
        );
        let mut upstream_request = Request::builder()
            .method(Method::GET)
            .uri(upstream_path)
            .body(Full::new(Bytes::new()))
            .map_err(|_| GatewayError::InternalError)?;
        for (name, value) in headers {
            if let Some(name) = name {
                upstream_request.headers_mut().append(name, value);
            }
        }

        let on_upgrade = hyper::upgrade::on(request);
        let started = tokio::time::Instant::now();
        let mut connector = UpstreamConnector::new(self.connect_timeout);
        let stream = connector
            .call(upstream_uri.clone())
            .await
            .map_err(|error| {
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
                {
                    GatewayError::UpstreamTimeout
                } else {
                    GatewayError::UpstreamConnectFailed
                }
            })?;

        // The upstream handshake is driven as an ordinary HTTP/1 exchange so a
        // rejection keeps its body as a live stream on this same connection.
        // Reading the head this way never buffers the whole body, and a `101`
        // ends the exchange so the untouched stream becomes the relay's.
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake::<_, Full<Bytes>>(stream)
                .await
                .map_err(|_| GatewayError::UpstreamConnectFailed)?;
        // The connection is driven without shutting the socket down, so a
        // `101` can take the raw stream back with the bytes already read past
        // the handshake head. A rejection lets it end with the body instead.
        let upstream_connection = tokio::spawn(async move { connection.without_shutdown().await });
        let connected = timeout(self.header_timeout, sender.send_request(upstream_request)).await;
        self.metrics.observe_upstream_latency(started.elapsed());
        let upstream_response = match connected {
            Err(_) => {
                upstream_connection.abort();
                return Err(GatewayError::UpstreamTimeout);
            }
            Ok(Err(_)) => {
                upstream_connection.abort();
                return Err(GatewayError::UpstreamConnectFailed);
            }
            Ok(Ok(response)) => response,
        };

        if upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS {
            // A rejected handshake is an ordinary HTTP response: the status and
            // every allowed end-to-end header travel back unchanged, and the
            // body is relayed as a stream that follows the consumer's pace.
            // The connection keeps running until that body ends, because the
            // body is read from it; a rejection never becomes a session and
            // nothing here may retry or replace it.
            let (mut parts, body) = upstream_response.into_parts();
            parts.headers = build_downstream_response_headers(&parts.headers);
            return Ok((
                Response::from_parts(parts, RejectionBody::new(body, self.idle_timeout)),
                None,
            ));
        }

        let response = switching_protocols(&downstream_key, upstream_response.headers())?;
        let relay: RelayFuture = Box::pin(run_after_upgrade(
            on_upgrade,
            upstream_connection,
            self.config,
            self.idle_timeout,
        ));
        Ok((response, Some(relay)))
    }

    /// Performs the handshake while emitting start and completion metadata to
    /// the non-blocking logger. Successful upgrades complete when the relay
    /// closes; rejected handshakes complete as ordinary upstream HTTP results.
    #[allow(clippy::too_many_arguments)]
    pub async fn handshake_logged(
        &self,
        snapshot: &ProviderSnapshot,
        route: &ResolvedRoute,
        query: Option<&str>,
        downstream_peer: SocketAddr,
        request: &mut Request<Incoming>,
        log_sink: LogSink,
        request_id: RequestId,
    ) -> Result<Handshake, GatewayError> {
        let mut lifecycle =
            RequestLogLifecycle::start(log_sink, request_id, snapshot, route).observe_websocket();
        let handshake = match self
            .handshake(snapshot, route, query, downstream_peer, request)
            .await
        {
            Ok(handshake) => handshake,
            Err(error) => {
                lifecycle.complete(None, Some(error.code()));
                return Err(error);
            }
        };
        let (response, relay) = handshake.into_parts();
        let status = response.status();
        let relay = match relay {
            None => {
                lifecycle.complete(Some(status), None);
                None
            }
            Some(relay) => Some(tokio::spawn(async move {
                let outcome = relay.await.unwrap_or(RelayOutcome::Failed);
                let error = match outcome {
                    RelayOutcome::Closed => None,
                    RelayOutcome::MessageTooLarge => Some("message_too_large"),
                    RelayOutcome::IdleTimeout => Some("idle_timeout"),
                    RelayOutcome::Failed => Some("relay_failed"),
                };
                lifecycle.complete(Some(status), error);
                outcome
            })),
        };
        Ok(Handshake { response, relay })
    }
}

fn single_header(
    headers: &hyper::HeaderMap,
    name: hyper::header::HeaderName,
) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => Some(value),
        _ => None,
    }
}

/// Rebuilds the accepted upgrade response from the upstream handshake head.
///
/// The protocol-required upgrade headers are regenerated for the downstream
/// peer, every other allowed end-to-end header is preserved, and the hop-by-hop
/// set together with headers nominated by `Connection` is dropped.
fn switching_protocols(
    downstream_key: &[u8],
    upstream_headers: &hyper::HeaderMap,
) -> Result<Response<HandshakeBody>, GatewayError> {
    let accept = HeaderValue::from_str(&derive_accept_key(downstream_key))
        .map_err(|_| GatewayError::InternalError)?;
    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body(HandshakeBody::empty())
        .map_err(|_| GatewayError::InternalError)?;
    {
        let headers = response.headers_mut();
        headers.extend(build_downstream_response_headers(upstream_headers));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(SEC_WEBSOCKET_ACCEPT, accept);
    }
    if upstream_headers.contains_key("sec-websocket-extensions") {
        return Err(GatewayError::UpstreamConnectFailed);
    }
    Ok(response)
}

/// Waits for both peers to be upgraded, then relays them under the idle bound.
///
/// Both upgrades are awaited under the same deadline: the downstream client
/// accepted the response and the upstream completed its handshake. A peer that
/// never arrives is closed with a normal close frame rather than left open.
async fn run_after_upgrade(
    on_upgrade: OnUpgrade,
    upstream_connection: JoinHandle<
        Result<hyper::client::conn::http1::Parts<UpstreamStream>, hyper::Error>,
    >,
    config: WebSocketConfig,
    idle_timeout: Duration,
) -> RelayOutcome {
    // Both handshakes finish independently, so neither peer waits on the other.
    // A downstream client that never completes its upgrade leaves the upstream
    // socket to be dropped with this future, never left half-open.
    let (downstream_result, upstream_socket) = tokio::join!(
        async {
            timeout(idle_timeout, on_upgrade)
                .await
                .map_err(|_| RelayOutcome::IdleTimeout)
                .and_then(|result| result.map_err(|_| RelayOutcome::Failed))
        },
        upstream_connection,
    );
    let upgraded_downstream = match downstream_result {
        Ok(upgraded) => upgraded,
        Err(RelayOutcome::IdleTimeout) => return RelayOutcome::IdleTimeout,
        Err(_) => return RelayOutcome::Failed,
    };
    // The upstream exchange ends on `101`; the socket and any bytes already
    // read past the handshake head come back together.
    let parts = match upstream_socket {
        Ok(Ok(parts)) => parts,
        _ => return RelayOutcome::Failed,
    };
    let upstream_io = RewoundIo::new(parts.io, parts.read_buf);
    // Both handshake heads were already exchanged and verified, so the raw
    // upgraded streams carry no bytes that still need parsing.
    let upstream = WebSocketStream::from_raw_socket(
        hyper_util::rt::TokioIo::new(upstream_io),
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        Some(config),
    )
    .await;
    let downstream = WebSocketStream::from_raw_socket(
        hyper_util::rt::TokioIo::new(upgraded_downstream),
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        Some(config),
    )
    .await;
    relay(downstream, upstream, idle_timeout).await
}

/// A socket preceded by bytes that were read past the handshake head.
///
/// The upstream may have sent its first WebSocket frames in the same packet as
/// the `101`. Those bytes are already owned by the HTTP exchange, so they are
/// replayed before the socket is read, and the pair is treated as one stream.
struct RewoundIo<S> {
    pending: Bytes,
    inner: S,
}

impl<S> RewoundIo<S> {
    fn new(inner: S, pending: Bytes) -> Self {
        Self { pending, inner }
    }
}

impl<S> hyper::rt::Read for RewoundIo<S>
where
    S: hyper::rt::Read + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut buffer: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.pending.is_empty() {
            let count = this.pending.len().min(buffer.remaining());
            buffer.put_slice(&this.pending.split_to(count));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

impl<S> hyper::rt::Write for RewoundIo<S>
where
    S: hyper::rt::Write + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(context, bufs)
    }
}

/// The body of a WebSocket handshake response.
///
/// An accepted upgrade has no HTTP body, so this body is immediately at end of
/// stream. A rejected handshake streams the upstream's own body: each poll
/// yields one upstream frame and returns `Pending` when no frame is ready, so a
/// slow downstream consumer exerts backpressure on the upstream socket instead
/// of filling a buffer, and a large or chunked error body is relayed in full
/// rather than truncated to whatever had already been read.
///
/// No body byte is inspected, rewritten, or logged. A stalled upstream body
/// ends the stream with a sanitized failure once the idle deadline passes.
pub struct RejectionBody {
    inner: Option<Incoming>,
    idle_timeout: Duration,
    deadline: Pin<Box<Sleep>>,
    finished: bool,
}

impl RejectionBody {
    /// An empty body for an accepted upgrade.
    pub fn empty() -> Self {
        Self {
            inner: None,
            idle_timeout: Duration::from_secs(0),
            deadline: Box::pin(tokio::time::sleep(Duration::from_secs(0))),
            finished: true,
        }
    }

    /// Wraps a rejected handshake's upstream body under the idle deadline.
    fn new(inner: Incoming, idle_timeout: Duration) -> Self {
        Self {
            inner: Some(inner),
            idle_timeout,
            deadline: Box::pin(tokio::time::sleep(idle_timeout)),
            finished: false,
        }
    }
}

impl fmt::Debug for RejectionBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectionBody")
            .field("streaming", &self.inner.is_some())
            .field("finished", &self.finished)
            .finish()
    }
}

impl Body for RejectionBody {
    type Data = Bytes;
    type Error = RejectionBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        let Some(inner) = this.inner.as_mut() else {
            this.finished = true;
            return Poll::Ready(None);
        };
        match Pin::new(inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                this.deadline
                    .as_mut()
                    .reset(tokio::time::Instant::now() + this.idle_timeout);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(_))) => {
                this.finished = true;
                Poll::Ready(Some(Err(RejectionBodyError::Stream)))
            }
            Poll::Ready(None) => {
                this.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => match this.deadline.as_mut().poll(context) {
                Poll::Ready(()) => {
                    this.finished = true;
                    Poll::Ready(Some(Err(RejectionBodyError::IdleTimeout)))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.as_ref().is_none_or(Incoming::is_end_stream)
    }
}

/// A sanitized failure of a relayed rejected-handshake body.
///
/// Response headers have already been sent, so the only available signal is
/// terminating the stream. The error carries no upstream text, no credential,
/// and no query string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionBodyError {
    /// The upstream body failed before it ended.
    Stream,
    /// The upstream made no body progress before the idle deadline.
    IdleTimeout,
}

impl fmt::Display for RejectionBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Stream => "the upstream response body failed",
            Self::IdleTimeout => "the upstream response body stalled",
        };
        formatter.write_str(message)
    }
}

impl Error for RejectionBodyError {}

/// Relays two established WebSocket peers until either direction terminates.
pub async fn relay<D, U>(
    downstream: WebSocketStream<D>,
    upstream: WebSocketStream<U>,
    idle_timeout: Duration,
) -> RelayOutcome
where
    D: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (downstream_write, downstream_read) = downstream.split();
    let (upstream_write, upstream_read) = upstream.split();
    let close_seen = Arc::new(AtomicBool::new(false));
    let (activity, activity_rx) = watch::channel(0_u64);
    let downstream_to_upstream = relay_direction(
        downstream_read,
        upstream_write,
        idle_timeout,
        Arc::clone(&close_seen),
        activity.clone(),
    );
    let upstream_to_downstream = relay_direction(
        upstream_read,
        downstream_write,
        idle_timeout,
        close_seen,
        activity,
    );
    let idle = idle_deadline(activity_rx, idle_timeout);
    tokio::pin!(downstream_to_upstream, upstream_to_downstream, idle);
    tokio::select! {
        outcome = &mut downstream_to_upstream => outcome,
        outcome = &mut upstream_to_downstream => outcome,
        outcome = &mut idle => outcome,
    }
}

async fn relay_direction<R, W>(
    mut source: R,
    mut destination: W,
    idle_timeout: Duration,
    close_seen: Arc<AtomicBool>,
    activity: watch::Sender<u64>,
) -> RelayOutcome
where
    R: Stream<Item = Result<Message, WebSocketError>> + Unpin,
    W: Sink<Message, Error = WebSocketError> + Unpin,
{
    loop {
        let message = match source.next().await {
            None => return RelayOutcome::Closed,
            Some(Err(WebSocketError::Capacity(_))) => {
                let _ = close_sink(
                    &mut destination,
                    MESSAGE_TOO_LARGE_CODE,
                    MESSAGE_TOO_LARGE_REASON,
                    idle_timeout,
                )
                .await;
                return RelayOutcome::MessageTooLarge;
            }
            Some(Err(WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed))
                if close_seen.load(Ordering::Acquire) =>
            {
                return RelayOutcome::Closed;
            }
            Some(Err(_)) => return RelayOutcome::Failed,
            Some(Ok(message)) => message,
        };
        activity.send_modify(|generation| *generation = generation.wrapping_add(1));
        let closed = message.is_close();
        match timeout(idle_timeout, destination.send(message)).await {
            Err(_) => return RelayOutcome::IdleTimeout,
            Ok(Err(WebSocketError::Capacity(_))) => return RelayOutcome::MessageTooLarge,
            Ok(Err(_)) => return RelayOutcome::Failed,
            Ok(Ok(())) if closed && close_seen.swap(true, Ordering::AcqRel) => {
                return RelayOutcome::Closed;
            }
            Ok(Ok(())) => {}
        }
    }
}

async fn idle_deadline(mut activity: watch::Receiver<u64>, idle_timeout: Duration) -> RelayOutcome {
    loop {
        match timeout(idle_timeout, activity.changed()).await {
            Err(_) => return RelayOutcome::IdleTimeout,
            Ok(Err(_)) => return RelayOutcome::Closed,
            Ok(Ok(())) => {}
        }
    }
}

async fn close_sink<W>(
    sink: &mut W,
    code: u16,
    reason: &'static str,
    idle_timeout: Duration,
) -> Result<(), WebSocketError>
where
    W: Sink<Message, Error = WebSocketError> + Unpin,
{
    timeout(
        idle_timeout,
        sink.send(Message::Close(Some(CloseFrame {
            code: code.into(),
            reason: Utf8Bytes::from_static(reason),
        }))),
    )
    .await
    .map_err(|_| WebSocketError::ConnectionClosed)?
}
