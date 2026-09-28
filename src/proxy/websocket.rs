//! Bounded Responses WebSocket handshake and bidirectional relay.
//!
//! The upstream handshake always finishes before the downstream upgrade is
//! accepted. An upstream HTTP rejection remains an ordinary HTTP response;
//! transport failures are reduced to the stable local gateway error classes.
//! Once both peers are upgraded, each direction moves one complete library
//! message at a time under read and write idle deadlines. Tungstenite bounds
//! frames, reassembled messages, and its write buffer, so neither fragmented
//! input nor a slow peer can grow memory without limit.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderValue, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Utf8Bytes};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};
use url::Url;

use crate::config::Config;
use crate::domain::{ProviderSnapshot, RequestId};
use crate::logging::{LogSink, RequestLogLifecycle};
use crate::proxy::admission::ProxyLimits;
use crate::proxy::error::GatewayError;
use crate::proxy::headers::{build_downstream_response_headers, build_upstream_request_headers};
use crate::routing::{ResolvedRoute, build_upstream_uri};
use crate::telemetry::Metrics;

const WEBSOCKET_VERSION: &str = "13";
const NORMAL_CLOSE_CODE: u16 = 1000;
const MESSAGE_TOO_LARGE_CODE: u16 = 1009;
const MESSAGE_TOO_LARGE_REASON: &str = "message exceeds configured limit";

type UpstreamSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
/// Result of preparing a downstream WebSocket handshake.
pub struct Handshake {
    response: Response<Full<Bytes>>,
    relay: Option<JoinHandle<RelayOutcome>>,
}

impl Handshake {
    /// HTTP response to return from the downstream request handler.
    pub fn into_response(self) -> Response<Full<Bytes>> {
        self.response
    }

    /// Separates the HTTP response from the optional accepted-connection task.
    pub fn into_parts(self) -> (Response<Full<Bytes>>, Option<JoinHandle<RelayOutcome>>) {
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
        let downstream_key = single_header(request.headers(), SEC_WEBSOCKET_KEY)
            .ok_or(GatewayError::InvalidUpgrade)?
            .as_bytes()
            .to_vec();
        let upstream_uri = build_upstream_uri(snapshot.endpoint(), route, query)?;
        let upstream_url = websocket_url(&upstream_uri.to_string())?;
        let mut upstream_request = upstream_url
            .as_str()
            .into_client_request()
            .map_err(|_| GatewayError::InternalError)?;
        let mut headers =
            build_upstream_request_headers(snapshot, request.headers(), downstream_peer)?;
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            "sec-websocket-version",
            HeaderValue::from_static(WEBSOCKET_VERSION),
        );
        headers.remove(SEC_WEBSOCKET_KEY);
        for (name, value) in headers {
            if let Some(name) = name {
                upstream_request.headers_mut().append(name, value);
            }
        }

        let on_upgrade = hyper::upgrade::on(request);
        let connect = connect_async_with_config(upstream_request, Some(self.config), false);
        let started = tokio::time::Instant::now();
        let connected = timeout(
            self.connect_timeout.saturating_add(self.header_timeout),
            connect,
        )
        .await;
        self.metrics.observe_upstream_latency(started.elapsed());
        let (upstream, upstream_response) = match connected {
            Err(_) => return Err(GatewayError::UpstreamTimeout),
            Ok(Ok(result)) => result,
            Ok(Err(WebSocketError::Http(response))) => {
                return Ok(Handshake {
                    response: rejected_response(*response),
                    relay: None,
                });
            }
            Ok(Err(_)) => return Err(GatewayError::UpstreamConnectFailed),
        };

        let response = switching_protocols(&downstream_key, upstream_response.headers())?;
        let relay = tokio::spawn(run_after_upgrade(
            on_upgrade,
            upstream,
            self.config,
            self.idle_timeout,
        ));
        Ok(Handshake {
            response,
            relay: Some(relay),
        })
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

fn websocket_url(raw: &str) -> Result<Url, GatewayError> {
    let mut url = Url::parse(raw).map_err(|_| GatewayError::InternalError)?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        _ => return Err(GatewayError::InternalError),
    };
    url.set_scheme(scheme)
        .map_err(|_| GatewayError::InternalError)?;
    Ok(url)
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

fn switching_protocols(
    downstream_key: &[u8],
    upstream_headers: &hyper::HeaderMap,
) -> Result<Response<Full<Bytes>>, GatewayError> {
    let accept = HeaderValue::from_str(&derive_accept_key(downstream_key))
        .map_err(|_| GatewayError::InternalError)?;
    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header(SEC_WEBSOCKET_ACCEPT, accept)
        .body(Full::new(Bytes::new()))
        .map_err(|_| GatewayError::InternalError)?;
    for name in ["sec-websocket-protocol"] {
        for value in upstream_headers.get_all(name) {
            response.headers_mut().append(name, value.clone());
        }
    }
    if upstream_headers.contains_key("sec-websocket-extensions") {
        return Err(GatewayError::UpstreamConnectFailed);
    }
    Ok(response)
}

fn rejected_response(upstream: hyper::Response<Option<Vec<u8>>>) -> Response<Full<Bytes>> {
    let (mut parts, body) = upstream.into_parts();
    parts.headers = build_downstream_response_headers(&parts.headers);
    Response::from_parts(parts, Full::new(Bytes::from(body.unwrap_or_default())))
}

async fn run_after_upgrade(
    on_upgrade: OnUpgrade,
    mut upstream: UpstreamSocket,
    config: WebSocketConfig,
    idle_timeout: Duration,
) -> RelayOutcome {
    let upgraded = match timeout(idle_timeout, on_upgrade).await {
        Err(_) => {
            let _ = close_with(
                &mut upstream,
                NORMAL_CLOSE_CODE,
                "downstream upgrade timed out",
            )
            .await;
            return RelayOutcome::IdleTimeout;
        }
        Ok(Err(_)) => {
            let _ = close_with(
                &mut upstream,
                NORMAL_CLOSE_CODE,
                "downstream upgrade failed",
            )
            .await;
            return RelayOutcome::Failed;
        }
        Ok(Ok(upgraded)) => upgraded,
    };
    let downstream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        Some(config),
    )
    .await;
    relay(downstream, upstream, idle_timeout).await
}

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

async fn close_with<S>(
    socket: &mut WebSocketStream<S>,
    code: u16,
    reason: &'static str,
) -> Result<(), WebSocketError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    socket
        .close(Some(CloseFrame {
            code: code.into(),
            reason: Utf8Bytes::from_static(reason),
        }))
        .await
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
