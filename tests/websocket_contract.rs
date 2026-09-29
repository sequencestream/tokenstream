//! WebSocket relay contracts for bidirectional traffic, fragmentation, control
//! messages, close propagation, capacity failures, and idle peers.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokenstream::domain::{
    AccountId, ApiKeyId, ProtocolType, ProviderId, ProviderSnapshot, RequestId, SecretString,
};
use tokenstream::logging::{LogEvent, LogStore, channel};
use tokenstream::persistence::RepositoryError;
use tokenstream::proxy::admission::ProxyLimits;
use tokenstream::proxy::error::{ERROR_CONTENT_TYPE, GatewayError};
use tokenstream::proxy::http::HttpProxy;
use tokenstream::proxy::websocket::{RejectionBody, WebSocketProxy};
use tokenstream::proxy::websocket::{RelayOutcome, relay};
use tokenstream::routing::resolve_route;
use tokenstream::telemetry::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, oneshot};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::Frame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Utf8Bytes};
use tokio_tungstenite::{
    WebSocketStream, accept_async, accept_async_with_config, client_async, connect_async,
};
use url::Url;

type Socket = WebSocketStream<DuplexStream>;

#[derive(Default)]
struct RecordingLogStore {
    events: Mutex<Vec<LogEvent>>,
}

impl LogStore for RecordingLogStore {
    async fn write_batch(&self, events: &[LogEvent]) -> Result<(), RepositoryError> {
        self.events.lock().await.extend_from_slice(events);
        Ok(())
    }
}

async fn socket_pair(server_config: WebSocketConfig) -> (Socket, Socket) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let client = client_async("ws://localhost/v1/responses", client_io);
    let server = accept_async_with_config(server_io, Some(server_config));
    let (client, server) = tokio::join!(client, server);
    (
        client.expect("client handshake").0,
        server.expect("server handshake"),
    )
}

async fn next_message(socket: &mut Socket) -> Message {
    tokio::time::timeout(Duration::from_secs(1), socket.next())
        .await
        .expect("message deadline")
        .expect("connection remains open")
        .expect("valid message")
}

fn limits() -> ProxyLimits {
    ProxyLimits::new(8, 64 * 1024, 64 * 1024, 256 * 1024, 4).expect("valid bounds")
}

fn snapshot(upstream: SocketAddr) -> ProviderSnapshot {
    ProviderSnapshot::new(
        AccountId::try_from(1).expect("positive account ID"),
        ApiKeyId::try_from(1).expect("positive credential ID"),
        ProviderId::try_from(1).expect("positive provider ID"),
        ProtocolType::OpenAi,
        Url::parse(&format!("http://{upstream}/provider-prefix")).expect("upstream URL"),
        SecretString::new("upstream-secret"),
    )
}

fn local_error(error: GatewayError) -> Response<Full<Bytes>> {
    Response::builder()
        .status(error.status())
        .header("content-type", ERROR_CONTENT_TYPE)
        .body(Full::new(error.render(&RequestId::generate())))
        .expect("local error response")
}

async fn spawn_gateway(upstream: SocketAddr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let address = listener.local_addr().expect("gateway address");
    let snapshot = Arc::new(snapshot(upstream));
    let proxy = Arc::new(WebSocketProxy::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
        &limits(),
    ));
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept downstream");
        let service = service_fn(move |mut request: Request<Incoming>| {
            let snapshot = Arc::clone(&snapshot);
            let proxy = Arc::clone(&proxy);
            async move {
                let route = match resolve_route(
                    snapshot.protocol_type(),
                    request.method(),
                    request.uri().path(),
                    request.headers(),
                ) {
                    Ok(route) => route,
                    Err(error) => {
                        return Ok::<_, Infallible>(boxed_full(local_error(error.into())));
                    }
                };
                let query = request.uri().query().map(str::to_owned);
                let response: Response<UnsyncBoxBody<Bytes, io::Error>> = match proxy
                    .handshake(&snapshot, &route, query.as_deref(), peer, &mut request)
                    .await
                {
                    Ok(handshake) => boxed_handshake(handshake.into_response()),
                    Err(error) => boxed_full(local_error(error)),
                };
                Ok::<_, Infallible>(response)
            }
        });
        http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await
            .expect("serve gateway connection");
    });
    (address, task)
}

fn client_request(address: SocketAddr) -> Request<()> {
    Request::builder()
        .method(Method::GET)
        .uri(format!("ws://{address}/v1/responses?opaque=%2Fvalue+kept"))
        .header("host", address.to_string())
        .header("authorization", "Bearer gateway-id.gateway-secret")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .expect("client request")
}

async fn read_http_head(stream: &mut TcpStream) -> String {
    let mut received = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream.read(&mut buffer).await.expect("read HTTP head");
        assert!(count > 0, "connection ended before HTTP head");
        received.extend_from_slice(&buffer[..count]);
        if received.windows(4).any(|window| window == b"\r\n\r\n") {
            return String::from_utf8(received).expect("ASCII HTTP head");
        }
    }
}

fn boxed_full(response: Response<Full<Bytes>>) -> Response<UnsyncBoxBody<Bytes, io::Error>> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, body.map_err(|never| match never {}).boxed_unsync())
}

/// Boxes a handshake response so a test service can return either outcome.
fn boxed_handshake(response: Response<RejectionBody>) -> Response<UnsyncBoxBody<Bytes, io::Error>> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, body.map_err(io::Error::other).boxed_unsync())
}

fn header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    let needle = format!("{name}:");
    head.split("\r\n")
        .filter(|line| {
            line.len() >= needle.len() && line[..needle.len()].eq_ignore_ascii_case(&needle)
        })
        .map(|line| line[needle.len()..].trim())
        .collect()
}

fn header_value<'a>(head: &'a str, name: &str) -> &'a str {
    let values = header_values(head, name);
    assert_eq!(values.len(), 1, "expected one {name} in {head}");
    values[0]
}

async fn handshake_status_for_upstream_101(
    build: impl FnOnce(&str) -> String + Send + 'static,
    extra_client_headers: &str,
) -> (StatusCode, String) {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await.expect("accept upstream");
        let head = read_http_head(&mut socket).await;
        let key = header_value(&head, "sec-websocket-key");
        socket
            .write_all(build(key).as_bytes())
            .await
            .expect("write handshake head");
        let _ = socket;
    });
    let (gateway_address, gateway) = spawn_gateway(upstream_address).await;
    let mut client = TcpStream::connect(gateway_address)
        .await
        .expect("connect to gateway");
    client
        .write_all(
            format!(
                "GET /v1/responses HTTP/1.1\r\nhost: {gateway_address}\r\nauthorization: Bearer gateway-id.gateway-secret\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n{extra_client_headers}\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send handshake request");
    let mut received = Vec::new();
    let mut buffer = [0_u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, client.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(count)) => received.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) => break,
        }
        if received.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    drop(client);
    upstream.await.expect("upstream task");
    let _ = gateway.await;
    let text = String::from_utf8_lossy(&received).into_owned();
    let status_line = text.lines().next().unwrap_or(&text);
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .map(StatusCode::from_u16)
        .and_then(Result::ok)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, text)
}

#[tokio::test]
async fn downstream_upgrade_waits_for_upstream_and_rewrites_the_handshake() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (stream, _) = upstream_listener.accept().await.expect("accept upstream");
        accepted_tx.send(()).expect("signal accepted TCP");
        release_rx.await.expect("release upstream handshake");
        let mut socket = accept_async(stream)
            .await
            .expect("accept upstream WebSocket");
        let message = socket
            .next()
            .await
            .expect("message")
            .expect("valid message");
        assert_eq!(message, Message::text("transparent"));
        socket.send(message).await.expect("echo message");
        let _ = socket.next().await;
    });
    let (gateway_address, gateway) = spawn_gateway(upstream_address).await;
    let client = tokio::spawn(async move { connect_async(client_request(gateway_address)).await });

    accepted_rx.await.expect("upstream TCP accepted");
    tokio::task::yield_now().await;
    assert!(
        !client.is_finished(),
        "the downstream handshake must wait for the upstream response"
    );
    release_tx.send(()).expect("allow upstream handshake");
    let (mut client, response) = client
        .await
        .expect("client task")
        .expect("client handshake");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    client
        .send(Message::text("transparent"))
        .await
        .expect("send through gateway");
    assert_eq!(
        client.next().await.expect("echo").expect("valid echo"),
        Message::text("transparent")
    );
    client.close(None).await.expect("close downstream");

    upstream.await.expect("upstream task");
    gateway.await.expect("gateway task");
}

#[tokio::test]
async fn an_upstream_http_rejection_remains_an_ordinary_http_response() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind rejecting upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
        let head = read_http_head(&mut stream).await;
        assert!(
            head.starts_with("GET /provider-prefix/v1/responses?opaque=%2Fvalue+kept HTTP/1.1")
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("authorization: bearer upstream-secret")
        );
        assert!(!head.contains("gateway-id.gateway-secret"));
        let body = br#"{"error":"upstream-rejected"}"#;
        let response = format!(
            "HTTP/1.1 429 Too Many Requests\r\ncontent-type: application/problem+json\r\nx-upstream-error: retained\r\nconnection: close\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        let mut response = response.into_bytes();
        response.extend_from_slice(body);
        stream
            .write_all(&response)
            .await
            .expect("write rejection response");
        stream.shutdown().await.expect("close upstream");
    });
    let (gateway_address, gateway) = spawn_gateway(upstream_address).await;

    let error = connect_async(client_request(gateway_address))
        .await
        .expect_err("upstream rejects the upgrade");
    let WebSocketError::Http(response) = error else {
        panic!("expected an HTTP rejection, got {error:?}");
    };
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get("x-upstream-error")
            .expect("retained header"),
        "retained"
    );
    assert_eq!(
        response.body().as_deref(),
        Some(br#"{"error":"upstream-rejected"}"#.as_slice())
    );

    upstream.await.expect("upstream task");
    gateway.await.expect("gateway task");
}

#[tokio::test]
async fn a_missing_upstream_response_becomes_a_sanitized_local_error() {
    let unavailable = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve unused address");
    let unavailable_address = unavailable.local_addr().expect("unused address");
    drop(unavailable);
    let (gateway_address, gateway) = spawn_gateway(unavailable_address).await;

    let error = connect_async(client_request(gateway_address))
        .await
        .expect_err("upstream connection is refused");
    let WebSocketError::Http(response) = error else {
        panic!("expected a local HTTP failure, got {error:?}");
    };
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = String::from_utf8(response.body().clone().expect("local error body"))
        .expect("JSON error text");
    assert!(body.contains("upstream_connect_failed"));
    assert!(!body.contains("gateway-id.gateway-secret"));
    assert!(!body.contains("opaque=%2Fvalue+kept"));
    assert!(!body.contains(&unavailable_address.to_string()));

    gateway.await.expect("gateway task");
}

#[tokio::test]
async fn a_client_owned_http_fallback_is_a_second_independent_request() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fallback upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let contacts = Arc::new(AtomicUsize::new(0));
    let upstream_contacts = Arc::clone(&contacts);
    let upstream = tokio::spawn(async move {
        let (mut websocket, _) = upstream_listener.accept().await.expect("accept WebSocket");
        upstream_contacts.fetch_add(1, Ordering::SeqCst);
        let websocket_head = read_http_head(&mut websocket).await;
        assert!(websocket_head.starts_with("GET /provider-prefix/v1/responses"));
        websocket
            .write_all(
                b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 18\r\nconnection: close\r\n\r\nwebsocket disabled",
            )
            .await
            .expect("reject WebSocket");
        websocket
            .shutdown()
            .await
            .expect("close WebSocket rejection");

        let (mut http, _) = upstream_listener
            .accept()
            .await
            .expect("accept HTTP fallback");
        upstream_contacts.fetch_add(1, Ordering::SeqCst);
        let http_head = read_http_head(&mut http).await;
        assert!(http_head.starts_with("POST /provider-prefix/v1/responses?fallback=true HTTP/1.1"));
        assert!(
            http_head
                .to_ascii_lowercase()
                .contains("authorization: bearer upstream-secret")
        );
        let body = b"data: first\n\ndata: second\n\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        http.write_all(response.as_bytes())
            .await
            .expect("write HTTP head");
        http.write_all(body).await.expect("write SSE body");
        http.shutdown().await.expect("finish fallback response");
    });

    let gateway_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fallback gateway");
    let gateway_address = gateway_listener.local_addr().expect("gateway address");
    let snapshot = Arc::new(snapshot(upstream_address));
    let websocket_proxy = Arc::new(WebSocketProxy::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
        &limits(),
    ));
    let http_proxy = Arc::new(HttpProxy::<Incoming>::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    ));
    let sequence = Arc::new(AtomicUsize::new(0));
    let log_store = Arc::new(RecordingLogStore::default());
    let metrics = Metrics::default();
    let (events, log_worker) = channel(Arc::clone(&log_store), 8, 4, Duration::from_millis(20));
    let log_worker = tokio::spawn(log_worker.run());
    let gateway_events = events.clone();
    let gateway = tokio::spawn(async move {
        let mut connections = Vec::new();
        for _ in 0..2 {
            let (stream, peer) = gateway_listener
                .accept()
                .await
                .expect("accept client request");
            let snapshot = Arc::clone(&snapshot);
            let websocket_proxy = Arc::clone(&websocket_proxy);
            let http_proxy = Arc::clone(&http_proxy);
            let sequence = Arc::clone(&sequence);
            let events = gateway_events.clone();
            let metrics = metrics.clone();
            connections.push(tokio::spawn(async move {
                let service = service_fn(move |mut request: Request<Incoming>| {
                    let snapshot = Arc::clone(&snapshot);
                    let websocket_proxy = Arc::clone(&websocket_proxy);
                    let http_proxy = Arc::clone(&http_proxy);
                    let sequence = Arc::clone(&sequence);
                    let events = events.clone();
                    let metrics = metrics.clone();
                    async move {
                        let number = sequence.fetch_add(1, Ordering::SeqCst) + 1;
                        let request_id =
                            RequestId::new(format!("request-{number}")).expect("request ID");
                        let route = resolve_route(
                            snapshot.protocol_type(),
                            request.method(),
                            request.uri().path(),
                            request.headers(),
                        )
                        .expect("supported fallback route");
                        let query = request.uri().query().map(str::to_owned);
                        let mut response = if request.method() == Method::GET {
                            let handshake = websocket_proxy
                                .handshake_logged(
                                    &snapshot,
                                    &route,
                                    query.as_deref(),
                                    peer,
                                    &mut request,
                                    events,
                                    metrics,
                                    request_id.clone(),
                                )
                                .await
                                .expect("upstream returns an HTTP rejection");
                            boxed_handshake(handshake.into_response())
                        } else {
                            let response = http_proxy
                                .forward_logged(
                                    &snapshot,
                                    &route,
                                    query.as_deref(),
                                    peer,
                                    request,
                                    events,
                                    metrics,
                                    request_id.clone(),
                                )
                                .await
                                .expect("forward HTTP fallback");
                            let (parts, body) = response.into_parts();
                            Response::from_parts(
                                parts,
                                body.map_err(io::Error::other).boxed_unsync(),
                            )
                        };
                        response.headers_mut().insert(
                            "x-request-id",
                            request_id.as_str().parse().expect("request ID header"),
                        );
                        Ok::<_, Infallible>(response)
                    }
                });
                http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await
                    .expect("serve fallback connection");
            }));
        }
        for connection in connections {
            connection.await.expect("gateway connection task");
        }
    });

    let websocket_error = connect_async(client_request(gateway_address))
        .await
        .expect_err("WebSocket path is unavailable");
    let WebSocketError::Http(websocket_response) = websocket_error else {
        panic!("expected HTTP WebSocket rejection, got {websocket_error:?}");
    };
    assert_eq!(websocket_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        websocket_response
            .headers()
            .get("x-request-id")
            .expect("WebSocket request ID"),
        "request-1"
    );
    assert_eq!(contacts.load(Ordering::SeqCst), 1);

    let mut fallback = TcpStream::connect(gateway_address)
        .await
        .expect("connect fallback client");
    let request = format!(
        "POST /v1/responses?fallback=true HTTP/1.1\r\nhost: {gateway_address}\r\nauthorization: Bearer gateway-id.gateway-secret\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}"
    );
    fallback
        .write_all(request.as_bytes())
        .await
        .expect("send explicit fallback");
    let mut response = Vec::new();
    fallback
        .read_to_end(&mut response)
        .await
        .expect("read fallback response");
    let response = String::from_utf8(response).expect("HTTP response text");
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-request-id: request-2")
    );
    assert!(response.ends_with("data: first\n\ndata: second\n\n"));
    assert_eq!(contacts.load(Ordering::SeqCst), 2);

    upstream.await.expect("upstream task");
    gateway.await.expect("gateway task");
    drop(events);
    log_worker.await.expect("log worker");

    let events = log_store.events.lock().await;
    assert_eq!(events.len(), 4);
    let LogEvent::Started(websocket_start) = &events[0] else {
        panic!("WebSocket start must be first");
    };
    let LogEvent::Completed(websocket_end) = &events[1] else {
        panic!("WebSocket completion must follow its start");
    };
    let LogEvent::Started(http_start) = &events[2] else {
        panic!("HTTP start must be independent");
    };
    let LogEvent::Completed(http_end) = &events[3] else {
        panic!("HTTP completion must follow its start");
    };
    assert_eq!(websocket_start.request_id().as_str(), "request-1");
    assert_eq!(
        websocket_start.transport_type(),
        tokenstream::domain::TransportType::WebSocket
    );
    assert_eq!(websocket_start.path(), "/v1/responses");
    assert_eq!(websocket_end.request_id().as_str(), "request-1");
    assert_eq!(websocket_end.status_code(), Some(503));
    assert_eq!(http_start.request_id().as_str(), "request-2");
    assert_eq!(
        http_start.transport_type(),
        tokenstream::domain::TransportType::Http
    );
    assert_eq!(http_start.path(), "/v1/responses");
    assert_eq!(http_end.request_id().as_str(), "request-2");
    assert_eq!(http_end.status_code(), Some(200));
    assert_ne!(
        websocket_start.request_id().as_str(),
        http_start.request_id().as_str()
    );
}

#[tokio::test]
async fn relay_preserves_simultaneous_messages_fragmentation_controls_and_close() {
    let (mut downstream_client, downstream_proxy) = socket_pair(WebSocketConfig::default()).await;
    let (mut upstream_peer, upstream_proxy) = socket_pair(WebSocketConfig::default()).await;
    let relay_task = tokio::spawn(relay(
        downstream_proxy,
        upstream_proxy,
        Duration::from_secs(2),
    ));

    let down_send = downstream_client.send(Message::text("toward upstream"));
    let up_send = upstream_peer.send(Message::binary(Bytes::from_static(b"toward downstream")));
    let (down_result, up_result) = tokio::join!(down_send, up_send);
    down_result.expect("downstream text send");
    up_result.expect("upstream binary send");
    assert_eq!(
        next_message(&mut upstream_peer).await,
        Message::text("toward upstream")
    );
    assert_eq!(
        next_message(&mut downstream_client).await,
        Message::binary(Bytes::from_static(b"toward downstream"))
    );

    downstream_client
        .send(Message::Frame(Frame::message(
            Bytes::from_static(b"frag"),
            OpCode::Data(Data::Text),
            false,
        )))
        .await
        .expect("first fragment");
    downstream_client
        .send(Message::Frame(Frame::message(
            Bytes::from_static(b"mented"),
            OpCode::Data(Data::Continue),
            true,
        )))
        .await
        .expect("last fragment");
    assert_eq!(
        next_message(&mut upstream_peer).await,
        Message::text("fragmented")
    );

    downstream_client
        .send(Message::Ping(Bytes::from_static(b"probe")))
        .await
        .expect("ping send");
    assert_eq!(
        next_message(&mut upstream_peer).await,
        Message::Ping(Bytes::from_static(b"probe"))
    );
    upstream_peer
        .send(Message::Pong(Bytes::from_static(b"reply")))
        .await
        .expect("pong send");
    loop {
        let message = next_message(&mut downstream_client).await;
        if message == Message::Pong(Bytes::from_static(b"reply")) {
            break;
        }
    }

    let close = CloseFrame {
        code: 4001_u16.into(),
        reason: Utf8Bytes::from_static("finished"),
    };
    downstream_client
        .send(Message::Close(Some(close.clone())))
        .await
        .expect("close send");
    assert_eq!(
        next_message(&mut upstream_peer).await,
        Message::Close(Some(close.clone()))
    );
    assert_eq!(
        next_message(&mut downstream_client).await,
        Message::Close(Some(close))
    );
    assert_eq!(relay_task.await.expect("relay task"), RelayOutcome::Closed);
}

#[tokio::test]
async fn an_oversized_reassembled_message_closes_with_code_1009() {
    let constrained = WebSocketConfig::default()
        .max_frame_size(Some(8))
        .max_message_size(Some(12));
    let (mut downstream_client, downstream_proxy) = socket_pair(constrained).await;
    let (mut upstream_peer, upstream_proxy) = socket_pair(constrained).await;
    let relay_task = tokio::spawn(relay(
        downstream_proxy,
        upstream_proxy,
        Duration::from_secs(1),
    ));

    downstream_client
        .send(Message::Frame(Frame::message(
            Bytes::from_static(b"12345678"),
            OpCode::Data(Data::Binary),
            false,
        )))
        .await
        .expect("first bounded fragment");
    downstream_client
        .send(Message::Frame(Frame::message(
            Bytes::from_static(b"abcdefgh"),
            OpCode::Data(Data::Continue),
            true,
        )))
        .await
        .expect("fragment that exceeds message bound");

    let close = next_message(&mut upstream_peer).await;
    let Message::Close(Some(frame)) = close else {
        panic!("expected an explicit capacity close, got {close:?}");
    };
    assert_eq!(u16::from(frame.code), 1009);
    assert_eq!(frame.reason, "message exceeds configured limit");
    assert_eq!(
        relay_task.await.expect("relay task"),
        RelayOutcome::MessageTooLarge
    );
}

#[tokio::test]
async fn a_completely_idle_connection_has_a_bounded_lifetime() {
    let (_downstream_client, downstream_proxy) = socket_pair(WebSocketConfig::default()).await;
    let (_upstream_peer, upstream_proxy) = socket_pair(WebSocketConfig::default()).await;

    let outcome = relay(downstream_proxy, upstream_proxy, Duration::from_millis(25)).await;
    assert_eq!(outcome, RelayOutcome::IdleTimeout);
}

#[tokio::test]
async fn a_slow_destination_times_out_without_spawning_unbounded_work() {
    let (mut downstream_client, downstream_proxy) = socket_pair(WebSocketConfig::default()).await;
    let (_upstream_peer, upstream_proxy) = socket_pair(WebSocketConfig::default()).await;
    let relay_task = tokio::spawn(relay(
        downstream_proxy,
        upstream_proxy,
        Duration::from_millis(40),
    ));
    let producer = tokio::spawn(async move {
        loop {
            if downstream_client
                .send(Message::binary(vec![7_u8; 32 * 1024]))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let outcome = tokio::time::timeout(Duration::from_secs(1), relay_task)
        .await
        .expect("relay has a bounded deadline")
        .expect("relay task");
    assert!(matches!(
        outcome,
        RelayOutcome::IdleTimeout | RelayOutcome::Failed
    ));
    producer.abort();
    let _ = producer.await;
}

#[test]
fn relay_outcomes_do_not_include_transport_or_payload_text() {
    let rendered = format!(
        "{:?} {:?} {:?}",
        RelayOutcome::Failed,
        RelayOutcome::MessageTooLarge,
        WebSocketError::ConnectionClosed
    );
    assert!(!rendered.contains("gateway-secret"));
    assert!(!rendered.contains("application-body"));
}

/// A rejected handshake whose body is relayed as an HTTP stream, not a buffer.
///
/// The upstream writes the head and body in separate writes with a pause
/// between them, then closes. The client reads the response as raw bytes so
/// the exact body bytes, their arrival after the head, and the absence of any
/// gateway-generated content are all observable.
#[tokio::test]
async fn a_rejected_handshake_relays_head_and_body_as_one_stream() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let payload = b"{\"error\":{\"message\":\"websocket upgrade is not available\"}}";
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
        let head = read_http_head(&mut stream).await;
        assert!(
            head.starts_with("GET /provider-prefix/v1/responses?opaque=%2Fvalue+kept HTTP/1.1")
        );
        // The head is sent alone; the body only follows well after it.
        stream
            .write_all(
                format!(
                    "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\nx-upstream-error: retained\r\ncontent-length: {}\r\n\r\n",
                    payload.len()
                )
                .as_bytes(),
            )
            .await
            .expect("write rejection head");
        tokio::time::sleep(Duration::from_millis(80)).await;
        stream
            .write_all(payload)
            .await
            .expect("write rejection body");
        stream.shutdown().await.expect("close upstream");
    });
    let (gateway_address, gateway) = spawn_gateway(upstream_address).await;

    let mut client = TcpStream::connect(gateway_address)
        .await
        .expect("connect to gateway");
    client
        .write_all(
            format!(
                "GET /v1/responses?opaque=%2Fvalue+kept HTTP/1.1\r\nhost: {gateway_address}\r\nauthorization: Bearer gateway-id.gateway-secret\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send handshake request");

    let mut received = Vec::new();
    let mut buffer = [0_u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let head_end = loop {
        match tokio::time::timeout_at(deadline, client.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => panic!("connection ended before the head"),
            Ok(Ok(count)) => received.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) => panic!("read failed before the head"),
        }
        if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&received[..head_end]).to_ascii_lowercase();
    assert!(
        head.starts_with("http/1.1 503 service unavailable"),
        "{head}"
    );
    assert!(head.contains("x-upstream-error: retained"), "{head}");
    // Hop-by-hop headers never travel to the client.
    assert!(!head.contains("connection:"), "{head}");

    // The body is still arriving on the same connection after the head.
    let body_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while received.len() < head_end + payload.len() {
        match tokio::time::timeout_at(body_deadline, client.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(count)) => received.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) => break,
        }
    }
    assert_eq!(
        &received[head_end..head_end + payload.len()],
        payload.as_slice(),
        "the rejection body must be relayed byte for byte"
    );
    assert!(
        !String::from_utf8_lossy(&received).contains("gateway-id.gateway-secret"),
        "no credential may appear in a relayed rejection"
    );
    drop(client);

    upstream.await.expect("upstream task");
    let _ = gateway.await;
}

/// A chunked rejection body is relayed frame by frame, so a body that never
/// ends inside one read is still delivered in full.
#[tokio::test]
async fn a_chunked_rejection_body_is_relayed_without_truncation() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let chunks: Vec<String> = (0..8).map(|index| format!("chunk-{index}\n")).collect();
    // The gateway is transparent, so the chunk framing itself is what travels.
    let expected: String = chunks
        .iter()
        .map(|chunk| format!("{:x}\r\n{chunk}\r\n", chunk.len()))
        .chain(std::iter::once("0\r\n\r\n".to_owned()))
        .collect();
    let upstream = tokio::spawn({
        let chunks = chunks.clone();
        async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
            read_http_head(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n",
                )
                .await
                .expect("write chunked head");
            for chunk in &chunks {
                stream
                    .write_all(format!("{:x}\r\n{chunk}\r\n", chunk.len()).as_bytes())
                    .await
                    .expect("write chunk");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            stream
                .write_all(b"0\r\n\r\n")
                .await
                .expect("write terminating chunk");
            stream.shutdown().await.expect("close upstream");
        }
    });
    let (gateway_address, gateway) = spawn_gateway(upstream_address).await;

    // The response is read as raw bytes: a client library stops at the first
    // frame, which would hide whether the rest of the body was relayed.
    let mut client = TcpStream::connect(gateway_address)
        .await
        .expect("connect to gateway");
    client
        .write_all(
            format!(
                "GET /v1/responses HTTP/1.1\r\nhost: {gateway_address}\r\nauthorization: Bearer gateway-id.gateway-secret\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send handshake request");
    let mut received = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    // The chunked body is self-delimiting: once the terminating chunk has
    // arrived, the full relayed body is present and the socket is closed.
    let needed = expected.len() + 128;
    while received.len() < needed {
        match tokio::time::timeout_at(deadline, client.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(count)) => received.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) => break,
        }
        let text = String::from_utf8_lossy(&received);
        if text
            .find("\r\n\r\n")
            .is_some_and(|position| text.len() >= position + 4 + expected.len())
        {
            break;
        }
    }
    let text = String::from_utf8_lossy(&received).to_string();
    assert!(
        text.to_ascii_lowercase()
            .starts_with("http/1.1 400 bad request"),
        "{text}"
    );
    let head_end = text.find("\r\n\r\n").expect("response head") + 4;
    assert_eq!(
        &text[head_end..head_end + expected.len()],
        expected,
        "every chunked frame must reach the client"
    );
    drop(client);

    upstream.await.expect("upstream task");
    let _ = gateway.await;
}

/// A rejection body larger than one socket read is delivered in full, which a
/// buffer of the already-read remainder could not achieve.
#[tokio::test]
async fn a_large_rejection_body_is_relayed_in_full() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let payload: Vec<u8> = (0..512 * 1024).map(|index| (index % 251) as u8).collect();
    let upstream = tokio::spawn({
        let payload = payload.clone();
        async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
            read_http_head(&mut stream).await;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 413 Payload Too Large\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\n\r\n",
                        payload.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("write head");
            for slice in payload.chunks(16 * 1024) {
                stream.write_all(slice).await.expect("write body slice");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            stream.shutdown().await.expect("close upstream");
        }
    });
    let (gateway_address, gateway) = spawn_gateway(upstream_address).await;

    let mut client = TcpStream::connect(gateway_address)
        .await
        .expect("connect to gateway");
    let head = format!(
        "GET /v1/responses HTTP/1.1\r\nhost: {gateway_address}\r\nauthorization: Bearer gateway-id.gateway-secret\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    client
        .write_all(head.as_bytes())
        .await
        .expect("send handshake request");

    let mut received = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let head_end = loop {
        match tokio::time::timeout_at(deadline, client.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => panic!("connection ended before the head"),
            Ok(Ok(count)) => received.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) => panic!("read failed before the head"),
        }
        if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let expected_total = head_end + payload.len();
    while received.len() < expected_total {
        match tokio::time::timeout_at(deadline, client.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(count)) => received.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) => break,
        }
    }
    assert_eq!(
        received.len(),
        expected_total,
        "a large rejection body must not be truncated"
    );
    assert_eq!(&received[head_end..], payload.as_slice());
    drop(client);

    upstream.await.expect("upstream task");
    let _ = gateway.await;
}

/// An accepted upgrade keeps the allowed end-to-end handshake headers and drops
/// the hop-by-hop set, while the required upgrade headers address the
/// downstream peer rather than being copied from the upstream.
#[tokio::test]
async fn an_accepted_upgrade_keeps_allowed_headers_and_rebuilds_the_upgrade() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await.expect("accept upstream");
        let head = read_http_head(&mut socket).await;
        let accept = derive_accept_key(header_value(&head, "sec-websocket-key").as_bytes());
        socket
            .write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: keep-alive, x-drop-me, Upgrade\r\nsec-websocket-accept: {accept}\r\nsec-websocket-protocol: openai-realtime-v1\r\nx-upstream-negotiated: retained\r\nx-drop-me: gone\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write upgrade head");
        let _ = socket;
    });
    let (gateway_address, gateway) = spawn_gateway(upstream_address).await;

    let mut client = TcpStream::connect(gateway_address)
        .await
        .expect("connect to gateway");
    client
        .write_all(
            format!(
                "GET /v1/responses HTTP/1.1\r\nhost: {gateway_address}\r\nauthorization: Bearer gateway-id.gateway-secret\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-protocol: openai-realtime-v1\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send handshake request");

    let mut received = Vec::new();
    let mut buffer = [0_u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, client.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(count)) => received.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) => break,
        }
        if received.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&received).to_ascii_lowercase();
    assert!(
        text.starts_with("http/1.1 101 switching protocols"),
        "{text}"
    );
    assert!(
        text.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="),
        "{text}"
    );
    assert!(
        text.contains("sec-websocket-protocol: openai-realtime-v1"),
        "{text}"
    );
    assert!(text.contains("x-upstream-negotiated: retained"), "{text}");
    // `x-drop-me` is nominated by `Connection` and is therefore hop-by-hop.
    assert!(!text.contains("x-drop-me"), "{text}");
    // `Connection` itself is rebuilt for the downstream upgrade, so neither
    // the upstream's nomination list nor its `keep-alive` token survives.
    assert!(text.contains("connection: upgrade"), "{text}");
    assert!(!text.contains("keep-alive"), "{text}");
    assert!(!text.contains("x-drop-me"), "{text}");

    upstream.await.expect("upstream task");
    let _ = gateway.await;
}

#[tokio::test]
async fn repeated_end_to_end_handshake_headers_reach_upstream_in_order() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let (observed_tx, observed_rx) = oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await.expect("accept upstream");
        let head = read_http_head(&mut socket).await;
        observed_tx
            .send(head.clone())
            .expect("observe upstream head");
        let accept = derive_accept_key(header_value(&head, "sec-websocket-key").as_bytes());
        socket
            .write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write upgrade head");
        let _ = socket;
    });
    let (gateway_address, gateway) = spawn_gateway(upstream_address).await;
    let mut client = TcpStream::connect(gateway_address)
        .await
        .expect("connect to gateway");
    client
        .write_all(
            format!(
                "GET /v1/responses HTTP/1.1\r\nhost: {gateway_address}\r\nauthorization: Bearer gateway-id.gateway-secret\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nx-end-to-end: first\r\nx-end-to-end: second\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send handshake request");

    let mut received = Vec::new();
    let mut buffer = [0_u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, client.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(count)) => received.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) => break,
        }
        if received.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&received).to_ascii_lowercase();
    assert!(
        text.starts_with("http/1.1 101 switching protocols"),
        "{text}"
    );
    let upstream_head = observed_rx.await.expect("upstream head");
    assert_eq!(
        header_values(&upstream_head, "x-end-to-end"),
        ["first", "second"]
    );

    upstream.await.expect("upstream task");
    let _ = gateway.await;
}

fn invalid_switch_head(case: &'static str, key: &str) -> String {
    let accept = derive_accept_key(key.as_bytes());
    match case {
        "missing accept" => {
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n"
                .to_owned()
        }
        "duplicate accept" => format!(
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\nsec-websocket-accept: {accept}\r\n\r\n"
        ),
        "wrong accept" => {
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
                .to_owned()
        }
        "missing upgrade" => format!(
            "HTTP/1.1 101 Switching Protocols\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n"
        ),
        "wrong upgrade" => format!(
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: h2c\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n"
        ),
        "connection without upgrade" => format!(
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: keep-alive\r\nsec-websocket-accept: {accept}\r\n\r\n"
        ),
        "unrequested subprotocol" => format!(
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\nsec-websocket-protocol: openai-realtime-v1\r\n\r\n"
        ),
        "unsupported extension" => format!(
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\nsec-websocket-extensions: permessage-deflate\r\n\r\n"
        ),
        _ => panic!("unknown invalid handshake case {case}"),
    }
}

#[tokio::test]
async fn an_invalid_upstream_switch_does_not_complete_the_downstream_upgrade() {
    for name in [
        "missing accept",
        "duplicate accept",
        "wrong accept",
        "missing upgrade",
        "wrong upgrade",
        "connection without upgrade",
        "unrequested subprotocol",
        "unsupported extension",
    ] {
        let (status, text) =
            handshake_status_for_upstream_101(move |key| invalid_switch_head(name, key), "").await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "{name} must not upgrade downstream: {text}"
        );
        assert!(
            text.to_ascii_lowercase()
                .contains("upstream_connect_failed"),
            "{name} must report a local handshake failure: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().starts_with("http/1.1 101 "),
            "{name} must not complete the downstream upgrade: {text}"
        );
    }
}
