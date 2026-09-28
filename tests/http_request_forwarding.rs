//! HTTP request-forwarding contract.
//!
//! These tests drive the request half of the proxy against a controllable mock
//! upstream. They assert that the application body reaches the upstream byte
//! for byte across arbitrary chunking and large sizes, that a slow upstream
//! exerts backpressure instead of letting the body accumulate, that the
//! rewritten envelope never carries the gateway credential, and that connect
//! and response-header deadlines fail closed with a sanitized local error
//! before any upstream response exists.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use hyper::header::HeaderMap;
use hyper::{Method, Request, StatusCode};
use tokenstream::domain::{ProtocolType, ProviderId, ProviderSnapshot, SecretString};
use tokenstream::proxy::error::GatewayError;
use tokenstream::proxy::http::HttpProxy;
use tokenstream::routing::{ResolvedRoute, resolve_route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

const GATEWAY_CREDENTIAL: &str = "gateway-key.secret-value";
const UPSTREAM_KEY: &str = "upstream-secret-value";

/// A request body that yields pre-set frames in order.
///
/// It also counts how many frames have been produced, so a test can observe
/// backpressure on the request body without reading it.
struct Chunks {
    frames: VecDeque<Bytes>,
    emitted: Arc<AtomicUsize>,
}

/// A body that sends one frame and then never produces another frame or EOF.
struct StalledBody {
    first: Option<Bytes>,
}

impl Body for StalledBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        match this.first.take() {
            Some(first) => Poll::Ready(Some(Ok(Frame::data(first)))),
            None => Poll::Pending,
        }
    }
}

impl Chunks {
    fn new(frames: Vec<Bytes>, emitted: Arc<AtomicUsize>) -> Self {
        Self {
            frames: frames.into(),
            emitted,
        }
    }
}

impl Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        match this.frames.pop_front() {
            Some(frame) => {
                this.emitted.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Some(Ok(Frame::data(frame))))
            }
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        let remaining: u64 = self.frames.iter().map(|frame| frame.len() as u64).sum();
        let mut hint = SizeHint::new();
        hint.set_exact(remaining);
        hint
    }
}

/// Behavior of the controllable mock upstream.
struct MockUpstream {
    status: &'static str,
    response_headers: &'static str,
    response_body: &'static str,
    /// Delay before reading the request body, so a slow upstream is observable.
    body_delay: Duration,
    /// Delay before writing the response head, so the header deadline is observable.
    head_delay: Duration,
}

impl Default for MockUpstream {
    fn default() -> Self {
        Self {
            status: "200 OK",
            response_headers: "",
            response_body: "",
            body_delay: Duration::ZERO,
            head_delay: Duration::ZERO,
        }
    }
}

/// A complete request as the upstream observed it.
struct Recorded {
    head: String,
    body: Vec<u8>,
}

/// Starts a mock upstream and returns its address and the recording task.
async fn mock_upstream(config: MockUpstream) -> (SocketAddr, tokio::task::JoinHandle<Recorded>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the mock upstream");
    let address = listener.local_addr().expect("mock upstream address");

    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept one connection");
        let (head, mut body) = read_request_head(&mut stream).await;

        if !config.body_delay.is_zero() {
            tokio::time::sleep(config.body_delay).await;
        }
        body = read_request_body(&mut stream, &head, body).await;

        if !config.head_delay.is_zero() {
            tokio::time::sleep(config.head_delay).await;
        }

        let response = format!(
            "HTTP/1.1 {}\r\n{}content-length: {}\r\nconnection: close\r\n\r\n{}",
            config.status,
            config.response_headers,
            config.response_body.len(),
            config.response_body,
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;

        Recorded { head, body }
    });

    (address, task)
}

/// Reads the request line and headers, stopping after the blank line.
async fn read_request_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.expect("read request head");
        assert!(read > 0, "upstream saw EOF before a complete request head");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_subslice(&buffer, b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let body = buffer[header_end..].to_vec();
    (head, body)
}

/// Reads the rest of the body using the framing the request declared.
async fn read_request_body(stream: &mut TcpStream, head: &str, mut body: Vec<u8>) -> Vec<u8> {
    let lower = head.to_ascii_lowercase();
    let Some(length) = content_length(&lower) else {
        return body;
    };
    let mut chunk = [0u8; 8192];
    while body.len() < length {
        let read = stream.read(&mut chunk).await.expect("read request body");
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    body
}

fn content_length(lowercased_head: &str) -> Option<usize> {
    lowercased_head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn snapshot(endpoint: SocketAddr) -> ProviderSnapshot {
    ProviderSnapshot::new(
        ProviderId::try_from(1).expect("positive provider ID"),
        ProtocolType::OpenAi,
        Url::parse(&format!("http://{endpoint}")).expect("valid endpoint"),
        SecretString::new(UPSTREAM_KEY),
    )
}

fn responses_route() -> ResolvedRoute {
    resolve_route(
        ProtocolType::OpenAi,
        &Method::POST,
        "/v1/responses",
        &HeaderMap::new(),
    )
    .expect("the responses route is allowed")
}

fn peer() -> SocketAddr {
    "203.0.113.7:5555".parse().expect("valid peer address")
}

fn downstream_request(frames: Vec<Bytes>, emitted: Arc<AtomicUsize>) -> Request<Chunks> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/responses?stream=true")
        .header("authorization", format!("Bearer {GATEWAY_CREDENTIAL}"))
        .header("content-type", "application/json")
        .header("x-request-tag", "kept")
        .header("proxy-authorization", "drop-me")
        .body(Chunks::new(frames, emitted))
        .expect("valid downstream request")
}

async fn unused_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    address
}

#[tokio::test]
async fn the_request_target_and_envelope_reach_the_upstream() {
    let (address, upstream) = mock_upstream(MockUpstream {
        response_headers: "content-type: text/event-stream\r\n",
        response_body: "data: ok\n\n",
        ..MockUpstream::default()
    })
    .await;

    let proxy = HttpProxy::<Chunks>::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let emitted = Arc::new(AtomicUsize::new(0));
    let body = Bytes::from_static(b"{\"model\":\"unknown-field\",\"stream\":true}");

    let response = proxy
        .forward(
            &snapshot(address),
            &responses_route(),
            Some("stream=true&unknown=1"),
            peer(),
            downstream_request(vec![body.clone()], Arc::clone(&emitted)),
        )
        .await
        .expect("the upstream answers");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );

    let recorded = upstream.await.expect("upstream task completes");
    assert!(
        recorded
            .head
            .starts_with("POST /v1/responses?stream=true&unknown=1 HTTP/1.1\r\n"),
        "{}",
        recorded.head
    );

    let head = recorded.head.to_ascii_lowercase();
    assert!(
        head.contains(&format!("authorization: bearer {UPSTREAM_KEY}")),
        "{}",
        recorded.head
    );
    assert!(!head.contains(&GATEWAY_CREDENTIAL.to_ascii_lowercase()));
    assert!(!head.contains("proxy-authorization"));
    assert!(head.contains("x-forwarded-for: 203.0.113.7"));
    assert!(head.contains("x-request-tag: kept"));
    assert!(head.contains(&format!("host: {address}")));
    assert_eq!(recorded.body, body.to_vec());
}

#[tokio::test]
async fn the_body_is_forwarded_byte_for_byte_across_arbitrary_chunks() {
    let (address, upstream) = mock_upstream(MockUpstream::default()).await;

    let proxy = HttpProxy::<Chunks>::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let emitted = Arc::new(AtomicUsize::new(0));

    // The same bytes split into frames of very different sizes, including
    // empty and single-byte frames, must arrive upstream concatenated in order.
    let mut expected = Vec::new();
    let mut frames = Vec::new();
    for size in [1, 0, 7, 1, 4096, 3, 0, 65536, 1, 11] {
        let frame = Bytes::from(
            (0..size)
                .map(|index| u8::try_from((index + size) % 251).expect("byte"))
                .collect::<Vec<u8>>(),
        );
        expected.extend_from_slice(&frame);
        frames.push(frame);
    }

    let response = proxy
        .forward(
            &snapshot(address),
            &responses_route(),
            None,
            peer(),
            downstream_request(frames, Arc::clone(&emitted)),
        )
        .await
        .expect("the upstream answers");

    assert_eq!(response.status(), StatusCode::OK);
    let recorded = upstream.await.expect("upstream task completes");
    assert_eq!(recorded.body, expected);
    assert_eq!(emitted.load(Ordering::SeqCst), 10);
}

#[tokio::test]
async fn a_slow_upstream_applies_backpressure_to_the_request_body() {
    const FRAME_BYTES: usize = 65_536;
    const FRAMES: usize = 256;

    let (address, upstream) = mock_upstream(MockUpstream {
        body_delay: Duration::from_millis(400),
        ..MockUpstream::default()
    })
    .await;

    let proxy = Arc::new(HttpProxy::<Chunks>::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    ));
    let emitted = Arc::new(AtomicUsize::new(0));
    let frames: Vec<Bytes> = (0..FRAMES)
        .map(|_| Bytes::from(vec![0x61u8; FRAME_BYTES]))
        .collect();

    let forwarding = {
        let proxy = Arc::clone(&proxy);
        let snapshot = snapshot(address);
        let route = responses_route();
        let emitted = Arc::clone(&emitted);
        tokio::spawn(async move {
            proxy
                .forward(
                    &snapshot,
                    &route,
                    None,
                    peer(),
                    downstream_request(frames, emitted),
                )
                .await
        })
    };

    // While the upstream is not reading, the body must not be drained into
    // memory: only what the transport can absorb should have been produced.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let paused = emitted.load(Ordering::SeqCst);
    assert!(
        paused < FRAMES,
        "the body was fully drained ({paused} frames) while the upstream was not reading"
    );

    let response = forwarding
        .await
        .expect("join the forwarding task")
        .expect("the upstream answers");
    assert_eq!(response.status(), StatusCode::OK);

    let recorded = upstream.await.expect("upstream task completes");
    assert_eq!(recorded.body.len(), FRAMES * FRAME_BYTES);
    assert!(recorded.body.iter().all(|byte| *byte == 0x61));
}

#[tokio::test]
async fn a_refused_connection_is_a_sanitized_connect_failure() {
    let address = unused_address().await;
    let proxy = HttpProxy::<Chunks>::new(
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let emitted = Arc::new(AtomicUsize::new(0));

    let error = proxy
        .forward(
            &snapshot(address),
            &responses_route(),
            None,
            peer(),
            downstream_request(vec![Bytes::from_static(b"{}")], emitted),
        )
        .await
        .expect_err("nothing listens at the address");

    assert_eq!(error, GatewayError::UpstreamConnectFailed);
    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_slow_response_head_is_a_sanitized_upstream_timeout() {
    let (address, _upstream) = mock_upstream(MockUpstream {
        head_delay: Duration::from_secs(5),
        ..MockUpstream::default()
    })
    .await;

    let proxy = HttpProxy::<Chunks>::new(
        Duration::from_secs(2),
        Duration::from_millis(150),
        Duration::from_secs(5),
    );
    let emitted = Arc::new(AtomicUsize::new(0));

    let error = proxy
        .forward(
            &snapshot(address),
            &responses_route(),
            None,
            peer(),
            downstream_request(vec![Bytes::from_static(b"{}")], emitted),
        )
        .await
        .expect_err("the response head never arrives in time");

    assert_eq!(error, GatewayError::UpstreamTimeout);
    assert_eq!(error.status(), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn cancelling_before_response_headers_closes_upstream_without_retrying() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind cancellation upstream");
    let address = listener.local_addr().expect("upstream address");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("the first request arrives");
        let (head, body) = read_request_head(&mut stream).await;
        let body = read_request_body(&mut stream, &head, body).await;
        ready_tx.send(()).expect("the test is waiting");

        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("cancellation closes the upstream promptly")
            .expect("read cancellation EOF");
        assert_eq!(read, 0, "the cancelled request must close its transport");

        assert!(
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err(),
            "the gateway must not create a retry request"
        );
        body
    });

    let proxy = Arc::new(HttpProxy::<Chunks>::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    ));
    let emitted = Arc::new(AtomicUsize::new(0));
    let forwarding = {
        let proxy = Arc::clone(&proxy);
        let snapshot = snapshot(address);
        let route = responses_route();
        tokio::spawn(async move {
            proxy
                .forward(
                    &snapshot,
                    &route,
                    None,
                    peer(),
                    downstream_request(vec![Bytes::from_static(b"{\"cancel\":true}")], emitted),
                )
                .await
        })
    };

    ready_rx.await.expect("the upstream received the request");
    forwarding.abort();
    assert!(
        forwarding
            .await
            .expect_err("the forwarding future is cancelled")
            .is_cancelled()
    );
    assert_eq!(
        upstream.await.expect("the upstream task completes"),
        b"{\"cancel\":true}"
    );
}

#[tokio::test]
async fn a_stalled_request_body_hits_the_stream_idle_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled-body upstream");
    let address = listener.local_addr().expect("upstream address");
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("the request arrives");
        let (_head, _body) = read_request_head(&mut stream).await;
        let mut remaining = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut remaining))
            .await
            .expect("the timed-out upload closes promptly")
            .expect("read upload cancellation");
        assert!(read < 1024, "a stalled upload must not accumulate data");
    });

    let proxy = HttpProxy::<StalledBody>::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_millis(80),
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/responses")
        .header("authorization", format!("Bearer {GATEWAY_CREDENTIAL}"))
        .body(StalledBody {
            first: Some(Bytes::from_static(b"{")),
        })
        .expect("valid downstream request");

    let error = proxy
        .forward(
            &snapshot(address),
            &responses_route(),
            None,
            peer(),
            request,
        )
        .await
        .expect_err("the upload remains idle");
    assert_eq!(error, GatewayError::UpstreamTimeout);
    upstream.await.expect("the upstream task completes");
}
