//! HTTP response and SSE relay contract.
//!
//! These tests drive the response half of the proxy against a controllable mock
//! upstream. The upstream releases its response head and body in explicit
//! steps, so the tests can observe that a status and its allowed headers are
//! forwarded as soon as the head arrives, that an SSE event split across
//! transport chunks is reassembled byte for byte downstream, that an upstream
//! error body is never wrapped or rewritten, that arbitrary chunking and a
//! `stream` application field change nothing, and that a stalled downstream
//! consumer keeps the upstream write backpressured instead of letting the body
//! accumulate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper::header::HeaderMap;
use hyper::{Method, Request, Response, StatusCode};
use tokenstream::domain::{
    AccountId, ApiKeyId, ProtocolType, ProviderId, ProviderSnapshot, SecretString,
};
use tokenstream::proxy::http::{HttpProxy, IdleTimeoutBody, relay_response};
use tokenstream::routing::{ResolvedRoute, resolve_route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use url::Url;

const UPSTREAM_KEY: &str = "upstream-secret-value";

/// One step of a scripted upstream response.
enum Command {
    /// Write the status line and headers, then flush.
    Head {
        status: &'static str,
        headers: Vec<(&'static str, &'static str)>,
    },
    /// Write one chunk of the (chunked) body and flush.
    Chunk(Bytes),
    /// Terminate the body and close the connection.
    Finish,
    /// Close the transport without a complete chunked-body terminator.
    Abort,
}

/// A mock upstream whose response the test releases one step at a time.
struct ScriptedUpstream {
    address: SocketAddr,
    ready: oneshot::Receiver<()>,
    commands: mpsc::UnboundedSender<Command>,
    closed: oneshot::Receiver<()>,
}

impl ScriptedUpstream {
    /// Waits until the upstream has read the whole request.
    async fn wait_ready(&mut self) {
        (&mut self.ready)
            .await
            .expect("the upstream read the request");
    }

    /// Releases the response head.
    fn head(&self, status: &'static str, headers: Vec<(&'static str, &'static str)>) {
        self.commands
            .send(Command::Head { status, headers })
            .expect("the upstream is still running");
    }

    /// Releases one body chunk.
    fn chunk(&self, bytes: impl Into<Bytes>) {
        self.commands
            .send(Command::Chunk(bytes.into()))
            .expect("the upstream is still running");
    }

    /// Ends the response body.
    fn finish(&self) {
        self.commands
            .send(Command::Finish)
            .expect("the upstream is still running");
    }

    /// Abruptly closes the response without a valid body terminator.
    fn abort(&self) {
        self.commands
            .send(Command::Abort)
            .expect("the upstream is still running");
    }

    /// Waits until the upstream connection has closed.
    async fn wait_closed(&mut self) {
        (&mut self.closed)
            .await
            .expect("the upstream reports connection closure");
    }
}

/// Starts a scripted mock upstream and returns its address and control handle.
async fn scripted_upstream() -> ScriptedUpstream {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the mock upstream");
    let address = listener.local_addr().expect("mock upstream address");
    let (ready_tx, ready) = oneshot::channel();
    let (closed_tx, closed) = oneshot::channel();
    let (commands, mut receiver) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept one connection");
        let (head, body) = read_request_head(&mut stream).await;
        let _ = read_request_body(&mut stream, &head, body).await;
        let _ = ready_tx.send(());

        loop {
            let command = tokio::select! {
                command = receiver.recv() => command,
                readiness = stream.readable() => {
                    if readiness.is_err() {
                        break;
                    }
                    let mut probe = [0u8; 1];
                    match stream.try_read(&mut probe) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(_) => break,
                    }
                }
            };
            let Some(command) = command else {
                break;
            };
            let result = match command {
                Command::Head { status, headers } => {
                    let mut head = format!("HTTP/1.1 {status}\r\n");
                    for (name, value) in headers {
                        head.push_str(name);
                        head.push_str(": ");
                        head.push_str(value);
                        head.push_str("\r\n");
                    }
                    head.push_str("transfer-encoding: chunked\r\nconnection: close\r\n\r\n");
                    stream.write_all(head.as_bytes()).await
                }
                Command::Chunk(bytes) => {
                    let mut result = stream
                        .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
                        .await;
                    if result.is_ok() {
                        result = stream.write_all(&bytes).await;
                    }
                    if result.is_ok() {
                        result = stream.write_all(b"\r\n").await;
                    }
                    result
                }
                Command::Finish => {
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                    break;
                }
                Command::Abort => break,
            };
            if result.is_err() {
                break;
            }
            let _ = stream.flush().await;
        }
        let _ = stream.shutdown().await;
        let _ = closed_tx.send(());
    });

    ScriptedUpstream {
        address,
        ready,
        commands,
        closed,
    }
}

/// The size of one firehose frame.
const FIREHOSE_FRAME: usize = 65_536;

/// A mock upstream that writes one large body as fast as the socket allows.
struct FirehoseUpstream {
    address: SocketAddr,
    ready: oneshot::Receiver<()>,
    write_done: oneshot::Receiver<()>,
    written: Arc<AtomicUsize>,
    completed: tokio::task::JoinHandle<()>,
}

/// Starts a mock upstream that streams `total` bytes of a single repeated byte.
async fn firehose_upstream(total: usize) -> FirehoseUpstream {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the firehose upstream");
    let address = listener.local_addr().expect("firehose address");
    let (ready_tx, ready) = oneshot::channel();
    let (done_tx, write_done) = oneshot::channel();
    let written = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&written);

    let completed = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept one connection");
        let (head, body) = read_request_head(&mut stream).await;
        let _ = read_request_body(&mut stream, &head, body).await;
        let _ = ready_tx.send(());

        let head = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
        if stream.write_all(head.as_bytes()).await.is_ok() {
            let prefix = format!("{FIREHOSE_FRAME:x}\r\n");
            let payload = vec![0x61u8; FIREHOSE_FRAME];
            let mut sent = 0usize;
            while sent < total {
                if stream.write_all(prefix.as_bytes()).await.is_err()
                    || stream.write_all(&payload).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    break;
                }
                sent += FIREHOSE_FRAME;
                counter.store(sent, Ordering::SeqCst);
                let _ = stream.flush().await;
            }
        }
        let _ = done_tx.send(());
        let _ = stream.shutdown().await;
    });

    FirehoseUpstream {
        address,
        ready,
        write_done,
        written,
        completed,
    }
}

/// Either mock upstream used by a test.
enum Upstream {
    Scripted(ScriptedUpstream),
    Firehose(FirehoseUpstream),
}

impl Upstream {
    fn address(&self) -> SocketAddr {
        match self {
            Self::Scripted(upstream) => upstream.address,
            Self::Firehose(upstream) => upstream.address,
        }
    }

    /// Waits until the upstream has read the whole request.
    async fn wait_ready(&mut self) {
        match self {
            Self::Scripted(upstream) => upstream.wait_ready().await,
            Self::Firehose(upstream) => {
                (&mut upstream.ready)
                    .await
                    .expect("the firehose upstream read the request");
            }
        }
    }
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
        AccountId::try_from(1).expect("positive account ID"),
        ApiKeyId::try_from(1).expect("positive credential ID"),
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

fn downstream_request() -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/responses")
        .header("authorization", "Bearer gateway-key.secret-value")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(b"{\"stream\":true}")))
        .expect("valid downstream request")
}

fn proxy() -> HttpProxy<Full<Bytes>> {
    HttpProxy::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
}

/// Sends one request and returns the relayed downstream response.
async fn relay(
    upstream: &mut Upstream,
    proxy: HttpProxy<Full<Bytes>>,
) -> Response<IdleTimeoutBody<Incoming>> {
    let snapshot = snapshot(upstream.address());
    let route = responses_route();
    let forwarding = tokio::spawn(async move {
        proxy
            .forward(&snapshot, &route, None, peer(), downstream_request())
            .await
    });
    upstream.wait_ready().await;
    relay_response(
        forwarding
            .await
            .expect("join the forwarding task")
            .expect("the upstream answers"),
        Duration::from_secs(5),
    )
}

#[tokio::test]
async fn a_stalled_body_times_out_after_response_headers_have_started() {
    let mut upstream = scripted_upstream().await;
    let proxy = HttpProxy::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_millis(80),
    );

    let snapshot = snapshot(upstream.address);
    let route = responses_route();
    let forwarding = tokio::spawn(async move {
        proxy
            .forward(&snapshot, &route, None, peer(), downstream_request())
            .await
    });
    upstream.wait_ready().await;
    upstream.head("200 OK", vec![("content-type", "text/event-stream")]);

    let upstream_response = forwarding
        .await
        .expect("join")
        .expect("the response head arrives");
    let mut response = relay_response(upstream_response, Duration::from_millis(80));
    assert_eq!(response.status(), StatusCode::OK);

    let error = tokio::time::timeout(Duration::from_secs(1), response.body_mut().frame())
        .await
        .expect("the idle deadline is bounded")
        .expect("the timeout is a body error")
        .expect_err("a stalled stream must terminate");
    assert!(error.is_idle_timeout());
    assert_eq!(error.to_string(), "the HTTP body stream timed out");
    assert!(response.body_mut().frame().await.is_none());

    drop(response);
    upstream.wait_closed().await;
}

#[tokio::test]
async fn an_abrupt_upstream_eof_terminates_the_started_stream_without_retry() {
    let mut upstream = scripted_upstream().await;
    let proxy = proxy();

    let snapshot = snapshot(upstream.address);
    let route = responses_route();
    let forwarding = tokio::spawn(async move {
        proxy
            .forward(&snapshot, &route, None, peer(), downstream_request())
            .await
    });
    upstream.wait_ready().await;
    upstream.head("200 OK", vec![("content-type", "text/event-stream")]);
    upstream.chunk(Bytes::from_static(b"data: partial\n\n"));
    upstream.abort();

    let upstream_response = forwarding
        .await
        .expect("join")
        .expect("the response head arrives");
    let mut response = relay_response(upstream_response, Duration::from_secs(5));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        next_bytes(response.body_mut()).await,
        Bytes::from_static(b"data: partial\n\n")
    );

    let error = response
        .body_mut()
        .frame()
        .await
        .expect("the abnormal EOF is reported")
        .expect_err("the incomplete chunked body must fail");
    assert!(!error.is_idle_timeout());
    assert_eq!(error.to_string(), "the HTTP body stream failed");
    assert!(response.body_mut().frame().await.is_none());
    upstream.wait_closed().await;
}

#[tokio::test]
async fn dropping_the_downstream_response_cancels_the_upstream_stream() {
    let mut upstream = scripted_upstream().await;
    let proxy = proxy();

    let snapshot = snapshot(upstream.address);
    let route = responses_route();
    let forwarding = tokio::spawn(async move {
        proxy
            .forward(&snapshot, &route, None, peer(), downstream_request())
            .await
    });
    upstream.wait_ready().await;
    upstream.head("200 OK", vec![("content-type", "text/event-stream")]);

    let upstream_response = forwarding
        .await
        .expect("join")
        .expect("the response head arrives");
    let response = relay_response(upstream_response, Duration::from_secs(5));
    drop(response);

    tokio::time::timeout(Duration::from_secs(1), upstream.wait_closed())
        .await
        .expect("downstream cancellation closes the upstream promptly");
}

/// Collects the next non-empty data frame from a response body.
async fn next_bytes<B>(body: &mut B) -> Bytes
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    loop {
        let frame = body
            .frame()
            .await
            .expect("a body frame arrives")
            .expect("the relayed frame is not an error");
        if let Ok(data) = frame.into_data()
            && !data.is_empty()
        {
            return data;
        }
    }
}

/// Reads frames until at least `target` bytes have arrived.
async fn read_at_least<B>(body: &mut B, target: usize) -> Vec<u8>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    let mut collected = Vec::new();
    while collected.len() < target {
        collected.extend_from_slice(&next_bytes(body).await);
    }
    collected
}

#[tokio::test]
async fn an_sse_event_split_across_chunks_is_relayed_incrementally() {
    let mut upstream = Upstream::Scripted(scripted_upstream().await);
    let proxy = proxy();

    let first = b"event: response.output_text.delta\ndata: {\"delta\":\"Hel";
    let second = b"lo\"}\n\n";
    let trailing = b"data: [DONE]\n\n";

    let snapshot = snapshot(upstream.address());
    let route = responses_route();
    let forwarding = tokio::spawn(async move {
        proxy
            .forward(&snapshot, &route, None, peer(), downstream_request())
            .await
    });
    upstream.wait_ready().await;

    let Upstream::Scripted(scripted) = &upstream else {
        unreachable!("the scripted upstream is used here");
    };
    scripted.head(
        "200 OK",
        vec![
            ("content-type", "text/event-stream"),
            ("x-request-tag", "kept"),
        ],
    );

    let upstream_response = forwarding
        .await
        .expect("join")
        .expect("the upstream answers");
    let mut response = relay_response(upstream_response, Duration::from_secs(5));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(
        response
            .headers()
            .get("x-request-tag")
            .and_then(|value| value.to_str().ok()),
        Some("kept")
    );

    // Release only the first half of the event: it must reach the downstream
    // before the second half exists at all, which proves the body streams.
    scripted.chunk(Bytes::from_static(first));
    let partial = read_at_least(response.body_mut(), first.len()).await;
    assert_eq!(
        partial, first,
        "the first half must arrive before the second half is sent"
    );

    scripted.chunk(Bytes::from_static(second));
    scripted.chunk(Bytes::from_static(trailing));
    scripted.finish();

    let rest = read_at_least(response.body_mut(), second.len() + trailing.len()).await;
    let mut complete = partial;
    complete.extend_from_slice(&rest);
    let mut expected = first.to_vec();
    expected.extend_from_slice(second);
    expected.extend_from_slice(trailing);
    assert_eq!(complete, expected);
}

#[tokio::test]
async fn an_upstream_error_body_is_relayed_unchanged() {
    let mut upstream = Upstream::Scripted(scripted_upstream().await);
    let proxy = proxy();

    let snapshot = snapshot(upstream.address());
    let route = responses_route();
    let forwarding = tokio::spawn(async move {
        proxy
            .forward(&snapshot, &route, None, peer(), downstream_request())
            .await
    });
    upstream.wait_ready().await;

    let body = Bytes::from_static(
        b"{\"error\":{\"type\":\"rate_limit_exceeded\",\"message\":\"slow down\"}}",
    );

    let Upstream::Scripted(scripted) = &upstream else {
        unreachable!("the scripted upstream is used here");
    };
    scripted.head(
        "429 Too Many Requests",
        vec![
            ("content-type", "application/json"),
            ("retry-after", "3"),
            ("x-upstream-tag", "kept"),
            ("connection", "x-hop"),
            ("x-hop", "nominated"),
        ],
    );
    scripted.chunk(body.clone());
    scripted.finish();

    let upstream_response = forwarding
        .await
        .expect("join")
        .expect("the upstream answers");
    let mut response = relay_response(upstream_response, Duration::from_secs(5));

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let headers = response.headers();
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        headers
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("3")
    );
    assert_eq!(
        headers
            .get("x-upstream-tag")
            .and_then(|value| value.to_str().ok()),
        Some("kept")
    );
    assert!(
        !headers.contains_key("x-hop"),
        "a connection-nominated header must be dropped"
    );
    assert!(!headers.contains_key("connection"));

    let received = read_at_least(response.body_mut(), body.len()).await;
    assert_eq!(
        received,
        body.to_vec(),
        "the upstream error body must not be rewritten"
    );
    assert!(
        !received
            .windows(b"internal_error".len())
            .any(|window| window == b"internal_error"),
        "the upstream body must not be wrapped in a gateway error envelope"
    );
}

#[tokio::test]
async fn arbitrary_chunking_preserves_the_payload_and_ignores_stream_fields() {
    let mut upstream = Upstream::Scripted(scripted_upstream().await);
    let proxy = proxy();

    let payload = Bytes::from_static(
        b"{\"model\":\"unknown\",\"stream\":true,\"metadata\":{\"kept\":[1,2,3]}}",
    );
    let sizes = [1usize, 1, 2, 3, 5, 8, 13, 21, 4, 2];

    let snapshot = snapshot(upstream.address());
    let route = responses_route();
    let forwarding = tokio::spawn(async move {
        proxy
            .forward(&snapshot, &route, None, peer(), downstream_request())
            .await
    });
    upstream.wait_ready().await;

    let Upstream::Scripted(scripted) = &upstream else {
        unreachable!("the scripted upstream is used here");
    };
    scripted.head("200 OK", vec![("content-type", "application/json")]);

    let mut offset = 0usize;
    let mut index = 0usize;
    while offset < payload.len() {
        let size = sizes[index % sizes.len()].min(payload.len() - offset);
        scripted.chunk(payload.slice(offset..offset + size));
        offset += size;
        index += 1;
    }
    scripted.finish();

    let upstream_response = forwarding
        .await
        .expect("join")
        .expect("the upstream answers");
    let mut response = relay_response(upstream_response, Duration::from_secs(5));

    assert_eq!(response.status(), StatusCode::OK);
    let received = read_at_least(response.body_mut(), payload.len()).await;
    assert_eq!(received, payload.to_vec());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "an application `stream` field must not change how the response is relayed"
    );
    assert!(
        !response
            .headers()
            .keys()
            .any(|name| name.as_str().starts_with("x-tokenstream")),
        "the gateway must not annotate a relayed response"
    );
}

#[tokio::test]
async fn a_slow_downstream_keeps_the_upstream_write_backpressured() {
    const TOTAL: usize = 8 * 1024 * 1024;

    let mut upstream = Upstream::Firehose(firehose_upstream(TOTAL).await);
    let proxy = proxy();

    let response = relay(&mut upstream, proxy).await;
    let mut response = response;
    assert_eq!(response.status(), StatusCode::OK);

    // Consume one frame and then stall. A gateway that buffered the body would
    // let the upstream finish; a streaming relay stops reading and the upstream
    // write blocks on its socket.
    let first = next_bytes(response.body_mut()).await;
    assert!(!first.is_empty());

    tokio::time::sleep(Duration::from_millis(300)).await;

    let Upstream::Firehose(firehose) = &mut upstream else {
        unreachable!("the firehose upstream is used here");
    };
    assert_eq!(
        firehose.write_done.try_recv(),
        Err(oneshot::error::TryRecvError::Empty),
        "the upstream drained its whole body while the downstream was stalled"
    );
    assert!(firehose.written.load(Ordering::SeqCst) < TOTAL);

    drop(response);
    tokio::time::timeout(Duration::from_secs(5), &mut firehose.completed)
        .await
        .expect("the upstream write ends once the downstream is gone")
        .expect("the upstream task does not panic");
}
