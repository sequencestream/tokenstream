//! Bounded idle HTTP connection reuse.
//!
//! These contracts prove that a positive per-origin idle cap reuses a keep-alive
//! connection without retrying, without mixing credentials across requests, and
//! without retaining sockets after the idle deadline. Tests that construct the
//! historical no-reuse proxy keep a dedicated connection per exchange.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::header::HeaderMap;
use hyper::{Method, Request};
use tokenstream::domain::{
    AccountId, ApiKeyId, ProtocolType, ProviderId, ProviderSnapshot, SecretString,
};
use tokenstream::proxy::http::HttpProxy;
use tokenstream::routing::{ResolvedRoute, resolve_route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use url::Url;

const GATEWAY_CREDENTIAL: &str = "gateway-key.secret-value";
const UPSTREAM_KEY_A: &str = "upstream-secret-a";
const UPSTREAM_KEY_B: &str = "upstream-secret-b";

struct OnceBody {
    payload: Option<Bytes>,
}

impl Body for OnceBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut().payload.take() {
            Some(payload) => Poll::Ready(Some(Ok(Frame::data(payload)))),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.payload.is_none()
    }
}

fn snapshot(endpoint: SocketAddr, secret: &'static str) -> ProviderSnapshot {
    ProviderSnapshot::new(
        AccountId::try_from(1).expect("positive account ID"),
        ApiKeyId::try_from(1).expect("positive credential ID"),
        ProviderId::try_from(1).expect("positive provider ID"),
        ProtocolType::OpenAi,
        Url::parse(&format!("http://{endpoint}")).expect("valid endpoint"),
        SecretString::new(secret),
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

fn reuse_proxy() -> HttpProxy<OnceBody> {
    HttpProxy::with_pool(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        65_536,
        4,
        Duration::from_secs(5),
    )
}

fn request(tag: &'static str) -> Request<OnceBody> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/responses")
        .header("authorization", format!("Bearer {GATEWAY_CREDENTIAL}"))
        .header("x-request-tag", tag)
        .body(OnceBody {
            payload: Some(Bytes::from_static(b"{}")),
        })
        .expect("valid downstream request")
}

async fn drain(response: hyper::Response<hyper::body::Incoming>) {
    response
        .into_body()
        .collect()
        .await
        .expect("drain the upstream body so the connection can return to the pool");
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

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

async fn read_request_body(stream: &mut TcpStream, head: &str, mut body: Vec<u8>) -> Vec<u8> {
    let length = head
        .to_ascii_lowercase()
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    while body.len() < length {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.expect("read request body");
        assert!(read > 0, "upstream saw EOF before a complete body");
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    body
}

async fn write_keep_alive(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("write keep-alive response");
}

#[tokio::test]
async fn sequential_requests_reuse_one_keep_alive_connection() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reuse upstream");
    let address = listener.local_addr().expect("upstream address");
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::clone(&accepts);

    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("first accept");
        accepted.fetch_add(1, Ordering::SeqCst);
        let mut heads = Vec::new();
        for _ in 0..2 {
            let (head, preview) = read_request_head(&mut stream).await;
            let _ = read_request_body(&mut stream, &head, preview).await;
            heads.push(head);
            write_keep_alive(&mut stream, "ok").await;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err(),
            "a second TCP connection must not be opened while the first stays idle"
        );
        heads
    });

    let proxy = reuse_proxy();
    for tag in ["first", "second"] {
        let response = proxy
            .forward(
                &snapshot(address, UPSTREAM_KEY_A),
                &responses_route(),
                None,
                peer(),
                request(tag),
            )
            .await
            .expect("keep-alive exchange");
        drain(response).await;
    }

    let heads = upstream.await.expect("upstream task");
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("x-request-tag: first")
    );
    assert!(
        heads[1]
            .to_ascii_lowercase()
            .contains("x-request-tag: second")
    );
}

#[tokio::test]
async fn reused_connections_replace_credentials_from_the_current_snapshot() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind credential upstream");
    let address = listener.local_addr().expect("upstream address");

    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("one shared connection");
        let mut heads = Vec::new();
        for _ in 0..2 {
            let (head, preview) = read_request_head(&mut stream).await;
            let _ = read_request_body(&mut stream, &head, preview).await;
            heads.push(head);
            write_keep_alive(&mut stream, "ok").await;
        }
        heads
    });

    let proxy = reuse_proxy();
    for secret in [UPSTREAM_KEY_A, UPSTREAM_KEY_B] {
        let response = proxy
            .forward(
                &snapshot(address, secret),
                &responses_route(),
                None,
                peer(),
                request("cred"),
            )
            .await
            .expect("credential replacement on a reused connection");
        drain(response).await;
    }

    let heads = upstream.await.expect("upstream task");
    let first = heads[0].to_ascii_lowercase();
    let second = heads[1].to_ascii_lowercase();
    assert!(first.contains(&format!("authorization: bearer {UPSTREAM_KEY_A}")));
    assert!(second.contains(&format!("authorization: bearer {UPSTREAM_KEY_B}")));
    assert!(!first.contains(UPSTREAM_KEY_B));
    assert!(!second.contains(UPSTREAM_KEY_A));
    assert!(!first.contains(&GATEWAY_CREDENTIAL.to_ascii_lowercase()));
    assert!(!second.contains(&GATEWAY_CREDENTIAL.to_ascii_lowercase()));
}

#[tokio::test]
async fn distinct_origins_do_not_share_idle_connections() {
    let first_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind first origin");
    let second_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind second origin");
    let first_address = first_listener.local_addr().expect("first address");
    let second_address = second_listener.local_addr().expect("second address");

    async fn serve_one(listener: TcpListener) -> String {
        let (mut stream, _) = listener.accept().await.expect("origin accept");
        let (head, preview) = read_request_head(&mut stream).await;
        let _ = read_request_body(&mut stream, &head, preview).await;
        write_keep_alive(&mut stream, "ok").await;
        head
    }

    let first_task = tokio::spawn(serve_one(first_listener));
    let second_task = tokio::spawn(serve_one(second_listener));
    let proxy = reuse_proxy();

    for address in [first_address, second_address] {
        let response = proxy
            .forward(
                &snapshot(address, UPSTREAM_KEY_A),
                &responses_route(),
                None,
                peer(),
                request("origin"),
            )
            .await
            .expect("per-origin exchange");
        drain(response).await;
    }

    first_task.await.expect("first origin");
    second_task.await.expect("second origin");
}

#[tokio::test]
async fn idle_deadline_reaps_a_kept_connection_instead_of_retaining_it() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind idle-reap upstream");
    let address = listener.local_addr().expect("upstream address");
    let (tx, mut rx) = mpsc::unbounded_channel();

    let upstream = tokio::spawn(async move {
        for expected in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept after idle reap");
            tx.send(expected).expect("record accept");
            let (head, preview) = read_request_head(&mut stream).await;
            let _ = read_request_body(&mut stream, &head, preview).await;
            write_keep_alive(&mut stream, "ok").await;
        }
    });

    let proxy = HttpProxy::<OnceBody>::with_pool(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        65_536,
        1,
        Duration::from_millis(80),
    );

    let first = proxy
        .forward(
            &snapshot(address, UPSTREAM_KEY_A),
            &responses_route(),
            None,
            peer(),
            request("early"),
        )
        .await
        .expect("first exchange");
    drain(first).await;
    assert_eq!(rx.recv().await, Some(1));

    tokio::time::sleep(Duration::from_millis(250)).await;

    let second = proxy
        .forward(
            &snapshot(address, UPSTREAM_KEY_A),
            &responses_route(),
            None,
            peer(),
            request("late"),
        )
        .await
        .expect("exchange after the idle connection is reaped");
    drain(second).await;
    assert_eq!(rx.recv().await, Some(2));
    upstream.await.expect("upstream task");
}

#[tokio::test]
async fn pooling_does_not_retry_a_cancelled_exchange() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind cancellation upstream");
    let address = listener.local_addr().expect("upstream address");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("the first request arrives");
        let (_head, _body) = read_request_head(&mut stream).await;
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
            "pooling must not replay the cancelled request"
        );
    });

    let proxy = Arc::new(reuse_proxy());
    let forwarding = {
        let proxy = Arc::clone(&proxy);
        tokio::spawn(async move {
            proxy
                .forward(
                    &snapshot(address, UPSTREAM_KEY_A),
                    &responses_route(),
                    None,
                    peer(),
                    request("cancel"),
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
    upstream.await.expect("the upstream task completes");
}
