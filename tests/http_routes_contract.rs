//! End-to-end contracts for every supported HTTP route.
//!
//! A controllable TCP upstream records the request exactly as it arrived and
//! returns ordinary, SSE, and error responses in deliberately uneven chunks.
//! The table shared by these tests proves that all three routes use the same
//! payload-transparent pipeline while retaining their provider-native
//! credential header.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::header::HeaderMap;
use hyper::{Method, Request, StatusCode};
use tokenstream::domain::{
    AccountId, ApiKeyId, ProtocolType, ProviderId, ProviderSnapshot, SecretString,
};
use tokenstream::proxy::http::HttpProxy;
use tokenstream::routing::{ResolvedRoute, resolve_route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

const GATEWAY_CREDENTIAL: &str = "gateway-id.gateway-secret";
const UPSTREAM_KEY: &str = "upstream-secret";
const QUERY: &str = "trace=%2Fopaque+value&&empty=";

#[derive(Clone, Copy)]
struct RouteCase {
    name: &'static str,
    protocol: ProtocolType,
    path: &'static str,
    request_body: &'static [u8],
}

const ROUTES: [RouteCase; 3] = [
    RouteCase {
        name: "chat_completions",
        protocol: ProtocolType::OpenAi,
        path: "/v1/chat/completions",
        request_body: br#"{"model":"future-chat","unknown":{"kept":true}}"#,
    },
    RouteCase {
        name: "responses",
        protocol: ProtocolType::OpenAi,
        path: "/v1/responses",
        request_body: br#"{"model":"future-response","new_field":[1,2,3]}"#,
    },
    RouteCase {
        name: "messages",
        protocol: ProtocolType::Anthropic,
        path: "/v1/messages",
        request_body: br#"{"model":"future-claude","unknown":"preserved"}"#,
    },
];

/// A body that exposes pre-cut application chunks without joining them first.
struct Chunks {
    frames: VecDeque<Bytes>,
    remaining: u64,
}

impl Chunks {
    fn from_bytes(bytes: &'static [u8]) -> Self {
        let first = 1;
        let second = bytes.len() / 2;
        let frames = [
            Bytes::from_static(&bytes[..first]),
            Bytes::from_static(&bytes[first..second]),
            Bytes::from_static(&bytes[second..]),
        ];
        Self {
            frames: frames.into(),
            remaining: bytes.len() as u64,
        }
    }
}

impl Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this.frames.pop_front() {
            Some(bytes) => {
                this.remaining -= bytes.len() as u64;
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        hint.set_exact(self.remaining);
        hint
    }
}

struct UpstreamResponse {
    status: &'static str,
    content_type: &'static str,
    chunks: &'static [&'static [u8]],
}

struct RecordedRequest {
    head: String,
    body: Vec<u8>,
}

async fn mock_upstream(
    response: UpstreamResponse,
) -> (SocketAddr, tokio::task::JoinHandle<RecordedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock upstream");
    let address = listener.local_addr().expect("mock upstream address");

    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept proxy connection");
        let (head, buffered) = read_head(&mut stream).await;
        let body = read_body(&mut stream, &head, buffered).await;

        let response_head = format!(
            "HTTP/1.1 {}\r\ncontent-type: {}\r\nx-upstream-contract: retained\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
            response.status, response.content_type,
        );
        stream
            .write_all(response_head.as_bytes())
            .await
            .expect("write response head");
        for chunk in response.chunks {
            stream
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .expect("write chunk size");
            stream.write_all(chunk).await.expect("write response chunk");
            stream.write_all(b"\r\n").await.expect("finish chunk");
            stream.flush().await.expect("release response chunk");
        }
        stream
            .write_all(b"0\r\n\r\n")
            .await
            .expect("finish response body");
        stream.shutdown().await.expect("close mock upstream");

        RecordedRequest { head, body }
    });

    (address, task)
}

async fn read_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut received = Vec::new();
    let mut buffer = [0u8; 1024];
    let header_end = loop {
        let count = stream.read(&mut buffer).await.expect("read request head");
        assert!(count > 0, "request ended before its head");
        received.extend_from_slice(&buffer[..count]);
        if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    (
        String::from_utf8_lossy(&received[..header_end]).into_owned(),
        received[header_end..].to_vec(),
    )
}

async fn read_body(stream: &mut TcpStream, head: &str, mut body: Vec<u8>) -> Vec<u8> {
    let length = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
                .and_then(|value| value.parse::<usize>().ok())
        })
        .expect("the exact body size produces content-length");
    let mut buffer = [0u8; 1024];
    while body.len() < length {
        let count = stream.read(&mut buffer).await.expect("read request body");
        assert!(count > 0, "request ended before its body");
        body.extend_from_slice(&buffer[..count]);
    }
    body.truncate(length);
    body
}

fn snapshot(case: RouteCase, address: SocketAddr) -> ProviderSnapshot {
    ProviderSnapshot::new(
        AccountId::try_from(1).expect("positive account ID"),
        ApiKeyId::try_from(1).expect("positive credential ID"),
        ProviderId::try_from(1).expect("positive provider ID"),
        case.protocol,
        Url::parse(&format!("http://{address}/provider-prefix")).expect("valid mock endpoint"),
        SecretString::new(UPSTREAM_KEY),
    )
}

fn route(case: RouteCase) -> ResolvedRoute {
    resolve_route(case.protocol, &Method::POST, case.path, &HeaderMap::new())
        .expect("the HTTP route is supported")
}

fn request(case: RouteCase) -> Request<Chunks> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("{}?{QUERY}", case.path))
        .header("content-type", "application/json")
        .header("x-client-contract", "retained");
    builder = match case.protocol {
        ProtocolType::OpenAi => {
            builder.header("authorization", format!("Bearer {GATEWAY_CREDENTIAL}"))
        }
        ProtocolType::Anthropic => builder
            .header("x-api-key", GATEWAY_CREDENTIAL)
            .header("anthropic-version", "2023-06-01")
            .header("anthropic-beta", "future-feature"),
    };
    builder
        .body(Chunks::from_bytes(case.request_body))
        .expect("valid downstream request")
}

async fn exchange(
    case: RouteCase,
    upstream_response: UpstreamResponse,
    expected_status: StatusCode,
    expected_body: &[u8],
) {
    let expected_content_type = upstream_response.content_type;
    let (address, upstream) = mock_upstream(upstream_response).await;
    let proxy = HttpProxy::<Chunks>::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    );

    let upstream_response = proxy
        .forward(
            &snapshot(case, address),
            &route(case),
            Some(QUERY),
            "203.0.113.9:4321".parse().expect("peer address"),
            request(case),
        )
        .await
        .expect("mock upstream returns response headers");
    let response = proxy.relay_response(upstream_response);

    assert_eq!(response.status(), expected_status, "{} status", case.name);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some(expected_content_type),
        "{} content type",
        case.name,
    );
    assert_eq!(
        response
            .headers()
            .get("x-upstream-contract")
            .and_then(|value| value.to_str().ok()),
        Some("retained"),
        "{} response header",
        case.name,
    );
    assert!(response.headers().get("connection").is_none());
    assert!(response.headers().get("transfer-encoding").is_none());
    let received = response
        .into_body()
        .collect()
        .await
        .expect("response stream completes")
        .to_bytes();
    assert_eq!(
        received.as_ref(),
        expected_body,
        "{} response body",
        case.name
    );

    let recorded = upstream.await.expect("mock upstream completes");
    assert!(
        recorded.head.starts_with(&format!(
            "POST /provider-prefix{}?{} HTTP/1.1\r\n",
            case.path, QUERY
        )),
        "{} request target was {:?}",
        case.name,
        recorded.head.lines().next(),
    );
    assert_eq!(
        recorded.body, case.request_body,
        "{} request body",
        case.name
    );
    let head = recorded.head.to_ascii_lowercase();
    assert!(head.contains("x-client-contract: retained"));
    assert!(head.contains("x-forwarded-for: 203.0.113.9"));
    assert!(head.contains(&format!("host: {address}")));
    assert!(!head.contains(GATEWAY_CREDENTIAL));
    match case.protocol {
        ProtocolType::OpenAi => {
            assert!(head.contains(&format!("authorization: bearer {UPSTREAM_KEY}")));
            assert!(!head.contains("x-api-key:"));
        }
        ProtocolType::Anthropic => {
            assert!(head.contains(&format!("x-api-key: {UPSTREAM_KEY}")));
            assert!(!head.contains("authorization:"));
            assert!(head.contains("anthropic-version: 2023-06-01"));
            assert!(head.contains("anthropic-beta: future-feature"));
        }
    }
}

async fn verify_route(case: RouteCase) {
    const ORDINARY_CHUNKS: &[&[u8]] = &[br#"{"result":""#, br#"ordinary","unknown":9}"#];
    const ORDINARY_BODY: &[u8] = br#"{"result":"ordinary","unknown":9}"#;
    exchange(
        case,
        UpstreamResponse {
            status: "200 OK",
            content_type: "application/json",
            chunks: ORDINARY_CHUNKS,
        },
        StatusCode::OK,
        ORDINARY_BODY,
    )
    .await;

    const SSE_CHUNKS: &[&[u8]] = &[
        b"event: delta\nda",
        b"ta: {\"unknown\":",
        b"true}\n\ndata: [DONE]\n\n",
    ];
    const SSE_BODY: &[u8] = b"event: delta\ndata: {\"unknown\":true}\n\ndata: [DONE]\n\n";
    exchange(
        case,
        UpstreamResponse {
            status: "200 OK",
            content_type: "text/event-stream",
            chunks: SSE_CHUNKS,
        },
        StatusCode::OK,
        SSE_BODY,
    )
    .await;

    const ERROR_CHUNKS: &[&[u8]] = &[b"opaque upstream ", b"error: do not wrap"];
    const ERROR_BODY: &[u8] = b"opaque upstream error: do not wrap";
    exchange(
        case,
        UpstreamResponse {
            status: "429 Too Many Requests",
            content_type: "application/problem+json",
            chunks: ERROR_CHUNKS,
        },
        StatusCode::TOO_MANY_REQUESTS,
        ERROR_BODY,
    )
    .await;
}

#[tokio::test]
async fn chat_completions_supports_ordinary_sse_and_error_contracts() {
    verify_route(ROUTES[0]).await;
}

#[tokio::test]
async fn responses_supports_ordinary_sse_and_error_contracts() {
    verify_route(ROUTES[1]).await;
}

#[tokio::test]
async fn messages_supports_ordinary_sse_and_error_contracts() {
    verify_route(ROUTES[2]).await;
}
