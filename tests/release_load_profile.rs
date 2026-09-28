//! Mixed long-lived transport profile used by the release gate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
use std::process::Command;

use bytes::Bytes;
use futures_util::SinkExt;
use http_body_util::{BodyExt, Empty};
use hyper::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use hyper::{Method, Request};
use tokenstream::domain::{ProtocolType, ProviderId, ProviderSnapshot, SecretString};
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::proxy::http::HttpProxy;
use tokenstream::proxy::websocket::relay;
use tokenstream::routing::{OPENAI_RESPONSES_PATH, resolve_route};
use tokenstream::telemetry::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_tungstenite::{WebSocketStream, accept_async_with_config, client_async};
use url::Url;

const HTTP_CONNECTIONS: usize = 24;
const WEBSOCKET_CONNECTIONS: usize = 24;
const PROFILE_DURATION: Duration = Duration::from_secs(3);
const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
const MAX_STEADY_RSS_SPREAD_KIB: u64 = 16 * 1024;

type Socket = WebSocketStream<DuplexStream>;

async fn socket_pair() -> (Socket, Socket) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        accept_async_with_config(server_io, Some(WebSocketConfig::default()))
            .await
            .expect("accept load-profile WebSocket")
    });
    let (client, _) = client_async("ws://load.invalid/v1/responses", client_io)
        .await
        .expect("open load-profile WebSocket");
    (client, server.await.expect("WebSocket accept task"))
}

async fn spawn_sse_upstream(
    connections: usize,
) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind load-profile upstream");
    let address = listener.local_addr().expect("upstream address");
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut handlers = Vec::with_capacity(connections);
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().await.expect("accept HTTP connection");
            let mut stop_rx = stop_rx.clone();
            handlers.push(tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.expect("read HTTP head");
                    assert!(read > 0, "HTTP request ended before headers");
                    request.extend_from_slice(&buffer[..read]);
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n")
                    .await
                    .expect("write SSE head");
                loop {
                    tokio::select! {
                        result = stop_rx.changed() => {
                            if result.is_err() || *stop_rx.borrow() {
                                let _ = stream.write_all(b"0\r\n\r\n").await;
                                break;
                            }
                        }
                        () = tokio::time::sleep(Duration::from_millis(40)) => {
                            if stream.write_all(b"c\r\ndata: tick\n\n\r\n").await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }));
        }
        for handler in handlers {
            handler.await.expect("SSE upstream handler");
        }
    });
    (address, stop, task)
}

fn rss_kib() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").expect("read process memory");
        let resident_pages: u64 = statm
            .split_whitespace()
            .nth(1)
            .expect("resident pages")
            .parse()
            .expect("numeric resident pages");
        return resident_pages * 4;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("sample process memory");
        assert!(output.status.success(), "ps must report process memory");
        String::from_utf8(output.stdout)
            .expect("ps output is UTF-8")
            .trim()
            .parse()
            .expect("numeric RSS")
    }
}

fn http_route() -> tokenstream::routing::ResolvedRoute {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer gateway.test"),
    );
    resolve_route(
        ProtocolType::OpenAi,
        &Method::POST,
        OPENAI_RESPONSES_PATH,
        &headers,
    )
    .expect("fixed HTTP route")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "executed explicitly by the release gate"]
async fn mixed_long_lived_transports_reach_stable_bounded_memory() {
    let total_connections = HTTP_CONNECTIONS + WEBSOCKET_CONNECTIONS;
    let limits = ProxyLimits::new(total_connections, 64 * 1024, 64 * 1024, 256 * 1024, 8)
        .expect("valid release bounds");
    let metrics = Metrics::default();
    let admission = AdmissionControl::with_metrics(limits, metrics.clone());
    let permits: Vec<_> = (0..total_connections)
        .map(|_| admission.try_admit().expect("connection fits profile"))
        .collect();
    assert_eq!(admission.in_flight(), total_connections);
    assert!(
        admission.try_admit().is_err(),
        "the global bound must shed excess load"
    );
    assert_eq!(admission.limits().http_buffer_bytes(), 64 * 1024);
    assert_eq!(admission.limits().websocket_queue_capacity(), 8);

    let (upstream_address, stop_upstream, upstream_task) =
        spawn_sse_upstream(HTTP_CONNECTIONS).await;
    let snapshot = Arc::new(ProviderSnapshot::new(
        ProviderId::try_from(1).expect("positive provider ID"),
        ProtocolType::OpenAi,
        Url::parse(&format!("http://{upstream_address}")).expect("upstream URL"),
        SecretString::new("upstream-key"),
    ));
    let proxy = Arc::new(HttpProxy::<Empty<Bytes>>::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    ));
    let mut http_tasks = Vec::with_capacity(HTTP_CONNECTIONS);
    for _ in 0..HTTP_CONNECTIONS {
        let proxy = Arc::clone(&proxy);
        let snapshot = Arc::clone(&snapshot);
        let active = metrics.start_http();
        http_tasks.push(tokio::spawn(async move {
            let request = Request::builder()
                .method(Method::POST)
                .uri(OPENAI_RESPONSES_PATH)
                .header(AUTHORIZATION, "Bearer gateway.test")
                .body(Empty::<Bytes>::new())
                .expect("HTTP request");
            let response = proxy
                .forward(
                    &snapshot,
                    &http_route(),
                    None,
                    "127.0.0.1:40000".parse().expect("peer address"),
                    request,
                )
                .await
                .expect("open long-lived SSE response");
            let mut body = proxy.relay_response(response).into_body();
            while let Some(frame) = body.frame().await {
                frame.expect("SSE frame");
            }
            drop(active);
        }));
    }

    let mut websocket_clients = Vec::with_capacity(WEBSOCKET_CONNECTIONS * 2);
    let mut websocket_tasks = Vec::with_capacity(WEBSOCKET_CONNECTIONS);
    for _ in 0..WEBSOCKET_CONNECTIONS {
        let (downstream_client, downstream_proxy) = socket_pair().await;
        let (upstream_client, upstream_proxy) = socket_pair().await;
        websocket_clients.push(downstream_client);
        websocket_clients.push(upstream_client);
        let active = metrics.start_websocket();
        websocket_tasks.push(tokio::spawn(async move {
            let outcome = relay(downstream_proxy, upstream_proxy, Duration::from_secs(10)).await;
            drop(active);
            outcome
        }));
    }

    assert_eq!(metrics.active_http(), HTTP_CONNECTIONS);
    assert_eq!(metrics.active_websockets(), WEBSOCKET_CONNECTIONS);

    let started = tokio::time::Instant::now();
    let mut samples = Vec::new();
    while started.elapsed() < PROFILE_DURATION {
        for socket in &mut websocket_clients {
            socket
                .send(Message::Ping(Bytes::from_static(b"bounded")))
                .await
                .expect("WebSocket load message");
        }
        samples.push(rss_kib());
        tokio::time::sleep(SAMPLE_INTERVAL).await;
    }
    let steady = &samples[samples.len() / 2..];
    let spread =
        steady.iter().max().expect("RSS maximum") - steady.iter().min().expect("RSS minimum");
    assert!(
        spread <= MAX_STEADY_RSS_SPREAD_KIB,
        "steady-state RSS spread {spread} KiB exceeded {MAX_STEADY_RSS_SPREAD_KIB} KiB; samples={samples:?}"
    );
    assert_eq!(admission.in_flight(), total_connections);

    stop_upstream.send(true).expect("stop SSE upstream");
    for task in http_tasks {
        task.await.expect("HTTP load task");
    }
    drop(websocket_clients);
    for task in websocket_tasks {
        task.await.expect("WebSocket load task");
    }
    upstream_task.await.expect("SSE upstream task");
    drop(permits);
    assert_eq!(admission.in_flight(), 0);
    assert_eq!(metrics.active_http(), 0);
    assert_eq!(metrics.active_websockets(), 0);
}
