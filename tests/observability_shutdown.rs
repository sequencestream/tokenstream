use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use hyper::Request;
use hyper::body::Incoming;
use tokenstream::domain::{
    AccountId, ApiKeyId, ProtocolType, ProviderId, RequestId, TransportType,
};
use tokenstream::events::{Admitted, EmitResult, Finished, LifecycleEvent, SubscriberName};
use tokenstream::logging::{LogEvent, LogStore, channel_with_metrics};
use tokenstream::persistence::RepositoryError;
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::telemetry::{Metrics, ProxyFailureCategory};
use tokenstream::{ControlPlaneAuthenticator, DataPlaneAuthenticator, MigrationRunner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[derive(Clone, Copy)]
struct Credentials;

impl DataPlaneAuthenticator for Credentials {
    fn authenticate(&self, _request: &Request<Incoming>) -> bool {
        false
    }
}

impl ControlPlaneAuthenticator for Credentials {
    fn authenticate(&self, request: &Request<Incoming>) -> bool {
        request
            .headers()
            .get("cookie")
            .is_some_and(|value| value == "session=admin")
    }
}

struct Migrations;

impl MigrationRunner for Migrations {
    async fn run(&self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct ImmediateStore;

impl LogStore for ImmediateStore {
    async fn write_batch(&self, _events: &[LogEvent]) -> Result<(), RepositoryError> {
        Ok(())
    }
}

#[derive(Default)]
struct BlockingStore {
    attempts: AtomicUsize,
    completed_events: AtomicUsize,
}

impl LogStore for BlockingStore {
    async fn write_batch(&self, events: &[LogEvent]) -> Result<(), RepositoryError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        self.completed_events.fetch_add(
            events
                .iter()
                .filter(|event| matches!(event, LogEvent::Completed(_)))
                .count(),
            Ordering::SeqCst,
        );
        std::future::pending().await
    }
}

fn admission(metrics: Metrics) -> AdmissionControl {
    AdmissionControl::with_metrics(
        ProxyLimits::new(8, 65_536, 1_048_576, 8_388_608, 32).expect("valid bounds"),
        metrics,
    )
}

fn started() -> LifecycleEvent {
    LifecycleEvent::Admitted(Admitted {
        request_id: RequestId::new("request-before-shutdown").expect("request ID"),
        account_id: AccountId::try_from(1).expect("account ID"),
        api_key_id: ApiKeyId::try_from(1).expect("credential ID"),
        provider_id: ProviderId::try_from(1).expect("provider ID"),
        protocol_type: ProtocolType::OpenAi,
        transport_type: TransportType::Http,
        path: "/v1/responses".to_owned(),
        observed_at: Utc::now(),
    })
}

/// The finished point, used to prove a persisted completion is never synthesized.
fn finished() -> LifecycleEvent {
    LifecycleEvent::Finished(Finished {
        request_id: RequestId::new("request-before-shutdown").expect("request ID"),
        status_code: Some(200),
        transport_type: TransportType::Http,
        outcome: None,
        elapsed: Duration::from_millis(1),
        finished_at: Utc::now(),
    })
}

fn request_log(metrics: &Metrics) -> (usize, u64) {
    let view = metrics.subscriber(SubscriberName::RequestLog);
    (view.queue_depth, view.dropped_events)
}

async fn unused_address() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

async fn wait_until_listening(address: SocketAddr) -> io::Result<()> {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(address).await {
            drop(stream);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "server did not bind",
    ))
}

#[tokio::test]
async fn authenticated_control_plane_exports_only_aggregate_metrics() -> io::Result<()> {
    let data = unused_address().await?;
    let control = unused_address().await?;
    let metrics = Metrics::default();
    metrics.record_failure(ProxyFailureCategory::UpstreamTimeout);
    let (events, worker) = channel_with_metrics(
        Arc::new(ImmediateStore),
        4,
        2,
        Duration::from_millis(10),
        metrics.clone(),
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(tokenstream::run_with_logging(
        data,
        control,
        Migrations,
        Credentials,
        Credentials,
        admission(metrics.clone()),
        metrics,
        async move {
            shutdown_rx.await.map_err(io::Error::other)?;
            Ok(())
        },
        Duration::from_millis(20),
        events,
        worker,
        Duration::from_millis(20),
    ));
    wait_until_listening(control).await?;

    let mut connection = TcpStream::connect(control).await?;
    connection
        .write_all(
            b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nCookie: session=admin\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut response = String::new();
    connection.read_to_string(&mut response).await?;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("tokenstream_proxy_failures_total{category=\"upstream_timeout\"} 1"));
    assert!(!response.contains("request-before-shutdown"));

    shutdown_tx.send(()).expect("server is running");
    server.await.expect("server task")?;
    Ok(())
}

#[tokio::test]
async fn shutdown_drains_connections_then_bounds_log_flush_without_synthesizing_completion()
-> io::Result<()> {
    let data = unused_address().await?;
    let control = unused_address().await?;
    let metrics = Metrics::default();
    let store = Arc::new(BlockingStore::default());
    let (events, worker) = channel_with_metrics(
        Arc::clone(&store),
        4,
        1,
        Duration::from_secs(1),
        metrics.clone(),
    );
    assert_eq!(events.emit(started()), EmitResult::Enqueued);
    assert_eq!(events.emit(finished()), EmitResult::Enqueued);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let drain_timeout = Duration::from_millis(30);
    let flush_timeout = Duration::from_millis(40);
    let server = tokio::spawn(tokenstream::run_with_logging(
        data,
        control,
        Migrations,
        Credentials,
        Credentials,
        admission(metrics.clone()),
        metrics.clone(),
        async move {
            shutdown_rx.await.map_err(io::Error::other)?;
            Ok(())
        },
        drain_timeout,
        events,
        worker,
        flush_timeout,
    ));
    wait_until_listening(data).await?;

    let mut held = TcpStream::connect(data).await?;
    held.write_all(b"GET /healthz HTTP/1.1\r\n").await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let shutdown_started = Instant::now();
    shutdown_tx.send(()).expect("server is running");
    tokio::time::timeout(Duration::from_millis(300), server)
        .await
        .expect("both shutdown phases are bounded")
        .expect("server task")?;

    assert!(shutdown_started.elapsed() >= drain_timeout + flush_timeout);
    assert_eq!(store.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(store.completed_events.load(Ordering::SeqCst), 0);
    assert_eq!(request_log(&metrics), (0, 1));
    assert!(TcpStream::connect(data).await.is_err());
    Ok(())
}
