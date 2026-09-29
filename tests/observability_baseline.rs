//! The operational exposition as the gateway actually produces it.
//!
//! These tests drive a real gateway so the facts are recorded by the same
//! points that serve traffic, rather than by a direct call into the metrics
//! registry. That is the only way to prove the property that matters here: a
//! refused request is counted once as a refusal, a completed exchange is counted
//! once under its transport and its result, and the series that appear are the
//! same set before and after traffic.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hyper::Request;
use hyper::body::Incoming;
use tokenstream::domain::TransportType;
use tokenstream::logging::{LogEvent, LogStore, channel_with_metrics};
use tokenstream::persistence::RepositoryError;
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::telemetry::{
    ExchangeOutcome, Metrics, ProxyFailureCategory, RejectionLayer, RejectionReason, ResultClass,
};
use tokenstream::{ControlPlaneAuthenticator, MigrationRunner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Migrations;

impl MigrationRunner for Migrations {
    async fn run(&self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct CountingStore {
    batches: AtomicUsize,
}

impl LogStore for CountingStore {
    async fn write_batch(&self, _events: &[LogEvent]) -> Result<(), RepositoryError> {
        self.batches.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

async fn unused_address() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

fn admission(metrics: Metrics, max_connections: usize) -> AdmissionControl {
    AdmissionControl::with_metrics(
        ProxyLimits::new(max_connections, 65_536, 1_048_576, 8_388_608, 32).expect("valid bounds"),
        metrics,
    )
}

fn series_names(rendered: &str) -> std::collections::BTreeSet<String> {
    rendered
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let name = line.split_once('{').map_or(line, |(name, _)| name);
            name.rsplit_once(' ')
                .map_or(name.to_owned(), |(name, _)| name.to_owned())
        })
        .collect()
}

#[test]
fn a_fresh_process_already_publishes_the_whole_series_set() {
    let rendered = Metrics::default().render();
    // Every series is present with a zero before any traffic, so a scraper's
    // view of the process does not depend on what the process has served.
    assert!(
        rendered.contains("tokenstream_exchanges_total{transport=\"http\",result=\"success\"} 0")
    );
    assert!(rendered.contains("tokenstream_exchanges_pass_total{transport=\"websocket\"} 0"));
    assert!(rendered.contains(
        "tokenstream_admission_rejections_total{layer=\"credential_rate\",reason=\"rate\"} 0"
    ));
    assert!(rendered.contains("tokenstream_exchange_duration_seconds_bucket"));
    assert!(rendered.contains("tokenstream_exchange_duration_quantile_seconds"));
    assert!(
        rendered
            .contains("tokenstream_event_subscriber_events_total{subscriber=\"request_log\"} 0")
    );
    // A quantile with no observation is unknown, not zero.
    assert!(rendered.contains("quantile=\"0.99\"} NaN"), "{rendered}");
}

#[test]
fn a_completed_exchange_is_counted_once_and_a_cancellation_is_neither_failure() {
    let metrics = Metrics::default();
    metrics.record_exchange(
        ExchangeOutcome::success(TransportType::Http),
        Duration::from_millis(20),
    );
    metrics.record_exchange(
        ExchangeOutcome::failure(
            TransportType::Http,
            ProxyFailureCategory::DownstreamCancelled,
        ),
        Duration::from_millis(5),
    );
    metrics.record_exchange(
        ExchangeOutcome::failure(
            TransportType::WebSocket,
            ProxyFailureCategory::UpstreamTimeout,
        ),
        Duration::from_secs(3),
    );

    assert_eq!(
        metrics.exchange_count(TransportType::Http, ResultClass::Success),
        1
    );
    assert_eq!(
        metrics.exchange_count(TransportType::Http, ResultClass::ClientCancellation),
        1,
        "a client that hung up is not a gateway or upstream failure"
    );
    assert_eq!(
        metrics.exchange_count(TransportType::WebSocket, ResultClass::UpstreamFailure),
        1
    );

    let rendered = metrics.render();
    assert!(rendered.contains("tokenstream_exchanges_pass_total{transport=\"http\"} 1"));
    // A cancellation counts against no error total at all.
    assert!(rendered.contains("tokenstream_exchanges_fail_total{transport=\"http\"} 0"));
    assert!(rendered.contains("tokenstream_exchanges_fail_total{transport=\"websocket\"} 1"));
}

#[test]
fn percentiles_are_read_from_the_histogram_over_the_whole_exchange() {
    let metrics = Metrics::default();
    // Ninety-nine observations sit in the 250ms bucket and one is far slower
    // than the last fixed boundary, so it lands in the unbounded top bucket.
    for _ in 0..99 {
        metrics.record_exchange(
            ExchangeOutcome::success(TransportType::Http),
            Duration::from_millis(120),
        );
    }
    metrics.record_exchange(
        ExchangeOutcome::success(TransportType::Http),
        Duration::from_secs(30),
    );
    let rendered = metrics.render();
    // P50 sits in the bucket holding the bulk.
    assert!(
        rendered.contains("transport=\"http\",result=\"success\",quantile=\"0.5\"} 0.25"),
        "{rendered}"
    );
    // The top bucket is unbounded, so the slowest observation is still counted
    // and the histogram total still matches the exchange count. A quantile that
    // discarded its tail would look calm rather than slow.
    assert!(rendered.contains(
        "tokenstream_exchange_duration_seconds_bucket{transport=\"http\",result=\"success\",le=\"+Inf\"} 100"
    ), "{rendered}");
    assert!(rendered.contains(
        "tokenstream_exchange_duration_seconds_bucket{transport=\"http\",result=\"success\",le=\"0.25\"} 99"
    ), "{rendered}");
    assert!(rendered.contains(
        "tokenstream_exchange_duration_seconds_count{transport=\"http\",result=\"success\"} 100"
    ));
    // A quantile below the single slow observation still reads from the bulk,
    // and every quantile is present, so the series set does not depend on the
    // traffic that produced it.
    assert!(rendered.contains("quantile=\"0.99\""));
}

#[test]
fn a_refusal_names_the_layer_that_refused_and_is_not_also_a_failed_exchange() {
    let metrics = Metrics::default();
    metrics.record_rejection(RejectionLayer::ProviderRate, RejectionReason::Rate);
    metrics.record_rejection(RejectionLayer::CredentialRate, RejectionReason::Rate);
    let rendered = metrics.render();
    assert!(
        rendered.contains(
            "tokenstream_admission_rejections_total{layer=\"provider_rate\",reason=\"rate\"} 1"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains(
            "tokenstream_admission_rejections_total{layer=\"credential_rate\",reason=\"rate\"} 1"
        ),
        "{rendered}"
    );
    assert_eq!(
        metrics.exchange_count_for_result(ResultClass::GatewayFailure),
        0,
        "a refused request never became an exchange"
    );
}

#[test]
fn the_exposition_grows_no_series_with_traffic() {
    let metrics = Metrics::default();
    let before = series_names(&metrics.render());
    for index in 0..2000 {
        metrics.record_exchange(
            ExchangeOutcome::failure(
                if index % 2 == 0 {
                    TransportType::Http
                } else {
                    TransportType::WebSocket
                },
                ProxyFailureCategory::RelayFailed,
            ),
            Duration::from_millis(index % 400),
        );
        metrics.record_rejection(RejectionLayer::GlobalGate, RejectionReason::Concurrency);
    }
    assert_eq!(
        series_names(&metrics.render()),
        before,
        "traffic changes values, never the set of series"
    );
}

#[test]
fn the_exposition_carries_no_request_identity_or_payload() {
    let metrics = Metrics::default();
    metrics.record_exchange(
        ExchangeOutcome::success(TransportType::Http),
        Duration::from_millis(7),
    );
    metrics.record_rejection(
        RejectionLayer::CredentialWebSockets,
        RejectionReason::Concurrency,
    );
    let rendered = metrics.render();
    for forbidden in [
        "account=",
        "provider=",
        "key_id",
        "request_id",
        "path=",
        "/v1/responses",
        "authorization",
        "?",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "{forbidden} leaked: {rendered}"
        );
    }
}

struct RejectingCredentials;

impl tokenstream::DataPlaneAuthenticator for RejectingCredentials {
    fn authenticate(&self, _request: &Request<Incoming>) -> bool {
        false
    }
}

struct AdminSession;

impl ControlPlaneAuthenticator for AdminSession {
    fn authenticate(&self, request: &Request<Incoming>) -> bool {
        request
            .headers()
            .get("cookie")
            .is_some_and(|value| value == "session=admin")
    }
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

/// The data plane serves the exposition at no path at all. It is a control-plane
/// surface, and the two planes never share a route tree.
#[tokio::test]
async fn the_data_plane_serves_no_exposition() -> io::Result<()> {
    let data = unused_address().await?;
    let control = unused_address().await?;
    let metrics = Metrics::default();
    let (events, worker) = channel_with_metrics(
        Arc::new(CountingStore::default()),
        8,
        4,
        Duration::from_millis(10),
        metrics.clone(),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(tokenstream::run_with_logging(
        data,
        control,
        Migrations,
        RejectingCredentials,
        AdminSession,
        admission(metrics.clone(), 8),
        metrics,
        async move {
            let _ = shutdown_rx.await;
            Ok(())
        },
        Duration::from_millis(20),
        events,
        worker,
        Duration::from_millis(20),
    ));
    wait_until_listening(data).await?;

    let mut plane = TcpStream::connect(data).await?;
    plane
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = String::new();
    plane.read_to_string(&mut response).await?;
    assert!(
        !response.contains("tokenstream_exchanges_total"),
        "the data plane must not serve the exposition: {response}"
    );
    assert!(
        !response.contains("tokenstream_exchange_duration"),
        "the data plane must not serve the exposition: {response}"
    );

    shutdown_tx.send(()).ok();
    server.await.expect("server task")?;
    Ok(())
}
