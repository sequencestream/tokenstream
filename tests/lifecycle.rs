use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use hyper::Request;
use hyper::body::Incoming;
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::{ControlPlaneAuthenticator, DataPlaneAuthenticator, MigrationRunner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};

#[derive(Clone)]
struct PlaneCredentials;

impl DataPlaneAuthenticator for PlaneCredentials {
    fn authenticate(&self, request: &Request<Incoming>) -> bool {
        request
            .headers()
            .get("authorization")
            .is_some_and(|value| value.as_bytes() == b"Bearer data-secret")
    }
}

impl ControlPlaneAuthenticator for PlaneCredentials {
    fn authenticate(&self, request: &Request<Incoming>) -> bool {
        request
            .headers()
            .get("cookie")
            .is_some_and(|value| value.as_bytes() == b"session=admin-secret")
    }
}

struct ImmediateMigrations;

fn admission(max_connections: usize) -> AdmissionControl {
    AdmissionControl::new(
        ProxyLimits::new(max_connections, 65_536, 1_048_576, 8_388_608, 32).expect("valid bounds"),
    )
}

impl MigrationRunner for ImmediateMigrations {
    async fn run(&self) -> io::Result<()> {
        Ok(())
    }
}

struct BlockingMigrations {
    started: Arc<AtomicBool>,
    release: Arc<Notify>,
}

impl MigrationRunner for BlockingMigrations {
    async fn run(&self) -> io::Result<()> {
        self.started.store(true, Ordering::SeqCst);
        self.release.notified().await;
        Ok(())
    }
}

async fn unused_address() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

async fn request(address: SocketAddr, path: &str, headers: &str) -> io::Result<String> {
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

async fn wait_until_listening(address: SocketAddr) -> io::Result<()> {
    for _ in 0..100 {
        match TcpStream::connect(address).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "server did not start listening",
    ))
}

#[tokio::test]
async fn migrations_finish_before_either_plane_binds() -> io::Result<()> {
    let data_address = unused_address().await?;
    let control_address = unused_address().await?;
    let started = Arc::new(AtomicBool::new(false));
    let release = Arc::new(Notify::new());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(tokenstream::run(
        data_address,
        control_address,
        BlockingMigrations {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        },
        PlaneCredentials,
        PlaneCredentials,
        admission(64),
        async move {
            shutdown_rx.await.map_err(io::Error::other)?;
            Ok(())
        },
        Duration::from_millis(100),
    ));

    while !started.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    assert!(TcpStream::connect(data_address).await.is_err());
    assert!(TcpStream::connect(control_address).await.is_err());

    release.notify_one();
    wait_until_listening(data_address).await?;
    wait_until_listening(control_address).await?;
    shutdown_tx
        .send(())
        .expect("shutdown receiver remains open");
    server.await.expect("server task completes")?;
    Ok(())
}

#[tokio::test]
async fn planes_have_independent_routes_and_credentials() -> io::Result<()> {
    let data_address = unused_address().await?;
    let control_address = unused_address().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(tokenstream::run(
        data_address,
        control_address,
        ImmediateMigrations,
        PlaneCredentials,
        PlaneCredentials,
        admission(64),
        async move {
            shutdown_rx.await.map_err(io::Error::other)?;
            Ok(())
        },
        Duration::from_millis(100),
    ));
    wait_until_listening(data_address).await?;
    wait_until_listening(control_address).await?;

    let data_health = request(data_address, "/healthz", "").await?;
    assert!(data_health.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(data_health.ends_with("\r\n\r\ndata plane ok\n"));
    let control_health = request(control_address, "/healthz", "").await?;
    assert!(control_health.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(control_health.ends_with("\r\n\r\ncontrol plane ok\n"));

    let data_credential = "Authorization: Bearer data-secret\r\n";
    let admin_credential = "Cookie: session=admin-secret\r\n";
    assert!(
        request(data_address, "/v1/responses", data_credential)
            .await?
            .starts_with("HTTP/1.1 404 Not Found\r\n")
    );
    assert!(
        request(control_address, "/admin/api/providers", admin_credential)
            .await?
            .starts_with("HTTP/1.1 404 Not Found\r\n")
    );
    assert!(
        request(data_address, "/v1/responses", admin_credential)
            .await?
            .starts_with("HTTP/1.1 401 Unauthorized\r\n")
    );
    assert!(
        request(control_address, "/admin/api/providers", data_credential)
            .await?
            .starts_with("HTTP/1.1 401 Unauthorized\r\n")
    );

    shutdown_tx
        .send(())
        .expect("shutdown receiver remains open");
    server.await.expect("server task completes")?;
    Ok(())
}

#[tokio::test]
async fn shutdown_stops_accepting_and_has_a_fixed_upper_bound() -> io::Result<()> {
    let data_address = unused_address().await?;
    let control_address = unused_address().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let drain_timeout = Duration::from_millis(50);
    let server = tokio::spawn(tokenstream::run(
        data_address,
        control_address,
        ImmediateMigrations,
        PlaneCredentials,
        PlaneCredentials,
        admission(64),
        async move {
            shutdown_rx.await.map_err(io::Error::other)?;
            Ok(())
        },
        drain_timeout,
    ));
    wait_until_listening(data_address).await?;

    let mut held_connection = TcpStream::connect(data_address).await?;
    held_connection
        .write_all(b"GET /healthz HTTP/1.1\r\n")
        .await?;
    tokio::time::sleep(Duration::from_millis(10)).await;

    let started = Instant::now();
    shutdown_tx
        .send(())
        .expect("shutdown receiver remains open");
    tokio::time::timeout(Duration::from_millis(250), server)
        .await
        .expect("shutdown has a deterministic upper bound")
        .expect("server task completes")?;
    assert!(started.elapsed() >= drain_timeout);
    assert!(TcpStream::connect(data_address).await.is_err());
    assert!(TcpStream::connect(control_address).await.is_err());
    Ok(())
}
