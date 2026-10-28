//! Global admission behavior of the data plane.
//!
//! The bound is observed through the real HTTP surface: a fully admitted
//! gateway answers proxy traffic with a sanitized `503` and returns capacity as
//! soon as a slot is released. Health checks are not proxy traffic and are
//! never shed.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokenstream::MigrationRunner;
use tokenstream::RejectAll;
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::proxy::error::ERROR_CONTENT_TYPE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct ImmediateMigrations;

impl MigrationRunner for ImmediateMigrations {
    async fn run(&self) -> io::Result<()> {
        Ok(())
    }
}

fn admission(max_connections: usize) -> AdmissionControl {
    AdmissionControl::new(
        ProxyLimits::new(max_connections, 65_536, 1_048_576, 8_388_608, 32).expect("valid bounds"),
    )
}

async fn unused_address() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
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

async fn request(address: SocketAddr, path: &str) -> io::Result<String> {
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

#[tokio::test]
async fn the_data_plane_sheds_load_with_a_sanitized_503() -> io::Result<()> {
    let data_address = unused_address().await?;
    let control_address = unused_address().await?;
    let control = admission(1);
    let held = control.try_admit().expect("the only slot");
    assert_eq!(control.in_flight(), 1);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(tokenstream::run(
        data_address,
        control_address,
        ImmediateMigrations,
        RejectAll,
        RejectAll,
        control.clone(),
        async move {
            shutdown_rx.await.map_err(io::Error::other)?;
            Ok(())
        },
        Duration::from_millis(50),
    ));
    wait_until_listening(data_address).await?;

    // Health checks are not proxy traffic and never consume a slot.
    let health = request(data_address, "/healthz").await?;
    assert!(health.starts_with("HTTP/1.1 200 OK\r\n"), "{health}");
    assert_eq!(control.in_flight(), 1);

    let rejected = request(data_address, "/v1/responses").await?;
    assert!(
        rejected.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "{rejected}"
    );
    assert!(rejected.contains(ERROR_CONTENT_TYPE), "{rejected}");
    let body = rejected
        .split("\r\n\r\n")
        .nth(1)
        .expect("an error envelope body");
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a JSON envelope");
    assert_eq!(parsed["error"]["code"], "connection_limit_reached");
    assert_eq!(
        parsed["error"]["message"],
        "The gateway is at its connection limit."
    );
    let request_id = parsed["error"]["request_id"]
        .as_str()
        .expect("a request id");
    assert!(request_id.starts_with("req_"), "{request_id}");
    assert_eq!(parsed["error"].as_object().expect("an object").len(), 3);
    assert_eq!(control.in_flight(), 1, "a shed request takes no slot");

    // Releasing the held slot immediately restores admission.
    drop(held);
    let admitted = request(data_address, "/v1/responses").await?;
    assert!(
        admitted.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "{admitted}"
    );
    assert_eq!(control.in_flight(), 0);

    shutdown_tx
        .send(())
        .expect("shutdown receiver remains open");
    server.await.expect("server task completes")?;
    Ok(())
}

#[tokio::test]
async fn every_admitted_request_returns_its_slot() -> io::Result<()> {
    let data_address = unused_address().await?;
    let control_address = unused_address().await?;
    let control = admission(1);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(tokenstream::run(
        data_address,
        control_address,
        ImmediateMigrations,
        RejectAll,
        RejectAll,
        control.clone(),
        async move {
            shutdown_rx.await.map_err(io::Error::other)?;
            Ok(())
        },
        Duration::from_millis(50),
    ));
    wait_until_listening(data_address).await?;

    for _ in 0..8 {
        let response = request(data_address, "/v1/responses").await?;
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "{response}"
        );
        assert_eq!(control.available(), 1, "the slot was returned");
        assert_eq!(control.in_flight(), 0);
    }

    shutdown_tx
        .send(())
        .expect("shutdown receiver remains open");
    server.await.expect("server task completes")?;
    Ok(())
}

#[tokio::test]
async fn cancelling_an_admitted_task_returns_its_slot() {
    let control = admission(1);
    let task_control = control.clone();
    let (held_tx, held_rx) = oneshot::channel();

    let task = tokio::spawn(async move {
        let _permit = task_control.try_admit().expect("the only slot");
        held_tx.send(()).expect("the test is waiting");
        std::future::pending::<()>().await;
    });
    held_rx.await.expect("the permit is held");
    assert_eq!(control.in_flight(), 1);

    task.abort();
    assert!(
        task.await
            .expect_err("the task is cancelled")
            .is_cancelled()
    );
    assert_eq!(control.in_flight(), 0);
    assert_eq!(control.available(), 1);
}
