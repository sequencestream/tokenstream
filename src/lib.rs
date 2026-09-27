use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;

pub mod config;
pub mod domain;
pub mod persistence;

type ResponseBody = Full<Bytes>;
const MAX_SCAFFOLD_CONNECTIONS_PER_PLANE: usize = 64;

/// Applies all registered schema migrations before either listening socket is bound.
pub trait MigrationRunner: Send + Sync {
    fn run(&self) -> impl Future<Output = io::Result<()>> + Send;
}

/// Authenticates requests entering the data-plane route tree.
pub trait DataPlaneAuthenticator: Send + Sync + 'static {
    fn authenticate(&self, request: &Request<Incoming>) -> bool;
}

/// Authenticates requests entering the control-plane route tree.
pub trait ControlPlaneAuthenticator: Send + Sync + 'static {
    fn authenticate(&self, request: &Request<Incoming>) -> bool;
}

/// Placeholder migration registry. Database migrations are added by the persistence layer.
#[derive(Clone, Copy, Debug, Default)]
pub struct RegisteredMigrations;

impl MigrationRunner for RegisteredMigrations {
    async fn run(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Closed authentication used until the corresponding credential verifier is installed.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectAll;

impl DataPlaneAuthenticator for RejectAll {
    fn authenticate(&self, _request: &Request<Incoming>) -> bool {
        false
    }
}

impl ControlPlaneAuthenticator for RejectAll {
    fn authenticate(&self, _request: &Request<Incoming>) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct BoundPlanes {
    pub data: SocketAddr,
    pub control: SocketAddr,
}

/// Runs migrations, binds both planes, and serves until shutdown has drained or timed out.
pub async fn run<M, D, C, S>(
    data_address: SocketAddr,
    control_address: SocketAddr,
    migrations: M,
    data_authenticator: D,
    control_authenticator: C,
    shutdown: S,
    drain_timeout: Duration,
) -> io::Result<BoundPlanes>
where
    M: MigrationRunner,
    D: DataPlaneAuthenticator,
    C: ControlPlaneAuthenticator,
    S: Future<Output = io::Result<()>>,
{
    migrations.run().await?;

    let data_listener = TcpListener::bind(data_address).await?;
    let control_listener = TcpListener::bind(control_address).await?;
    let bound = BoundPlanes {
        data: data_listener.local_addr()?,
        control: control_listener.local_addr()?,
    };

    serve(
        data_listener,
        control_listener,
        Arc::new(data_authenticator),
        Arc::new(control_authenticator),
        shutdown,
        drain_timeout,
    )
    .await?;
    Ok(bound)
}

async fn serve<D, C, S>(
    data_listener: TcpListener,
    control_listener: TcpListener,
    data_authenticator: Arc<D>,
    control_authenticator: Arc<C>,
    shutdown: S,
    drain_timeout: Duration,
) -> io::Result<()>
where
    D: DataPlaneAuthenticator,
    C: ControlPlaneAuthenticator,
    S: Future<Output = io::Result<()>>,
{
    let mut connections = JoinSet::new();
    let (stop_connections, stop_receiver) = watch::channel(false);
    let data_permits = Arc::new(Semaphore::new(MAX_SCAFFOLD_CONNECTIONS_PER_PLANE));
    let control_permits = Arc::new(Semaphore::new(MAX_SCAFFOLD_CONNECTIONS_PER_PLANE));
    tokio::pin!(shutdown);

    let shutdown_result = loop {
        tokio::select! {
            result = &mut shutdown => break result,
            result = data_listener.accept() => {
                let (stream, _) = result?;
                let Ok(permit) = Arc::clone(&data_permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                spawn_data_connection(
                    &mut connections,
                    stream,
                    Arc::clone(&data_authenticator),
                    stop_receiver.clone(),
                    permit,
                );
            }
            result = control_listener.accept() => {
                let (stream, _) = result?;
                let Ok(permit) = Arc::clone(&control_permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                spawn_control_connection(
                    &mut connections,
                    stream,
                    Arc::clone(&control_authenticator),
                    stop_receiver.clone(),
                    permit,
                );
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };

    drop(data_listener);
    drop(control_listener);
    let _ = stop_connections.send(true);

    if tokio::time::timeout(drain_timeout, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }

    shutdown_result
}

fn spawn_data_connection<D>(
    connections: &mut JoinSet<()>,
    stream: TcpStream,
    authenticator: Arc<D>,
    mut stop: watch::Receiver<bool>,
    permit: OwnedSemaphorePermit,
) where
    D: DataPlaneAuthenticator,
{
    connections.spawn(async move {
        let _permit = permit;
        let connection = http1::Builder::new().serve_connection(
            TokioIo::new(stream),
            service_fn(move |request| data_route(request, Arc::clone(&authenticator))),
        );
        tokio::pin!(connection);
        tokio::select! {
            _ = &mut connection => {}
            _ = stop.changed() => {
                connection.as_mut().graceful_shutdown();
                let _ = connection.await;
            }
        }
    });
}

fn spawn_control_connection<C>(
    connections: &mut JoinSet<()>,
    stream: TcpStream,
    authenticator: Arc<C>,
    mut stop: watch::Receiver<bool>,
    permit: OwnedSemaphorePermit,
) where
    C: ControlPlaneAuthenticator,
{
    connections.spawn(async move {
        let _permit = permit;
        let connection = http1::Builder::new().serve_connection(
            TokioIo::new(stream),
            service_fn(move |request| control_route(request, Arc::clone(&authenticator))),
        );
        tokio::pin!(connection);
        tokio::select! {
            _ = &mut connection => {}
            _ = stop.changed() => {
                connection.as_mut().graceful_shutdown();
                let _ = connection.await;
            }
        }
    });
}

async fn data_route<D>(
    request: Request<Incoming>,
    authenticator: Arc<D>,
) -> Result<Response<ResponseBody>, hyper::Error>
where
    D: DataPlaneAuthenticator,
{
    if is_health_request(&request) {
        return Ok(text_response(StatusCode::OK, "data plane ok\n"));
    }
    if !authenticator.authenticate(&request) {
        return Ok(text_response(StatusCode::UNAUTHORIZED, "unauthorized\n"));
    }
    Ok(text_response(StatusCode::NOT_FOUND, "not found\n"))
}

async fn control_route<C>(
    request: Request<Incoming>,
    authenticator: Arc<C>,
) -> Result<Response<ResponseBody>, hyper::Error>
where
    C: ControlPlaneAuthenticator,
{
    if is_health_request(&request) {
        return Ok(text_response(StatusCode::OK, "control plane ok\n"));
    }
    if !authenticator.authenticate(&request) {
        return Ok(text_response(StatusCode::UNAUTHORIZED, "unauthorized\n"));
    }
    Ok(text_response(StatusCode::NOT_FOUND, "not found\n"))
}

fn is_health_request(request: &Request<Incoming>) -> bool {
    request.method() == Method::GET && request.uri().path() == "/healthz"
}

fn text_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static response is valid")
}
