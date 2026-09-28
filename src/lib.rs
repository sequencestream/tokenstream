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

use crate::domain::RequestId;
use crate::proxy::admission::{AdmissionControl, AdmissionPermit};
use crate::proxy::error::GatewayError;
use crate::proxy::gateway::{Exchange, Session, boxed, error_response};
use crate::telemetry::{Metrics, ProxyFailureCategory};

pub mod admin;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod logging;
pub mod persistence;
pub mod providers;
pub mod proxy;
pub mod routing;
pub mod telemetry;

pub type ResponseBody = Full<Bytes>;
const MAX_SCAFFOLD_CONNECTIONS_PER_PLANE: usize = 64;

/// Applies all registered schema migrations before either listening socket is bound.
pub trait MigrationRunner: Send + Sync {
    fn run(&self) -> impl Future<Output = io::Result<()>> + Send;
}

/// Authenticates requests entering the data-plane route tree.
pub trait DataPlaneAuthenticator: Send + Sync + 'static {
    fn authenticate(&self, request: &Request<Incoming>) -> bool;
}

/// Serves admitted requests and returns any connection-owned upgraded session.
pub trait DataPlaneService: Send + Sync + 'static {
    fn serve(
        &self,
        request: Request<Incoming>,
        peer: SocketAddr,
        permit: AdmissionPermit,
        id: RequestId,
        metrics: Metrics,
    ) -> impl Future<Output = Exchange> + Send;
}

impl<T: DataPlaneAuthenticator> DataPlaneService for T {
    async fn serve(
        &self,
        request: Request<Incoming>,
        _peer: SocketAddr,
        _permit: AdmissionPermit,
        id: RequestId,
        metrics: Metrics,
    ) -> Exchange {
        let error = if self.authenticate(&request) {
            GatewayError::UnsupportedRoute
        } else {
            GatewayError::InvalidGatewayCredential
        };
        metrics.record_failure(if error == GatewayError::UnsupportedRoute {
            ProxyFailureCategory::UnsupportedRoute
        } else {
            ProxyFailureCategory::InvalidGatewayCredential
        });
        (error_response(error, &id), None)
    }
}

/// Authenticates requests entering the control-plane route tree.
pub trait ControlPlaneAuthenticator: Send + Sync + 'static {
    fn authenticate(&self, request: &Request<Incoming>) -> bool;
}

/// Serves one request on the isolated administration plane.
pub trait ControlPlaneService: Send + Sync + 'static {
    fn serve(
        &self,
        request: Request<Incoming>,
        metrics: Metrics,
    ) -> impl Future<Output = Response<ResponseBody>> + Send;
}

struct AuthenticatedControl<C>(C);

impl<C> ControlPlaneService for AuthenticatedControl<C>
where
    C: ControlPlaneAuthenticator,
{
    async fn serve(&self, request: Request<Incoming>, metrics: Metrics) -> Response<ResponseBody> {
        control_route(request, &self.0, metrics).await
    }
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
///
/// This composition root assembles one dependency per plane concern, so its
/// explicit parameter list is intentionally longer than the lint default.
#[allow(clippy::too_many_arguments)]
pub async fn run<M, D, C, S>(
    data_address: SocketAddr,
    control_address: SocketAddr,
    migrations: M,
    data_authenticator: D,
    control_authenticator: C,
    admission: AdmissionControl,
    shutdown: S,
    drain_timeout: Duration,
) -> io::Result<BoundPlanes>
where
    M: MigrationRunner,
    D: DataPlaneService,
    C: ControlPlaneAuthenticator,
    S: Future<Output = io::Result<()>>,
{
    run_observed(
        data_address,
        control_address,
        migrations,
        data_authenticator,
        control_authenticator,
        admission,
        Metrics::default(),
        shutdown,
        drain_timeout,
    )
    .await
}

/// Runs both planes, then closes and flushes the request-log worker in its own
/// bounded phase after proxy connections have drained.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_logging<M, D, C, S, L>(
    data_address: SocketAddr,
    control_address: SocketAddr,
    migrations: M,
    data_authenticator: D,
    control_authenticator: C,
    admission: AdmissionControl,
    metrics: Metrics,
    shutdown: S,
    drain_timeout: Duration,
    log_sink: crate::logging::LogSink,
    log_worker: crate::logging::LogWorker<L>,
    log_flush_timeout: Duration,
) -> io::Result<BoundPlanes>
where
    M: MigrationRunner,
    D: DataPlaneService,
    C: ControlPlaneAuthenticator,
    S: Future<Output = io::Result<()>>,
    L: crate::logging::LogStore,
{
    run_with_control_and_logging(
        data_address,
        control_address,
        migrations,
        data_authenticator,
        AuthenticatedControl(control_authenticator),
        admission,
        metrics,
        shutdown,
        drain_timeout,
        log_sink,
        log_worker,
        log_flush_timeout,
    )
    .await
}

/// Runs both planes with a complete administration service and bounded log shutdown.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_control_and_logging<M, D, C, S, L>(
    data_address: SocketAddr,
    control_address: SocketAddr,
    migrations: M,
    data_authenticator: D,
    control_service: C,
    admission: AdmissionControl,
    metrics: Metrics,
    shutdown: S,
    drain_timeout: Duration,
    log_sink: crate::logging::LogSink,
    log_worker: crate::logging::LogWorker<L>,
    log_flush_timeout: Duration,
) -> io::Result<BoundPlanes>
where
    M: MigrationRunner,
    D: DataPlaneService,
    C: ControlPlaneService,
    S: Future<Output = io::Result<()>>,
    L: crate::logging::LogStore,
{
    let mut worker_task = tokio::spawn(log_worker.run());
    let flush_metrics = log_sink.metrics().clone();
    let server_result = run_observed_with_control(
        data_address,
        control_address,
        migrations,
        data_authenticator,
        control_service,
        admission,
        metrics,
        shutdown,
        drain_timeout,
    )
    .await;

    // All connection tasks have completed or been aborted before the last
    // composition-root sender closes. No synthetic completion events are made.
    drop(log_sink);
    if tokio::time::timeout(log_flush_timeout, &mut worker_task)
        .await
        .is_err()
    {
        worker_task.abort();
        let _ = worker_task.await;
        flush_metrics.drop_all_queued_log_events();
    }
    server_result
}

#[allow(clippy::too_many_arguments)]
async fn run_observed<M, D, C, S>(
    data_address: SocketAddr,
    control_address: SocketAddr,
    migrations: M,
    data_authenticator: D,
    control_authenticator: C,
    admission: AdmissionControl,
    metrics: Metrics,
    shutdown: S,
    drain_timeout: Duration,
) -> io::Result<BoundPlanes>
where
    M: MigrationRunner,
    D: DataPlaneService,
    C: ControlPlaneAuthenticator,
    S: Future<Output = io::Result<()>>,
{
    run_observed_with_control(
        data_address,
        control_address,
        migrations,
        data_authenticator,
        AuthenticatedControl(control_authenticator),
        admission,
        metrics,
        shutdown,
        drain_timeout,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_observed_with_control<M, D, C, S>(
    data_address: SocketAddr,
    control_address: SocketAddr,
    migrations: M,
    data_authenticator: D,
    control_service: C,
    admission: AdmissionControl,
    metrics: Metrics,
    shutdown: S,
    drain_timeout: Duration,
) -> io::Result<BoundPlanes>
where
    M: MigrationRunner,
    D: DataPlaneService,
    C: ControlPlaneService,
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
        Arc::new(control_service),
        Arc::new(admission),
        metrics,
        shutdown,
        drain_timeout,
    )
    .await?;
    Ok(bound)
}

#[allow(clippy::too_many_arguments)]
async fn serve<D, C, S>(
    data_listener: TcpListener,
    control_listener: TcpListener,
    data_authenticator: Arc<D>,
    control_authenticator: Arc<C>,
    admission: Arc<AdmissionControl>,
    metrics: Metrics,
    shutdown: S,
    drain_timeout: Duration,
) -> io::Result<()>
where
    D: DataPlaneService,
    C: ControlPlaneService,
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
                    Arc::clone(&admission),
                    metrics.clone(),
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
                    metrics.clone(),
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
    admission: Arc<AdmissionControl>,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
    permit: OwnedSemaphorePermit,
) where
    D: DataPlaneService,
{
    connections.spawn(async move {
        let _permit = permit;
        let peer = match stream.peer_addr() {
            Ok(peer) => peer,
            Err(_) => return,
        };
        let session: Arc<std::sync::Mutex<Option<Session>>> = Arc::default();
        let session_slot = session.clone();
        let connection = http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| {
                    let authenticator = authenticator.clone();
                    let admission = admission.clone();
                    let metrics = metrics.clone();
                    let session_slot = session_slot.clone();
                    async move {
                        let (response, relay) =
                            data_route(request, authenticator, admission, metrics, peer).await;
                        if let Some(relay) = relay {
                            *session_slot.lock().expect("session lock") = Some(relay);
                        }
                        Ok::<_, hyper::Error>(response)
                    }
                }),
            )
            .with_upgrades();
        tokio::pin!(connection);
        tokio::select! {
            _ = &mut connection => {}
            _ = stop.changed() => {
                connection.as_mut().graceful_shutdown();
                let _ = connection.await;
            }
        }
        let relay = session.lock().expect("session lock").take();
        if let Some(relay) = relay {
            relay.await;
        }
    });
}

fn spawn_control_connection<C>(
    connections: &mut JoinSet<()>,
    stream: TcpStream,
    authenticator: Arc<C>,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
    permit: OwnedSemaphorePermit,
) where
    C: ControlPlaneService,
{
    connections.spawn(async move {
        let _permit = permit;
        let connection = http1::Builder::new().serve_connection(
            TokioIo::new(stream),
            service_fn(move |request| {
                let authenticator = Arc::clone(&authenticator);
                let metrics = metrics.clone();
                async move { Ok::<_, hyper::Error>(authenticator.serve(request, metrics).await) }
            }),
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

/// Routes one data-plane request.
///
/// Admission precedes authentication so an overloaded gateway performs no
/// credential lookup and never queues work. The permit is held for the whole
/// request and released on every exit path, including cancellation.
async fn data_route<D>(
    request: Request<Incoming>,
    authenticator: Arc<D>,
    admission: Arc<AdmissionControl>,
    metrics: Metrics,
    peer: SocketAddr,
) -> Exchange
where
    D: DataPlaneService,
{
    if is_health_request(&request) {
        return (
            text_response(StatusCode::OK, "data plane ok\n").map(boxed),
            None,
        );
    }
    let id = RequestId::generate();
    let permit = match admission.try_admit() {
        Ok(permit) => permit,
        Err(error) => return (error_response(error, &id), None),
    };
    authenticator
        .serve(request, peer, permit, id, metrics)
        .await
}

async fn control_route<C>(
    request: Request<Incoming>,
    authenticator: &C,
    metrics: Metrics,
) -> Response<ResponseBody>
where
    C: ControlPlaneAuthenticator,
{
    if is_health_request(&request) {
        return text_response(StatusCode::OK, "control plane ok\n");
    }
    if !authenticator.authenticate(&request) {
        return text_response(StatusCode::UNAUTHORIZED, "unauthorized\n");
    }
    if request.method() == Method::GET && request.uri().path() == "/metrics" {
        return metrics_response(&metrics);
    }
    text_response(StatusCode::NOT_FOUND, "not found\n")
}

fn metrics_response(metrics: &Metrics) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Full::new(Bytes::from(metrics.render())))
        .expect("the metrics response is valid")
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
