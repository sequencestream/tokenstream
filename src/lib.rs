use std::future::Future;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

pub mod config;

const MAX_HEALTH_CONNECTIONS: usize = 64;

async fn health_response(
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (status, body) = if request.method() == Method::GET && request.uri().path() == "/healthz" {
        (StatusCode::OK, "ok\n")
    } else {
        (StatusCode::NOT_FOUND, "not found\n")
    };
    Ok(Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static response is valid"))
}

/// Runs the initial loopback health service until shutdown is requested.
pub async fn serve(
    listener: TcpListener,
    shutdown: impl Future<Output = io::Result<()>>,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_HEALTH_CONNECTIONS));
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = &mut shutdown => return result,
            result = listener.accept() => {
                let (stream, _) = result?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service_fn(health_response))
                        .await;
                });
            }
        }
    }
}
