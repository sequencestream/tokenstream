//! One account alias becomes a different upstream model on each selected provider.
//!
//! The cases run the real gateway over a socket. A refusal is observed as the
//! status and the error code, and as the upstream receiving nothing.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokenstream::DataPlaneService;
use tokenstream::config::Config;
use tokenstream::credentials::{CreateApiKeyRequest, CredentialService};
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier, PasswordWork, SharedCipher};
use tokenstream::domain::{
    ApiKeyStatus, ProtocolType, ProviderId, ProviderStatus, RequestId, SecretString,
};
use tokenstream::logging::channel;
use tokenstream::model_aliases::{
    CreateModelAliasRequest, ModelAliasService, ModelAliasTargetInput,
};
use tokenstream::persistence::Database;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::providers::{CreateProviderRequest, ProviderService};
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::proxy::gateway::Gateway;
use tokenstream::telemetry::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[path = "../support/mod.rs"]
mod support;
use support::bootstrap_account;

const MASTER_KEY: [u8; 32] = [0x11; 32];
const UPSTREAM_KEY: &str = "sk-upstream-secret-value";

struct Upstream {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<String>>>,
}

async fn spawn_upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let address = listener.local_addr().expect("upstream address");
    let hits = Arc::new(AtomicUsize::new(0));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let counted = Arc::clone(&hits);
    let recorded = Arc::clone(&bodies);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let counted = Arc::clone(&counted);
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let Ok(body) = read_body(&mut socket).await else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                recorded.lock().await.push(body);
                let response = "HTTP/1.1 200 OK\r\ncontent-length: 11\r\nconnection: close\r\n\r\n{\"ok\":true}";
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    Upstream {
        address,
        hits,
        bodies,
    }
}

async fn read_body(socket: &mut TcpStream) -> std::io::Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 2048];
    let header_end = loop {
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request ended before the header",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut body = buffer[header_end..].to_vec();
    if let Some(length) = header_value(&head, "content-length") {
        let length: usize = length.parse().unwrap_or(0);
        while body.len() < length {
            let read = socket.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(length);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

struct Deployment {
    address: SocketAddr,
    credential: String,
    second: ProviderId,
    upstream: Upstream,
    _directory: tempfile::TempDir,
}

async fn deploy() -> Deployment {
    let upstream = spawn_upstream().await;
    let directory = tempfile::tempdir().expect("temporary directory");
    let sqlite = SqliteDatabase::connect(
        &format!("sqlite://{}", directory.path().join("gateway.db").display()),
        4,
    )
    .await
    .expect("connect SQLite");
    sqlite.migrate().await.expect("migrate SQLite");
    let database = Database::Sqlite(sqlite.clone());
    let config = Config::from_settings(&std::collections::HashMap::from([
        ("TOKENSTREAM_DEVELOPMENT_MODE".to_owned(), "true".to_owned()),
        ("TOKENSTREAM_MASTER_KEY".to_owned(), "11".repeat(32)),
        (
            "TOKENSTREAM_ADMIN_PASSWORD_HASH".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA".to_owned(),
        ),
    ]))
    .expect("configuration");

    let accounts = CredentialService::new(sqlite.clone(), Argon2GatewaySecretVerifier::new());
    let account = bootstrap_account(&accounts).await;
    let providers = ProviderService::new(sqlite.clone(), AesGcmCipher::new(&MASTER_KEY), true);
    let endpoint = format!("http://{}", upstream.address);
    let first = providers
        .create(CreateProviderRequest::new(
            "first".to_owned(),
            ProtocolType::OpenAi,
            endpoint.clone(),
            SecretString::new(UPSTREAM_KEY),
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create the first provider")
        .id();
    let second = providers
        .create(CreateProviderRequest::new(
            "second".to_owned(),
            ProtocolType::OpenAi,
            endpoint,
            SecretString::new(UPSTREAM_KEY),
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create the second provider")
        .id();
    let issued = accounts
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "rewrite".to_owned(),
            vec![first, second],
            Some(first),
            None,
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect("issue the credential");
    let aliases = ModelAliasService::new(sqlite);
    aliases
        .create(CreateModelAliasRequest::new(
            account.id(),
            "coding".to_owned(),
            vec![
                ModelAliasTargetInput::new(first, "gpt-5.2-codex".to_owned()),
                ModelAliasTargetInput::new(second, "claude-sonnet".to_owned()),
            ],
        ))
        .await
        .expect("create the shared alias");
    aliases
        .create(CreateModelAliasRequest::new(
            account.id(),
            "writing".to_owned(),
            vec![ModelAliasTargetInput::new(second, "claude-opus".to_owned())],
        ))
        .await
        .expect("create the alias that misses the default provider");
    aliases
        .create(CreateModelAliasRequest::new(
            account.id(),
            "quoted".to_owned(),
            vec![ModelAliasTargetInput::new(first, "gpt\"5".to_owned())],
        ))
        .await
        .expect("create the alias whose upstream name needs escaping");

    let metrics = Metrics::default();
    let (logs, _worker) = channel(
        Arc::new(database.clone()),
        1,
        1,
        std::time::Duration::from_secs(60),
    );
    let admission =
        AdmissionControl::with_metrics(ProxyLimits::from_config(&config), metrics.clone());
    let gateway = Arc::new(Gateway::with_shared_cipher(
        &config,
        database,
        logs,
        metrics.clone(),
        PasswordWork::default(),
        SharedCipher::new(config.master_key().expose()),
    ));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let address = listener.local_addr().expect("gateway address");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let gateway = Arc::clone(&gateway);
            let admission = admission.clone();
            let metrics = metrics.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let gateway = Arc::clone(&gateway);
                    let admission = admission.clone();
                    let metrics = metrics.clone();
                    async move {
                        let Ok(permit) = admission.try_admit() else {
                            let response = hyper::Response::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .body(
                                    Full::new(Bytes::new())
                                        .map_err(|never| match never {})
                                        .boxed_unsync(),
                                )
                                .expect("shed response");
                            return Ok::<_, Infallible>(response);
                        };
                        let (response, session) = gateway
                            .serve(
                                request,
                                "127.0.0.1:40000".parse().expect("peer address"),
                                permit,
                                RequestId::generate(),
                                metrics,
                            )
                            .await;
                        if let Some(session) = session {
                            tokio::spawn(session);
                        }
                        Ok(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    Deployment {
        address,
        credential: issued.credential().render(),
        second,
        upstream,
        _directory: directory,
    }
}

async fn post(
    deployment: &Deployment,
    provider: Option<ProviderId>,
    body: &str,
) -> (StatusCode, String) {
    let mut stream = TcpStream::connect(deployment.address)
        .await
        .expect("connect gateway");
    let selection = provider
        .map(|id| format!("x-tokenstream-provider: {}\r\n", id.get()))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: Bearer {credential}\r\n{selection}\
                 Content-Type: application/json\r\nContent-Length: {length}\r\n\
                 Connection: close\r\n\r\n{body}",
                credential = deployment.credential,
                length = body.len(),
            )
            .as_bytes(),
        )
        .await
        .expect("send request");
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_string(&mut response),
    )
    .await
    .expect("response deadline")
    .expect("read response");
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let envelope = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, envelope)
}

async fn next_upstream(deployment: &Deployment) -> String {
    let started = std::time::Instant::now();
    loop {
        if let Some(body) = deployment.upstream.bodies.lock().await.pop() {
            return body;
        }
        if started.elapsed() > std::time::Duration::from_secs(5) {
            panic!(
                "upstream received {} requests and no pending body",
                deployment.upstream.hits.load(Ordering::SeqCst)
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn an_alias_is_rewritten_for_the_selected_provider_only() {
    let deployment = deploy().await;

    let (status, envelope) = post(&deployment, None, r#"{"model":"writing"}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(envelope.contains("model_alias_unavailable"), "{envelope}");
    assert!(!envelope.contains("writing"), "{envelope}");
    assert!(!envelope.contains("claude-opus"), "{envelope}");
    assert_eq!(deployment.upstream.hits.load(Ordering::SeqCst), 0);

    let (status, envelope) = post(&deployment, None, r#"{"model":1}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(envelope.contains("invalid_model_field"), "{envelope}");
    assert_eq!(deployment.upstream.hits.load(Ordering::SeqCst), 0);

    let (status, _) = post(
        &deployment,
        None,
        r#"{"input":{"model":"coding"},"model":"coding","n":1}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        next_upstream(&deployment).await,
        r#"{"input":{"model":"coding"},"model":"gpt-5.2-codex","n":1}"#
    );

    let (status, _) = post(
        &deployment,
        Some(deployment.second),
        r#"{"model":"coding","n":1}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        next_upstream(&deployment).await,
        r#"{"model":"claude-sonnet","n":1}"#
    );

    let (status, _) = post(&deployment, None, r#"{"model":"gpt-4o","n":1}"#).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        next_upstream(&deployment).await,
        r#"{"model":"gpt-4o","n":1}"#
    );

    let (status, _) = post(&deployment, None, r#"{"n":1}"#).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(next_upstream(&deployment).await, r#"{"n":1}"#);

    let (status, _) = post(&deployment, None, r#"{"model":"quoted"}"#).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(next_upstream(&deployment).await, r#"{"model":"gpt\"5"}"#);
}
