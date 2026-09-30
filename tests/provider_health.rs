use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::StatusCode;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokenstream::DataPlaneService;
use tokenstream::MigrationRunner;
use tokenstream::config::Config;
use tokenstream::credentials::{CreateApiKeyRequest, CredentialService};
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier, PasswordWork, SharedCipher};
use tokenstream::domain::{
    ApiKeyStatus, ProtocolType, ProviderHealthState, ProviderId, ProviderStatus, RequestId,
    SecretString, validate_provider_probe,
};
use tokenstream::logging::channel;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{Database, ProviderRepository};
use tokenstream::providers::health::HealthProber;
use tokenstream::providers::{CreateProviderRequest, ProviderService};
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::proxy::gateway::Gateway;
use tokenstream::telemetry::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

mod support;
use support::bootstrap_account;

const MASTER_KEY: [u8; 32] = [0x29; 32];
const UPSTREAM_KEY: &str = "sk-upstream-secret-value";

#[tokio::test]
async fn probes_isolate_recover_and_stop_during_maintenance() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe upstream");
    let address = listener.local_addr().expect("probe upstream address");
    let status = Arc::new(AtomicU16::new(503));
    let hits = Arc::new(AtomicUsize::new(0));
    let server_status = status.clone();
    let server_hits = hits.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept probe");
            let status = server_status.clone();
            let hits = server_hits.clone();
            tokio::spawn(async move {
                let mut request = [0_u8; 2048];
                let read = stream.read(&mut request).await.expect("read probe");
                let request = String::from_utf8_lossy(&request[..read]);
                assert!(request.starts_with("GET /base/ready HTTP/1.1\r\n"));
                assert!(!request.to_ascii_lowercase().contains("authorization:"));
                hits.fetch_add(1, Ordering::SeqCst);
                let code = status.load(Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 {code} probe\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write probe response");
            });
        }
    });

    let directory = tempfile::tempdir().expect("temporary directory");
    let database_url = format!("sqlite://{}", directory.path().join("health.db").display());
    let database = Database::connect(&database_url, 2)
        .await
        .expect("connect database");
    database.run().await.expect("migrate database");
    let endpoint = format!("http://{address}/base");
    let endpoint_url = Url::parse(&endpoint).expect("provider endpoint");
    let probe = validate_provider_probe(Some("/ready"), Some(2), Some(1), Some(500))
        .expect("valid probe")
        .expect("configured probe")
        .resolve(&endpoint_url)
        .expect("resolved probe");
    let service = ProviderService::new(database.clone(), AesGcmCipher::new(&MASTER_KEY), true);
    let provider = service
        .create(
            CreateProviderRequest::new(
                "probe-target".to_owned(),
                ProtocolType::OpenAi,
                endpoint,
                SecretString::new("upstream-secret"),
                ProviderStatus::Enabled,
            )
            .with_probe(Some(probe)),
        )
        .await
        .expect("create provider");
    let metrics = Metrics::default();
    let prober = HealthProber::new(
        database.clone(),
        Duration::from_millis(500),
        metrics.clone(),
    );

    prober.tick().await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    prober.tick().await;
    assert_eq!(
        database
            .find_by_id(provider.id())
            .await
            .expect("read isolated provider")
            .expect("provider exists")
            .health(),
        ProviderHealthState::Isolated
    );

    status.store(204, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2)).await;
    prober.tick().await;
    assert_eq!(
        database
            .find_by_id(provider.id())
            .await
            .expect("read recovered provider")
            .expect("provider exists")
            .health(),
        ProviderHealthState::Healthy
    );

    service
        .set_health(provider.id(), ProviderHealthState::Maintenance)
        .await
        .expect("enter maintenance");
    let hits_before_maintenance = hits.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2)).await;
    prober.tick().await;
    assert_eq!(hits.load(Ordering::SeqCst), hits_before_maintenance);
    assert_eq!(
        metrics.probe_outcome_count(tokenstream::telemetry::ProbeOutcomeLabel::Failing),
        2
    );
    assert_eq!(
        metrics.probe_outcome_count(tokenstream::telemetry::ProbeOutcomeLabel::Reachable),
        1
    );

    server.abort();
}

/// How long an admitted upstream exchange is held open so isolation can race it.
const HOLD: Duration = Duration::from_millis(400);

struct CountingUpstream {
    address: SocketAddr,
    received: Arc<AtomicUsize>,
}

async fn spawn_counting_upstream() -> CountingUpstream {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let address = listener.local_addr().expect("upstream address");
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let counted = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 1024];
                let _ = socket.read(&mut buffer).await;
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(HOLD).await;
                let response = "HTTP/1.1 200 OK\r\n\
                                content-type: application/json\r\n\
                                content-length: 11\r\n\
                                connection: close\r\n\r\n{\"ok\":true}";
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    CountingUpstream { address, received }
}

struct IsolatedDeployment {
    address: SocketAddr,
    credential: String,
    provider_id: ProviderId,
    database: Database,
    upstream: CountingUpstream,
    _directory: tempfile::TempDir,
}

async fn deploy_isolated_gateway() -> IsolatedDeployment {
    let upstream = spawn_counting_upstream().await;
    let directory = tempfile::tempdir().expect("temporary directory");
    let sqlite = SqliteDatabase::connect(
        &format!("sqlite://{}", directory.path().join("gateway.db").display()),
        4,
    )
    .await
    .expect("connect SQLite");
    sqlite.migrate().await.expect("migrate SQLite");
    let database = Database::Sqlite(sqlite.clone());

    let config = Config::from_settings(&HashMap::from([
        ("TOKENSTREAM_DEVELOPMENT_MODE".to_owned(), "true".to_owned()),
        ("TOKENSTREAM_MASTER_KEY".to_owned(), "29".repeat(32)),
        (
            "TOKENSTREAM_ADMIN_PASSWORD_HASH".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA".to_owned(),
        ),
    ]))
    .expect("a defaulted configuration");

    let accounts = CredentialService::new(sqlite.clone(), Argon2GatewaySecretVerifier::new());
    let account = bootstrap_account(&accounts).await;
    let provider = ProviderService::new(sqlite.clone(), AesGcmCipher::new(&MASTER_KEY), true)
        .create(CreateProviderRequest::new(
            "upstream".to_owned(),
            ProtocolType::OpenAi,
            format!("http://{}", upstream.address),
            SecretString::new(UPSTREAM_KEY),
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let issued = accounts
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "caller".to_owned(),
            vec![provider.id()],
            Some(provider.id()),
            None,
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect("issue credential");

    let metrics = Metrics::default();
    let (logs, _worker) = channel(Arc::new(database.clone()), 1, 1, Duration::from_secs(60));
    let admission =
        AdmissionControl::with_metrics(ProxyLimits::from_config(&config), metrics.clone());
    let gateway = Arc::new(Gateway::with_shared_cipher(
        &config,
        database.clone(),
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
                            let shed = hyper::Response::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .body(Full::new(Bytes::new()))
                                .expect("shed response");
                            let (parts, body) = shed.into_parts();
                            return Ok::<_, Infallible>(hyper::Response::from_parts(
                                parts,
                                body.map_err(|never| match never {}).boxed_unsync(),
                            ));
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
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });

    IsolatedDeployment {
        address,
        credential: issued.credential().render(),
        provider_id: provider.id(),
        database,
        upstream,
        _directory: directory,
    }
}

async fn post_responses(address: SocketAddr, credential: &str) -> (StatusCode, String) {
    let mut stream = TcpStream::connect(address).await.expect("connect gateway");
    let body = r#"{"model":"opaque-to-the-gateway"}"#;
    stream
        .write_all(
            format!(
                "POST /v1/responses HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: Bearer {credential}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("send request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read response");
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    let envelope = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, envelope)
}

async fn upgrade_responses(address: SocketAddr, credential: &str) -> (StatusCode, String) {
    let mut stream = TcpStream::connect(address).await.expect("connect gateway");
    stream
        .write_all(
            format!(
                "GET /v1/responses HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: Bearer {credential}\r\nConnection: Upgrade\r\n\
                 Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send upgrade");
    let mut head = [0_u8; 4096];
    let read = stream.read(&mut head).await.expect("read upgrade head");
    let response = String::from_utf8_lossy(&head[..read]).into_owned();
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(StatusCode::NO_CONTENT);
    let envelope = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, envelope)
}

#[tokio::test]
async fn isolation_refuses_http_and_websocket_before_upstream_contact() {
    let deployment = deploy_isolated_gateway().await;
    let in_flight = tokio::spawn({
        let credential = deployment.credential.clone();
        let address = deployment.address;
        async move { post_responses(address, &credential).await }
    });
    for _ in 0..100 {
        if deployment.upstream.received.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        deployment.upstream.received.load(Ordering::SeqCst),
        1,
        "the admitted exchange must reach the upstream before isolation"
    );

    deployment
        .database
        .set_health(
            deployment.provider_id,
            ProviderHealthState::Healthy,
            ProviderHealthState::Isolated,
        )
        .await
        .expect("isolate provider");

    let (status, envelope) = post_responses(deployment.address, &deployment.credential).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        envelope.contains("provider_unhealthy"),
        "an isolated provider reports the health refusal: {envelope}"
    );
    assert!(
        !envelope.to_ascii_lowercase().starts_with("http/1.1 101"),
        "a refused HTTP exchange is never an upgrade: {envelope}"
    );

    let (upgrade_status, upgrade_envelope) =
        upgrade_responses(deployment.address, &deployment.credential).await;
    assert_eq!(upgrade_status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        upgrade_envelope.contains("provider_unhealthy"),
        "an isolated provider refuses the upgrade before a handshake: {upgrade_envelope}"
    );
    assert!(
        !upgrade_envelope.to_ascii_lowercase().contains("101"),
        "isolation is a refusal, not a failed handshake: {upgrade_envelope}"
    );

    let (first_status, first_envelope) = in_flight.await.expect("in-flight exchange");
    assert_eq!(first_status, StatusCode::OK, "{first_envelope}");
    assert_eq!(
        deployment.upstream.received.load(Ordering::SeqCst),
        1,
        "refused work never reaches the upstream"
    );
}
