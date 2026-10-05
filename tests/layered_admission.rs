//! Layered admission as the data plane actually applies it.
//!
//! Every case runs the real gateway over a real socket against a controllable
//! upstream, so a bound is observed where a client sees it: in the status and
//! the sanitized error envelope, and in whether the upstream was contacted at
//! all.

use std::collections::HashMap;
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
use tokenstream::credentials::{CreateApiKeyRequest, CredentialService, UpdateApiKeyRequest};
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier, PasswordWork, SharedCipher};
use tokenstream::domain::{
    ApiKeyStatus, CredentialAdmission, ProtocolType, ProviderAdmission, ProviderStatus, RequestId,
    SecretString,
};
use tokenstream::logging::channel;
use tokenstream::persistence::Database;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::providers::{CreateProviderRequest, ProviderService};
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::proxy::gateway::Gateway;
use tokenstream::telemetry::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod support;
use support::bootstrap_account;

const MASTER_KEY: [u8; 32] = [0x11; 32];
const UPSTREAM_KEY: &str = "sk-upstream-secret-value";

/// A configurable upstream that records how many requests reached it.
///
/// The count is what proves a refusal happened before upstream contact rather
/// than as a failed relay after it.
struct CountingUpstream {
    address: SocketAddr,
    received: Arc<AtomicUsize>,
}

/// How long an upstream holds each response before completing it.
///
/// A concurrency bound is about work in flight, so the upstream has to keep an
/// exchange open for the bound to mean anything. A short hold would let every
/// request finish before the next one arrives and the bound would never fire.
const HOLD: std::time::Duration = std::time::Duration::from_millis(400);

/// How long an admitted upstream socket is held open before it is closed.
///
/// A long-lived connection bound only means anything while a socket is still
/// attached, so this has to outlast the attempts that arrive after the first
/// one. It is far longer than the short exchange hold on purpose: the point is
/// a socket a client keeps open, not a request in flight.
const SOCKET_HOLD: std::time::Duration = std::time::Duration::from_secs(5);

async fn spawn_upstream() -> CountingUpstream {
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
                let head = read_upstream_head(&mut socket).await;
                counted.fetch_add(1, Ordering::SeqCst);
                // An upgrade is answered with a handshake the gateway accepts,
                // and the socket is then held open. Holding it is what gives a
                // long-lived connection bound something to refuse: a socket that
                // closed the instant the handshake returned would release the
                // slot before the next attempt arrived.
                if head.to_ascii_lowercase().contains("upgrade: websocket") {
                    let key = header_value(&head, "sec-websocket-key");
                    let accept = handshake_accept(&key);
                    let _ = socket
                        .write_all(
                            format!(
                                "HTTP/1.1 101 Switching Protocols\r\n\
                                 upgrade: websocket\r\n\
                                 connection: Upgrade\r\n\
                                 sec-websocket-accept: {accept}\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .await;
                    // Hold the socket open without answering, so the
                    // connection is genuinely long-lived from the gateway's
                    // point of view and a connection bound has something to
                    // refuse.
                    tokio::time::sleep(SOCKET_HOLD).await;
                    return;
                }
                // An ordinary exchange is held open for the whole window
                // before it answers, so a second request really does find the
                // first one still in flight. A bound is about work in flight,
                // so an upstream that answered immediately would let every
                // request finish before the next arrived and the bound could
                // never fire.
                tokio::time::sleep(HOLD).await;
                let response = "HTTP/1.1 200 OK\r\n\
                                content-type: application/json\r\n\
                                content-length: 11\r\n\
                                connection: close\r\n\r\n{\"ok\":true}";
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    CountingUpstream { address, received }
}

/// Reads one upstream request head, up to and including the blank line.
async fn read_upstream_head(socket: &mut TcpStream) -> String {
    let mut received = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = match socket.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        received.extend_from_slice(&buffer[..read]);
        if received.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&received).into_owned()
}

/// One header value from a raw request head, or the empty string.
fn header_value(head: &str, name: &str) -> String {
    head.lines()
        .find_map(|line| {
            let (field, value) = line.split_once(':')?;
            field
                .trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
        .unwrap_or_default()
}

/// The `Sec-WebSocket-Accept` value for a downstream key.
///
/// This is the SHA-1 the WebSocket handshake is defined in terms of. It is
/// computed here rather than borrowed so the upstream can answer an upgrade
/// without adding a dependency for one line of test scaffolding.
fn handshake_accept(key: &str) -> String {
    use base64::Engine as _;
    let digest = sha1(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// A minimal SHA-1 over `data`.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut message = data.to_vec();
    let bit_length = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    for block in message.chunks(64) {
        let mut w = [0_u32; 80];
        for (index, chunk) in block.chunks(4).enumerate() {
            w[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..80 {
            w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (index, word) in w.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut digest = [0_u8; 20];
    for (index, word) in h.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

struct Deployment {
    address: SocketAddr,
    credential: String,
    upstream: CountingUpstream,
    /// The service and identifier an in-flight edit needs, so a bound can be
    /// changed while the gateway is serving and the change observed by the
    /// traffic that is already admitted.
    credentials: CredentialService<SqliteDatabase, Argon2GatewaySecretVerifier>,
    key_id: tokenstream::domain::ApiKeyId,
    /// Held so the database directory outlives every request the gateway
    /// serves. A pool that is still open while its directory is gone reports
    /// the next new connection as an ordinary storage failure, which would
    /// masquerade as a gateway fault instead of a fault in the test.
    _directory: tempfile::TempDir,
}

/// Starts a real gateway whose single provider carries `provider_admission` and
/// whose single credential carries `credential_admission`.
async fn deploy(
    provider_admission: ProviderAdmission,
    credential_admission: CredentialAdmission,
) -> Deployment {
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

    let config = Config::from_settings(&HashMap::from([
        ("TOKENSTREAM_DEVELOPMENT_MODE".to_owned(), "true".to_owned()),
        ("TOKENSTREAM_MASTER_KEY".to_owned(), "11".repeat(32)),
        (
            "TOKENSTREAM_ADMIN_PASSWORD_HASH".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA".to_owned(),
        ),
    ]))
    .expect("a defaulted configuration");

    let accounts = CredentialService::new(sqlite.clone(), Argon2GatewaySecretVerifier::new());
    let account = bootstrap_account(&accounts).await;
    let provider = ProviderService::new(sqlite.clone(), AesGcmCipher::new(&MASTER_KEY), true)
        .create(
            CreateProviderRequest::new(
                "upstream".to_owned(),
                ProtocolType::OpenAi,
                format!("http://{}", upstream.address),
                SecretString::new(UPSTREAM_KEY),
                ProviderStatus::Enabled,
            )
            .with_admission(provider_admission),
        )
        .await
        .expect("create provider");
    let issued = accounts
        .create_api_key(
            CreateApiKeyRequest::new(
                account.id(),
                "limited".to_owned(),
                vec![provider.id()],
                Some(provider.id()),
                None,
                ApiKeyStatus::Enabled,
            )
            .with_admission(credential_admission),
        )
        .await
        .expect("issue credential");
    let credential = issued.credential().render();
    let key_id = issued.api_key().api_key().id();

    let metrics = Metrics::default();
    // A one-slot log queue keeps metadata emission best-effort and
    // non-blocking on the request path, exactly as production does.
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
                        // An upgraded connection is owned by the session, which
                        // the supervisor drives to completion here.
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

    Deployment {
        address,
        credential,
        upstream,
        credentials: accounts,
        key_id,
        _directory: directory,
    }
}

/// Sends one HTTP/SSE exchange and returns the status and the error envelope.
async fn post_responses(address: SocketAddr, credential: String) -> (StatusCode, String) {
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

/// The upgrade attempt one connection makes.
fn upgrade_request(credential: &str) -> String {
    format!(
        "GET /v1/responses HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer {credential}\r\nConnection: Upgrade\r\n\
         Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    )
}

/// Opens an upgrade attempt and returns the status and the error envelope.
///
/// The attempt reads only the response head: a refused upgrade is a plain
/// `503` envelope, while an accepted one becomes a socket this client does not
/// need to finish using.
async fn upgrade_responses(address: SocketAddr, credential: String) -> (StatusCode, String) {
    let mut stream = TcpStream::connect(address).await.expect("connect gateway");
    stream
        .write_all(upgrade_request(&credential).as_bytes())
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
async fn a_credential_over_its_concurrency_bound_is_refused_before_the_upstream() {
    let deployment = deploy(
        ProviderAdmission::default(),
        CredentialAdmission::new(Some(1), None, None).expect("valid bounds"),
    )
    .await;

    // The two exchanges overlap, so the second finds the first still in flight
    // and the bound decides rather than the upstream's completion.
    let first = tokio::spawn(post_responses(
        deployment.address,
        deployment.credential.clone(),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let (status, envelope) =
        post_responses(deployment.address, deployment.credential.clone()).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        envelope.contains("connection_limit_reached"),
        "a full concurrency bound reports the existing connection limit: {envelope}"
    );
    let (first_status, first_envelope) = first.await.expect("first exchange task");
    assert_eq!(first_status, StatusCode::OK, "{first_envelope}");
    assert_eq!(
        deployment.upstream.received.load(Ordering::SeqCst),
        1,
        "a refused request never reaches the upstream"
    );
}

#[tokio::test]
async fn a_credential_over_its_rate_bound_is_refused_before_the_upstream() {
    // One request per second leaves a single token in the bucket, so a burst
    // wider than that has exactly one admitted member no matter how the
    // requests interleave. A wider bound would make the assertion depend on
    // refill timing rather than on the bound.
    const BURST: usize = 6;
    let deployment = deploy(
        ProviderAdmission::default(),
        CredentialAdmission::new(None, Some(1), None).expect("valid bounds"),
    )
    .await;

    let mut burst = Vec::new();
    for _ in 0..BURST {
        burst.push(tokio::spawn(post_responses(
            deployment.address,
            deployment.credential.clone(),
        )));
    }

    let mut refused = 0;
    for task in burst {
        let (status, envelope) = task.await.expect("burst exchange task");
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert!(
                envelope.contains("resource_exhausted"),
                "an exhausted rate reports the existing capacity error: {envelope}"
            );
            refused += 1;
        } else {
            assert_eq!(status, StatusCode::OK, "{envelope}");
        }
    }
    assert_eq!(
        refused,
        BURST - 1,
        "only the bound's own allowance is admitted"
    );
    assert_eq!(
        deployment.upstream.received.load(Ordering::SeqCst),
        1,
        "a refused request never reaches the upstream"
    );
}

#[tokio::test]
async fn a_provider_over_its_concurrency_bound_refuses_its_own_traffic() {
    let deployment = deploy(
        ProviderAdmission::new(Some(1), None).expect("valid bounds"),
        CredentialAdmission::default(),
    )
    .await;

    let first = tokio::spawn(post_responses(
        deployment.address,
        deployment.credential.clone(),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let (second, envelope) =
        post_responses(deployment.address, deployment.credential.clone()).await;
    assert_eq!(second, StatusCode::SERVICE_UNAVAILABLE);
    assert!(envelope.contains("connection_limit_reached"), "{envelope}");
    let (first_status, _) = first.await.expect("first exchange task");
    assert_eq!(first_status, StatusCode::OK);
}

#[tokio::test]
async fn a_websocket_over_the_credential_connection_bound_is_refused_without_an_upgrade() {
    let deployment = deploy(
        ProviderAdmission::default(),
        CredentialAdmission::new(None, None, Some(1)).expect("valid bounds"),
    )
    .await;

    // The first socket is held open, so the second attempt meets a credential
    // that is already at its connection bound.
    let held = TcpStream::connect(deployment.address)
        .await
        .expect("connect gateway");
    let mut first = held;
    first
        .write_all(upgrade_request(&deployment.credential).as_bytes())
        .await
        .expect("send upgrade");
    let mut head = [0_u8; 1024];
    let read = first
        .read(&mut head)
        .await
        .expect("read first upgrade head");
    assert!(
        String::from_utf8_lossy(&head[..read]).starts_with("HTTP/1.1 101"),
        "the first connection is admitted"
    );

    let (status, envelope) =
        upgrade_responses(deployment.address, deployment.credential.clone()).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the second connection is refused"
    );
    assert!(
        envelope.contains("connection_limit_reached"),
        "a full connection bound reports the existing connection limit: {envelope}"
    );
    assert_eq!(
        deployment.upstream.received.load(Ordering::SeqCst),
        1,
        "a refused connection never reaches the upstream"
    );
}

#[tokio::test]
async fn an_http_exchange_never_consumes_the_websocket_connection_bound() {
    let deployment = deploy(
        ProviderAdmission::default(),
        CredentialAdmission::new(None, None, Some(1)).expect("valid bounds"),
    )
    .await;

    // The connection bound is for long-lived sockets, so a short exchange must
    // not spend it.
    for _ in 0..3 {
        let (status, _) = post_responses(deployment.address, deployment.credential.clone()).await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn an_unlimited_credential_and_provider_are_unaffected_by_the_layers() {
    let deployment = deploy(ProviderAdmission::default(), CredentialAdmission::default()).await;
    for _ in 0..8 {
        let (status, _) = post_responses(deployment.address, deployment.credential.clone()).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(deployment.upstream.received.load(Ordering::SeqCst), 8);
}

/// Waits until the upstream has received `expected` requests.
///
/// The upstream only counts what reached it, so this is how a case knows the
/// work it started is genuinely in flight rather than merely dispatched.
async fn wait_for_upstream(upstream: &CountingUpstream, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while upstream.received.load(Ordering::SeqCst) < expected {
        assert!(
            std::time::Instant::now() < deadline,
            "the upstream received {} requests, expected {expected}",
            upstream.received.load(Ordering::SeqCst)
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Narrows the credential's bounds while the gateway is serving.
///
/// An edit binds work that arrives after it and leaves already-admitted work
/// holding the snapshot it froze at authentication, so tightening a bound never
/// reaches back and terminates a stream or connection that is already running.
/// The narrowed bound counts the work admitted under it, which is what "applies
/// to new work only" means for a limit that is edited rather than configured once.
#[tokio::test]
async fn tightening_bounds_never_terminates_admitted_work_and_spares_the_new_limit() {
    // Start wide so two exchanges and one connection are all admitted at once
    // under the original bounds.
    let deployment = deploy(
        ProviderAdmission::default(),
        CredentialAdmission::new(Some(8), None, Some(4)).expect("valid bounds"),
    )
    .await;

    // Admit one long-lived connection and two concurrent exchanges under the
    // original bounds.
    let connection = tokio::spawn(upgrade_responses(
        deployment.address,
        deployment.credential.clone(),
    ));
    let first = tokio::spawn(post_responses(
        deployment.address,
        deployment.credential.clone(),
    ));
    let second = tokio::spawn(post_responses(
        deployment.address,
        deployment.credential.clone(),
    ));
    // Wait until the upstream has actually received all three, so the edit
    // provably happens after they were admitted rather than before. Polling
    // rather than sleeping keeps the case honest about how long credential
    // verification takes on this machine.
    wait_for_upstream(&deployment.upstream, 3).await;

    // Narrow both bounds while that work is still running.
    let current = deployment
        .credentials
        .get_api_key(deployment.key_id)
        .await
        .expect("read the credential before the edit");
    deployment
        .credentials
        .update_api_key(
            deployment.key_id,
            &current,
            UpdateApiKeyRequest::new().with_admission(
                CredentialAdmission::new(Some(1), None, Some(1)).expect("valid bounds"),
            ),
        )
        .await
        .expect("narrow the bounds");

    // Everything already admitted still completes: the edit did not reach back
    // and tear down work that was already running.
    let connection_status = connection.await.expect("connection task");
    assert_eq!(connection_status.0, StatusCode::SWITCHING_PROTOCOLS);
    let (first_status, _) = first.await.expect("first exchange task");
    assert_eq!(first_status, StatusCode::OK);
    let (second_status, _) = second.await.expect("second exchange task");
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(deployment.upstream.received.load(Ordering::SeqCst), 3);

    // The narrowed connection bound is now in force for work admitted after the
    // edit. Two connections are attempted at once; one is admitted and the other
    // is refused, and the refusal happens before the upstream is contacted,
    // which the unchanged count proves.
    let (accepted, refused) = tokio::join!(
        upgrade_responses(deployment.address, deployment.credential.clone()),
        upgrade_responses(deployment.address, deployment.credential.clone()),
    );
    assert_eq!(
        deployment.upstream.received.load(Ordering::SeqCst),
        4,
        "only the admitted connection reaches the upstream"
    );
    let statuses = [accepted.0, refused.0];
    assert!(
        statuses.contains(&StatusCode::SWITCHING_PROTOCOLS),
        "one connection is admitted under the narrowed bound: {statuses:?}"
    );
    let refused_envelope = if refused.0 == StatusCode::SERVICE_UNAVAILABLE {
        refused.1
    } else {
        accepted.1
    };
    assert!(
        refused_envelope.contains("connection_limit_reached"),
        "the refusal names the credential bound: {refused_envelope}"
    );
}

/// A narrowed HTTP concurrency bound refuses work that exceeds it, before the
/// upstream is contacted, and leaves already-running exchanges alone.
#[tokio::test]
async fn a_narrowed_concurrency_bound_refuses_the_excess_and_spares_the_running_ones() {
    let deployment = deploy(
        ProviderAdmission::default(),
        CredentialAdmission::new(Some(8), None, None).expect("valid bounds"),
    )
    .await;

    // Two exchanges are admitted and running under the original bounds.
    let first = tokio::spawn(post_responses(
        deployment.address,
        deployment.credential.clone(),
    ));
    let second = tokio::spawn(post_responses(
        deployment.address,
        deployment.credential.clone(),
    ));
    wait_for_upstream(&deployment.upstream, 2).await;

    // Narrow the concurrency bound to one while those two are still running.
    let current = deployment
        .credentials
        .get_api_key(deployment.key_id)
        .await
        .expect("read the credential before the edit");
    deployment
        .credentials
        .update_api_key(
            deployment.key_id,
            &current,
            UpdateApiKeyRequest::new().with_admission(
                CredentialAdmission::new(Some(1), None, None).expect("valid bounds"),
            ),
        )
        .await
        .expect("narrow the concurrency bound");

    // Neither running exchange was disturbed by the edit.
    let (first_status, _) = first.await.expect("first exchange task");
    assert_eq!(first_status, StatusCode::OK);
    let (second_status, _) = second.await.expect("second exchange task");
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(deployment.upstream.received.load(Ordering::SeqCst), 2);

    // Work admitted after the edit is held to the narrowed bound: two
    // concurrent exchanges are attempted, one is admitted and one is refused
    // before the upstream is contacted.
    let (accepted, refused) = tokio::join!(
        post_responses(deployment.address, deployment.credential.clone()),
        post_responses(deployment.address, deployment.credential.clone()),
    );
    assert_eq!(
        deployment.upstream.received.load(Ordering::SeqCst),
        3,
        "only the admitted exchange reaches the upstream"
    );
    let statuses = [accepted.0, refused.0];
    assert!(
        statuses.contains(&StatusCode::OK),
        "one exchange is admitted under the narrowed bound: {statuses:?}"
    );
    let refused_envelope = if refused.0 == StatusCode::SERVICE_UNAVAILABLE {
        refused.1
    } else {
        accepted.1
    };
    assert!(
        refused_envelope.contains("connection_limit_reached"),
        "the refusal names the credential bound: {refused_envelope}"
    );
}

/// Widening takes effect for work admitted afterwards, without disturbing the
/// work that was already running.
#[tokio::test]
async fn widening_bounds_admits_work_the_old_bound_refused() {
    // A concurrency bound of one refuses a second concurrent exchange, so the
    // sequence below starts by proving the bound bites.
    let deployment = deploy(
        ProviderAdmission::default(),
        CredentialAdmission::new(Some(1), None, None).expect("valid bounds"),
    )
    .await;

    let in_flight = tokio::spawn(post_responses(
        deployment.address,
        deployment.credential.clone(),
    ));
    wait_for_upstream(&deployment.upstream, 1).await;

    // While one exchange is running, the bound of one refuses the next.
    let (status, _) = post_responses(deployment.address, deployment.credential.clone()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // Widen the bound while the first exchange is still running.
    let current = deployment
        .credentials
        .get_api_key(deployment.key_id)
        .await
        .expect("read the credential before the edit");
    deployment
        .credentials
        .update_api_key(
            deployment.key_id,
            &current,
            UpdateApiKeyRequest::new().with_admission(
                CredentialAdmission::new(Some(4), None, None).expect("valid bounds"),
            ),
        )
        .await
        .expect("widen the bound");

    // The edit did not disturb the exchange that was already running.
    let (in_flight_status, _) = in_flight.await.expect("in-flight exchange task");
    assert_eq!(in_flight_status, StatusCode::OK);

    // Work arriving after the widened edit is admitted, where the old bound of
    // one would have refused a second concurrent exchange.
    let concurrent = post_responses(deployment.address, deployment.credential.clone());
    let (status, _) = concurrent.await;
    assert_eq!(status, StatusCode::OK);
}

/// Clearing every bound releases the credential entirely: after the edit the
/// same request the old bound refused is admitted.
#[tokio::test]
async fn clearing_every_bound_admits_work_the_old_bound_refused() {
    let deployment = deploy(
        ProviderAdmission::default(),
        CredentialAdmission::new(Some(1), None, None).expect("valid bounds"),
    )
    .await;

    let in_flight = tokio::spawn(post_responses(
        deployment.address,
        deployment.credential.clone(),
    ));
    wait_for_upstream(&deployment.upstream, 1).await;
    let (status, _) = post_responses(deployment.address, deployment.credential.clone()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let current = deployment
        .credentials
        .get_api_key(deployment.key_id)
        .await
        .expect("read the credential before the edit");
    deployment
        .credentials
        .update_api_key(
            deployment.key_id,
            &current,
            UpdateApiKeyRequest::new().with_admission(CredentialAdmission::default()),
        )
        .await
        .expect("clear every bound");

    // The running exchange finished unaffected, and the credential is now
    // unbounded, so the same request that was just refused is admitted.
    let (in_flight_status, _) = in_flight.await.expect("in-flight exchange task");
    assert_eq!(in_flight_status, StatusCode::OK);
    let (status, _) = post_responses(deployment.address, deployment.credential.clone()).await;
    assert_eq!(status, StatusCode::OK);
}

/// Editing a credential does not rotate it: the same plaintext keeps working
/// afterwards, so no client has to be reconfigured after an edit.
#[tokio::test]
async fn an_edited_credential_keeps_working_without_being_reissued() {
    let deployment = deploy(
        ProviderAdmission::default(),
        CredentialAdmission::new(Some(2), None, Some(2)).expect("valid bounds"),
    )
    .await;
    let before = deployment.upstream.received.load(Ordering::SeqCst);

    let current = deployment
        .credentials
        .get_api_key(deployment.key_id)
        .await
        .expect("read the credential before the edit");
    let key_id_before = current.api_key().key_id().clone();
    deployment
        .credentials
        .update_api_key(
            deployment.key_id,
            &current,
            UpdateApiKeyRequest::new()
                .with_name("edited-in-flight".to_owned())
                .with_admission(
                    CredentialAdmission::new(Some(1), Some(1), Some(1)).expect("valid bounds"),
                ),
        )
        .await
        .expect("edit the credential");

    let after = deployment
        .credentials
        .get_api_key(deployment.key_id)
        .await
        .expect("read the credential after the edit");
    assert_eq!(
        after.api_key().key_id(),
        &key_id_before,
        "the identifier stands"
    );

    // The very same plaintext still authenticates and reaches the upstream.
    let (status, _) = post_responses(deployment.address, deployment.credential.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        deployment.upstream.received.load(Ordering::SeqCst),
        before + 1
    );
}
