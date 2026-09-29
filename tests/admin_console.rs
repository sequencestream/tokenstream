//! The administration page is reachable on the control-plane origin, its assets
//! are confined to the compiled page, and session cookies keep their production
//! attributes while a development deployment runs on plaintext.

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, SET_COOKIE};
use hyper::{Method, Request, StatusCode};
use serde_json::json;
use tokenstream::admin::AdminApi;
use tokenstream::admin::assets::AdminAssets;
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::telemetry::Metrics;

const PASSWORD: &str = "correct horse battery staple";
const MASTER_KEY: [u8; 32] = [0x53; 32];

type Api = AdminApi<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>;

fn built_page() -> AdminAssets {
    AdminAssets::from_files([
        ("index.html", b"<div id=\"app\"></div>" as &[u8]),
        ("assets/index-abc123.js", b"console.log('page')"),
        ("secrets.txt", b"not page content"),
    ])
}

async fn api(development: bool, page: Option<AdminAssets>) -> Api {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = SqliteDatabase::connect(
        &format!("sqlite://{}", directory.path().join("console.db").display()),
        2,
    )
    .await
    .expect("connect SQLite");
    database.migrate().await.expect("migrate SQLite");
    let hash = Argon2::default()
        .hash_password(
            PASSWORD.as_bytes(),
            &SaltString::encode_b64(b"console-test-salt!").expect("valid salt"),
        )
        .expect("hash password")
        .to_string();
    let mut api = AdminApi::new(
        database,
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
        development,
        hash,
    );
    if let Some(page) = page {
        api = api.with_assets(page);
    }
    api
}

async fn send(api: &Api, method: Method, path: &str) -> (StatusCode, hyper::HeaderMap, Bytes) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(http_body_util::Full::new(Bytes::new()))
        .expect("request");
    let response = api.handle(request, Metrics::default()).await;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    (status, headers, bytes)
}

async fn sign_in(api: &Api) -> String {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/admin/api/session")
        .header(CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(Bytes::from(
            json!({"password": PASSWORD}).to_string(),
        )))
        .expect("request");
    let response = api.handle(request, Metrics::default()).await;
    assert_eq!(response.status(), StatusCode::OK);
    response
        .headers()
        .get(SET_COOKIE)
        .expect("session cookie")
        .to_str()
        .expect("ASCII cookie")
        .to_owned()
}

#[tokio::test]
async fn the_page_is_served_before_a_session_and_only_its_own_assets_are_readable() {
    let api = api(false, Some(built_page())).await;
    api.verify_assets().expect("compiled page is usable");

    for path in ["/", "/index.html"] {
        let (status, headers, body) = send(&api, Method::GET, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(&body[..], b"<div id=\"app\"></div>");
        assert_eq!(
            headers.get(CONTENT_TYPE).expect("content type"),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            headers.get(CACHE_CONTROL).expect("cache policy"),
            "no-store"
        );
        assert_eq!(
            headers.get(CONTENT_SECURITY_POLICY).expect("page policy"),
            "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
        );
    }

    let (status, headers, body) = send(&api, Method::GET, "/assets/index-abc123.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"console.log('page')");
    assert_eq!(
        headers.get(CONTENT_TYPE).expect("content type"),
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "public, max-age=31536000, immutable"
    );

    // Files outside the page, traversal attempts and the administration API keep
    // their own behaviour instead of becoming page content. Unauthenticated API
    // JSON still forbids storage; it must not inherit the page's CSP.
    for path in [
        "/secrets.txt",
        "/../secrets.txt",
        "/assets/../secrets.txt",
        "/admin/api/providers",
        "/metrics",
    ] {
        let (status, headers, _) = send(&api, Method::GET, path).await;
        assert_ne!(status, StatusCode::OK, "{path} must not serve page content");
        assert!(
            !headers.contains_key(CONTENT_SECURITY_POLICY),
            "{path} must not receive the page content security policy"
        );
        assert_eq!(
            headers.get(CACHE_CONTROL).expect("cache policy"),
            "no-store",
            "{path} must forbid storage of administration JSON"
        );
    }
    let (status, _, _) = send(&api, Method::GET, "/admin/api/providers").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_page_without_a_built_document_fails_before_listening() {
    let without_page = api(false, Some(AdminAssets::from_files::<&str, Vec<u8>>([]))).await;
    assert!(without_page.verify_assets().is_err());
}

#[tokio::test]
async fn session_cookies_keep_production_attributes_and_development_drops_only_secure() {
    let production = api(false, Some(built_page())).await;
    let cookie = sign_in(&production).await;
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");

    // A plaintext development origin cannot keep a cookie marked secure, but
    // every other restriction of the cookie is retained.
    let development = api(true, Some(built_page())).await;
    let cookie = sign_in(&development).await;
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    assert!(!cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("Path=/"), "{cookie}");
}

#[tokio::test]
async fn the_compiled_page_is_served_from_the_process() {
    let api = api(false, None).await;
    api.verify_assets()
        .expect("the compiled page is present in the process");
    let (status, headers, body) = send(&api, Method::GET, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get(CONTENT_TYPE)
            .expect("content type")
            .to_str()
            .expect("ASCII content type")
            .starts_with("text/html")
    );
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert!(!body.is_empty());
    let (status, _, _) = send(&api, Method::GET, "/admin/api/providers").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
