use std::time::Duration;

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use http_body_util::{BodyExt, Full};
use hyper::header::{CACHE_CONTROL, COOKIE, SET_COOKIE};
use hyper::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tokenstream::admin::AdminApi;
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier};
use tokenstream::domain::{ProtocolType, ProviderId, RequestId, TransportType};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{RequestLogRepository, RequestLogStarted};
use tokenstream::telemetry::Metrics;

const PASSWORD: &str = "correct horse battery staple";
const MASTER_KEY: [u8; 32] = [0x53; 32];

async fn api(
    ttl: Duration,
) -> (
    AdminApi<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>,
    SqliteDatabase,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("admin.db");
    let database = SqliteDatabase::connect(&format!("sqlite://{}", path.display()), 2)
        .await
        .expect("connect SQLite");
    database.migrate().await.expect("migrate SQLite");
    let salt = SaltString::encode_b64(b"admin-test-salt!").expect("valid salt");
    let hash = Argon2::default()
        .hash_password(PASSWORD.as_bytes(), &salt)
        .expect("hash password")
        .to_string();
    let api = AdminApi::with_session_ttl(
        database.clone(),
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
        false,
        hash,
        ttl,
    );
    (api, database, directory)
}

fn request(
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(COOKIE, cookie);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    builder
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&body).expect("JSON"),
        )))
        .expect("request")
}

async fn send(
    api: &AdminApi<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>,
    request: Request<Full<Bytes>>,
) -> (StatusCode, hyper::HeaderMap, Value) {
    let response = api.handle(request, Metrics::default()).await;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON response")
    };
    (status, headers, value)
}

async fn sign_in(
    api: &AdminApi<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>,
) -> (String, String) {
    let (status, headers, body) = send(
        api,
        request(
            Method::POST,
            "/admin/api/session",
            json!({"password": PASSWORD}),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    let set_cookie = headers
        .get(SET_COOKIE)
        .expect("session cookie")
        .to_str()
        .expect("ASCII cookie");
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("SameSite=Strict"));
    let cookie = set_cookie
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned();
    let csrf = body["csrf_token"].as_str().expect("CSRF token").to_owned();
    (cookie, csrf)
}

#[tokio::test]
async fn sessions_require_valid_password_csrf_and_reject_expired_or_revoked_access() {
    let (api, _, _directory) = api(Duration::from_millis(20)).await;
    let (status, headers, body) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/session",
            json!({"password": "wrong-secret"}),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert!(!body.to_string().contains("wrong-secret"));

    let (cookie, csrf) = sign_in(&api).await;
    let (status, _, _) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/providers",
            json!({}),
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, headers, body) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/session",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert_eq!(body["signed_in"], true);

    let (status, headers, _) = send(
        &api,
        request(
            Method::DELETE,
            "/admin/api/session",
            Value::Null,
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert!(
        headers
            .get(SET_COOKIE)
            .expect("cleared cookie")
            .to_str()
            .expect("ASCII")
            .contains("Max-Age=0")
    );
    let (status, _, _) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/session",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (cookie, _) = sign_in(&api).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    let (status, _, _) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/session",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn provider_and_log_endpoints_enforce_redaction_cursor_and_filter_contracts() {
    let (api, database, _directory) = api(Duration::from_secs(60)).await;
    let (cookie, csrf) = sign_in(&api).await;
    let create = json!({
        "name": "primary-openai",
        "protocol_type": "openai",
        "endpoint": "https://api.example.com/base",
        "upstream_api_key": "upstream-secret",
        "status": "enabled"
    });
    let (status, headers, created) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/providers",
            create,
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    let provider_id = created["provider"]["id"].as_i64().expect("provider ID");
    let first_gateway_key = created["gateway_api_key"]
        .as_str()
        .expect("one-time credential")
        .to_owned();
    let rendered = created.to_string();
    assert!(!rendered.contains("upstream-secret"));
    assert!(!rendered.contains("ciphertext"));
    assert!(!rendered.contains("password_hash"));

    let (status, headers, listed) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/providers?limit=100",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert_eq!(listed["items"].as_array().expect("items").len(), 1);
    assert!(listed["items"][0].get("gateway_api_key").is_none());
    assert_eq!(listed["next_after_id"], provider_id);
    let (status, _, empty) = send(
        &api,
        request(
            Method::GET,
            &format!("/admin/api/providers?after_id={provider_id}"),
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(empty["next_after_id"], Value::Null);
    let (status, _, _) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/providers?after_id=0",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/providers?limit=101",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _, updated) = send(
        &api,
        request(
            Method::PATCH,
            &format!("/admin/api/providers/{provider_id}"),
            json!({"status": "disabled"}),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["status"], "disabled");
    let (status, headers, rotated) = send(
        &api,
        request(
            Method::POST,
            &format!("/admin/api/providers/{provider_id}/gateway-key:rotate"),
            Value::Null,
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert_ne!(
        rotated["gateway_api_key"].as_str().expect("rotated key"),
        first_gateway_key
    );

    let started_at = Utc
        .with_ymd_and_hms(2026, 9, 28, 8, 0, 0)
        .single()
        .expect("timestamp");
    database
        .insert_started(RequestLogStarted::new(
            RequestId::new("admin-api-log").expect("request ID"),
            ProviderId::try_from(provider_id).expect("provider ID"),
            ProtocolType::OpenAi,
            TransportType::Http,
            "/v1/responses".to_owned(),
            started_at,
        ))
        .await
        .expect("insert log");
    let filter = format!(
        "/admin/api/request-logs?provider_id={provider_id}&transport_type=http&start_time_gte=2026-09-28T07%3A00%3A00Z&start_time_lt=2026-09-28T09%3A00%3A00Z"
    );
    let (status, headers, logs) = send(
        &api,
        request(Method::GET, &filter, Value::Null, Some(&cookie), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert_eq!(logs["items"].as_array().expect("log items").len(), 1);
    assert_eq!(logs["items"][0]["incomplete"], true);
    assert_eq!(logs["items"][0]["path"], "/v1/responses");

    let (status, headers, conflict) = send(
        &api,
        request(
            Method::DELETE,
            &format!("/admin/api/providers/{provider_id}"),
            Value::Null,
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert_eq!(conflict["error"]["code"], "provider_in_use");
}

#[tokio::test]
async fn settings_table_lists_and_updates_live_password() {
    let (api, _, directory) = api(Duration::from_secs(60)).await;
    let state = directory.path().join("state");
    std::fs::create_dir_all(&state).expect("state directory");
    let mut values = std::collections::HashMap::new();
    values.insert("TOKENSTREAM_DEVELOPMENT_MODE".into(), "false".into());
    let config = tokenstream::config::Config::from_map(&values)
        .expect("defaults")
        .with_data_dir(Some(state));
    let api = api.with_runtime(&config, tokenstream::crypto::PasswordWork::default());
    let (cookie, csrf) = sign_in(&api).await;
    let (status, headers, listed) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/settings",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    let items = listed["items"].as_array().expect("settings");
    assert!(
        items
            .iter()
            .any(|item| item["name"] == "TOKENSTREAM_DATA_LISTEN_ADDR")
    );
    assert!(
        items
            .iter()
            .any(|item| item["name"] == "TOKENSTREAM_MASTER_KEY" && item["value"].is_null())
    );

    let (status, _, _) = send(
        &api,
        request(
            Method::PATCH,
            "/admin/api/settings",
            json!({
                "TOKENSTREAM_ADMIN_PASSWORD": "new-admin-password",
                "TOKENSTREAM_ADMIN_SESSION_TTL_MS": "120000"
            }),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/session",
            json!({"password": PASSWORD}),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, body) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/session",
            json!({"password": "new-admin-password"}),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["csrf_token"].as_str().is_some());
}
