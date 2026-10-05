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
use tokenstream::domain::{
    AccountId, ApiKeyId, ProtocolType, ProviderId, RequestId, TransportType,
};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{AccountRepository, RequestLogRepository, RequestLogStarted};
use tokenstream::telemetry::Metrics;

const ADMIN_NAME: &str = "admin";
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
    // The first account is the one a client signs in as, so the control plane
    // is only usable once the deployment has created it.
    api.ensure_bootstrap_account(ADMIN_NAME, PASSWORD)
        .await
        .expect("create the bootstrap account");
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

/// Signs in as the named account and returns its cookie and CSRF token.
async fn sign_in_as(
    api: &AdminApi<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>,
    name: &str,
    password: &str,
) -> (String, String) {
    let (status, headers, body) = send(
        api,
        request(
            Method::POST,
            "/admin/api/session",
            json!({"name": name, "password": password}),
            None,
            None,
        ),
    )
    .await;
    if status != StatusCode::OK {
        panic!(
            "sign-in for {name} failed: {status} {}",
            body.get("error").cloned().unwrap_or(Value::Null)
        );
    }
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
    assert_eq!(body["account_name"], name);
    (cookie, csrf)
}

async fn sign_in(
    api: &AdminApi<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>,
) -> (String, String) {
    sign_in_as(api, ADMIN_NAME, PASSWORD).await
}

/// Creates a regular account and returns its identifier with its password.
async fn create_user(
    api: &AdminApi<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>,
    cookie: &str,
    csrf: &str,
    name: &str,
) -> (i64, String) {
    let (status, _, created) = send(
        api,
        request(
            Method::POST,
            "/admin/api/accounts",
            json!({"name": name, "role": "user", "status": "enabled"}),
            Some(cookie),
            Some(csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["account"]["id"].as_i64().expect("account ID");
    let password = created["generated_password"]
        .as_str()
        .expect("a one-time password")
        .to_owned();
    assert!(
        !serde_json::to_string(&created)
            .expect("render")
            .contains("password_hash"),
        "an account view must never carry a password hash"
    );
    (id, password)
}

#[tokio::test]
async fn sessions_require_valid_password_csrf_and_reject_expired_or_revoked_access() {
    let (api, _, _directory) = api(Duration::from_millis(20)).await;
    let (status, headers, body) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/session",
            json!({"name": ADMIN_NAME, "password": "wrong-secret"}),
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
        "status": "enabled",
        "health": {
            "probe_path": "/ready",
            "failure_threshold": 3,
            "probe_interval_ms": 30000,
            "probe_timeout_ms": 5000
        }
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
    let provider_id = created["id"].as_i64().expect("provider ID");
    // A provider no longer issues a credential, so creation returns the record
    // alone and nothing a client could present as a key.
    assert!(created.get("gateway_api_key").is_none());
    let rendered = created.to_string();
    assert!(!rendered.contains("upstream-secret"));
    assert!(!rendered.contains("ciphertext"));
    assert!(!rendered.contains("password_hash"));
    assert_eq!(created["health"], "healthy");
    assert_eq!(created["health_probe"]["probe_path"], "/ready");

    let (status, _, maintenance) = send(
        &api,
        request(
            Method::PUT,
            &format!("/admin/api/providers/{provider_id}/maintenance"),
            Value::Null,
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(maintenance["health"], "maintenance");
    let (status, _, healthy) = send(
        &api,
        request(
            Method::DELETE,
            &format!("/admin/api/providers/{provider_id}/maintenance"),
            Value::Null,
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(healthy["health"], "healthy");

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
    let _ = &rotated;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );

    let started_at = Utc
        .with_ymd_and_hms(2026, 9, 28, 8, 0, 0)
        .single()
        .expect("timestamp");
    let account_id = AccountId::try_from(
        database
            .find_bootstrap()
            .await
            .expect("read the bootstrap account")
            .expect("the bootstrap account exists")
            .id()
            .get(),
    )
    .expect("positive account ID");
    let (status, _, issued) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/api-keys",
            json!({
                "account_id": account_id.get(),
                "name": "ci",
                "provider_ids": [provider_id],
                "default_provider_id": provider_id,
                "status": "enabled"
            }),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let api_key_id = ApiKeyId::try_from(issued["api_key"]["id"].as_i64().expect("credential ID"))
        .expect("positive credential ID");
    database
        .insert_started(RequestLogStarted::new(
            RequestId::new("admin-api-log").expect("request ID"),
            account_id,
            api_key_id,
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
    assert!(
        items
            .iter()
            .all(|item| item["name"] != "TOKENSTREAM_ADMIN_STATIC_ROOT")
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
            json!({"name": ADMIN_NAME, "password": PASSWORD}),
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
            json!({"name": ADMIN_NAME, "password": "new-admin-password"}),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["csrf_token"].as_str().is_some());
}

#[tokio::test]
async fn accounts_and_credentials_are_role_scoped_and_never_return_a_secret() {
    let (api, _database, _directory) = api(Duration::from_secs(60)).await;
    let (cookie, csrf) = sign_in(&api).await;

    // A regular account can sign in and issue credentials for itself, but it
    // cannot reach accounts, providers, or settings.
    let (user_id, user_password) = create_user(&api, &cookie, &csrf, "analyst").await;
    let (user_cookie, user_csrf) = sign_in_as(&api, "analyst", &user_password).await;
    for (method, path) in [
        (Method::GET, "/admin/api/accounts"),
        (Method::GET, "/admin/api/settings"),
        // The operational exposition is an administrator surface too: it
        // describes the whole process, so a regular account is refused rather
        // than shown a partial view.
        (Method::GET, "/metrics"),
    ] {
        let (status, _, _) = send(
            &api,
            request(method, path, Value::Null, Some(&user_cookie), None),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{path} must stay administrator-only"
        );
    }

    // The administrator does receive it, and the response is not cacheable.
    // The exposition is text, so it is read directly rather than through the
    // JSON helper the API responses use.
    let response = api
        .handle(
            request(Method::GET, "/metrics", Value::Null, Some(&cookie), None),
            Metrics::default(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    let rendered = String::from_utf8(bytes.to_vec()).expect("text exposition");
    assert!(rendered.contains("tokenstream_exchanges_total"));
    assert!(rendered.contains("tokenstream_admission_rejections_total"));
    let (status, _, _) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/providers",
            json!({
                "name": "forbidden",
                "protocol_type": "openai",
                "endpoint": "https://api.example.com/base",
                "upstream_api_key": "upstream-secret",
                "status": "enabled"
            }),
            Some(&user_cookie),
            Some(&user_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A provider has to exist before a credential can bind to it, and only an
    // administrator can create one.
    let (status, _, provider) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/providers",
            json!({
                "name": "primary-openai",
                "protocol_type": "openai",
                "endpoint": "https://api.example.com/base",
                "upstream_api_key": "upstream-secret",
                "status": "enabled"
            }),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let provider_id = provider["id"].as_i64().expect("provider ID");

    let (status, _, _) = send(
        &api,
        request(
            Method::PUT,
            &format!("/admin/api/providers/{provider_id}/maintenance"),
            Value::Null,
            Some(&user_cookie),
            Some(&user_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, issued) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/api-keys",
            json!({
                "account_id": user_id,
                "name": "ci",
                "provider_ids": [provider_id],
                "default_provider_id": provider_id,
                "status": "enabled"
            }),
            Some(&user_cookie),
            Some(&user_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let first_secret = issued["api_key_secret"]
        .as_str()
        .expect("a one-time plaintext")
        .to_owned();
    let key_id = issued["api_key"]["id"].as_i64().expect("credential ID");
    assert_eq!(issued["api_key"]["account_id"], user_id);
    assert!(!issued.to_string().contains("secret_hash"));

    // A regular user may not issue a credential in another account's name.
    let bootstrap_id = send(
        &api,
        request(
            Method::GET,
            "/admin/api/accounts?limit=100",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await
    .2["items"]
        .as_array()
        .expect("accounts")
        .iter()
        .find(|item| item["is_bootstrap"] == json!(true))
        .expect("the bootstrap account")["id"]
        .as_i64()
        .expect("account ID");
    let (status, _, _) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/api-keys",
            json!({
                "account_id": bootstrap_id,
                "name": "stolen",
                "provider_ids": [provider_id],
                "status": "enabled"
            }),
            Some(&user_cookie),
            Some(&user_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The listing is scoped to the caller, so an administrator sees the
    // bootstrap credential-less account and the user's own credential.
    let (status, _, listed) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/api-keys?limit=100",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["items"].as_array().expect("items").len(), 1);
    let (status, _, own) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/api-keys?limit=100",
            Value::Null,
            Some(&user_cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let own_items = own["items"].as_array().expect("items");
    assert_eq!(own_items.len(), 1);
    assert_eq!(own_items[0]["id"], key_id);
    assert!(
        own_items[0].get("api_key_secret").is_none(),
        "a listing must never repeat the plaintext"
    );

    // Rotation retires the previous plaintext and returns a fresh one.
    let (status, _, rotated) = send(
        &api,
        request(
            Method::POST,
            &format!("/admin/api/api-keys/{key_id}:rotate"),
            Value::Null,
            Some(&user_cookie),
            Some(&user_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second_secret = rotated["api_key_secret"]
        .as_str()
        .expect("a rotated plaintext")
        .to_owned();
    assert_ne!(second_secret, first_secret);

    // A credential that names a provider nobody created is refused rather
    // than issued into a state it could never resolve.
    let (status, _, body) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/api-keys",
            json!({
                "account_id": user_id,
                "name": "dangling",
                "provider_ids": [i64::MAX],
                "status": "enabled"
            }),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "provider_not_found");

    // The bootstrap account is the operator's way back in, so it can be
    // neither disabled nor demoted nor deleted.
    for (method, path, change) in [
        (
            Method::PATCH,
            format!("/admin/api/accounts/{bootstrap_id}"),
            json!({"status": "disabled"}),
        ),
        (
            Method::PATCH,
            format!("/admin/api/accounts/{bootstrap_id}"),
            json!({"role": "user"}),
        ),
        (
            Method::DELETE,
            format!("/admin/api/accounts/{bootstrap_id}"),
            Value::Null,
        ),
    ] {
        let (status, _, _) = send(
            &api,
            request(method, &path, change, Some(&cookie), Some(&csrf)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{path} must protect the bootstrap account"
        );
    }
}

#[tokio::test]
async fn request_log_storage_failure_returns_a_generic_internal_error() {
    let (api, database, _directory) = api(Duration::from_secs(60)).await;
    let (cookie, _) = sign_in(&api).await;
    sqlx::query("DROP TABLE ts_request_log")
        .execute(database.pool())
        .await
        .expect("drop request log table");
    let (status, headers, body) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/request-logs?limit=100",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert_eq!(body["error"]["code"], "internal_error");
    assert_eq!(
        body["error"]["message"],
        "The request could not be completed."
    );
    let rendered = body.to_string();
    assert!(
        !rendered.contains("request_log") && !rendered.contains("no such table"),
        "the generic envelope must not carry the storage message: {rendered}"
    );
}

/// The API handle and the temporary directory that keeps its database alive.
type TestApi = AdminApi<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>;

/// Three providers plus one credential owned by a regular user, so a credential
/// edit can be driven end to end and a second user can prove that the same edit
/// is refused for somebody else's credential.
struct EditFixture {
    api: TestApi,
    _database: SqliteDatabase,
    _directory: tempfile::TempDir,
    provider_ids: Vec<i64>,
    key_id: i64,
    /// The credential owner's session cookie and CSRF token.
    owner: (String, String),
    admin: (String, String),
    other: (String, String),
}

async fn edit_fixture() -> EditFixture {
    let (api, database, directory) = api(Duration::from_secs(300)).await;
    let (admin_cookie, admin_csrf) = sign_in(&api).await;
    let mut provider_ids = Vec::new();
    for number in 0..3 {
        let (status, _, provider) = send(
            &api,
            request(
                Method::POST,
                "/admin/api/providers",
                json!({
                    "name": format!("edit-provider-{number}"),
                    "protocol_type": "openai",
                    "endpoint": format!("https://provider-{number}.example.com/base"),
                    "upstream_api_key": "upstream-secret",
                    "status": "enabled"
                }),
                Some(&admin_cookie),
                Some(&admin_csrf),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        provider_ids.push(provider["id"].as_i64().expect("provider ID"));
    }

    let (owner_id, owner_password) = create_user(&api, &admin_cookie, &admin_csrf, "owner").await;
    let (_, other_password) = create_user(&api, &admin_cookie, &admin_csrf, "other").await;
    let owner = sign_in_as(&api, "owner", &owner_password).await;
    let other = sign_in_as(&api, "other", &other_password).await;

    let (status, _, issued) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/api-keys",
            json!({
                "account_id": owner_id,
                "name": "ci",
                "provider_ids": provider_ids,
                "default_provider_id": provider_ids[0],
                "status": "enabled",
                "max_concurrent_requests": 10,
                "max_requests_per_second": 20,
                "max_websockets": 30
            }),
            Some(&owner.0),
            Some(&owner.1),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "fixture credential: {issued}");
    let key_id = issued["api_key"]["id"].as_i64().expect("credential ID");

    EditFixture {
        api,
        _database: database,
        _directory: directory,
        provider_ids,
        key_id,
        owner,
        admin: (admin_cookie, admin_csrf),
        other,
    }
}

/// Reads one credential back, asserting it is the one the fixture issued.
async fn read_key(fixture: &EditFixture, cookie: &str) -> Value {
    let (status, _, body) = send(
        &fixture.api,
        request(
            Method::GET,
            &format!("/admin/api/api-keys/{}", fixture.key_id),
            Value::Null,
            Some(cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "read key: {body}");
    // Both the read and the edit return the redacted credential view directly.
    body
}

/// Issues one edit as `session` and returns its status, code, and body.
async fn patch_key(
    fixture: &EditFixture,
    session: &(String, String),
    body: Value,
) -> (StatusCode, Value) {
    let (status, _, response) = send(
        &fixture.api,
        request(
            Method::PATCH,
            &format!("/admin/api/api-keys/{}", fixture.key_id),
            body,
            Some(&session.0),
            Some(&session.1),
        ),
    )
    .await;
    (status, response)
}

/// The identifiers of a credential's provider bindings, in preference order.
fn provider_ids_of(view: &Value) -> Vec<i64> {
    view["provider_ids"]
        .as_array()
        .expect("an ordered provider set")
        .iter()
        .map(|value| value.as_i64().expect("provider ID"))
        .collect()
}

#[tokio::test]
async fn one_patch_applies_every_named_field_and_reads_back_consistently() {
    let fixture = edit_fixture().await;
    let expires_at = (Utc::now() + chrono::Duration::hours(48)).to_rfc3339();

    // One edit names every editable field: the provider set loses its first
    // member and reverses, the default moves with it, all three bounds change,
    // and the name, expiry, and status are rewritten together.
    let (status, edited) = patch_key(
        &fixture,
        &fixture.owner,
        json!({
            "name": "edited",
            "status": "disabled",
            "expires_at": expires_at,
            "provider_ids": [fixture.provider_ids[2], fixture.provider_ids[1]],
            "default_provider_id": fixture.provider_ids[2],
            "admission": {
                "max_concurrent_requests": 2,
                "max_requests_per_second": 3,
                "max_websockets": 4
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch: {edited}");
    let view = &edited;
    assert_eq!(view["name"], "edited");
    assert_eq!(view["status"], "disabled");
    assert_eq!(
        provider_ids_of(view),
        vec![fixture.provider_ids[2], fixture.provider_ids[1]]
    );
    assert_eq!(view["default_provider_id"], fixture.provider_ids[2]);
    assert_eq!(view["max_concurrent_requests"], 2);
    assert_eq!(view["max_requests_per_second"], 3);
    assert_eq!(view["max_websockets"], 4);
    assert!(view["expires_at"].is_string());

    // A fresh read agrees with the edit response, field for field.
    let reread = read_key(&fixture, &fixture.owner.0).await;
    assert_eq!(reread["name"], "edited");
    assert_eq!(reread["status"], "disabled");
    assert_eq!(
        provider_ids_of(&reread),
        vec![fixture.provider_ids[2], fixture.provider_ids[1]]
    );
    assert_eq!(reread["default_provider_id"], fixture.provider_ids[2]);
    assert_eq!(reread["max_concurrent_requests"], 2);
    assert_eq!(reread["max_requests_per_second"], 3);
    assert_eq!(reread["max_websockets"], 4);
    assert_eq!(reread["expires_at"], view["expires_at"]);

    // The listing reads back the same values, in the same provider order.
    let (status, _, listed) = send(
        &fixture.api,
        request(
            Method::GET,
            "/admin/api/api-keys?limit=100",
            Value::Null,
            Some(&fixture.owner.0),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = listed["items"].as_array().expect("items");
    let listed_view = items
        .iter()
        .find(|item| item["id"] == json!(fixture.key_id))
        .expect("the edited credential is listed");
    assert_eq!(
        provider_ids_of(listed_view),
        vec![fixture.provider_ids[2], fixture.provider_ids[1]]
    );
    assert_eq!(listed_view["default_provider_id"], fixture.provider_ids[2]);
    assert_eq!(listed_view["max_websockets"], 4);
}

#[tokio::test]
async fn an_edit_keeps_the_key_identifier_and_returns_no_plaintext() {
    let fixture = edit_fixture().await;
    let before = read_key(&fixture, &fixture.owner.0).await;
    let key_id = before["key_id"].clone();

    let (status, edited) = patch_key(
        &fixture,
        &fixture.owner,
        json!({"name": "renamed", "admission": {
            "max_concurrent_requests": 1,
            "max_requests_per_second": null,
            "max_websockets": null
        }}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Editing reissues nothing, so the identifier the client holds still works.
    assert_eq!(edited["key_id"], key_id);

    let rendered = edited.to_string();
    assert!(
        !rendered.contains("api_key_secret"),
        "an edit must never return a plaintext"
    );
    assert!(
        !rendered.contains("secret_hash"),
        "an edit must never return a stored hash"
    );
    let single = read_key(&fixture, &fixture.owner.0).await;
    assert!(!single.to_string().contains("api_key_secret"));
    assert!(!single.to_string().contains("secret_hash"));
    assert_eq!(single["key_id"], key_id);
    // One bound set and two cleared, written together.
    assert_eq!(single["max_concurrent_requests"], 1);
    assert_eq!(single["max_requests_per_second"], Value::Null);
    assert_eq!(single["max_websockets"], Value::Null);
}

#[tokio::test]
async fn clearing_the_expiry_and_every_bound_is_expressed_as_null() {
    let fixture = edit_fixture().await;
    // An explicit null clears; the credential starts with an expiry to clear.
    let (status, _, issued) = send(
        &fixture.api,
        request(
            Method::PATCH,
            &format!("/admin/api/api-keys/{}", fixture.key_id),
            json!({"expires_at": (Utc::now() + chrono::Duration::hours(6)).to_rfc3339()}),
            Some(&fixture.owner.0),
            Some(&fixture.owner.1),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(issued["expires_at"].is_string());

    let (status, cleared) = patch_key(
        &fixture,
        &fixture.owner,
        json!({
            "expires_at": null,
            "admission": {
                "max_concurrent_requests": null,
                "max_requests_per_second": null,
                "max_websockets": null
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after = read_key(&fixture, &fixture.owner.0).await;
    assert_eq!(after["expires_at"], Value::Null);
    assert_eq!(after["max_concurrent_requests"], Value::Null);
    assert_eq!(after["max_requests_per_second"], Value::Null);
    assert_eq!(after["max_websockets"], Value::Null);
    assert_eq!(cleared["expires_at"], Value::Null);
}

#[tokio::test]
async fn an_absent_field_leaves_the_stored_value_alone() {
    let fixture = edit_fixture().await;
    let before = read_key(&fixture, &fixture.owner.0).await;
    assert_eq!(before["max_concurrent_requests"], 10);

    let (status, edited) =
        patch_key(&fixture, &fixture.owner, json!({"name": "only-the-name"})).await;
    assert_eq!(status, StatusCode::OK, "patch: {edited}");
    let view = &edited;
    // Everything not named is unchanged, including the bound and the set.
    assert_eq!(view["name"], "only-the-name");
    assert_eq!(view["max_concurrent_requests"], 10);
    assert_eq!(view["max_requests_per_second"], 20);
    assert_eq!(view["max_websockets"], 30);
    assert_eq!(view["status"], "enabled");
    assert_eq!(provider_ids_of(view), fixture.provider_ids);
    assert_eq!(view["default_provider_id"], fixture.provider_ids[0]);
}

#[tokio::test]
async fn editing_a_credential_is_scoped_to_its_owner_or_an_administrator() {
    let fixture = edit_fixture().await;
    let before = read_key(&fixture, &fixture.owner.0).await;

    // A regular user may not edit, or even read, somebody else's credential.
    for method in [Method::GET, Method::PATCH] {
        let csrf = if method == Method::PATCH {
            Some(fixture.other.1.as_str())
        } else {
            None
        };
        let label = if method == Method::PATCH {
            "PATCH"
        } else {
            "GET"
        };
        let (status, _, _) = send(
            &fixture.api,
            request(
                method,
                &format!("/admin/api/api-keys/{}", fixture.key_id),
                json!({"name": "stolen"}),
                Some(&fixture.other.0),
                csrf,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label} must not reach it");
    }

    // The refused attempts left the credential exactly as it was.
    assert_eq!(read_key(&fixture, &fixture.owner.0).await, before);

    // The owner may edit its own credential.
    let (status, edited) = patch_key(&fixture, &fixture.owner, json!({"name": "mine"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(edited["name"], "mine");

    // An administrator may edit any credential, including another account's.
    let (status, edited) =
        patch_key(&fixture, &fixture.admin, json!({"name": "administered"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(edited["name"], "administered");
    assert_eq!(
        read_key(&fixture, &fixture.owner.0).await["name"],
        "administered"
    );
}

#[tokio::test]
async fn replacing_the_provider_set_rechecks_the_stored_default() {
    let fixture = edit_fixture().await;
    // Dropping the default's provider without naming a new default would leave
    // the stored default outside the new set, so it is refused rather than
    // silently cleared.
    let (status, body) = patch_key(
        &fixture,
        &fixture.owner,
        json!({"provider_ids": [fixture.provider_ids[1], fixture.provider_ids[2]]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");

    // Nothing was written, so the credential still has its original set.
    let after = read_key(&fixture, &fixture.owner.0).await;
    assert_eq!(provider_ids_of(&after), fixture.provider_ids);
    assert_eq!(after["default_provider_id"], fixture.provider_ids[0]);
}

#[tokio::test]
async fn a_default_outside_the_named_set_is_refused() {
    let fixture = edit_fixture().await;
    let (status, body) = patch_key(
        &fixture,
        &fixture.owner,
        json!({
            "provider_ids": [fixture.provider_ids[0], fixture.provider_ids[1]],
            "default_provider_id": fixture.provider_ids[2]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn an_edit_can_clear_the_default_provider() {
    let fixture = edit_fixture().await;
    let (status, edited) = patch_key(
        &fixture,
        &fixture.owner,
        json!({"default_provider_id": null}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "clear default: {edited}");
    assert_eq!(edited["default_provider_id"], Value::Null);
    assert_eq!(provider_ids_of(&edited), fixture.provider_ids);
}

/// Every refusal below lands before persistence, so the credential afterwards is
/// byte-for-byte the credential that was there before the attempt.
#[tokio::test]
async fn a_refused_edit_leaves_no_partial_write_behind() {
    let fixture = edit_fixture().await;
    let mut oversized = fixture.provider_ids.clone();
    for number in 10..40 {
        oversized.push(number);
    }
    let duplicate = vec![
        fixture.provider_ids[0],
        fixture.provider_ids[1],
        fixture.provider_ids[0],
    ];

    let cases: Vec<(&str, Value, StatusCode, &str)> = vec![
        (
            "an empty provider set",
            json!({"provider_ids": []}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "an oversized provider set",
            json!({"provider_ids": oversized}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "a repeated provider",
            json!({"provider_ids": duplicate, "default_provider_id": fixture.provider_ids[0]}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "an unknown provider",
            json!({"provider_ids": [fixture.provider_ids[0], i64::MAX]}),
            StatusCode::NOT_FOUND,
            "provider_not_found",
        ),
        (
            "an empty name",
            json!({"name": "   "}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "an oversized name",
            json!({"name": "n".repeat(129)}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "a name carrying control characters",
            json!({"name": "bad\u{7}name"}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "an expiry in the past",
            json!({"expires_at": (Utc::now() - chrono::Duration::hours(1)).to_rfc3339()}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "an unknown status",
            json!({"status": "paused"}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "a zero concurrency bound",
            json!({"admission": {
                "max_concurrent_requests": 0,
                "max_requests_per_second": null,
                "max_websockets": null
            }}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "a zero rate bound",
            json!({"admission": {
                "max_concurrent_requests": null,
                "max_requests_per_second": 0,
                "max_websockets": null
            }}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "a zero websocket bound",
            json!({"admission": {
                "max_concurrent_requests": null,
                "max_requests_per_second": null,
                "max_websockets": 0
            }}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "an empty change set",
            json!({}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
    ];

    for (label, body, expected_status, expected_code) in cases {
        let before = read_key(&fixture, &fixture.owner.0).await;
        let (status, response) = patch_key(&fixture, &fixture.owner, body).await;
        assert_eq!(status, expected_status, "{label}");
        assert_eq!(response["error"]["code"], expected_code, "{label}");
        // No half-written field survives a refusal.
        assert_eq!(
            read_key(&fixture, &fixture.owner.0).await,
            before,
            "{label}"
        );
    }
}

#[tokio::test]
async fn a_negative_or_unparsable_bound_is_refused() {
    let fixture = edit_fixture().await;
    // A bound is a count, so a negative or non-numeric one never reaches a
    // stored credential, whether the parser or the value type refuses it.
    for body in [
        json!({"admission": {
            "max_concurrent_requests": -1,
            "max_requests_per_second": null,
            "max_websockets": null
        }}),
        json!({"admission": {
            "max_concurrent_requests": null,
            "max_requests_per_second": "many",
            "max_websockets": null
        }}),
    ] {
        let (status, response) = patch_key(&fixture, &fixture.owner, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"]["code"], "invalid_request");
    }
    let after = read_key(&fixture, &fixture.owner.0).await;
    assert_eq!(after["max_concurrent_requests"], 10);
    assert_eq!(after["max_requests_per_second"], 20);
    assert_eq!(after["max_websockets"], 30);
}

#[tokio::test]
async fn an_edit_requires_a_csrf_token_and_an_identifiable_path() {
    let fixture = edit_fixture().await;
    let before = read_key(&fixture, &fixture.owner.0).await;

    // A write without the CSRF token never reaches the service.
    let (status, _, _) = send(
        &fixture.api,
        request(
            Method::PATCH,
            &format!("/admin/api/api-keys/{}", fixture.key_id),
            json!({"name": "no-csrf"}),
            Some(&fixture.owner.0),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(read_key(&fixture, &fixture.owner.0).await, before);

    // An unknown field is refused rather than silently ignored, so a caller
    // never believes an edit applied something the contract does not carry.
    let (status, response) = patch_key(
        &fixture,
        &fixture.owner,
        json!({"max_concurrent_requests": 3}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["error"]["code"], "invalid_request");
    assert_eq!(read_key(&fixture, &fixture.owner.0).await, before);
}
