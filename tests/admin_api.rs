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

#[tokio::test]
async fn model_alias_api_enforces_ownership_validation_and_cursor_contracts() {
    let (api, _, _directory) = api(Duration::from_secs(60)).await;
    let (admin_cookie, admin_csrf) = sign_in(&api).await;
    let (first_user_id, first_password) =
        create_user(&api, &admin_cookie, &admin_csrf, "alias-owner").await;
    let (second_user_id, second_password) =
        create_user(&api, &admin_cookie, &admin_csrf, "alias-other").await;

    let (status, _, provider) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/providers",
            json!({
                "name": "alias-provider",
                "protocol_type": "openai",
                "endpoint": "https://api.example.com",
                "upstream_api_key": "upstream-secret",
                "status": "enabled"
            }),
            Some(&admin_cookie),
            Some(&admin_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let provider_id = provider["id"].as_i64().expect("provider ID");

    let (first_cookie, first_csrf) = sign_in_as(&api, "alias-owner", &first_password).await;
    let (second_cookie, second_csrf) = sign_in_as(&api, "alias-other", &second_password).await;

    let create_body = json!({
        "account_id": first_user_id,
        "name": " coding ",
        "targets": [{"provider_id": provider_id, "upstream_model": " model-a "}]
    });
    let (status, _, _) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/model-aliases",
            create_body.clone(),
            Some(&first_cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "writes require CSRF");

    let (status, headers, created) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/model-aliases",
            create_body,
            Some(&first_cookie),
            Some(&first_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert_eq!(created["account_id"], first_user_id);
    assert_eq!(created["name"], "coding");
    assert_eq!(created["targets"][0]["upstream_model"], "model-a");
    let alias_id = created["id"].as_i64().expect("alias ID");

    let (status, _, body) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/model-aliases",
            json!({
                "account_id": second_user_id,
                "name": "forbidden",
                "targets": [{"provider_id": provider_id, "upstream_model": "model-b"}]
            }),
            Some(&first_cookie),
            Some(&first_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");

    let (status, _, body) = send(
        &api,
        request(
            Method::GET,
            "/admin/api/model-aliases?limit=1",
            Value::Null,
            Some(&first_cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().expect("items").len(), 1);
    assert_eq!(body["items"][0]["id"], alias_id);

    for path in [
        format!("/admin/api/model-aliases/{alias_id}"),
        format!("/admin/api/model-aliases?account_id={first_user_id}"),
    ] {
        let (status, _, body) = send(
            &api,
            request(Method::GET, &path, Value::Null, Some(&second_cookie), None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(body["error"]["code"], "forbidden");
    }

    let (status, _, updated) = send(
        &api,
        request(
            Method::PATCH,
            &format!("/admin/api/model-aliases/{alias_id}"),
            json!({
                "name": "coding-next",
                "targets": [{"provider_id": provider_id, "upstream_model": "model-next"}]
            }),
            Some(&first_cookie),
            Some(&first_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["name"], "coding-next");
    assert_eq!(updated["targets"][0]["upstream_model"], "model-next");

    let (status, _, body) = send(
        &api,
        request(
            Method::PATCH,
            &format!("/admin/api/model-aliases/{alias_id}"),
            json!({}),
            Some(&first_cookie),
            Some(&first_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");

    let (status, _, body) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/model-aliases",
            json!({
                "account_id": second_user_id,
                "name": "coding-next",
                "targets": [{"provider_id": provider_id, "upstream_model": "other-model"}]
            }),
            Some(&second_cookie),
            Some(&second_csrf),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "same name in another account: {body}"
    );

    let (status, _, body) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/model-aliases",
            json!({
                "account_id": first_user_id,
                "name": "bad-targets",
                "targets": [
                    {"provider_id": provider_id, "upstream_model": "one"},
                    {"provider_id": provider_id, "upstream_model": "two"}
                ]
            }),
            Some(&first_cookie),
            Some(&first_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");

    let (status, _, _) = send(
        &api,
        request(
            Method::DELETE,
            &format!("/admin/api/model-aliases/{alias_id}"),
            Value::Null,
            Some(&first_cookie),
            Some(&first_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, body) = send(
        &api,
        request(
            Method::GET,
            &format!("/admin/api/model-aliases/{alias_id}"),
            Value::Null,
            Some(&admin_cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "model_alias_not_found");
}

#[tokio::test]
async fn a_model_alias_reference_blocks_deletion_and_names_itself_in_the_conflict() {
    let (api, _, _directory) = api(Duration::from_secs(60)).await;
    let (admin_cookie, admin_csrf) = sign_in(&api).await;
    let (owner_id, owner_password) =
        create_user(&api, &admin_cookie, &admin_csrf, "alias-ref-owner").await;

    let (status, _, provider) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/providers",
            json!({
                "name": "alias-ref-provider",
                "protocol_type": "openai",
                "endpoint": "https://api.example.com",
                "upstream_api_key": "upstream-secret",
                "status": "enabled"
            }),
            Some(&admin_cookie),
            Some(&admin_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{provider}");
    let provider_id = provider["id"].as_i64().expect("provider ID");

    let (owner_cookie, owner_csrf) = sign_in_as(&api, "alias-ref-owner", &owner_password).await;
    let (status, _, created) = send(
        &api,
        request(
            Method::POST,
            "/admin/api/model-aliases",
            json!({
                "account_id": owner_id,
                "name": "referencing-alias",
                "targets": [{"provider_id": provider_id, "upstream_model": "model-a"}]
            }),
            Some(&owner_cookie),
            Some(&owner_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let alias_id = created["id"].as_i64().expect("alias ID");

    // An alias is a real reference, so it must block a provider deletion just
    // as a request log does, and the conflict must say so rather than sending an
    // operator to delete logs that may not exist.
    let (status, headers, conflict) = send(
        &api,
        request(
            Method::DELETE,
            &format!("/admin/api/providers/{provider_id}"),
            Value::Null,
            Some(&admin_cookie),
            Some(&admin_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("cache policy"),
        "no-store"
    );
    assert_eq!(conflict["error"]["code"], "provider_in_use");
    let message = conflict["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("model alias"),
        "the conflict must name what references the provider: {message}"
    );

    // The same holds for the owning account, which an alias also references.
    let (status, _, conflict) = send(
        &api,
        request(
            Method::DELETE,
            &format!("/admin/api/accounts/{owner_id}"),
            Value::Null,
            Some(&admin_cookie),
            Some(&admin_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["error"]["code"], "in_use");
    let message = conflict["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("model alias"),
        "the conflict must name what references the account: {message}"
    );

    // Removing the alias releases both references.
    let (status, _, _) = send(
        &api,
        request(
            Method::DELETE,
            &format!("/admin/api/model-aliases/{alias_id}"),
            Value::Null,
            Some(&owner_cookie),
            Some(&owner_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = send(
        &api,
        request(
            Method::DELETE,
            &format!("/admin/api/providers/{provider_id}"),
            Value::Null,
            Some(&admin_cookie),
            Some(&admin_csrf),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}
