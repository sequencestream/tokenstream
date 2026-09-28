use hyper::header::{AUTHORIZATION, HeaderValue};
use hyper::{HeaderMap, Method};
use tokenstream::auth::{GatewayAuthError, GatewayAuthenticator};
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier};
use tokenstream::domain::{
    ProtocolType, ProviderAdminView, ProviderStatus, RequestId, SecretString,
};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::providers::{CreateProviderRequest, ProviderService, UpdateProviderRequest};
use tokenstream::proxy::error::GatewayError;
use tokenstream::routing::{RouteError, resolve_route};
use tokenstream::telemetry::{Metrics, ProxyFailureCategory};

const MASTER_KEY: [u8; 32] = [0x71; 32];
const UPSTREAM_SECRET: &str = "sk-upstream-must-not-leak";
const HOSTILE_INPUT: &str = "query-secret=never-log&payload=private-header-token";

fn bearer(credential: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {credential}"))
            .expect("generated credential is a valid header"),
    );
    headers
}

fn api_key(credential: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-api-key",
        HeaderValue::from_str(credential).expect("generated credential is a valid header"),
    );
    headers
}

#[tokio::test]
async fn security_gate_keeps_secrets_out_and_closes_new_access_after_policy_changes() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database_url = format!(
        "sqlite://{}",
        directory.path().join("security.db").display()
    );
    let database = SqliteDatabase::connect(&database_url, 2)
        .await
        .expect("connect SQLite");
    database.migrate().await.expect("migrate SQLite");

    let service = ProviderService::new(
        database.clone(),
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
        false,
    );
    let authenticator = GatewayAuthenticator::new(
        database,
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
    );

    let created = service
        .create(CreateProviderRequest::new(
            "security-openai".to_owned(),
            ProtocolType::OpenAi,
            "https://api.example.com/base".to_owned(),
            SecretString::new(UPSTREAM_SECRET),
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let provider_id = created.provider().id();
    let original_credential = created.gateway_credential().render();

    let admin_json = serde_json::to_string(&ProviderAdminView::from(created.provider()))
        .expect("serialize redacted administration view");
    for forbidden in [UPSTREAM_SECRET, "ciphertext", "gateway_api_key_hash"] {
        assert!(
            !admin_json.contains(forbidden),
            "administration response leaked {forbidden}"
        );
    }

    let request_id = RequestId::new("security-regression").expect("request ID");
    let local_error = String::from_utf8(
        GatewayError::UpstreamConnectFailed
            .render(&request_id)
            .to_vec(),
    )
    .expect("UTF-8 error response");
    let metrics = Metrics::default();
    metrics.record_failure(ProxyFailureCategory::UpstreamConnectFailed);
    let rendered_metrics = metrics.render();
    for output in [&local_error, &rendered_metrics] {
        assert!(!output.contains(UPSTREAM_SECRET));
        assert!(!output.contains(HOSTILE_INPUT));
    }

    assert_eq!(
        authenticator
            .authenticate(&api_key(&original_credential))
            .await
            .expect_err("an OpenAI credential in an Anthropic header is rejected"),
        GatewayAuthError::ConflictingCredential
    );
    assert_eq!(
        resolve_route(
            ProtocolType::OpenAi,
            &Method::POST,
            "/v1/messages",
            &HeaderMap::new(),
        ),
        Err(RouteError::UnsupportedRoute)
    );

    service
        .update(
            provider_id,
            UpdateProviderRequest::new().with_status(ProviderStatus::Disabled),
        )
        .await
        .expect("disable provider");
    assert_eq!(
        authenticator
            .authenticate(&bearer(&original_credential))
            .await
            .expect_err("disabled provider is rejected"),
        GatewayAuthError::ProviderDisabled
    );

    service
        .update(
            provider_id,
            UpdateProviderRequest::new().with_status(ProviderStatus::Enabled),
        )
        .await
        .expect("re-enable provider");
    let rotated = service
        .rotate_gateway_credential(provider_id)
        .await
        .expect("rotate credential");
    assert_eq!(
        authenticator
            .authenticate(&bearer(&original_credential))
            .await
            .expect_err("retired credential is rejected"),
        GatewayAuthError::UnknownCredential
    );
    authenticator
        .authenticate(&bearer(&rotated.gateway_credential().render()))
        .await
        .expect("new credential authenticates");
}
