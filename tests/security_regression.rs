use hyper::header::{AUTHORIZATION, HeaderValue};
use hyper::{HeaderMap, Method};
use tokenstream::auth::{GatewayAuthError, GatewayAuthenticator};
use tokenstream::credentials::CredentialService;
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier};
use tokenstream::domain::{
    ProtocolType, ProviderAdminView, ProviderStatus, RequestId, SecretString,
};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::providers::{CreateProviderRequest, ProviderService, UpdateProviderRequest};

mod support;
use support::{bootstrap_account, issue_api_key};
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

    let service = ProviderService::new(database.clone(), AesGcmCipher::new(&MASTER_KEY), false);
    let accounts = CredentialService::new(database.clone(), Argon2GatewaySecretVerifier::new());
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
    let provider_id = created.id();
    let account = bootstrap_account(&accounts).await;
    let issued = issue_api_key(&accounts, account.id(), vec![provider_id]).await;
    let original_credential = issued.credential().render();
    let api_key_id = issued.api_key().api_key().id();

    let admin_json = serde_json::to_string(&ProviderAdminView::from(&created))
        .expect("serialize redacted administration view");
    let key_json = serde_json::to_string(&tokenstream::domain::ApiKeyAdminView::new(
        issued.api_key().api_key(),
        issued.api_key().bindings(),
    ))
    .expect("serialize redacted credential view");
    for forbidden in [UPSTREAM_SECRET, "ciphertext", "secret_hash"] {
        assert!(
            !key_json.contains(forbidden),
            "credential response leaked {forbidden}"
        );
    }
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
    let rotated = accounts
        .rotate_api_key(api_key_id)
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
        .authenticate(&bearer(&rotated.credential().render()))
        .await
        .expect("new credential authenticates");

    // Disabling the owning account closes every credential it holds, which a
    // provider status change could never do on its own. The bootstrap account
    // is protected, so a second account owns this credential.
    let (owner, _) = support::create_user_account(&accounts, "security-user").await;
    let owned = issue_api_key(&accounts, owner.id(), vec![provider_id]).await;
    let owned_credential = owned.credential().render();
    accounts
        .update_account(
            owner.id(),
            tokenstream::credentials::UpdateAccountRequest::new()
                .with_status(tokenstream::domain::AccountStatus::Disabled),
        )
        .await
        .expect("disable the account");
    assert_eq!(
        authenticator
            .authenticate(&bearer(&owned_credential))
            .await
            .expect_err("a credential of a disabled account is rejected"),
        GatewayAuthError::AccountDisabled
    );
}
