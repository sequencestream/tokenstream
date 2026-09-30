use std::path::Path;

use chrono::Utc;
use hyper::HeaderMap;
use hyper::header::{AUTHORIZATION, HeaderValue};
use tokenstream::auth::{GatewayAuthError, GatewayAuthenticator};
use tokenstream::credentials::CredentialService;
use tokenstream::credentials::{CreateApiKeyRequest, UpdateAccountRequest, UpdateApiKeyRequest};
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier};
use tokenstream::domain::{
    AccountStatus, ApiKeyStatus, GATEWAY_SECRET_LENGTH, GatewayCredential, GatewayKeyId,
    ProtocolType, ProviderHealthState, ProviderStatus, SecretString,
};
use tokenstream::persistence::ProviderRepository;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::providers::{CreateProviderRequest, ProviderService, UpdateProviderRequest};

const MASTER_KEY: [u8; 32] = [0x5c; 32];
const UPSTREAM_KEY: &str = "sk-upstream-secret-value";
const ROTATED_UPSTREAM_KEY: &str = "sk-rotated-secret-value";

mod support;

use support::{bootstrap_account, issue_api_key, render};

type Service = ProviderService<SqliteDatabase, AesGcmCipher>;
type Authenticator =
    GatewayAuthenticator<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>;

async fn sqlite_database(path: &Path) -> SqliteDatabase {
    let url = format!("sqlite://{}", path.display());
    let database = SqliteDatabase::connect(&url, 2)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    database
}

fn service(database: SqliteDatabase) -> Service {
    ProviderService::new(database, AesGcmCipher::new(&MASTER_KEY), false)
}

fn authenticator(database: SqliteDatabase) -> Authenticator {
    GatewayAuthenticator::new(
        database,
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
    )
}

fn request(
    name: &str,
    protocol_type: ProtocolType,
    endpoint: &str,
    status: ProviderStatus,
) -> CreateProviderRequest {
    CreateProviderRequest::new(
        name.to_owned(),
        protocol_type,
        endpoint.to_owned(),
        SecretString::new(UPSTREAM_KEY),
        status,
    )
}

/// Builds the credential service a test issues credentials through.
fn credentials(
    database: SqliteDatabase,
) -> CredentialService<SqliteDatabase, Argon2GatewaySecretVerifier> {
    CredentialService::new(database, Argon2GatewaySecretVerifier::new())
}

/// Selects one of a credential's providers through the dedicated header.
fn with_selection(credential: &str, provider_id: i64) -> HeaderMap {
    let mut headers = with_bearer(credential);
    headers.insert(
        "x-tokenstream-provider",
        HeaderValue::from_str(&provider_id.to_string()).expect("valid selection header"),
    );
    headers
}

fn with_bearer(credential: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {credential}")).expect("valid authorization header"),
    );
    headers
}

fn with_api_key(credential: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-api-key",
        HeaderValue::from_str(credential).expect("valid api key header"),
    );
    headers
}

#[tokio::test]
async fn authenticates_each_provider_native_credential_into_a_snapshot() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("native.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let openai = service
        .create(request(
            "openai",
            ProtocolType::OpenAi,
            "https://api.openai.example/v1",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create openai provider");
    let anthropic = service
        .create(request(
            "anthropic",
            ProtocolType::Anthropic,
            "https://api.anthropic.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create anthropic provider");

    let openai_key = issue_api_key(&accounts, account.id(), vec![openai.id()]).await;
    let anthropic_key = issue_api_key(&accounts, account.id(), vec![anthropic.id()]).await;

    let snapshot = authenticator
        .authenticate(&with_bearer(&render(&openai_key)))
        .await
        .expect("authenticate openai credential");
    assert_eq!(snapshot.id(), openai.id());
    assert_eq!(snapshot.account_id(), account.id());
    assert_eq!(snapshot.api_key_id(), openai_key.api_key().api_key().id());
    assert_eq!(snapshot.protocol_type(), ProtocolType::OpenAi);
    assert_eq!(
        snapshot.endpoint().as_str(),
        "https://api.openai.example/v1"
    );
    assert_eq!(snapshot.upstream_api_key().expose(), UPSTREAM_KEY);

    let snapshot = authenticator
        .authenticate(&with_api_key(&render(&anthropic_key)))
        .await
        .expect("authenticate anthropic credential");
    assert_eq!(snapshot.id(), anthropic.id());
    assert_eq!(snapshot.protocol_type(), ProtocolType::Anthropic);
    assert_eq!(snapshot.upstream_api_key().expose(), UPSTREAM_KEY);
}

#[tokio::test]
async fn one_credential_selects_exactly_one_bound_provider() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("selection.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let first = service
        .create(request(
            "first",
            ProtocolType::OpenAi,
            "https://api.first.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create first provider");
    let second = service
        .create(request(
            "second",
            ProtocolType::OpenAi,
            "https://api.second.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create second provider");

    let issued = accounts
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "both".to_owned(),
            vec![first.id(), second.id()],
            Some(first.id()),
            None,
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect("issue a credential bound to both providers");
    let credential = render(&issued);

    // With no selection the default binding decides.
    let snapshot = authenticator
        .authenticate(&with_bearer(&credential))
        .await
        .expect("authenticate with the default binding");
    assert_eq!(snapshot.id(), first.id());

    // The dedicated header picks the other member of the allowed set.
    let snapshot = authenticator
        .authenticate(&with_selection(&credential, second.id().get()))
        .await
        .expect("authenticate with an explicit selection");
    assert_eq!(snapshot.id(), second.id());

    // A provider outside the allowed set is refused rather than silently
    // falling back to the default, so a misconfigured client fails visibly.
    let unrelated = service
        .create(request(
            "unrelated",
            ProtocolType::OpenAi,
            "https://api.unrelated.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create an unrelated provider");
    assert_eq!(
        authenticator
            .authenticate(&with_selection(&credential, unrelated.id().get()))
            .await
            .expect_err("a provider outside the allowed set is refused"),
        GatewayAuthError::UnknownCredential
    );
}

#[tokio::test]
async fn a_credential_without_a_default_or_selection_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("noprovider.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let provider = service
        .create(request(
            "primary",
            ProtocolType::OpenAi,
            "https://api.openai.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    // A stored credential always resolves to its single binding, so the
    // fail-closed path needs a credential whose set is genuinely empty.
    let issued = accounts
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "empty".to_owned(),
            vec![],
            None,
            None,
            ApiKeyStatus::Enabled,
        ))
        .await;
    assert_eq!(
        issued
            .expect_err("an empty allowed set is refused")
            .to_string(),
        "provider selection is invalid"
    );

    // With a selection naming the only bound provider the request succeeds.
    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let snapshot = authenticator
        .authenticate(&with_selection(&render(&issued), provider.id().get()))
        .await
        .expect("authenticate with the only bound provider");
    assert_eq!(snapshot.id(), provider.id());
}

#[tokio::test]
async fn snapshots_are_request_local_and_new_requests_observe_edits() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("local.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let provider = service
        .create(request(
            "primary",
            ProtocolType::OpenAi,
            "https://api.openai.example/v1",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let credential = render(&issued);

    let snapshot = authenticator
        .authenticate(&with_bearer(&credential))
        .await
        .expect("authenticate credential");

    service
        .update(
            provider.id(),
            UpdateProviderRequest::new()
                .with_endpoint("https://api.updated.example/base")
                .with_upstream_api_key(SecretString::new(ROTATED_UPSTREAM_KEY)),
        )
        .await
        .expect("update provider");

    assert_eq!(
        snapshot.endpoint().as_str(),
        "https://api.openai.example/v1"
    );
    assert_eq!(snapshot.upstream_api_key().expose(), UPSTREAM_KEY);

    let refreshed = authenticator
        .authenticate(&with_bearer(&credential))
        .await
        .expect("authenticate updated provider");
    assert_eq!(
        refreshed.endpoint().as_str(),
        "https://api.updated.example/base"
    );
    assert_eq!(refreshed.upstream_api_key().expose(), ROTATED_UPSTREAM_KEY);
}

#[tokio::test]
async fn disabling_an_account_stops_its_traffic_without_touching_its_credentials() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("account.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());

    let provider = service
        .create(request(
            "primary",
            ProtocolType::OpenAi,
            "https://api.openai.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");

    let (user, _) = support::create_user_account(&accounts, "alice").await;
    let issued = issue_api_key(&accounts, user.id(), vec![provider.id()]).await;
    let credential = render(&issued);
    authenticator
        .authenticate(&with_bearer(&credential))
        .await
        .expect("authenticate before the account is disabled");

    accounts
        .update_account(
            user.id(),
            UpdateAccountRequest::new().with_status(AccountStatus::Disabled),
        )
        .await
        .expect("disable the account");

    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&credential))
            .await
            .expect_err("a disabled account stops its traffic"),
        GatewayAuthError::AccountDisabled
    );
}

#[tokio::test]
async fn expired_and_disabled_credentials_fail_before_upstream_contact() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("lifecycle.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let provider = service
        .create(request(
            "primary",
            ProtocolType::OpenAi,
            "https://api.openai.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");

    // An expiration in the past is refused at issuance, because a credential
    // that can never authenticate is a configuration mistake, not a lifecycle.
    let already_expired = accounts
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "expired".to_owned(),
            vec![provider.id()],
            None,
            Some(Utc::now() - chrono::Duration::minutes(1)),
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect_err("an expiration in the past is refused");
    assert_eq!(already_expired.to_string(), "expiration is invalid");

    // A credential whose expiration passes while it is stored fails new work.
    let soon = accounts
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "briefly-valid".to_owned(),
            vec![provider.id()],
            None,
            Some(Utc::now() + chrono::Duration::milliseconds(1)),
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect("issue a credential that expires immediately");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&render(&soon)))
            .await
            .expect_err("an expired credential is rejected"),
        GatewayAuthError::KeyExpired
    );

    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let credential = render(&issued);
    accounts
        .update_api_key(
            issued.api_key().api_key().id(),
            issued.api_key(),
            UpdateApiKeyRequest::new().with_status(ApiKeyStatus::Disabled),
        )
        .await
        .expect("disable the credential");
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&credential))
            .await
            .expect_err("a disabled credential is rejected"),
        GatewayAuthError::InvalidCredential
    );
}

#[tokio::test]
async fn rejects_missing_duplicate_and_conflicting_credentials() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("shape.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let provider = service
        .create(request(
            "primary",
            ProtocolType::OpenAi,
            "https://api.openai.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let credential = render(&issued);

    assert_eq!(
        authenticator
            .authenticate(&HeaderMap::new())
            .await
            .expect_err("missing credential is rejected"),
        GatewayAuthError::MissingCredential
    );

    let mut duplicate_authorization = with_bearer(&credential);
    duplicate_authorization.append(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {credential}")).expect("valid header"),
    );
    assert_eq!(
        authenticator
            .authenticate(&duplicate_authorization)
            .await
            .expect_err("duplicate authorization is rejected"),
        GatewayAuthError::DuplicateCredential
    );

    let mut duplicate_api_key = with_api_key(&credential);
    duplicate_api_key.append(
        "x-api-key",
        HeaderValue::from_str(&credential).expect("valid header"),
    );
    assert_eq!(
        authenticator
            .authenticate(&duplicate_api_key)
            .await
            .expect_err("duplicate api key is rejected"),
        GatewayAuthError::DuplicateCredential
    );

    let mut conflicting = with_bearer(&credential);
    conflicting.insert(
        "x-api-key",
        HeaderValue::from_str(&credential).expect("valid header"),
    );
    assert_eq!(
        authenticator
            .authenticate(&conflicting)
            .await
            .expect_err("conflicting credential headers are rejected"),
        GatewayAuthError::ConflictingCredential
    );
}

#[tokio::test]
async fn rejects_unknown_and_wrong_secrets() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("unknown.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let provider = service
        .create(request(
            "primary",
            ProtocolType::OpenAi,
            "https://api.openai.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let credential = issued.credential();

    let unknown = GatewayCredential::new(
        GatewayKeyId::new("unknown-key-id").expect("non-empty key id"),
        SecretString::new("A".repeat(GATEWAY_SECRET_LENGTH)),
    )
    .render();
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&unknown))
            .await
            .expect_err("unknown credential is rejected"),
        GatewayAuthError::UnknownCredential
    );

    let mut wrong_secret = credential.secret().expose().to_owned();
    let replacement = if wrong_secret.ends_with('A') {
        'B'
    } else {
        'A'
    };
    wrong_secret.pop();
    wrong_secret.push(replacement);
    let wrong =
        GatewayCredential::new(credential.key_id().clone(), SecretString::new(wrong_secret))
            .render();
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&wrong))
            .await
            .expect_err("wrong secret is rejected"),
        GatewayAuthError::InvalidCredential
    );
}

#[tokio::test]
async fn the_native_credential_header_follows_the_resolved_provider() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("protocol.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let openai = service
        .create(request(
            "openai",
            ProtocolType::OpenAi,
            "https://api.openai.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create openai provider");
    let anthropic = service
        .create(request(
            "anthropic",
            ProtocolType::Anthropic,
            "https://api.anthropic.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create anthropic provider");

    let openai_key = issue_api_key(&accounts, account.id(), vec![openai.id()]).await;
    assert_eq!(
        authenticator
            .authenticate(&with_api_key(&render(&openai_key)))
            .await
            .expect_err("an openai provider rejects the anthropic header"),
        GatewayAuthError::ConflictingCredential
    );

    let anthropic_key = issue_api_key(&accounts, account.id(), vec![anthropic.id()]).await;
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&render(&anthropic_key)))
            .await
            .expect_err("an anthropic provider rejects the openai header"),
        GatewayAuthError::ConflictingCredential
    );
}

#[tokio::test]
async fn a_disabled_provider_is_still_selectable_and_reported_as_disabled() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("disabled.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let provider = service
        .create(request(
            "disabled",
            ProtocolType::OpenAi,
            "https://api.disabled.example",
            ProviderStatus::Disabled,
        ))
        .await
        .expect("create disabled provider");
    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;

    // The binding is still configuration, so resolution succeeds and the
    // failure is the provider's own disabled status rather than a missing
    // selection.
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&render(&issued)))
            .await
            .expect_err("a disabled provider is reported as disabled"),
        GatewayAuthError::ProviderDisabled
    );
}

#[tokio::test]
async fn maintenance_refuses_new_work_without_changing_an_existing_snapshot() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("maintenance.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;
    let provider = service
        .create(request(
            "maintained",
            ProtocolType::OpenAi,
            "https://api.maintained.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let credential = render(&issued);
    let snapshot = authenticator
        .authenticate(&with_bearer(&credential))
        .await
        .expect("authenticate before maintenance");

    service
        .set_health(provider.id(), ProviderHealthState::Maintenance)
        .await
        .expect("enter maintenance");
    assert_eq!(snapshot.health(), ProviderHealthState::Healthy);
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&credential))
            .await
            .expect_err("maintenance refuses new work"),
        GatewayAuthError::ProviderUnhealthy
    );

    service
        .set_health(provider.id(), ProviderHealthState::Healthy)
        .await
        .expect("leave maintenance");
    authenticator
        .authenticate(&with_bearer(&credential))
        .await
        .expect("new work resumes after maintenance");
}

#[tokio::test]
async fn isolation_refuses_new_work_without_changing_an_existing_snapshot() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("isolated.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;
    let provider = service
        .create(request(
            "isolated",
            ProtocolType::OpenAi,
            "https://api.isolated.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let credential = render(&issued);
    let snapshot = authenticator
        .authenticate(&with_bearer(&credential))
        .await
        .expect("authenticate before isolation");

    database
        .set_health(
            provider.id(),
            ProviderHealthState::Healthy,
            ProviderHealthState::Isolated,
        )
        .await
        .expect("isolate provider");
    assert_eq!(snapshot.health(), ProviderHealthState::Healthy);
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&credential))
            .await
            .expect_err("isolation refuses new work"),
        GatewayAuthError::ProviderUnhealthy
    );

    database
        .set_health(
            provider.id(),
            ProviderHealthState::Isolated,
            ProviderHealthState::Healthy,
        )
        .await
        .expect("recover provider");
    authenticator
        .authenticate(&with_bearer(&credential))
        .await
        .expect("new work resumes after recovery");
}

#[tokio::test]
async fn rotating_a_credential_invalidates_the_previous_secret() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("rotation.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let provider = service
        .create(request(
            "primary",
            ProtocolType::OpenAi,
            "https://api.openai.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let previous = render(&issued);
    authenticator
        .authenticate(&with_bearer(&previous))
        .await
        .expect("authenticate the original credential");

    let rotated = accounts
        .rotate_api_key(issued.api_key().api_key().id())
        .await
        .expect("rotate the credential");

    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&previous))
            .await
            .expect_err("the rotated-away secret is rejected"),
        GatewayAuthError::UnknownCredential
    );

    let snapshot = authenticator
        .authenticate(&with_bearer(&render(&rotated)))
        .await
        .expect("authenticate the rotated credential");
    assert_eq!(snapshot.id(), provider.id());
}

#[tokio::test]
async fn successful_and_failed_authentication_never_render_secrets() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("redaction.db")).await;
    let service = service(database.clone());
    let accounts = credentials(database.clone());
    let authenticator = authenticator(database.clone());
    let account = bootstrap_account(&accounts).await;

    let provider = service
        .create(request(
            "primary",
            ProtocolType::OpenAi,
            "https://api.openai.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let issued = issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let credential = issued.credential();

    let snapshot = authenticator
        .authenticate(&with_bearer(&credential.render()))
        .await
        .expect("authenticate credential");
    let rendered_snapshot = format!("{snapshot:?}");
    assert!(rendered_snapshot.contains("[REDACTED]"));
    assert!(!rendered_snapshot.contains(UPSTREAM_KEY));
    assert!(!rendered_snapshot.contains(credential.secret().expose()));

    let wrong = GatewayCredential::new(
        credential.key_id().clone(),
        SecretString::new("A".repeat(GATEWAY_SECRET_LENGTH)),
    )
    .render();
    let error = authenticator
        .authenticate(&with_bearer(&wrong))
        .await
        .expect_err("wrong secret is rejected");
    assert_eq!(error, GatewayAuthError::InvalidCredential);
    assert!(!error.to_string().contains(credential.secret().expose()));
    assert!(!format!("{error:?}").contains(credential.secret().expose()));
    assert!(!error.to_string().contains(UPSTREAM_KEY));
}

#[tokio::test]
async fn rejects_malformed_credentials_without_echoing_them() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("malformed.db")).await;
    let authenticator = authenticator(database);

    let short_secret = format!("{}.{}", "k".repeat(22), "A".repeat(8));
    let padded_value = format!("{}.{}", "k".repeat(22), "A".repeat(GATEWAY_SECRET_LENGTH));
    let long_value = format!("Bearer {}", "A".repeat(4096));

    let cases: [(&str, Option<&str>); 5] = [
        ("Basic Zm9vYmFy", None),
        ("Bearer", None),
        (long_value.as_str(), None),
        ("", Some("not-a-credential")),
        ("", Some(short_secret.as_str())),
    ];

    for (authorization, api_key) in cases {
        let mut headers = HeaderMap::new();
        if !authorization.is_empty() {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(authorization).expect("valid header"),
            );
        }
        if let Some(value) = api_key {
            headers.insert(
                "x-api-key",
                HeaderValue::from_str(value).expect("valid header"),
            );
        }
        let error = authenticator
            .authenticate(&headers)
            .await
            .expect_err("a malformed credential is rejected");
        assert_eq!(error, GatewayAuthError::MalformedCredential);
        for secret in [short_secret.as_str(), padded_value.as_str()] {
            assert!(!error.to_string().contains(secret));
        }
    }
}
