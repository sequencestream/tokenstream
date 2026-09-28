use std::path::Path;

use hyper::HeaderMap;
use hyper::header::{AUTHORIZATION, HeaderValue};
use tokenstream::auth::{GatewayAuthError, GatewayAuthenticator};
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier};
use tokenstream::domain::{
    GATEWAY_SECRET_LENGTH, GatewayCredential, GatewayKeyId, ProtocolType, ProviderStatus,
    SecretString,
};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::providers::{CreateProviderRequest, ProviderService, UpdateProviderRequest};

const MASTER_KEY: [u8; 32] = [0x5c; 32];
const UPSTREAM_KEY: &str = "sk-upstream-secret-value";
const ROTATED_UPSTREAM_KEY: &str = "sk-rotated-secret-value";

type Service = ProviderService<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier>;
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
    ProviderService::new(
        database,
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
        false,
    )
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
    let authenticator = authenticator(database.clone());

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

    let snapshot = authenticator
        .authenticate(&with_bearer(&openai.gateway_credential().render()))
        .await
        .expect("authenticate openai credential");
    assert_eq!(snapshot.id(), openai.provider().id());
    assert_eq!(snapshot.protocol_type(), ProtocolType::OpenAi);
    assert_eq!(
        snapshot.endpoint().as_str(),
        "https://api.openai.example/v1"
    );
    assert_eq!(snapshot.upstream_api_key().expose(), UPSTREAM_KEY);

    let snapshot = authenticator
        .authenticate(&with_api_key(&anthropic.gateway_credential().render()))
        .await
        .expect("authenticate anthropic credential");
    assert_eq!(snapshot.id(), anthropic.provider().id());
    assert_eq!(snapshot.protocol_type(), ProtocolType::Anthropic);
    assert_eq!(snapshot.upstream_api_key().expose(), UPSTREAM_KEY);
}

#[tokio::test]
async fn snapshots_are_request_local_and_new_requests_observe_edits() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("local.db")).await;
    let service = service(database.clone());
    let authenticator = authenticator(database.clone());

    let provider = service
        .create(request(
            "primary",
            ProtocolType::OpenAi,
            "https://api.openai.example/v1",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider");
    let credential = provider.gateway_credential().render();

    let snapshot = authenticator
        .authenticate(&with_bearer(&credential))
        .await
        .expect("authenticate credential");

    service
        .update(
            provider.provider().id(),
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
async fn rejects_missing_duplicate_and_conflicting_credentials() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("shape.db")).await;
    let service = service(database.clone());
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
    let credential = provider.gateway_credential().render();

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
async fn rejects_malformed_credentials_without_echoing_them() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("malformed.db")).await;
    let authenticator = authenticator(database);

    let short_secret = format!("{}.{}", "k".repeat(22), "A".repeat(8));
    let mut cases = Vec::new();

    let mut basic = HeaderMap::new();
    basic.insert(
        AUTHORIZATION,
        HeaderValue::from_str("Basic Zm9vYmFy").expect("valid header"),
    );
    cases.push((basic, "Zm9vYmFy"));

    let mut schemeless = HeaderMap::new();
    schemeless.insert(
        AUTHORIZATION,
        HeaderValue::from_str("Bearer").expect("valid header"),
    );
    cases.push((schemeless, "Bearer"));

    let long_value = format!("Bearer {}", "A".repeat(4096));
    let mut oversized = HeaderMap::new();
    oversized.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&long_value).expect("valid header"),
    );
    cases.push((oversized, long_value.as_str()));

    let mut plain = HeaderMap::new();
    plain.insert(
        "x-api-key",
        HeaderValue::from_str("not-a-credential").expect("valid header"),
    );
    cases.push((plain, "not-a-credential"));

    let mut short = HeaderMap::new();
    short.insert(
        "x-api-key",
        HeaderValue::from_str(&short_secret).expect("valid header"),
    );
    cases.push((short, short_secret.as_str()));

    let padded_value = format!("{}.{}", "k".repeat(22), "A".repeat(GATEWAY_SECRET_LENGTH));
    let mut padded = HeaderMap::new();
    padded.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer  {padded_value}")).expect("valid header"),
    );
    cases.push((padded, padded_value.as_str()));

    for (headers, rendered) in cases {
        let error = authenticator
            .authenticate(&headers)
            .await
            .expect_err("malformed credential is rejected");
        assert_eq!(error, GatewayAuthError::MalformedCredential);
        assert!(!error.to_string().contains(rendered));
        assert!(!format!("{error:?}").contains(rendered));
    }
}

#[tokio::test]
async fn rejects_unknown_wrong_disabled_and_cross_provider_credentials() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("reject.db")).await;
    let service = service(database.clone());
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
    let credential = provider.gateway_credential();

    let unknown = GatewayCredential::new(
        GatewayKeyId::new("unknown-lookup-id").expect("non-empty key id"),
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

    let disabled = service
        .create(request(
            "disabled",
            ProtocolType::OpenAi,
            "https://api.disabled.example",
            ProviderStatus::Disabled,
        ))
        .await
        .expect("create disabled provider");
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&disabled.gateway_credential().render()))
            .await
            .expect_err("disabled credential is rejected"),
        GatewayAuthError::ProviderDisabled
    );

    assert_eq!(
        authenticator
            .authenticate(&with_api_key(&credential.render()))
            .await
            .expect_err("openai provider rejects the anthropic header"),
        GatewayAuthError::ConflictingCredential
    );

    let anthropic = service
        .create(request(
            "anthropic",
            ProtocolType::Anthropic,
            "https://api.anthropic.example",
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create anthropic provider");
    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&anthropic.gateway_credential().render()))
            .await
            .expect_err("anthropic provider rejects the openai header"),
        GatewayAuthError::ConflictingCredential
    );
}

#[tokio::test]
async fn rotating_the_gateway_key_invalidates_the_previous_credential() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("rotation.db")).await;
    let service = service(database.clone());
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
    let previous = provider.gateway_credential().render();
    authenticator
        .authenticate(&with_bearer(&previous))
        .await
        .expect("authenticate the original credential");

    let rotated = service
        .rotate_gateway_credential(provider.provider().id())
        .await
        .expect("rotate gateway credential");

    assert_eq!(
        authenticator
            .authenticate(&with_bearer(&previous))
            .await
            .expect_err("rotated credential is rejected"),
        GatewayAuthError::UnknownCredential
    );

    let snapshot = authenticator
        .authenticate(&with_bearer(&rotated.gateway_credential().render()))
        .await
        .expect("authenticate the rotated credential");
    assert_eq!(snapshot.id(), provider.provider().id());
}

#[tokio::test]
async fn successful_and_failed_authentication_never_render_secrets() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("redaction.db")).await;
    let service = service(database.clone());
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
    let credential = provider.gateway_credential();

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
