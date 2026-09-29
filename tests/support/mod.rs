//! Shared requirement for layers that need an external dependency.
//!
//! A layer that needs an external dependency must fail when the dependency is
//! missing. A silently skipped layer is indistinguishable from a passing one
//! in a test report, so absence is reported as a failure that names the
//! setting that supplies the dependency.

// Each test binary compiles this module separately and uses only part of it, so
// an unused helper here is expected rather than dead.
#![allow(dead_code)]

use std::env;

/// Returns the PostgreSQL connection string that every dual-backend layer
/// requires, failing rather than skipping when it is absent.
pub fn require_postgres_url(layer: &str) -> String {
    match env::var("TOKENSTREAM_TEST_POSTGRES_URL") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "{layer} requires a PostgreSQL server: set TOKENSTREAM_TEST_POSTGRES_URL, or run \
             scripts/release-gate.sh, which provisions one when it is not supplied"
        ),
    }
}

use tokenstream::credentials::{
    CreateAccountRequest, CreateApiKeyRequest, CredentialService, IssuedApiKey,
};
use tokenstream::crypto::Argon2GatewaySecretVerifier;
use tokenstream::domain::{
    AccountId, AccountRole, AccountStatus, ApiKeyStatus, ProviderId, SecretString,
};
use tokenstream::persistence::{AccountRepository, ApiKeyRepository};

/// Creates the bootstrap account, which the repository adopts legacy keys into.
pub async fn bootstrap_account<R>(
    service: &CredentialService<R, Argon2GatewaySecretVerifier>,
) -> Account
where
    R: AccountRepository + ApiKeyRepository + tokenstream::persistence::ProviderRepository,
{
    service
        .ensure_bootstrap("admin".to_owned(), SecretString::new("admin-password"))
        .await
        .expect("create the bootstrap account")
        .expect("the bootstrap account did not exist yet")
}

/// Creates a regular account and returns it with its one-time password.
pub async fn create_user_account<R>(
    service: &CredentialService<R, Argon2GatewaySecretVerifier>,
    name: &str,
) -> (Account, String)
where
    R: AccountRepository + ApiKeyRepository + tokenstream::persistence::ProviderRepository,
{
    let created = service
        .create_account(CreateAccountRequest::new(
            name.to_owned(),
            None,
            AccountRole::User,
            AccountStatus::Enabled,
        ))
        .await
        .expect("create the account");
    let password = created
        .generated_password()
        .expect("a request without a password gets a generated one")
        .expose()
        .to_owned();
    (created.account().clone(), password)
}

/// Issues a credential bound to `provider_ids` and returns it with its plaintext.
pub async fn issue_api_key<R>(
    service: &CredentialService<R, Argon2GatewaySecretVerifier>,
    account_id: AccountId,
    provider_ids: Vec<ProviderId>,
) -> IssuedApiKey
where
    R: AccountRepository + ApiKeyRepository + tokenstream::persistence::ProviderRepository,
{
    service
        .create_api_key(CreateApiKeyRequest::new(
            account_id,
            "test-credential".to_owned(),
            provider_ids,
            None,
            None,
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect("issue the credential")
}

/// Renders an issued credential the way a client would present it.
pub fn render(issued: &IssuedApiKey) -> String {
    issued.credential().render()
}

/// A provider identifier a test can bind to without creating the provider.
pub fn provider_id(value: i64) -> ProviderId {
    ProviderId::try_from(value).expect("positive provider ID")
}

/// A timestamp a test can use as a credential expiration.
pub fn later() -> chrono::DateTime<Utc> {
    Utc::now() + chrono::Duration::hours(1)
}

use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicU64, Ordering};

use tokenstream::domain::{
    Account, ApiKeyId, GatewayKeyId, PasswordHash, ProtocolType, ProviderStatus, SecretCiphertext,
};
use tokenstream::persistence::{NewAccount, NewApiKey, NewProvider};
use url::Url;

/// A value unique to one process and call, so parallel tests never collide on a
/// name or key uniqueness constraint.
pub fn unique_value(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    format!(
        "{prefix}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// A random, non-secret key identifier for a repository test.
pub fn key_id(prefix: &str) -> GatewayKeyId {
    GatewayKeyId::new(unique_value(prefix)).expect("non-empty key identifier")
}

/// A provider record with fixed values, for a repository test.
pub fn new_provider(name: &str, status: ProviderStatus, created_at: DateTime<Utc>) -> NewProvider {
    NewProvider::new(
        name.to_owned(),
        ProtocolType::OpenAi,
        Url::parse("https://example.com").expect("valid endpoint"),
        SecretCiphertext::new("ciphertext"),
        status,
        created_at,
    )
}

/// Creates the bootstrap account a request log then pins.
///
/// A repository that already has one returns it, so a test that runs twice
/// against the same database does not collide on the single-bootstrap index.
pub async fn ensure_bootstrap<R>(repository: &R) -> Account
where
    R: AccountRepository,
{
    if let Ok(Some(existing)) = repository.find_bootstrap().await {
        return existing;
    }
    repository
        .create(NewAccount::new(
            format!("bootstrap-{}", unique_value("account")),
            PasswordHash::new("hash"),
            AccountRole::Admin,
            AccountStatus::Enabled,
            true,
            Utc::now(),
        ))
        .await
        .expect("create the bootstrap account")
}

/// A real credential owned by `account` and bound to `provider`.
///
/// A stored request log names the credential that presented it, so a repository
/// test that writes a row needs a credential that exists. The stored hash is
/// deliberately not a real Argon2 hash: the repository never verifies it, and
/// the plaintext is never returned.
pub async fn stored_api_key<R>(repository: &R, account: &Account, provider: ProviderId) -> ApiKeyId
where
    R: AccountRepository + ApiKeyRepository,
{
    ApiKeyRepository::create(
        repository,
        NewApiKey::new(
            account.id(),
            unique_value("test-credential"),
            key_id("test-key"),
            PasswordHash::new("hash"),
            ApiKeyStatus::Enabled,
            Some(provider),
            None,
            vec![provider],
            Utc::now(),
        ),
    )
    .await
    .expect("create the credential")
    .api_key()
    .id()
}
