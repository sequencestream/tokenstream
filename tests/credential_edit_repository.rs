//! The credential update as one storage write, on both engines.
//!
//! The bindings and the scalar fields must land together or not at all: a
//! credential whose default points outside its stored set, or that holds two of
//! three bounds, is a state the service works hard to prevent and storage must
//! not be able to produce. Each engine runs the same contract.

use std::path::Path;

use chrono::{Duration, Utc};
use tokenstream::domain::{
    AccountId, ApiKeyId, ApiKeyStatus, ApiKeyWithBindings, CredentialAdmission, GatewayKeyId,
    PasswordHash, ProtocolType, ProviderId, ProviderStatus, SecretCiphertext,
};
use tokenstream::persistence::postgres::PostgresDatabase;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{
    AccountRepository, ApiKeyRepository, ApiKeyUpdate, NewApiKey, NewProvider, ProviderRepository,
    RepositoryError,
};
use url::Url;

mod support;
use support::{ensure_bootstrap, key_id, unique_value};

async fn issue_provider<R: ProviderRepository>(
    repository: &R,
    prefix: &str,
    number: usize,
) -> ProviderId {
    ProviderRepository::create(repository, new_provider(prefix, number))
        .await
        .expect("create a provider")
        .id()
}

fn new_provider(prefix: &str, number: usize) -> NewProvider {
    NewProvider::new(
        format!("{prefix}-provider-{number}"),
        ProtocolType::OpenAi,
        Url::parse(&format!("https://provider-{number}.example.com/base")).expect("valid endpoint"),
        SecretCiphertext::new(format!("ciphertext-{number}")),
        ProviderStatus::Enabled,
        Utc::now(),
    )
}

fn bound(value: Option<u32>) -> CredentialAdmission {
    CredentialAdmission::new(value, value, value).expect("positive bounds")
}

fn stored_provider_ids(stored: &ApiKeyWithBindings) -> Vec<ProviderId> {
    stored
        .bindings()
        .iter()
        .map(|binding| binding.provider_id)
        .collect()
}

async fn issue<R>(
    repository: &R,
    account_id: AccountId,
    provider_ids: &[ProviderId],
    prefix: &str,
) -> (ApiKeyWithBindings, GatewayKeyId)
where
    R: ApiKeyRepository,
{
    let stored = ApiKeyRepository::create(
        repository,
        NewApiKey::new(
            account_id,
            format!("{prefix}-credential"),
            key_id(prefix),
            PasswordHash::new("hash"),
            ApiKeyStatus::Enabled,
            provider_ids.first().copied(),
            None,
            provider_ids.to_vec(),
            Utc::now(),
        )
        .with_admission(bound(Some(5))),
    )
    .await
    .expect("issue a credential");
    let issued_key_id = stored.api_key().key_id().clone();
    (stored, issued_key_id)
}

/// One update writes the binding set, the default, and all three bounds in a
/// single transaction, so both engines must read back the same result.
async fn verify_contract<R>(repository: &R, prefix: &str)
where
    R: ApiKeyRepository + ProviderRepository + AccountRepository,
{
    let mut providers = Vec::with_capacity(3);
    for number in 0..3 {
        providers.push(issue_provider(repository, prefix, number).await);
    }
    let account = ensure_bootstrap(repository).await;
    let (stored, issued_key_id) = issue(repository, account.id(), &providers, prefix).await;
    let id = stored.api_key().id();
    assert_eq!(stored_provider_ids(&stored), providers);

    let expires_at = Utc::now() + Duration::hours(6);
    let admission = CredentialAdmission::new(Some(2), Some(3), Some(4)).expect("positive bounds");
    let updated = ApiKeyRepository::update(
        repository,
        id,
        // Remove the first provider and reverse the rest, so the stored order
        // can only match if the rewrite really followed the given order.
        ApiKeyUpdate::new()
            .with_name(format!("{prefix}-edited"))
            .with_status(ApiKeyStatus::Disabled)
            .with_expires_at(Some(expires_at))
            .with_provider_ids(vec![providers[2], providers[1]])
            .with_default_provider_id(Some(providers[2]))
            .with_admission(admission),
    )
    .await
    .expect("apply one update");

    assert_eq!(
        stored_provider_ids(&updated),
        vec![providers[2], providers[1]]
    );
    assert_eq!(updated.api_key().default_provider_id(), Some(providers[2]));
    assert_eq!(updated.api_key().name(), format!("{prefix}-edited"));
    assert_eq!(updated.api_key().status(), ApiKeyStatus::Disabled);
    assert_eq!(updated.api_key().expires_at(), Some(expires_at));
    assert_eq!(
        updated
            .api_key()
            .admission()
            .max_concurrent_requests()
            .get(),
        Some(2)
    );
    assert_eq!(
        updated
            .api_key()
            .admission()
            .max_requests_per_second()
            .get(),
        Some(3)
    );
    assert_eq!(
        updated.api_key().admission().max_websockets().get(),
        Some(4)
    );
    // Editing never reissues, so the identifier the client already holds stands.
    assert_eq!(updated.api_key().key_id(), &issued_key_id);

    // A separate read after the commit agrees with the returned row.
    let reread = ApiKeyRepository::find_by_id(repository, id)
        .await
        .expect("read back after commit")
        .expect("the credential exists");
    assert_eq!(
        stored_provider_ids(&reread),
        vec![providers[2], providers[1]]
    );
    assert_eq!(reread.api_key().default_provider_id(), Some(providers[2]));
    assert_eq!(reread.api_key().admission().max_websockets().get(), Some(4));
    assert_eq!(reread.api_key().key_id(), &issued_key_id);

    assert_eq!(
        ApiKeyRepository::update(repository, id, ApiKeyUpdate::new())
            .await
            .expect_err("an empty change set is refused"),
        RepositoryError::NoFieldsToUpdate
    );
}

/// Clearing the expiry and every bound writes NULLs, not stale values.
async fn verify_clearing<R>(repository: &R, prefix: &str)
where
    R: ApiKeyRepository + ProviderRepository + AccountRepository,
{
    let provider = ProviderRepository::create(repository, new_provider(prefix, 7))
        .await
        .expect("create a provider")
        .id();
    let account = ensure_bootstrap(repository).await;
    let (stored, _) = issue(repository, account.id(), &[provider], prefix).await;
    let id = stored.api_key().id();

    let bounded = ApiKeyRepository::update(
        repository,
        id,
        ApiKeyUpdate::new()
            .with_expires_at(Some(Utc::now() + Duration::hours(1)))
            .with_admission(bound(Some(9))),
    )
    .await
    .expect("set an expiry and bounds");
    assert_eq!(
        bounded
            .api_key()
            .admission()
            .max_concurrent_requests()
            .get(),
        Some(9)
    );

    let cleared = ApiKeyRepository::update(
        repository,
        id,
        ApiKeyUpdate::new()
            .with_expires_at(None)
            .with_admission(CredentialAdmission::default()),
    )
    .await
    .expect("clear the expiry and every bound");
    assert_eq!(cleared.api_key().expires_at(), None);
    assert!(cleared.api_key().admission().is_unbounded());

    // Absent means unbounded, so clearing all three really removes the bounds.
    let reread = ApiKeyRepository::find_by_id(repository, id)
        .await
        .expect("read back after clearing")
        .expect("the credential exists");
    assert!(reread.api_key().admission().is_unbounded());
    assert_eq!(reread.api_key().expires_at(), None);
}

/// Narrowing the set removes the bindings that left it, on both engines.
async fn verify_set_rewrite<R>(repository: &R, prefix: &str)
where
    R: ApiKeyRepository + ProviderRepository + AccountRepository,
{
    let mut providers = Vec::with_capacity(3);
    for number in 10..13 {
        providers.push(issue_provider(repository, prefix, number).await);
    }
    let account = ensure_bootstrap(repository).await;
    let (stored, _) = issue(repository, account.id(), &providers, prefix).await;
    let id = stored.api_key().id();

    ApiKeyRepository::update(
        repository,
        id,
        ApiKeyUpdate::new()
            .with_provider_ids(vec![providers[1]])
            .with_default_provider_id(Some(providers[1])),
    )
    .await
    .expect("narrow the set");

    let after = ApiKeyRepository::find_by_id(repository, id)
        .await
        .expect("read back after narrowing")
        .expect("the credential exists");
    assert_eq!(stored_provider_ids(&after), vec![providers[1]]);
    assert_eq!(after.api_key().default_provider_id(), Some(providers[1]));
}

/// An update naming no row reports not found rather than creating one.
async fn verify_missing<R>(repository: &R, prefix: &str)
where
    R: ApiKeyRepository + AccountRepository,
{
    let account = ensure_bootstrap(repository).await;
    let provider = ProviderId::try_from(1).expect("positive identifier");
    let stored = ApiKeyRepository::create(
        repository,
        NewApiKey::new(
            account.id(),
            format!("{prefix}-probe"),
            key_id(prefix),
            PasswordHash::new("hash"),
            ApiKeyStatus::Enabled,
            Some(provider),
            None,
            vec![provider],
            Utc::now(),
        ),
    )
    .await
    .expect("issue a probe credential");
    let absent = ApiKeyId::try_from(stored.api_key().id().get() + 1_000_000).expect("positive ID");
    assert_eq!(
        ApiKeyRepository::update(
            repository,
            absent,
            ApiKeyUpdate::new().with_name(format!("{prefix}-none"))
        )
        .await
        .expect_err("no such credential"),
        RepositoryError::NotFound
    );
}

async fn sqlite_database(path: &Path) -> SqliteDatabase {
    let url = format!("sqlite://{}", path.display());
    let database = SqliteDatabase::connect(&url, 2)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    database
}

#[tokio::test]
async fn sqlite_credential_update_satisfies_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("edit.sqlite")).await;
    let prefix = unique_value("sqlite-credential-edit");
    verify_contract(&database, &prefix).await;
    verify_clearing(&database, &prefix).await;
    verify_set_rewrite(&database, &prefix).await;
    verify_missing(&database, &prefix).await;
}

#[tokio::test]
async fn postgres_credential_update_satisfies_contract() {
    let url = support::require_postgres_url("the PostgreSQL credential update layer");
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");
    let prefix = unique_value("postgres-credential-edit");
    verify_contract(&database, &prefix).await;
    verify_clearing(&database, &prefix).await;
    verify_set_rewrite(&database, &prefix).await;
    verify_missing(&database, &prefix).await;
}
