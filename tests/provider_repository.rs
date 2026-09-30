use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{TimeZone, Utc};
use sqlx::{PgPool, SqlitePool};
use tokenstream::domain::{
    AccountId, ApiKeyId, ProtocolType, ProviderCursor, ProviderHealthState, ProviderId,
    ProviderStatus, SecretCiphertext, validate_provider_probe,
};
use tokenstream::persistence::postgres::PostgresDatabase;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{
    NewProvider, ProviderListRequest, ProviderRepository, ProviderUpdate, RepositoryError,
};
use url::Url;

mod support;
use support::{key_id, require_postgres_url};

use tokenstream::domain::{ApiKeyStatus, PasswordHash};
use tokenstream::persistence::NewApiKey;

/// Issues a credential so a request log has something to pin besides a provider.
async fn issue_key<R>(
    repository: &R,
    account_id: AccountId,
    provider_id: ProviderId,
    prefix: &str,
) -> ApiKeyId
where
    R: tokenstream::persistence::ApiKeyRepository,
{
    tokenstream::persistence::ApiKeyRepository::create(
        repository,
        NewApiKey::new(
            account_id,
            format!("{prefix}-log-key"),
            key_id(prefix),
            PasswordHash::new("hash"),
            ApiKeyStatus::Enabled,
            Some(provider_id),
            None,
            vec![provider_id],
            Utc::now(),
        ),
    )
    .await
    .expect("issue a credential for the log")
    .api_key()
    .id()
}

fn unique_value(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn new_provider(prefix: &str, number: usize) -> NewProvider {
    NewProvider::new(
        format!("{prefix}-provider-{number}"),
        ProtocolType::OpenAi,
        Url::parse(&format!("https://provider-{number}.example.com/base")).expect("valid endpoint"),
        SecretCiphertext::new(format!("ciphertext-{number}")),
        ProviderStatus::Enabled,
        Utc.with_ymd_and_hms(2026, 9, 28, 10, 0, number as u32)
            .single()
            .expect("valid timestamp"),
    )
}

fn provider_update(prefix: &str, number: usize, name: String) -> ProviderUpdate {
    let _ = prefix;
    ProviderUpdate::new()
        .with_name(name)
        .with_endpoint(
            Url::parse(&format!("https://updated-{number}.example.com/api"))
                .expect("valid endpoint"),
        )
        .with_upstream_api_key_ciphertext(SecretCiphertext::new(format!(
            "updated-ciphertext-{number}"
        )))
        .with_status(ProviderStatus::Disabled)
}

async fn verify_contract<R>(repository: &R, prefix: &str) -> Vec<ProviderId>
where
    R: ProviderRepository,
{
    assert_eq!(
        ProviderListRequest::new(None, 0)
            .expect_err("zero limit is invalid")
            .to_string(),
        "provider page size must be between 1 and 100"
    );
    assert!(ProviderListRequest::new(None, 101).is_err());

    let first = repository
        .create(new_provider(prefix, 0))
        .await
        .expect("create first provider");
    assert!(first.id().get() > 0);
    let first_created_at = first.created_at();

    let found_by_id = repository
        .find_by_id(first.id())
        .await
        .expect("find provider by id")
        .expect("provider exists");
    assert_eq!(found_by_id.id(), first.id());
    assert_eq!(found_by_id.name(), format!("{prefix}-provider-0"));

    assert_eq!(
        repository
            .create(new_provider(prefix, 0))
            .await
            .expect_err("duplicate provider is rejected"),
        RepositoryError::Conflict
    );

    let second = repository
        .create(new_provider(prefix, 1))
        .await
        .expect("create second provider");
    let updated_name = format!("{prefix}-provider-updated");
    let updated = repository
        .update(
            first.id(),
            provider_update(prefix, 20, updated_name.clone()),
        )
        .await
        .expect("update provider");
    assert_eq!(updated.id(), first.id());
    assert_eq!(updated.name(), updated_name);
    assert_eq!(updated.protocol_type(), ProtocolType::OpenAi);
    assert_eq!(updated.status(), ProviderStatus::Disabled);
    assert_eq!(
        updated.endpoint().as_str(),
        "https://updated-20.example.com/api"
    );
    assert_eq!(updated.created_at(), first_created_at);
    assert!(
        updated
            .upstream_api_key_ciphertext()
            .expose()
            .contains("updated-ciphertext-20")
    );
    assert_eq!(
        repository
            .update(first.id(), ProviderUpdate::new())
            .await
            .expect_err("an empty change set is refused"),
        RepositoryError::NoFieldsToUpdate
    );

    let failed_update = provider_update(prefix, 21, updated.name().to_owned());
    assert_eq!(
        repository
            .update(second.id(), failed_update)
            .await
            .expect_err("duplicate name update is rejected"),
        RepositoryError::Conflict
    );
    let unchanged = repository
        .find_by_id(second.id())
        .await
        .expect("lookup after failed update")
        .expect("failed update was rolled back");
    assert_eq!(unchanged.id(), second.id());
    assert_eq!(
        unchanged.endpoint().as_str(),
        "https://provider-1.example.com/base"
    );
    assert_eq!(unchanged.status(), ProviderStatus::Enabled);

    let mut ids = vec![first.id(), second.id()];
    for number in 2..14 {
        ids.push(
            repository
                .create(new_provider(prefix, number))
                .await
                .expect("create cursor fixture")
                .id(),
        );
    }
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));

    let cursor = ProviderCursor::try_from(ids[7].get()).expect("positive cursor");
    let page = repository
        .list(ProviderListRequest::new(Some(cursor), 3).expect("valid page request"))
        .await
        .expect("list providers");
    let page_ids: Vec<i64> = page
        .items()
        .iter()
        .map(|provider| provider.id().get())
        .collect();
    assert_eq!(
        page_ids,
        ids[8..11].iter().map(|id| id.get()).collect::<Vec<_>>()
    );
    assert!(page_ids.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(page.has_more());
    assert_eq!(
        page.next_after_id().expect("page cursor").get(),
        ids[10].get()
    );

    let deleted = repository
        .create(new_provider(prefix, 14))
        .await
        .expect("create provider to delete");
    repository
        .delete(deleted.id())
        .await
        .expect("delete unreferenced provider");
    let after_delete = repository
        .create(new_provider(prefix, 15))
        .await
        .expect("create provider after deletion");
    assert!(after_delete.id() > deleted.id());
    ids.push(after_delete.id());

    let missing_id = ProviderId::try_from(i64::MAX).expect("positive ID");
    assert!(
        repository
            .find_by_id(missing_id)
            .await
            .expect("find missing provider")
            .is_none()
    );
    assert_eq!(
        repository
            .update(
                missing_id,
                provider_update(prefix, 99, format!("{prefix}-missing")),
            )
            .await
            .expect_err("missing update is rejected"),
        RepositoryError::NotFound
    );
    assert_eq!(
        repository
            .delete(missing_id)
            .await
            .expect_err("missing delete is rejected"),
        RepositoryError::NotFound
    );

    let endpoint = Url::parse("https://health.example.com/base").expect("valid endpoint");
    let probe = validate_provider_probe(Some("/ready"), Some(2), Some(30_000), Some(5_000))
        .expect("valid probe")
        .expect("configured probe")
        .resolve(&endpoint)
        .expect("probe target");
    let observed = repository
        .create(
            NewProvider::new(
                format!("{prefix}-health"),
                ProtocolType::OpenAi,
                endpoint,
                SecretCiphertext::new("health-ciphertext"),
                ProviderStatus::Enabled,
                Utc::now(),
            )
            .with_probe(Some(probe)),
        )
        .await
        .expect("create observed provider");
    repository
        .set_health(
            observed.id(),
            ProviderHealthState::Healthy,
            ProviderHealthState::Isolated,
        )
        .await
        .expect("isolate provider");
    let cleared = repository
        .update(observed.id(), ProviderUpdate::new().with_probe(None))
        .await
        .expect("remove probe");
    assert_eq!(cleared.health(), ProviderHealthState::Healthy);
    assert!(cleared.probe().is_none());
    ids
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
async fn sqlite_provider_repository_satisfies_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("providers.db")).await;
    let prefix = unique_value("sqlite-provider-contract");
    verify_contract(&database, &prefix).await;

    verify_sqlite_restricted_delete(&database, &prefix).await;
}

async fn verify_sqlite_restricted_delete(database: &SqliteDatabase, prefix: &str) {
    let provider = database
        .create(new_provider(prefix, 50))
        .await
        .expect("create referenced provider");
    let account = support::ensure_bootstrap(database).await;
    let api_key = issue_key(database, account.id(), provider.id(), prefix).await;
    insert_sqlite_request_log(
        database.pool(),
        account.id(),
        api_key,
        provider.id(),
        prefix,
    )
    .await;
    assert_eq!(
        database
            .delete(provider.id())
            .await
            .expect_err("referenced provider cannot be deleted"),
        RepositoryError::ProviderInUse
    );
}

async fn insert_sqlite_request_log(
    pool: &SqlitePool,
    account_id: AccountId,
    api_key_id: ApiKeyId,
    provider_id: ProviderId,
    prefix: &str,
) {
    sqlx::query(
        "INSERT INTO request_log (
             request_id, account_id, api_key_id, provider_id, protocol_type,
             transport_type, path, start_time
         ) VALUES (?, ?, ?, ?, 'openai', 'http', '/v1/responses', 1)",
    )
    .bind(format!("{prefix}-request"))
    .bind(account_id.get())
    .bind(api_key_id.get())
    .bind(provider_id.get())
    .execute(pool)
    .await
    .expect("insert request log");
}

#[tokio::test]
async fn postgres_provider_repository_satisfies_contract() {
    let url = require_postgres_url("the PostgreSQL provider repository layer");
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");
    let prefix = unique_value("postgres-provider-contract");
    verify_contract(&database, &prefix).await;

    verify_postgres_restricted_delete(&database, &prefix).await;
}

async fn verify_postgres_restricted_delete(database: &PostgresDatabase, prefix: &str) {
    let provider = database
        .create(new_provider(prefix, 50))
        .await
        .expect("create referenced provider");
    let account = support::ensure_bootstrap(database).await;
    let api_key = issue_key(database, account.id(), provider.id(), prefix).await;
    insert_postgres_request_log(
        database.pool(),
        account.id(),
        api_key,
        provider.id(),
        prefix,
    )
    .await;
    assert_eq!(
        database
            .delete(provider.id())
            .await
            .expect_err("referenced provider cannot be deleted"),
        RepositoryError::ProviderInUse
    );
}

async fn insert_postgres_request_log(
    pool: &PgPool,
    account_id: AccountId,
    api_key_id: ApiKeyId,
    provider_id: ProviderId,
    prefix: &str,
) {
    sqlx::query(
        "INSERT INTO request_log (
             request_id, account_id, api_key_id, provider_id, protocol_type,
             transport_type, path, start_time
         ) VALUES ($1, $2, $3, $4, 'openai', 'http', '/v1/responses', 1)",
    )
    .bind(format!("{prefix}-request"))
    .bind(account_id.get())
    .bind(api_key_id.get())
    .bind(provider_id.get())
    .execute(pool)
    .await
    .expect("insert request log");
}
