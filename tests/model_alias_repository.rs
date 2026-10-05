use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use tokenstream::domain::{
    AccountRole, AccountStatus, ModelAliasCursor, PasswordHash, ProtocolType, ProviderStatus,
    SecretCiphertext,
};
use tokenstream::persistence::postgres::PostgresDatabase;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{
    AccountRepository, ModelAliasListRequest, ModelAliasRepository, ModelAliasUpdate, NewAccount,
    NewModelAlias, NewProvider, ProviderRepository, RepositoryError,
};
use url::Url;

mod support;
use support::require_postgres_url;

fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

async fn sqlite(path: &Path) -> SqliteDatabase {
    let database = SqliteDatabase::connect(&format!("sqlite://{}", path.display()), 2)
        .await
        .expect("connect SQLite");
    database.migrate().await.expect("migrate SQLite");
    database
}

async fn verify_contract<R>(repository: &R, prefix: &str)
where
    R: AccountRepository + ProviderRepository + ModelAliasRepository,
{
    assert!(ModelAliasListRequest::new(None, 0, None).is_err());
    assert!(ModelAliasListRequest::new(None, 101, None).is_err());

    let first_account = AccountRepository::create(
        repository,
        NewAccount::new(
            format!("{prefix}-one"),
            PasswordHash::new("hash"),
            AccountRole::User,
            AccountStatus::Enabled,
            false,
            Utc::now(),
        ),
    )
    .await
    .expect("create first account");
    let second_account = AccountRepository::create(
        repository,
        NewAccount::new(
            format!("{prefix}-two"),
            PasswordHash::new("hash"),
            AccountRole::User,
            AccountStatus::Enabled,
            false,
            Utc::now(),
        ),
    )
    .await
    .expect("create second account");
    let first_provider = ProviderRepository::create(
        repository,
        NewProvider::new(
            format!("{prefix}-provider-one"),
            ProtocolType::OpenAi,
            Url::parse("https://one.example.com").expect("URL"),
            SecretCiphertext::new("ciphertext"),
            ProviderStatus::Enabled,
            Utc::now(),
        ),
    )
    .await
    .expect("create first provider");
    let second_provider = ProviderRepository::create(
        repository,
        NewProvider::new(
            format!("{prefix}-provider-two"),
            ProtocolType::Anthropic,
            Url::parse("https://two.example.com").expect("URL"),
            SecretCiphertext::new("ciphertext"),
            ProviderStatus::Enabled,
            Utc::now(),
        ),
    )
    .await
    .expect("create second provider");

    let created = repository
        .create_model_alias(NewModelAlias::new(
            first_account.id(),
            "coding".to_owned(),
            vec![
                (first_provider.id(), "model-one".to_owned()),
                (second_provider.id(), "model-two".to_owned()),
            ],
            Utc::now(),
        ))
        .await
        .expect("create alias");
    assert_eq!(created.alias().account_id(), first_account.id());
    assert_eq!(created.targets()[0].upstream_model(), "model-one");
    assert_eq!(created.targets()[1].provider_id(), second_provider.id());

    assert_eq!(
        repository
            .create_model_alias(NewModelAlias::new(
                first_account.id(),
                "coding".to_owned(),
                vec![(first_provider.id(), "other".to_owned())],
                Utc::now(),
            ))
            .await
            .expect_err("same-account duplicate"),
        RepositoryError::Conflict
    );
    let other = repository
        .create_model_alias(NewModelAlias::new(
            second_account.id(),
            "coding".to_owned(),
            vec![(first_provider.id(), "other".to_owned())],
            Utc::now(),
        ))
        .await
        .expect("same name under another account");

    let page = repository
        .list_model_aliases(
            ModelAliasListRequest::new(None, 1, Some(first_account.id())).expect("page"),
        )
        .await
        .expect("list aliases");
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].alias().id(), created.alias().id());
    let cursor = ModelAliasCursor::try_from(created.alias().id().get()).expect("cursor");
    let after = repository
        .list_model_aliases(ModelAliasListRequest::new(Some(cursor), 10, None).expect("page"))
        .await
        .expect("list after cursor");
    assert_eq!(after.items()[0].alias().id(), other.alias().id());

    let updated = repository
        .update_model_alias(
            created.alias().id(),
            ModelAliasUpdate::new()
                .with_name("coding-next".to_owned())
                .with_targets(vec![(second_provider.id(), "replacement".to_owned())]),
        )
        .await
        .expect("update alias");
    assert_eq!(updated.alias().name(), "coding-next");
    assert_eq!(updated.targets().len(), 1);
    assert_eq!(updated.targets()[0].upstream_model(), "replacement");
    assert_eq!(
        repository
            .update_model_alias(created.alias().id(), ModelAliasUpdate::new())
            .await
            .expect_err("empty update"),
        RepositoryError::NoFieldsToUpdate
    );

    assert_eq!(
        AccountRepository::delete(repository, first_account.id())
            .await
            .expect_err("alias pins account"),
        RepositoryError::InUse
    );
    assert_eq!(
        ProviderRepository::delete(repository, second_provider.id())
            .await
            .expect_err("alias pins provider"),
        RepositoryError::ProviderInUse
    );

    repository
        .delete_model_alias(created.alias().id())
        .await
        .expect("delete alias");
    repository
        .delete_model_alias(other.alias().id())
        .await
        .expect("delete other alias");
    ProviderRepository::delete(repository, first_provider.id())
        .await
        .expect("delete first provider");
    ProviderRepository::delete(repository, second_provider.id())
        .await
        .expect("delete second provider");
    AccountRepository::delete(repository, first_account.id())
        .await
        .expect("delete first account");
    AccountRepository::delete(repository, second_account.id())
        .await
        .expect("delete second account");
}

#[tokio::test]
async fn sqlite_model_alias_repository_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite(&directory.path().join("aliases.db")).await;
    verify_contract(&database, &unique("sqlite-alias")).await;
}

#[tokio::test]
async fn postgres_model_alias_repository_contract() {
    let url = require_postgres_url("the PostgreSQL model alias repository");
    let database = PostgresDatabase::connect(&url, 2)
        .await
        .expect("connect PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");
    verify_contract(&database, &unique("postgres-alias")).await;
}
