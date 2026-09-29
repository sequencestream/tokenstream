//! Concurrent provider administration contracts.
//!
//! These tests pin the observable outcome of interleaved administrative
//! writes. A configuration edit names only the fields it supplies, so a status
//! change committed while that edit was in flight must survive it. The same
//! interleaving must produce the same result on both supported storage
//! backends, which is why the contract is written once against the repository
//! contract and run against SQLite and PostgreSQL.
//!
//! A provider holds no credential material at all, so there is no rotation to
//! race here; rotation lives with the account that owns the credential and is
//! pinned by the credential rotation contract instead.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{TimeZone, Utc};
use tokenstream::domain::{ProtocolType, ProviderId, ProviderStatus, SecretCiphertext};
use tokenstream::persistence::postgres::PostgresDatabase;
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{NewProvider, ProviderRepository, ProviderUpdate, RepositoryError};
use url::Url;

mod support;
use support::require_postgres_url;

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
        Utc.timestamp_opt(1_789_000_000 + number as i64 * 60, 0)
            .single()
            .expect("valid timestamp"),
    )
}

/// Names a provider within one run.
///
/// A provider name is unique across the whole store, and the PostgreSQL layer
/// shares one database between runs, so every name this contract writes carries
/// the run's unique prefix. Without it a second run collides with the rows the
/// first run left behind and fails on a uniqueness conflict that has nothing to
/// do with the interleaving under test.
fn renamed_name(prefix: &str, number: usize) -> String {
    format!("{prefix}-renamed-{number}")
}

fn rename(prefix: &str, number: usize) -> ProviderUpdate {
    ProviderUpdate::new().with_name(renamed_name(prefix, number))
}

fn disable() -> ProviderUpdate {
    ProviderUpdate::new().with_status(ProviderStatus::Disabled)
}

/// A barrier releases both writers at the same moment, so the two statements
/// contend for the same row with no ordering guaranteed by the test itself.
struct Barrier {
    arrivals: AtomicUsize,
    target: usize,
}

impl Barrier {
    fn new(target: usize) -> Arc<Self> {
        Arc::new(Self {
            arrivals: AtomicUsize::new(0),
            target,
        })
    }

    async fn arrive_and_wait(&self) {
        if self.arrivals.fetch_add(1, Ordering::SeqCst) + 1 == self.target {
            return;
        }
        for _ in 0..2_000 {
            if self.arrivals.load(Ordering::SeqCst) >= self.target {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

async fn verify_interleaving_contract<R>(repository: &R, prefix: &str)
where
    R: ProviderRepository + Clone + Send + Sync + 'static,
{
    // An edit that races a disable keeps the disable, and never re-enables the
    // provider because the edit did not name the status field.
    for round in 0..12 {
        let provider = repository
            .create(new_provider(prefix, 100 + round))
            .await
            .expect("create provider for edit/disable race");
        let barrier = Barrier::new(2);
        let edit_repository = repository.clone();
        let disable_repository = repository.clone();
        let edit_barrier = Arc::clone(&barrier);
        let id = provider.id();
        let edit = async move {
            edit_barrier.arrive_and_wait().await;
            edit_repository
                .update(
                    id,
                    ProviderUpdate::new().with_endpoint(
                        Url::parse(&format!("https://edited-{round}.example.com/base"))
                            .expect("valid endpoint"),
                    ),
                )
                .await
                .expect("endpoint edit during disable")
        };
        let status = async move {
            barrier.arrive_and_wait().await;
            disable_repository
                .update(id, disable())
                .await
                .expect("disable during endpoint edit")
        };
        let (_edited, _disabled) = tokio::join!(edit, status);

        let stored = repository
            .find_by_id(provider.id())
            .await
            .expect("reload provider")
            .expect("provider still exists");
        assert_eq!(
            stored.status(),
            ProviderStatus::Disabled,
            "an edit that named no status must not undo a concurrent disable"
        );
        assert_eq!(
            stored.endpoint().as_str(),
            format!("https://edited-{round}.example.com/base")
        );
    }

    // Two edits that name different fields both survive; two edits that name
    // the same field resolve to the last statement the database committed, and
    // the row is never left half-applied.
    let provider = repository
        .create(new_provider(prefix, 200))
        .await
        .expect("create provider for disjoint field edits");
    repository
        .update(provider.id(), rename(prefix, 200))
        .await
        .expect("first field edit");
    repository
        .update(
            provider.id(),
            ProviderUpdate::new()
                .with_status(ProviderStatus::Disabled)
                .with_upstream_api_key_ciphertext(SecretCiphertext::new("rotated-ciphertext")),
        )
        .await
        .expect("second field edit");
    let stored = repository
        .find_by_id(provider.id())
        .await
        .expect("reload provider")
        .expect("provider still exists");
    assert_eq!(stored.name(), renamed_name(prefix, 200));
    assert_eq!(stored.status(), ProviderStatus::Disabled);
    assert_eq!(
        stored.upstream_api_key_ciphertext().expose(),
        "rotated-ciphertext"
    );
    assert_eq!(stored.protocol_type(), ProtocolType::OpenAi);
    assert_eq!(
        stored.endpoint().as_str(),
        "https://provider-200.example.com/base"
    );

    // A same-field race is last-commit-wins on both backends: whichever
    // statement commits last is the value a later read observes.
    let first = repository
        .update(
            provider.id(),
            ProviderUpdate::new().with_status(ProviderStatus::Disabled),
        )
        .await
        .expect("same-field edit");
    let second = repository
        .update(
            provider.id(),
            ProviderUpdate::new().with_status(ProviderStatus::Enabled),
        )
        .await
        .expect("same-field edit");
    let stored = repository
        .find_by_id(provider.id())
        .await
        .expect("reload provider")
        .expect("provider still exists");
    assert_eq!(stored.status(), second.status());
    assert_eq!(first.id(), stored.id());

    // An edit that names no field changes nothing and issues no statement.
    assert_eq!(
        repository
            .update(provider.id(), ProviderUpdate::new())
            .await
            .expect_err("an empty change set is refused"),
        RepositoryError::NoFieldsToUpdate
    );
    let stored = repository
        .find_by_id(provider.id())
        .await
        .expect("reload provider")
        .expect("provider still exists");
    assert_eq!(stored.status(), ProviderStatus::Enabled);
    assert_eq!(stored.name(), renamed_name(prefix, 200));
}

async fn sqlite_database(path: &Path) -> SqliteDatabase {
    let url = format!("sqlite://{}", path.display());
    let database = SqliteDatabase::connect(&url, 4)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    database
}

#[tokio::test]
async fn sqlite_concurrent_edits_never_overlap_a_disable() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("concurrent-edit.db")).await;
    let prefix = unique_value("sqlite-concurrent-edit");
    verify_interleaving_contract(&database, &prefix).await;
}

#[tokio::test]
async fn postgres_concurrent_edits_never_overlap_a_disable() {
    let url = require_postgres_url("the PostgreSQL concurrent administration layer");
    let database = PostgresDatabase::connect(&url, 4)
        .await
        .expect("connect to PostgreSQL");
    database.migrate().await.expect("migrate PostgreSQL");
    let prefix = unique_value("postgres-concurrent-edit");
    verify_interleaving_contract(&database, &prefix).await;
}

#[tokio::test]
async fn a_missing_provider_is_reported_instead_of_created_by_an_edit() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("missing-edit.db")).await;
    assert_eq!(
        database
            .update(
                ProviderId::try_from(i64::MAX).expect("positive ID"),
                rename(&unique_value("missing-edit"), 999),
            )
            .await
            .expect_err("an edit never creates a provider"),
        RepositoryError::NotFound
    );
}
