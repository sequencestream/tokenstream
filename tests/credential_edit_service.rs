//! In-place editing of an issued credential, at the service boundary.
//!
//! One edit expresses one intent, so these cases drive the whole change set at
//! once and then check what a fresh read observes. Every rejection is checked
//! against a read taken afterwards, because "refused before persistence" is only
//! meaningful if nothing partial survived.

use std::path::Path;

use chrono::{Duration, Utc};
use tokenstream::credentials::{
    CreateApiKeyRequest, CredentialService, CredentialServiceError, UpdateApiKeyRequest,
};
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier};
use tokenstream::domain::ApiKeyWithBindings;
use tokenstream::domain::{
    AccountId, ApiKeyId, ApiKeyStatus, CredentialAdmission, ProtocolType, ProviderId,
    ProviderStatus, SecretString,
};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::providers::{CreateProviderRequest, ProviderService};

mod support;
use support::{bootstrap_account, later, provider_id, unique_value};

const MASTER_KEY: [u8; 32] = [0x5c; 32];

type Service = CredentialService<SqliteDatabase, Argon2GatewaySecretVerifier>;

async fn sqlite_database(path: &Path) -> SqliteDatabase {
    let url = format!("sqlite://{}", path.display());
    let database = SqliteDatabase::connect(&url, 2)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    database
}

fn credentials(database: SqliteDatabase) -> Service {
    CredentialService::new(database, Argon2GatewaySecretVerifier::new())
}

/// Creates `count` enabled providers and returns their identifiers in order.
async fn providers(database: &SqliteDatabase, count: i64) -> Vec<ProviderId> {
    let service = ProviderService::new(database.clone(), AesGcmCipher::new(&MASTER_KEY), false);
    let mut ids = Vec::with_capacity(count as usize);
    for number in 0..count {
        let name = unique_value(&format!("edit-provider-{number}"));
        let created = service
            .create(CreateProviderRequest::new(
                name,
                ProtocolType::OpenAi,
                format!("https://provider-{number}.example.com/base"),
                SecretString::new("sk-upstream"),
                ProviderStatus::Enabled,
            ))
            .await
            .expect("create a provider");
        ids.push(created.id());
    }
    ids
}

/// A bootstrap account with one enabled credential bound to all `provider_ids`.
async fn issued_credential(
    database: &SqliteDatabase,
    provider_ids: &[ProviderId],
) -> (Service, AccountId, ApiKeyId) {
    let service = credentials(database.clone());
    let account = bootstrap_account(&service).await;
    let issued = service
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "editable".to_owned(),
            provider_ids.to_vec(),
            provider_ids.first().copied(),
            None,
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect("issue an editable credential");
    (service, account.id(), issued.api_key().api_key().id())
}

/// The provider identifiers of a stored credential, in stored preference order.
fn stored_provider_ids(stored: &ApiKeyWithBindings) -> Vec<ProviderId> {
    stored
        .bindings()
        .iter()
        .map(|binding| binding.provider_id)
        .collect()
}

fn bounds(
    max_concurrent: Option<u32>,
    rate: Option<u32>,
    websockets: Option<u32>,
) -> CredentialAdmission {
    CredentialAdmission::new(max_concurrent, rate, websockets).expect("positive bounds")
}

#[tokio::test]
async fn one_edit_applies_every_named_field_at_once() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 3).await;
    let (service, account_id, id) = issued_credential(&database, &provider_ids).await;
    let before = service.get_api_key(id).await.expect("read before");

    let expires_at = later() + Duration::hours(24);
    let edited = service
        .update_api_key(
            id,
            &before,
            UpdateApiKeyRequest::new()
                .with_name("edited".to_owned())
                .with_status(ApiKeyStatus::Disabled)
                .with_expires_at(Some(expires_at))
                // Remove the first provider, keep two, and reverse them so the
                // stored order differs from the order the page listed them in.
                .with_provider_ids(vec![provider_ids[2], provider_ids[1]])
                .with_default_provider_id(Some(provider_ids[2]))
                .with_admission(bounds(Some(4), Some(7), Some(9))),
        )
        .await
        .expect("apply one edit");

    // The stored binding order is the preference order, so it reads back reversed.
    assert_eq!(
        stored_provider_ids(&edited),
        vec![provider_ids[2], provider_ids[1]]
    );
    assert_eq!(
        edited.api_key().default_provider_id(),
        Some(provider_ids[2])
    );
    assert_eq!(edited.api_key().name(), "edited");
    assert_eq!(edited.api_key().status(), ApiKeyStatus::Disabled);
    assert_eq!(edited.api_key().expires_at(), Some(expires_at));
    let admission = edited.api_key().admission();
    assert_eq!(admission.max_concurrent_requests().get(), Some(4));
    assert_eq!(admission.max_requests_per_second().get(), Some(7));
    assert_eq!(admission.max_websockets().get(), Some(9));

    // A fresh read agrees with the response, and the owner is unchanged.
    let reread = service.get_api_key(id).await.expect("read after");
    assert_eq!(
        stored_provider_ids(&reread),
        vec![provider_ids[2], provider_ids[1]]
    );
    assert_eq!(
        reread.api_key().default_provider_id(),
        Some(provider_ids[2])
    );
    assert_eq!(reread.api_key().name(), "edited");
    assert_eq!(reread.api_key().status(), ApiKeyStatus::Disabled);
    assert_eq!(reread.api_key().account_id(), account_id);
}

#[tokio::test]
async fn an_edit_keeps_the_key_identifier_and_the_secret() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 1).await;
    let (service, _, id) = issued_credential(&database, &provider_ids).await;
    let before = service.get_api_key(id).await.expect("read before");

    service
        .update_api_key(
            id,
            &before,
            UpdateApiKeyRequest::new()
                .with_name("renamed".to_owned())
                .with_admission(bounds(Some(2), None, None)),
        )
        .await
        .expect("apply the edit");

    let after = service.get_api_key(id).await.expect("read after");
    // No redistribution is required, so the identifier survives the edit.
    assert_eq!(after.api_key().key_id(), before.api_key().key_id());
    assert_eq!(
        after.api_key().secret_hash(),
        before.api_key().secret_hash()
    );
}

#[tokio::test]
async fn an_edit_can_clear_the_expiry_and_every_bound() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 1).await;
    let (service, _, id) = issued_credential(&database, &provider_ids).await;
    let before = service.get_api_key(id).await.expect("read before");
    service
        .update_api_key(
            id,
            &before,
            UpdateApiKeyRequest::new()
                .with_expires_at(Some(later()))
                .with_admission(bounds(Some(3), Some(3), Some(3))),
        )
        .await
        .expect("set an expiry and bounds");

    let bounded = service.get_api_key(id).await.expect("read bounded");
    let cleared = service
        .update_api_key(
            id,
            &bounded,
            UpdateApiKeyRequest::new()
                .with_expires_at(None)
                .with_admission(bounds(None, None, None)),
        )
        .await
        .expect("clear the expiry and every bound");

    assert_eq!(cleared.api_key().expires_at(), None);
    // An absent bound is unbounded, so the credential needs no counter state.
    assert!(cleared.api_key().admission().is_unbounded());
}

#[tokio::test]
async fn an_absent_expiry_field_leaves_the_stored_expiry_alone() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 1).await;
    let (service, _, id) = issued_credential(&database, &provider_ids).await;
    let before = service.get_api_key(id).await.expect("read before");
    let expires_at = later() + Duration::hours(3);
    service
        .update_api_key(
            id,
            &before,
            UpdateApiKeyRequest::new().with_expires_at(Some(expires_at)),
        )
        .await
        .expect("set the expiry");

    let with_expiry = service.get_api_key(id).await.expect("read with expiry");
    let renamed = service
        .update_api_key(
            id,
            &with_expiry,
            UpdateApiKeyRequest::new().with_name("unrelated".to_owned()),
        )
        .await
        .expect("edit only the name");
    // An edit that does not name the expiry must not clear it.
    assert_eq!(renamed.api_key().expires_at(), Some(expires_at));
}

#[tokio::test]
async fn an_empty_change_set_is_refused() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 1).await;
    let (service, _, id) = issued_credential(&database, &provider_ids).await;
    let before = service.get_api_key(id).await.expect("read before");
    assert_eq!(
        service
            .update_api_key(id, &before, UpdateApiKeyRequest::new())
            .await
            .expect_err("an empty edit names nothing"),
        CredentialServiceError::NoFieldsToUpdate
    );
}

#[tokio::test]
async fn replacing_the_provider_set_rechecks_the_stored_default() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 3).await;
    let (service, _, id) = issued_credential(&database, &provider_ids).await;
    // The stored default is the first provider of the issued set.
    let before = service.get_api_key(id).await.expect("read before");
    assert_eq!(
        before.api_key().default_provider_id(),
        Some(provider_ids[0])
    );

    // Dropping the default's provider without naming a new default would leave
    // the stored default outside the new set, so the edit is refused rather than
    // silently clearing the default.
    assert_eq!(
        service
            .update_api_key(
                id,
                &before,
                UpdateApiKeyRequest::new()
                    .with_provider_ids(vec![provider_ids[1], provider_ids[2]])
            )
            .await
            .expect_err("the stored default leaves the new set"),
        CredentialServiceError::DefaultNotInProviderSet
    );

    // The same edit that names a compatible default succeeds.
    let edited = service
        .update_api_key(
            id,
            &before,
            UpdateApiKeyRequest::new()
                .with_provider_ids(vec![provider_ids[1], provider_ids[2]])
                .with_default_provider_id(Some(provider_ids[2])),
        )
        .await
        .expect("replace the set and the default together");
    assert_eq!(
        stored_provider_ids(&edited),
        vec![provider_ids[1], provider_ids[2]]
    );
    assert_eq!(
        edited.api_key().default_provider_id(),
        Some(provider_ids[2])
    );
}

#[tokio::test]
async fn an_edit_can_clear_the_default_provider() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 2).await;
    let (service, _, id) = issued_credential(&database, &provider_ids).await;
    let before = service.get_api_key(id).await.expect("read before");
    let cleared = service
        .update_api_key(
            id,
            &before,
            UpdateApiKeyRequest::new().with_default_provider_id(None),
        )
        .await
        .expect("clear the default");
    assert_eq!(cleared.api_key().default_provider_id(), None);
}

#[tokio::test]
async fn a_past_expiry_is_refused_on_the_edit_path() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 1).await;
    let (service, _, id) = issued_credential(&database, &provider_ids).await;
    let before = service.get_api_key(id).await.expect("read before");
    assert_eq!(
        service
            .update_api_key(
                id,
                &before,
                UpdateApiKeyRequest::new().with_expires_at(Some(Utc::now() - Duration::minutes(1)))
            )
            .await
            .expect_err("an expiry in the past can never authenticate"),
        CredentialServiceError::InvalidExpiry
    );
}

/// Every refusal below lands in the same place: the credential is exactly as it
/// was, so no field of a refused edit survives anywhere.
#[tokio::test]
async fn a_refused_edit_leaves_the_credential_untouched() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 3).await;
    let unknown = provider_id(999_999);
    let mut oversized: Vec<ProviderId> = provider_ids.clone();
    for number in 4..40 {
        oversized.push(provider_id(number));
    }
    let mut duplicated = vec![provider_ids[0], provider_ids[1]];
    duplicated.push(provider_ids[0]);

    let cases: Vec<(&str, UpdateApiKeyRequest, CredentialServiceError)> = vec![
        (
            "an empty provider set",
            UpdateApiKeyRequest::new().with_provider_ids(vec![]),
            CredentialServiceError::InvalidProviders,
        ),
        (
            "an oversized provider set",
            UpdateApiKeyRequest::new().with_provider_ids(oversized),
            CredentialServiceError::InvalidProviders,
        ),
        (
            "a repeated provider",
            UpdateApiKeyRequest::new().with_provider_ids(duplicated),
            CredentialServiceError::InvalidProviders,
        ),
        (
            "an unknown provider",
            UpdateApiKeyRequest::new()
                .with_provider_ids(vec![provider_ids[0], unknown])
                .with_default_provider_id(Some(unknown)),
            CredentialServiceError::ProviderNotFound,
        ),
        (
            "a default outside the final set",
            UpdateApiKeyRequest::new()
                .with_provider_ids(vec![provider_ids[0], provider_ids[1]])
                .with_default_provider_id(Some(provider_ids[2])),
            CredentialServiceError::DefaultNotInProviderSet,
        ),
        (
            "an empty name",
            UpdateApiKeyRequest::new().with_name("   ".to_owned()),
            CredentialServiceError::InvalidName,
        ),
        (
            "an oversized name",
            UpdateApiKeyRequest::new().with_name("n".repeat(129)),
            CredentialServiceError::InvalidName,
        ),
        (
            "a name carrying control characters",
            UpdateApiKeyRequest::new().with_name("bad\u{7}name".to_owned()),
            CredentialServiceError::InvalidName,
        ),
    ];

    let service = credentials(database.clone());
    let account = bootstrap_account(&service).await;
    for (label, request, expected) in cases {
        // Each case edits its own credential, so one refused edit cannot be
        // confused with another's leftover.
        let issued = service
            .create_api_key(CreateApiKeyRequest::new(
                account.id(),
                "editable".to_owned(),
                provider_ids.clone(),
                provider_ids.first().copied(),
                None,
                ApiKeyStatus::Enabled,
            ))
            .await
            .expect("issue an editable credential");
        let id = issued.api_key().api_key().id();
        let before = service.get_api_key(id).await.expect("read before");
        assert_eq!(
            service
                .update_api_key(id, &before, request)
                .await
                .expect_err(label),
            expected,
            "{label}"
        );
        let after = service.get_api_key(id).await.expect("read after");
        assert_eq!(after.api_key().name(), before.api_key().name(), "{label}");
        assert_eq!(
            after.api_key().default_provider_id(),
            before.api_key().default_provider_id(),
            "{label}"
        );
        assert_eq!(
            stored_provider_ids(&after),
            stored_provider_ids(&before),
            "{label}"
        );
    }
}

#[tokio::test]
async fn a_zero_bound_never_reaches_the_service() {
    // A non-positive bound is refused by the value type that carries it, so the
    // edit path never has to see one.
    assert!(CredentialAdmission::new(Some(0), None, None).is_err());
    assert!(CredentialAdmission::new(None, Some(0), None).is_err());
    assert!(CredentialAdmission::new(None, None, Some(0)).is_err());
}

#[tokio::test]
async fn a_stored_name_is_the_trimmed_name() {
    let database = sqlite_database(Path::new(":memory:")).await;
    let provider_ids = providers(&database, 1).await;
    let (service, _, id) = issued_credential(&database, &provider_ids).await;
    let before = service.get_api_key(id).await.expect("read before");
    let edited = service
        .update_api_key(
            id,
            &before,
            UpdateApiKeyRequest::new().with_name("  spaced  ".to_owned()),
        )
        .await
        .expect("edit the name");
    // Storing the untrimmed form would make two spellings of one name, which is
    // what creation already refuses by trimming.
    assert_eq!(edited.api_key().name(), "spaced");
}
