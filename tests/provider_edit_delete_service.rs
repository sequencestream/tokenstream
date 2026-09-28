use std::path::Path;

use chrono::Utc;
use tokenstream::crypto::{
    AesGcmCipher, Argon2GatewaySecretVerifier, GatewaySecretVerifier, SecretCipher,
};
use tokenstream::domain::{
    ProtocolType, ProviderId, ProviderSnapshot, ProviderStatus, RequestId, SecretString,
    TransportType,
};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{
    ProviderListRequest, ProviderRepository, RequestLogRepository, RequestLogStarted,
};
use tokenstream::providers::{
    CreateProviderRequest, ProviderService, ProviderServiceError, UpdateProviderRequest,
};

const MASTER_KEY: [u8; 32] = [0x5c; 32];
const UPSTREAM_KEY: &str = "sk-original-upstream-key";
const ROTATED_KEY: &str = "sk-edited-upstream-key";

async fn sqlite_database(path: &Path) -> SqliteDatabase {
    let url = format!("sqlite://{}", path.display());
    let database = SqliteDatabase::connect(&url, 2)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    database
}

fn service(
    database: SqliteDatabase,
    allow_insecure_endpoints: bool,
) -> ProviderService<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier> {
    ProviderService::new(
        database,
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
        allow_insecure_endpoints,
    )
}

fn create_request(name: &str, endpoint: &str, upstream_key: &str) -> CreateProviderRequest {
    CreateProviderRequest::new(
        name.to_owned(),
        ProtocolType::OpenAi,
        endpoint.to_owned(),
        SecretString::new(upstream_key),
        ProviderStatus::Enabled,
    )
}

fn decrypt(cipher: &AesGcmCipher, provider: &tokenstream::domain::Provider) -> String {
    cipher
        .decrypt(provider.upstream_api_key_ciphertext())
        .expect("decrypt stored upstream key")
        .expose()
        .to_owned()
}

async fn provider_count<R: ProviderRepository>(repository: &R) -> usize {
    repository
        .list(ProviderListRequest::new(None, 100).expect("valid page request"))
        .await
        .expect("list providers")
        .items()
        .len()
}

#[tokio::test]
async fn edit_commits_only_named_fields_and_keeps_credential() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("edit.db")).await;
    let service = service(database.clone(), false);
    let cipher = AesGcmCipher::new(&MASTER_KEY);

    let created = service
        .create(create_request(
            "primary",
            "https://api.example.com/base",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create provider");
    let id = created.provider().id();
    let key_id = created.gateway_credential().key_id().clone();
    let created_at = created.provider().created_at();
    let ciphertext_before = created.provider().upstream_api_key_ciphertext().clone();

    let renamed = service
        .update(id, UpdateProviderRequest::new().with_name("  renamed  "))
        .await
        .expect("rename provider");
    assert_eq!(renamed.name(), "renamed");
    assert_eq!(renamed.endpoint().as_str(), "https://api.example.com/base");
    assert_eq!(renamed.status(), ProviderStatus::Enabled);
    assert_eq!(renamed.gateway_key_id(), &key_id);
    assert_eq!(renamed.created_at(), created_at);
    assert_eq!(
        renamed.upstream_api_key_ciphertext().expose(),
        ciphertext_before.expose(),
        "a name-only edit must not touch the stored credential"
    );

    let moved = service
        .update(
            id,
            UpdateProviderRequest::new().with_endpoint("https://other.example.com/v1"),
        )
        .await
        .expect("move provider");
    assert_eq!(moved.name(), "renamed");
    assert_eq!(moved.endpoint().as_str(), "https://other.example.com/v1");
    assert_eq!(decrypt(&cipher, &moved), UPSTREAM_KEY);
    assert_eq!(provider_count(&database).await, 1);

    let stored = database
        .find_by_id(id)
        .await
        .expect("find provider by id")
        .expect("provider exists");
    assert_eq!(stored.endpoint().as_str(), "https://other.example.com/v1");
    assert_eq!(provider_count(&database).await, 1);
}

#[tokio::test]
async fn an_edit_that_names_no_field_changes_nothing() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("empty-edit.db")).await;
    let service = service(database.clone(), false);
    let cipher = AesGcmCipher::new(&MASTER_KEY);

    let created = service
        .create(create_request(
            "primary",
            "https://api.example.com/base",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create provider");
    let id = created.provider().id();

    assert_eq!(
        service
            .update(id, UpdateProviderRequest::new())
            .await
            .expect_err("an empty edit is refused before storage"),
        ProviderServiceError::NoFieldsToUpdate
    );

    let stored = database
        .find_by_id(id)
        .await
        .expect("find provider by id")
        .expect("provider exists");
    assert_eq!(stored.name(), "primary");
    assert_eq!(stored.endpoint().as_str(), "https://api.example.com/base");
    assert_eq!(stored.status(), ProviderStatus::Enabled);
    assert_eq!(decrypt(&cipher, &stored), UPSTREAM_KEY);
}

#[tokio::test]
async fn a_late_configuration_edit_never_restores_a_rotated_credential() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("edit-after-rotate.db")).await;
    let service = service(database.clone(), false);
    let verifier = Argon2GatewaySecretVerifier::new();

    let created = service
        .create(create_request(
            "primary",
            "https://api.example.com/base",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create provider");
    let id = created.provider().id();
    let old_secret = created.gateway_credential().secret().clone();

    let rotated = service
        .rotate_gateway_credential(id)
        .await
        .expect("rotate gateway credential");
    let new_secret = rotated.gateway_credential().secret().clone();

    // The edit runs after the rotation committed, reading no earlier state
    // from storage, so the write set it names is exactly the name column.
    service
        .update(id, UpdateProviderRequest::new().with_name("renamed"))
        .await
        .expect("rename after rotation");

    let stored = database
        .find_by_id(id)
        .await
        .expect("find provider by id")
        .expect("provider exists");
    assert_eq!(stored.name(), "renamed");
    assert_eq!(
        stored.gateway_key_id(),
        rotated.gateway_credential().key_id(),
        "a configuration edit must not write the gateway key columns"
    );
    assert!(
        !verifier
            .verify(&old_secret, stored.gateway_api_key_hash())
            .expect("stored hash is well formed"),
        "the retired credential must stop verifying"
    );
    assert!(
        verifier
            .verify(&new_secret, stored.gateway_api_key_hash())
            .expect("stored hash is well formed"),
        "the rotated credential must keep verifying after an edit"
    );
}

#[tokio::test]
async fn edit_re_encrypts_upstream_key_and_leaves_snapshot_untouched() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("key-edit.db")).await;
    let service = service(database.clone(), false);
    let cipher = AesGcmCipher::new(&MASTER_KEY);

    let created = service
        .create(create_request(
            "primary",
            "https://api.example.com",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create provider");
    let id = created.provider().id();
    let key_id = created.gateway_credential().key_id().clone();
    let snapshot = ProviderSnapshot::new(
        id,
        created.provider().protocol_type(),
        created.provider().endpoint().clone(),
        SecretString::new(decrypt(&cipher, created.provider())),
    );
    let ciphertext_before = created.provider().upstream_api_key_ciphertext().clone();

    let updated = service
        .update(
            id,
            UpdateProviderRequest::new().with_upstream_api_key(SecretString::new(ROTATED_KEY)),
        )
        .await
        .expect("replace upstream key");

    assert_ne!(
        updated.upstream_api_key_ciphertext().expose(),
        ciphertext_before.expose(),
        "the upstream key must be re-encrypted"
    );
    assert_eq!(decrypt(&cipher, &updated), ROTATED_KEY);
    assert_eq!(updated.gateway_key_id(), &key_id);
    assert_eq!(
        updated.gateway_api_key_hash().expose(),
        created.provider().gateway_api_key_hash().expose(),
        "an upstream-key edit must not rotate the gateway credential"
    );

    assert_eq!(snapshot.endpoint().as_str(), "https://api.example.com/");
    assert_eq!(snapshot.upstream_api_key().expose(), UPSTREAM_KEY);

    let debug = format!("{updated:?}");
    assert!(!debug.contains(ROTATED_KEY));
    assert!(!debug.contains(UPSTREAM_KEY));
}

#[tokio::test]
async fn set_status_disables_and_reenables_without_touching_other_fields() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("status.db")).await;
    let service = service(database.clone(), false);

    let created = service
        .create(create_request(
            "primary",
            "https://api.example.com",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create provider");
    let id = created.provider().id();

    let disabled = service
        .set_status(id, ProviderStatus::Disabled)
        .await
        .expect("disable provider");
    assert_eq!(disabled.status(), ProviderStatus::Disabled);
    assert_eq!(disabled.endpoint().as_str(), "https://api.example.com/");

    let stored = database
        .find_by_id(id)
        .await
        .expect("find provider by id")
        .expect("provider exists");
    assert_eq!(stored.status(), ProviderStatus::Disabled);

    let enabled = service
        .set_status(id, ProviderStatus::Enabled)
        .await
        .expect("reenable provider");
    assert_eq!(enabled.status(), ProviderStatus::Enabled);
}

#[tokio::test]
async fn rejected_edits_leave_the_stored_record_untouched() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("reject-edit.db")).await;
    let service = service(database.clone(), false);
    let cipher = AesGcmCipher::new(&MASTER_KEY);

    let created = service
        .create(create_request(
            "primary",
            "https://api.example.com",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create provider");
    let id = created.provider().id();

    let cases = [
        (
            UpdateProviderRequest::new().with_name("bad\nname"),
            ProviderServiceError::InvalidName,
        ),
        (
            UpdateProviderRequest::new().with_endpoint("http://api.example.com"),
            ProviderServiceError::InsecureEndpoint,
        ),
        (
            UpdateProviderRequest::new().with_endpoint("https://api.example.com?token=leak"),
            ProviderServiceError::InvalidEndpoint,
        ),
        (
            UpdateProviderRequest::new().with_upstream_api_key(SecretString::new("")),
            ProviderServiceError::InvalidUpstreamApiKey,
        ),
    ];

    for (request, expected) in cases {
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("leak"));
        let error = service
            .update(id, request)
            .await
            .expect_err("edit is rejected");
        assert_eq!(error, expected);
    }

    let stored = database
        .find_by_id(id)
        .await
        .expect("find provider by id")
        .expect("provider exists");
    assert_eq!(stored.name(), "primary");
    assert_eq!(stored.endpoint().as_str(), "https://api.example.com/");
    assert_eq!(decrypt(&cipher, &stored), UPSTREAM_KEY);
    assert_eq!(stored.status(), ProviderStatus::Enabled);
}

#[tokio::test]
async fn editing_or_deleting_a_missing_provider_reports_not_found() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("missing.db")).await;
    let service = service(database.clone(), false);
    let missing = ProviderId::try_from(i64::MAX).expect("positive ID");

    assert_eq!(
        service
            .update(missing, UpdateProviderRequest::new().with_name("ghost"))
            .await
            .expect_err("editing a missing provider fails"),
        ProviderServiceError::NotFound
    );
    assert_eq!(
        service
            .delete(missing)
            .await
            .expect_err("deleting a missing provider fails"),
        ProviderServiceError::NotFound
    );
}

#[tokio::test]
async fn delete_removes_unreferenced_provider_and_refuses_referenced_one() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("delete.db")).await;
    let service = service(database.clone(), false);

    let removable = service
        .create(create_request(
            "removable",
            "https://removable.example.com",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create removable provider");
    let referenced = service
        .create(create_request(
            "referenced",
            "https://referenced.example.com",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create referenced provider");

    service
        .delete(removable.provider().id())
        .await
        .expect("delete unreferenced provider");
    assert!(
        database
            .find_by_id(removable.provider().id())
            .await
            .expect("find deleted provider")
            .is_none()
    );

    database
        .insert_started(RequestLogStarted::new(
            RequestId::new("req-delete-guard").expect("non-empty request id"),
            referenced.provider().id(),
            ProtocolType::OpenAi,
            TransportType::Http,
            "/v1/chat/completions".to_owned(),
            Utc::now(),
        ))
        .await
        .expect("record a request log referencing the provider");

    assert_eq!(
        service
            .delete(referenced.provider().id())
            .await
            .expect_err("referenced provider cannot be deleted"),
        ProviderServiceError::InUse
    );
    assert!(
        database
            .find_by_id(referenced.provider().id())
            .await
            .expect("find referenced provider")
            .is_some(),
        "a refused delete must leave the provider in place"
    );
}

#[test]
fn edit_request_debug_redacts_endpoint_and_key() {
    let request = UpdateProviderRequest::new()
        .with_endpoint("https://api.example.com?token=hidden")
        .with_upstream_api_key(SecretString::new("sk-secret-value"));
    let rendered = format!("{request:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("hidden"));
    assert!(!rendered.contains("sk-secret-value"));
}
