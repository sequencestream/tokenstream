use std::path::Path;

use tokenstream::crypto::{
    AesGcmCipher, Argon2GatewaySecretVerifier, GatewaySecretVerifier, SecretCipher,
};
use tokenstream::domain::{
    ProtocolType, ProviderId, ProviderSnapshot, ProviderStatus, SecretString,
};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{ProviderListRequest, ProviderRepository};
use tokenstream::providers::{CreateProviderRequest, ProviderService, ProviderServiceError};

const MASTER_KEY: [u8; 32] = [0x3d; 32];
const UPSTREAM_KEY: &str = "sk-rotation-upstream-key";

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
) -> ProviderService<SqliteDatabase, AesGcmCipher, Argon2GatewaySecretVerifier> {
    ProviderService::new(
        database,
        AesGcmCipher::new(&MASTER_KEY),
        Argon2GatewaySecretVerifier::new(),
        false,
    )
}

fn create_request(name: &str, endpoint: &str) -> CreateProviderRequest {
    CreateProviderRequest::new(
        name.to_owned(),
        ProtocolType::OpenAi,
        endpoint.to_owned(),
        SecretString::new(UPSTREAM_KEY),
        ProviderStatus::Enabled,
    )
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
async fn rotation_replaces_key_material_and_retires_the_old_credential() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("rotate.db")).await;
    let service = service(database.clone());
    let verifier = Argon2GatewaySecretVerifier::new();

    let created = service
        .create(create_request("primary", "https://api.example.com/base"))
        .await
        .expect("create provider");
    let id = created.provider().id();
    let old_key_id = created.gateway_credential().key_id().clone();
    let old_secret = created.gateway_credential().secret().clone();
    let old_hash = created.provider().gateway_api_key_hash().clone();
    let ciphertext_before = created.provider().upstream_api_key_ciphertext().clone();
    let created_at = created.provider().created_at();

    let rotated = service
        .rotate_gateway_credential(id)
        .await
        .expect("rotate gateway credential");
    let new_key_id = rotated.gateway_credential().key_id().clone();
    let new_secret = rotated.gateway_credential().secret().clone();
    let new_hash = rotated.provider().gateway_api_key_hash().clone();

    assert_ne!(new_key_id, old_key_id, "rotation issues a fresh key id");
    assert_ne!(
        new_secret.expose(),
        old_secret.expose(),
        "rotation issues a fresh secret"
    );
    assert_ne!(
        new_hash.expose(),
        old_hash.expose(),
        "rotation stores a new hash"
    );
    assert_eq!(rotated.provider().gateway_key_id(), &new_key_id);

    let stored_provider = rotated.provider();
    assert_eq!(stored_provider.id(), id);
    assert_eq!(stored_provider.name(), "primary");
    assert_eq!(
        stored_provider.endpoint().as_str(),
        "https://api.example.com/base"
    );
    assert_eq!(stored_provider.status(), ProviderStatus::Enabled);
    assert_eq!(stored_provider.created_at(), created_at);
    assert_eq!(
        stored_provider.upstream_api_key_ciphertext().expose(),
        ciphertext_before.expose(),
        "rotation must not touch the encrypted upstream key"
    );

    assert!(
        verifier
            .verify(&new_secret, &new_hash)
            .expect("verify rotated secret"),
        "the rotated secret must verify against the stored hash"
    );
    assert!(
        !verifier
            .verify(&old_secret, &new_hash)
            .expect("verify retired secret"),
        "the retired secret must no longer verify"
    );
    assert!(
        !new_hash.expose().contains(new_secret.expose()),
        "the stored hash must not contain the secret"
    );

    assert!(
        database
            .find_by_key_id(&old_key_id)
            .await
            .expect("lookup retired key id")
            .is_none(),
        "the retired key id must no longer resolve"
    );
    let found = database
        .find_by_key_id(&new_key_id)
        .await
        .expect("lookup rotated key id")
        .expect("rotated key id resolves");
    assert_eq!(found.id(), id);
    assert_eq!(provider_count(&database).await, 1);

    let rendered = format!("{rotated:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(new_secret.expose()));

    let again = service
        .rotate_gateway_credential(id)
        .await
        .expect("rotate again");
    assert_ne!(again.gateway_credential().key_id(), &new_key_id);
    assert!(
        verifier
            .verify(
                again.gateway_credential().secret(),
                again.provider().gateway_api_key_hash()
            )
            .expect("verify second rotation")
    );
    assert_eq!(provider_count(&database).await, 1);
}

#[tokio::test]
async fn rotation_leaves_an_established_snapshot_and_upstream_key_untouched() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("snapshot.db")).await;
    let service = service(database.clone());
    let cipher = AesGcmCipher::new(&MASTER_KEY);

    let created = service
        .create(create_request("primary", "https://api.example.com"))
        .await
        .expect("create provider");
    let id = created.provider().id();
    let snapshot = ProviderSnapshot::new(
        id,
        created.provider().protocol_type(),
        created.provider().endpoint().clone(),
        cipher
            .decrypt(created.provider().upstream_api_key_ciphertext())
            .expect("decrypt upstream key for snapshot"),
    );
    let ciphertext_before = created.provider().upstream_api_key_ciphertext().clone();

    service
        .rotate_gateway_credential(id)
        .await
        .expect("rotate gateway credential");

    assert_eq!(
        snapshot.upstream_api_key().expose(),
        UPSTREAM_KEY,
        "an established snapshot keeps its decrypted upstream key"
    );
    let stored = database
        .find_by_id(id)
        .await
        .expect("find provider")
        .expect("provider exists");
    assert_eq!(
        stored.upstream_api_key_ciphertext().expose(),
        ciphertext_before.expose()
    );
    assert_eq!(
        cipher
            .decrypt(stored.upstream_api_key_ciphertext())
            .expect("decrypt stored upstream key")
            .expose(),
        UPSTREAM_KEY
    );
}

#[tokio::test]
async fn rotating_a_missing_provider_reports_not_found() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("missing.db")).await;
    let service = service(database);
    let missing = ProviderId::try_from(i64::MAX).expect("positive ID");

    assert_eq!(
        service
            .rotate_gateway_credential(missing)
            .await
            .expect_err("rotating a missing provider fails"),
        ProviderServiceError::NotFound
    );
}
