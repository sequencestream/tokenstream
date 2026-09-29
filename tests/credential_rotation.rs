use std::path::Path;

use tokenstream::credentials::{CreateApiKeyRequest, CredentialService};
use tokenstream::crypto::{Argon2GatewaySecretVerifier, GatewaySecretVerifier, SecretCipher};
use tokenstream::domain::{
    ApiKeyId, ApiKeyStatus, ProtocolType, ProviderSnapshot, ProviderStatus, SecretString,
};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{ApiKeyRepository, ProviderRepository};
use tokenstream::providers::{CreateProviderRequest, ProviderService};

mod support;
use support::bootstrap_account;

const UPSTREAM_KEY: &str = "sk-rotation-upstream-key";

async fn sqlite_database(path: &Path) -> SqliteDatabase {
    let url = format!("sqlite://{}", path.display());
    let database = SqliteDatabase::connect(&url, 2)
        .await
        .expect("connect to SQLite");
    database.migrate().await.expect("migrate SQLite");
    database
}

fn providers(
    database: SqliteDatabase,
) -> ProviderService<SqliteDatabase, tokenstream::crypto::AesGcmCipher> {
    ProviderService::new(
        database,
        tokenstream::crypto::AesGcmCipher::new(&[0x3d; 32]),
        false,
    )
}

fn credentials(
    database: SqliteDatabase,
) -> CredentialService<SqliteDatabase, Argon2GatewaySecretVerifier> {
    CredentialService::new(database, Argon2GatewaySecretVerifier::new())
}

async fn provider(
    service: &ProviderService<SqliteDatabase, tokenstream::crypto::AesGcmCipher>,
    name: &str,
) -> tokenstream::domain::Provider {
    service
        .create(CreateProviderRequest::new(
            name.to_owned(),
            ProtocolType::OpenAi,
            "https://api.example.com/base".to_owned(),
            SecretString::new(UPSTREAM_KEY),
            ProviderStatus::Enabled,
        ))
        .await
        .expect("create provider")
}

#[tokio::test]
async fn rotation_replaces_the_secret_and_retires_the_previous_credential() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("rotate.db")).await;
    let service = providers(database.clone());
    let accounts = credentials(database.clone());
    let verifier = Argon2GatewaySecretVerifier::new();
    let account = bootstrap_account(&accounts).await;

    let provider = provider(&service, "primary").await;
    let issued = accounts
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "ci".to_owned(),
            vec![provider.id()],
            Some(provider.id()),
            None,
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect("issue a credential");
    let id = issued.api_key().api_key().id();
    let old_key_id = issued.api_key().api_key().key_id().clone();
    let old_secret = issued.credential().secret().clone();
    let old_hash = issued.api_key().api_key().secret_hash().clone();

    let rotated = accounts
        .rotate_api_key(id)
        .await
        .expect("rotate the credential");
    let new_key_id = rotated.api_key().api_key().key_id().clone();
    let new_secret = rotated.credential().secret().clone();
    let new_hash = rotated.api_key().api_key().secret_hash().clone();

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

    let stored = rotated.api_key().api_key();
    assert_eq!(stored.id(), id);
    assert_eq!(stored.account_id(), account.id());
    assert_eq!(stored.name(), "ci");
    assert_eq!(stored.status(), ApiKeyStatus::Enabled);
    // Rotation replaces only the secret; bindings and owner are untouched.
    assert_eq!(stored.default_provider_id(), Some(provider.id()));
    assert_eq!(rotated.api_key().bindings().len(), 1);
    assert_eq!(rotated.api_key().bindings()[0].provider_id, provider.id());

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
        ApiKeyRepository::find_by_key_id(&database, &old_key_id)
            .await
            .expect("lookup retired key id")
            .is_none(),
        "the retired key id must no longer resolve"
    );
    let found = ApiKeyRepository::find_by_key_id(&database, &new_key_id)
        .await
        .expect("lookup rotated key id")
        .expect("rotated key id resolves");
    assert_eq!(found.api_key().id(), id);

    let rendered = format!("{rotated:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(new_secret.expose()));

    let again = accounts.rotate_api_key(id).await.expect("rotate again");
    assert_ne!(again.api_key().api_key().key_id(), &new_key_id);
    assert!(
        verifier
            .verify(
                again.credential().secret(),
                again.api_key().api_key().secret_hash()
            )
            .expect("verify second rotation")
    );
}

#[tokio::test]
async fn rotation_leaves_an_established_snapshot_untouched() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("snapshot.db")).await;
    let service = providers(database.clone());
    let accounts = credentials(database.clone());
    let cipher = tokenstream::crypto::AesGcmCipher::new(&[0x3d; 32]);
    let account = bootstrap_account(&accounts).await;

    let provider = provider(&service, "primary").await;
    let issued = accounts
        .create_api_key(CreateApiKeyRequest::new(
            account.id(),
            "ci".to_owned(),
            vec![provider.id()],
            Some(provider.id()),
            None,
            ApiKeyStatus::Enabled,
        ))
        .await
        .expect("issue a credential");

    // The snapshot an admitted request would already hold.
    let snapshot = ProviderSnapshot::new(
        account.id(),
        issued.api_key().api_key().id(),
        provider.id(),
        provider.protocol_type(),
        provider.endpoint().clone(),
        cipher
            .decrypt(provider.upstream_api_key_ciphertext())
            .expect("decrypt upstream key for snapshot"),
    );
    let ciphertext_before = provider.upstream_api_key_ciphertext().clone();

    accounts
        .rotate_api_key(issued.api_key().api_key().id())
        .await
        .expect("rotate the credential");

    assert_eq!(
        snapshot.upstream_api_key().expose(),
        UPSTREAM_KEY,
        "an established snapshot keeps its decrypted upstream key"
    );
    let stored = ProviderRepository::find_by_id(&database, provider.id())
        .await
        .expect("find provider")
        .expect("provider exists");
    assert_eq!(
        stored.upstream_api_key_ciphertext().expose(),
        ciphertext_before.expose()
    );
}

#[tokio::test]
async fn rotating_a_missing_credential_reports_not_found() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("missing.db")).await;
    let accounts = credentials(database);
    let missing = ApiKeyId::try_from(i64::MAX).expect("positive ID");

    assert_eq!(
        accounts
            .rotate_api_key(missing)
            .await
            .expect_err("rotating a missing credential is refused")
            .to_string(),
        "record was not found"
    );
}
