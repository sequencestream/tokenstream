use std::path::Path;

use tokenstream::credentials::{CreateApiKeyRequest, CredentialService};
use tokenstream::crypto::{Argon2GatewaySecretVerifier, GatewaySecretVerifier, SecretCipher};
use tokenstream::domain::{
    ApiKeyId, ApiKeyStatus, ProtocolType, ProviderSnapshot, ProviderStatus, SecretString,
};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{ApiKeyRepository, ProviderRepository};
use tokenstream::providers::{CreateProviderRequest, ProviderService};

#[path = "../support/mod.rs"]
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

fn master_config(dir: &Path, url: &str, external: Option<u8>) -> tokenstream::config::Config {
    let mut values = std::collections::HashMap::from([
        ("TOKENSTREAM_DATABASE_URL".to_owned(), url.to_owned()),
        (
            "TOKENSTREAM_ADMIN_PASSWORD_HASH".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA".to_owned(),
        ),
    ]);
    if let Some(byte) = external {
        values.insert(
            "TOKENSTREAM_MASTER_KEY".to_owned(),
            format!("{byte:02x}").repeat(32),
        );
    }
    tokenstream::config::Config::from_settings(&values)
        .expect("config")
        .with_data_dir(Some(dir.to_owned()))
}

fn master_provider(name: &str) -> CreateProviderRequest {
    CreateProviderRequest::new(
        name.to_owned(),
        ProtocolType::OpenAi,
        "https://upstream.example".to_owned(),
        SecretString::new(UPSTREAM_KEY),
        ProviderStatus::Enabled,
    )
}

#[tokio::test]
async fn partial_master_rotation_is_readable_and_resumes_after_restart() {
    use tokenstream::crypto::SharedCipher;
    use tokenstream::providers::ProviderServiceError;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("master.db");
    let url = format!("sqlite://{}", path.display());
    let config = master_config(directory.path(), &url, Some(0x11));
    let database = sqlite_database(&path).await;
    let cipher = SharedCipher::new(config.master_key().expose());
    let service = ProviderService::new(database.clone(), cipher.clone(), false);
    let first = service.create(master_provider("first")).await.unwrap();
    let second = service.create(master_provider("second")).await.unwrap();
    // A deterministic storage fault after the first provider was committed.
    sqlx::query(&format!("CREATE TRIGGER stop_rotation BEFORE UPDATE OF upstream_api_key_ciphertext ON ts_provider WHEN OLD.id = {} BEGIN SELECT RAISE(ABORT, 'injected failure'); END", second.id().get())).execute(database.pool()).await.unwrap();
    assert!(
        service
            .rotate_master_key(&config, &[0x22; 32])
            .await
            .is_err()
    );
    let record = tokenstream::local_state::load_key_rotation(directory.path())
        .unwrap()
        .unwrap();
    assert!(!record.complete);
    let a = service.get(first.id()).await.unwrap();
    let b = service.get(second.id()).await.unwrap();
    assert!(a.upstream_api_key_ciphertext().expose().starts_with("v2."));
    assert!(b.upstream_api_key_ciphertext().expose().starts_with("v1."));
    for provider in [&a, &b] {
        assert_eq!(
            cipher
                .decrypt(provider.upstream_api_key_ciphertext())
                .unwrap()
                .expose(),
            UPSTREAM_KEY
        );
    }
    assert_eq!(
        service
            .rotate_master_key(&config, &[0x33; 32])
            .await
            .unwrap_err(),
        ProviderServiceError::Conflict
    );
    sqlx::query("DROP TRIGGER stop_rotation")
        .execute(database.pool())
        .await
        .unwrap();
    // Reconstruct runtime state using the stale external source, as a restart does.
    let restarted_cipher = SharedCipher::new(config.master_key().expose());
    let restarted = ProviderService::new(database.clone(), restarted_cipher.clone(), false);
    restarted.recover_master_key(&config).await.unwrap();
    assert!(
        tokenstream::local_state::load_key_rotation(directory.path())
            .unwrap()
            .unwrap()
            .complete
    );
    for id in [first.id(), second.id()] {
        let provider = restarted.get(id).await.unwrap();
        assert!(
            provider
                .upstream_api_key_ciphertext()
                .expose()
                .starts_with("v2.")
        );
        assert_eq!(
            restarted_cipher
                .decrypt(provider.upstream_api_key_ciphertext())
                .unwrap()
                .expose(),
            UPSTREAM_KEY
        );
    }
    restarted
        .rotate_master_key(&config, &[0x22; 32])
        .await
        .unwrap();
    assert_eq!(
        restarted
            .rotate_master_key(&config, &[0x33; 32])
            .await
            .unwrap_err(),
        ProviderServiceError::Conflict
    );
    let acknowledged = master_config(directory.path(), &url, Some(0x22));
    restarted
        .rotate_master_key(&acknowledged, &[0x33; 32])
        .await
        .unwrap();
    let record = tokenstream::local_state::load_key_rotation(directory.path())
        .unwrap()
        .unwrap();
    assert_eq!(record.ring.current.version, 3);
    assert_eq!(record.ring.previous.as_ref().unwrap().version, 2);
    assert!(
        restarted.recover_master_key(&config).await.is_err(),
        "retired external key cannot reopen the deployment"
    );
    let other_database = master_config(directory.path(), "sqlite://different.db", Some(0x33));
    assert!(
        restarted.recover_master_key(&other_database).await.is_err(),
        "recovery is bound to one database"
    );
}

#[tokio::test]
async fn rotation_keeps_readers_running_and_sheds_concurrent_secret_writers() {
    use tokenstream::crypto::SharedCipher;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("concurrent.db");
    let config = master_config(
        directory.path(),
        &format!("sqlite://{}", path.display()),
        Some(0x11),
    );
    let database = SqliteDatabase::connect_with_bounds(
        &format!("sqlite://{}", path.display()),
        tokenstream::persistence::DatabaseBounds {
            max_connections: 4,
            auth_connections: 2,
            ..tokenstream::persistence::DatabaseBounds::for_tests(4)
        },
    )
    .await
    .unwrap();
    database.migrate().await.unwrap();
    let cipher = SharedCipher::new(config.master_key().expose());
    let service = std::sync::Arc::new(ProviderService::new(
        database.clone(),
        cipher.clone(),
        false,
    ));
    let provider = service.create(master_provider("primary")).await.unwrap();
    let accounts = credentials(database.clone());
    let account = bootstrap_account(&accounts).await;
    let issued = support::issue_api_key(&accounts, account.id(), vec![provider.id()]).await;
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        hyper::header::AUTHORIZATION,
        format!("Bearer {}", issued.credential().render())
            .parse()
            .unwrap(),
    );
    let authenticator = tokenstream::auth::GatewayAuthenticator::new(
        database.clone(),
        cipher.clone(),
        Argon2GatewaySecretVerifier::new(),
    );
    let mut blocked = database.auth_pool().begin().await.unwrap();
    sqlx::query("UPDATE ts_provider SET name = name")
        .execute(&mut *blocked)
        .await
        .unwrap();
    let rotating = service.clone();
    let rotate_config = config.clone();
    let task = tokio::spawn(async move {
        rotating
            .rotate_master_key(&rotate_config, &[0x22; 32])
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while cipher.ring().current.version != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        service
            .create(master_provider("blocked-writer"))
            .await
            .unwrap_err(),
        tokenstream::providers::ProviderServiceError::Busy
    );
    let snapshot = authenticator.authenticate(&headers).await.unwrap();
    assert_eq!(snapshot.upstream_api_key().expose(), UPSTREAM_KEY);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    blocked.rollback().await.unwrap();
    // Cancelled migration leaves a recoverable journal, not an untracked partial write.
    let restarted = ProviderService::new(
        database.clone(),
        SharedCipher::new(config.master_key().expose()),
        false,
    );
    restarted.recover_master_key(&config).await.unwrap();
    assert_eq!(snapshot.upstream_api_key().expose(), UPSTREAM_KEY);
    restarted
        .create(master_provider("after-recovery"))
        .await
        .unwrap();
}

#[tokio::test]
async fn rotation_persistence_failure_changes_neither_runtime_nor_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("persistence.db");
    let config = master_config(
        directory.path(),
        &format!("sqlite://{}", path.display()),
        None,
    );
    let database = sqlite_database(&path).await;
    let cipher = tokenstream::crypto::SharedCipher::new(config.master_key().expose());
    let service = ProviderService::new(database, cipher.clone(), false);
    let provider = service.create(master_provider("primary")).await.unwrap();
    std::fs::create_dir(directory.path().join("master.rotation.json")).unwrap();
    assert!(
        service
            .rotate_master_key(&config, &[0x22; 32])
            .await
            .is_err()
    );
    assert_eq!(cipher.ring().current.version, 1);
    let unchanged = service.get(provider.id()).await.unwrap();
    assert_eq!(
        provider.upstream_api_key_ciphertext().expose(),
        unchanged.upstream_api_key_ciphertext().expose()
    );
    std::fs::remove_dir(directory.path().join("master.rotation.json")).unwrap();
    service
        .rotate_master_key(&config, &[0x22; 32])
        .await
        .unwrap();
    service
        .rotate_master_key(&config, &[0x33; 32])
        .await
        .unwrap();
    service
        .rotate_master_key(&config, &[0x44; 32])
        .await
        .unwrap();
    let record = tokenstream::local_state::load_key_rotation(directory.path())
        .unwrap()
        .unwrap();
    assert_eq!(record.ring.current.version, 4);
    assert_eq!(record.ring.previous.as_ref().unwrap().version, 3);
    // The completed journal also repairs failure of the final ordinary-key write.
    std::fs::remove_file(directory.path().join("master.key")).unwrap();
    std::fs::create_dir(directory.path().join("master.key")).unwrap();
    assert!(
        service
            .rotate_master_key(&config, &[0x55; 32])
            .await
            .is_err()
    );
    assert!(
        tokenstream::local_state::load_key_rotation(directory.path())
            .unwrap()
            .unwrap()
            .complete
    );
    assert_eq!(cipher.ring().current.version, 5);
    std::fs::remove_dir(directory.path().join("master.key")).unwrap();
    service
        .rotate_master_key(&config, &[0x55; 32])
        .await
        .unwrap();
    assert_eq!(
        tokenstream::local_state::load_master_key_file(directory.path())
            .unwrap()
            .unwrap(),
        "55".repeat(32)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(directory.path().join("master.rotation.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn postgres_partial_master_rotation_resumes_with_the_previous_external_key() {
    use tokenstream::crypto::SharedCipher;
    use tokenstream::persistence::postgres::PostgresDatabase;
    let url = support::require_postgres_url("master-key recovery equivalence");
    let administrative = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!(
        "rotation_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&administrative)
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    let database = PostgresDatabase::connect(scoped.as_str(), 3).await.unwrap();
    database.migrate().await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = master_config(directory.path(), scoped.as_str(), Some(0x11));
    let cipher = SharedCipher::new(config.master_key().expose());
    let service = ProviderService::new(database.clone(), cipher, false);
    let first = service.create(master_provider("first")).await.unwrap();
    let second = service.create(master_provider("second")).await.unwrap();
    sqlx::query(&format!("CREATE FUNCTION stop_rotation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.id = {} THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$", second.id().get())).execute(database.pool()).await.unwrap();
    sqlx::query("CREATE TRIGGER stop_rotation BEFORE UPDATE OF upstream_api_key_ciphertext ON ts_provider FOR EACH ROW EXECUTE FUNCTION stop_rotation()").execute(database.pool()).await.unwrap();
    assert!(
        service
            .rotate_master_key(&config, &[0x22; 32])
            .await
            .is_err()
    );
    assert!(
        !tokenstream::local_state::load_key_rotation(directory.path())
            .unwrap()
            .unwrap()
            .complete
    );
    assert!(
        service
            .get(first.id())
            .await
            .unwrap()
            .upstream_api_key_ciphertext()
            .expose()
            .starts_with("v2.")
    );
    assert!(
        service
            .get(second.id())
            .await
            .unwrap()
            .upstream_api_key_ciphertext()
            .expose()
            .starts_with("v1.")
    );
    sqlx::query("DROP TRIGGER stop_rotation ON ts_provider")
        .execute(database.pool())
        .await
        .unwrap();
    let restarted_cipher = SharedCipher::new(config.master_key().expose());
    let restarted = ProviderService::new(database.clone(), restarted_cipher.clone(), false);
    restarted.recover_master_key(&config).await.unwrap();
    for id in [first.id(), second.id()] {
        let provider = restarted.get(id).await.unwrap();
        assert!(
            provider
                .upstream_api_key_ciphertext()
                .expose()
                .starts_with("v2.")
        );
        assert_eq!(
            restarted_cipher
                .decrypt(provider.upstream_api_key_ciphertext())
                .unwrap()
                .expose(),
            UPSTREAM_KEY
        );
    }
    database.pool().close().await;
    database.auth_pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administrative)
        .await
        .unwrap();
    administrative.close().await;
}

#[tokio::test]
async fn cancelled_secret_writes_settle_before_a_generation_switch() {
    use tokenstream::crypto::SharedCipher;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cancelled-write.db");
    let url = format!("sqlite://{}", path.display());
    let config = tokenstream::config::Config::from_settings(&std::collections::HashMap::from([
        ("TOKENSTREAM_DATABASE_URL".to_owned(), url),
        (
            "TOKENSTREAM_ADMIN_DB_TIMEOUT_MS".to_owned(),
            "500".to_owned(),
        ),
        (
            "TOKENSTREAM_ADMIN_PASSWORD_HASH".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA".to_owned(),
        ),
    ]))
    .unwrap()
    .with_data_dir(Some(directory.path().to_owned()));
    let database = sqlite_database(&path).await;
    let cipher = SharedCipher::new(config.master_key().expose());
    let service = std::sync::Arc::new(ProviderService::new(
        database.clone(),
        cipher.clone(),
        false,
    ));
    let mut blocked = database.pool().begin().await.unwrap();
    sqlx::query("INSERT INTO ts_provider (name, protocol_type, endpoint, upstream_api_key_ciphertext, status, created_at) VALUES ('lock-holder', 'openai', 'https://example.com', 'temporary', 'enabled', 0)").execute(&mut *blocked).await.unwrap();
    let writing = service.clone();
    let writer =
        tokio::spawn(async move { writing.create(master_provider("cancelled-writer")).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while database.pool().num_idle() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());
    assert_eq!(
        service
            .rotate_master_key(&config, &[0x22; 32])
            .await
            .unwrap_err(),
        tokenstream::providers::ProviderServiceError::Busy
    );
    assert_eq!(cipher.ring().current.version, 1);
    assert!(
        tokenstream::local_state::load_key_rotation(directory.path())
            .unwrap()
            .is_none()
    );
    blocked.rollback().await.unwrap();
    service
        .rotate_master_key(&config, &[0x22; 32])
        .await
        .unwrap();
    service
        .rotate_master_key(&config, &[0x33; 32])
        .await
        .unwrap();
    let page = service
        .list(tokenstream::persistence::ProviderListRequest::new(None, 100).unwrap())
        .await
        .unwrap();
    for provider in page.items() {
        assert!(
            provider
                .upstream_api_key_ciphertext()
                .expose()
                .starts_with("v3.")
        );
        assert_eq!(
            cipher
                .decrypt(provider.upstream_api_key_ciphertext())
                .unwrap()
                .expose(),
            UPSTREAM_KEY
        );
    }
}
