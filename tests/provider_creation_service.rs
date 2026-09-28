use std::path::Path;

use tokenstream::crypto::{
    AesGcmCipher, Argon2GatewaySecretVerifier, GatewaySecretVerifier, SecretCipher,
};
use tokenstream::domain::{ProtocolType, ProviderStatus, SecretString};
use tokenstream::persistence::sqlite::SqliteDatabase;
use tokenstream::persistence::{ProviderListRequest, ProviderRepository};
use tokenstream::providers::{
    CreateProviderRequest, MAX_PROVIDER_NAME_LEN, ProviderService, ProviderServiceError,
};

const MASTER_KEY: [u8; 32] = [0x2a; 32];
const UPSTREAM_KEY: &str = "sk-upstream-secret-value";

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

fn request(name: &str, endpoint: &str, upstream_key: &str) -> CreateProviderRequest {
    CreateProviderRequest::new(
        name.to_owned(),
        ProtocolType::OpenAi,
        endpoint.to_owned(),
        SecretString::new(upstream_key),
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
async fn creates_provider_with_encrypted_key_and_one_time_credential() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("create.db")).await;
    let service = service(database.clone(), false);
    let cipher = AesGcmCipher::new(&MASTER_KEY);
    let verifier = Argon2GatewaySecretVerifier::new();

    let created = service
        .create(request(
            "  primary-openai  ",
            "https://api.example.com/gateway",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create provider");

    let provider = created.provider();
    assert!(provider.id().get() > 0);
    assert_eq!(provider.name(), "primary-openai");
    assert_eq!(provider.protocol_type(), ProtocolType::OpenAi);
    assert_eq!(
        provider.endpoint().as_str(),
        "https://api.example.com/gateway"
    );
    assert_eq!(provider.status(), ProviderStatus::Enabled);
    assert_eq!(
        provider.gateway_key_id(),
        created.gateway_credential().key_id()
    );

    assert!(
        verifier
            .verify(
                created.gateway_credential().secret(),
                provider.gateway_api_key_hash(),
            )
            .expect("verify credential hash")
    );

    let decrypted = cipher
        .decrypt(provider.upstream_api_key_ciphertext())
        .expect("decrypt stored upstream key");
    assert_eq!(decrypted.expose(), UPSTREAM_KEY);

    let stored = database
        .find_by_key_id(created.gateway_credential().key_id())
        .await
        .expect("lookup by key id")
        .expect("provider exists");
    assert_eq!(stored.id(), provider.id());

    let rendered = created.gateway_credential().render();
    assert!(rendered.contains(created.gateway_credential().key_id().as_str()));
    assert!(rendered.contains(created.gateway_credential().secret().expose()));
    assert!(
        !provider
            .gateway_api_key_hash()
            .expose()
            .contains(UPSTREAM_KEY)
    );
    assert!(!format!("{created:?}").contains(UPSTREAM_KEY));
}

#[tokio::test]
async fn rejected_requests_leave_no_record_and_echo_no_secret() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("reject.db")).await;
    let service = service(database.clone(), false);
    let secret = "sk-must-never-be-echoed";

    let cases = [
        (
            request("", "https://api.example.com", secret),
            ProviderServiceError::InvalidName,
        ),
        (
            request("   ", "https://api.example.com", secret),
            ProviderServiceError::InvalidName,
        ),
        (
            request("bad\nname", "https://api.example.com", secret),
            ProviderServiceError::InvalidName,
        ),
        (
            request(
                &"n".repeat(MAX_PROVIDER_NAME_LEN + 1),
                "https://api.example.com",
                secret,
            ),
            ProviderServiceError::InvalidName,
        ),
        (
            request("plain-http", "http://api.example.com", secret),
            ProviderServiceError::InsecureEndpoint,
        ),
        (
            request("wrong-scheme", "ftp://api.example.com", secret),
            ProviderServiceError::InvalidEndpoint,
        ),
        (
            request("no-host", "https://", secret),
            ProviderServiceError::InvalidEndpoint,
        ),
        (
            request("query", "https://api.example.com?token=hidden", secret),
            ProviderServiceError::InvalidEndpoint,
        ),
        (
            request("fragment", "https://api.example.com#frag", secret),
            ProviderServiceError::InvalidEndpoint,
        ),
        (
            request("userinfo", "https://user:pass@api.example.com", secret),
            ProviderServiceError::InvalidEndpoint,
        ),
        (
            request("empty-key", "https://api.example.com", ""),
            ProviderServiceError::InvalidUpstreamApiKey,
        ),
        (
            request("control-key", "https://api.example.com", "sk-with\nnewline"),
            ProviderServiceError::InvalidUpstreamApiKey,
        ),
    ];

    for (candidate, expected) in cases {
        let rendered = format!("{candidate:?}");
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("hidden"));
        let error = service
            .create(candidate)
            .await
            .expect_err("request is rejected");
        assert_eq!(error, expected);
        assert!(!error.to_string().contains(secret));
        assert_eq!(provider_count(&database).await, 0);
    }
}

#[tokio::test]
async fn duplicate_name_conflicts_without_adding_a_record() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("conflict.db")).await;
    let service = service(database.clone(), false);

    service
        .create(request("primary", "https://api.example.com", UPSTREAM_KEY))
        .await
        .expect("create first provider");

    let error = service
        .create(request(
            "primary",
            "https://other.example.com",
            "other-secret",
        ))
        .await
        .expect_err("duplicate name is rejected");
    assert_eq!(error, ProviderServiceError::Conflict);
    assert_eq!(provider_count(&database).await, 1);
}

#[tokio::test]
async fn development_mode_admits_plain_http_endpoints() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = sqlite_database(&directory.path().join("dev.db")).await;
    let service = service(database.clone(), true);
    assert!(service.allows_insecure_endpoints());

    let created = service
        .create(request(
            "dev-upstream",
            "http://127.0.0.1:8080/base",
            UPSTREAM_KEY,
        ))
        .await
        .expect("create provider over plain HTTP in development mode");
    assert_eq!(
        created.provider().endpoint().as_str(),
        "http://127.0.0.1:8080/base"
    );
}
