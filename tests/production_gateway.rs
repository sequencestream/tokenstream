use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};

#[test]
fn production_process_relays_http_tls_and_websocket_and_drains_sessions() {
    let hash = Argon2::default()
        .hash_password(
            b"test-admin",
            &SaltString::encode_b64(b"production-test-salt").unwrap(),
        )
        .unwrap()
        .to_string();
    let output = std::process::Command::new("python3")
        .arg("tests/support/production_gateway.py")
        .env("GATEWAY_BINARY", env!("CARGO_BIN_EXE_tokenstream"))
        .env("TEST_ADMIN_HASH", hash)
        .output()
        .expect("Python 3 and OpenSSL are required for local TLS process contracts");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
