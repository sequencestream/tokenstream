//! Sustained mixed load profile executed against a real Tokenstream process.
//!
//! The component profile in `release_load_profile` bounds the proxy in
//! isolation. This profile drives the deployed process through its formal
//! listeners so admission, authentication, routing, database and logging are
//! all part of the measurement: default hashing, declared admission, mixed
//! short requests and long-lived streams, bounded HTTP reuse, and sampled
//! process resources.

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};

#[test]
fn real_process_sustains_mixed_load_with_bounded_memory() {
    let hash = Argon2::default()
        .hash_password(
            b"test-admin",
            &SaltString::encode_b64(b"tokenstream-load-profile").unwrap(),
        )
        .unwrap()
        .to_string();
    let output = std::process::Command::new("python3")
        .arg("tests/gateway_load_profile.py")
        .env("GATEWAY_BINARY", env!("CARGO_BIN_EXE_tokenstream"))
        .env("TEST_ADMIN_HASH", hash)
        .output()
        .expect("Python 3 is required for the real-process load profile");
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
