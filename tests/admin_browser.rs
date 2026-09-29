//! Real-browser administration acceptance is a release check: a successful
//! frontend build cannot substitute for sign-in, session, credential, and
//! filter interaction against a running control plane.

use std::path::Path;
use std::process::Command;

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};

#[test]
fn real_browser_accepts_hosted_and_proxied_administration_pages() {
    let hash = Argon2::default()
        .hash_password(
            b"test-admin",
            &SaltString::encode_b64(b"admin-browser-salt").unwrap(),
        )
        .unwrap()
        .to_string();

    if !Path::new("web/node_modules/playwright").exists() {
        run(Command::new("npm").args(["--prefix", "web", "ci"]));
    }
    run(Command::new("npx")
        .current_dir("web")
        .args(["playwright", "install", "chromium"]));
    run(Command::new("npm").args(["--prefix", "web", "run", "build"]));
    run(Command::new("node")
        .arg("web/e2e/run.mjs")
        .env("GATEWAY_BINARY", env!("CARGO_BIN_EXE_tokenstream"))
        .env("TEST_ADMIN_HASH", hash)
        .env("TEST_ADMIN_PASSWORD", "test-admin"));
}

fn run(command: &mut Command) {
    let output = command.output().expect("browser acceptance command starts");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
