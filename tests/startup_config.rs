use std::process::Command;

#[test]
fn startup_fails_safely_before_listening_when_configuration_is_missing() {
    let output = Command::new(env!("CARGO_BIN_EXE_tokenstream"))
        .env_clear()
        .output()
        .expect("run tokenstream binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(stderr.contains("TOKENSTREAM_DATA_LISTEN_ADDR"));
    assert!(stderr.contains("missing"));
}

#[test]
fn startup_error_does_not_echo_an_invalid_secret() {
    let secret = "this-value-must-not-be-printed";
    let output = Command::new(env!("CARGO_BIN_EXE_tokenstream"))
        .env_clear()
        .env("TOKENSTREAM_DATA_LISTEN_ADDR", "127.0.0.1:3000")
        .env("TOKENSTREAM_ADMIN_LISTEN_ADDR", "127.0.0.1:3001")
        .env("TOKENSTREAM_DATABASE_URL", "sqlite::memory:")
        .env("TOKENSTREAM_MASTER_KEY", secret)
        .output()
        .expect("run tokenstream binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(stderr.contains("TOKENSTREAM_MASTER_KEY"));
    assert!(!stderr.contains(secret));
}
