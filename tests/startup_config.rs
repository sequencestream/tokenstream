use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn startup_with_only_home_uses_compiled_defaults() {
    let directory = tempfile::tempdir().expect("temporary home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tokenstream"))
        .env_clear()
        .env("HOME", directory.path())
        .env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| String::new()),
        )
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("run tokenstream binary");

    let data_dir = directory.path().join(".tokenstream");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if data_dir.join("master.key").is_file() {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("gateway exited before writing defaults: {status}\n{stderr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        data_dir.join("master.key").is_file(),
        "expected a generated master key in the data directory"
    );
    assert!(
        data_dir.join("admin.hash").is_file(),
        "expected a persisted administrator password hash"
    );
}

#[test]
fn startup_error_does_not_echo_an_invalid_secret() {
    let secret = "this-value-must-not-be-printed";
    let output = Command::new(env!("CARGO_BIN_EXE_tokenstream"))
        .env_clear()
        .env("HOME", tempfile::tempdir().expect("home").path())
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
