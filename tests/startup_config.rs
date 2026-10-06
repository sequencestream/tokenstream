use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;

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
    let event: Value = serde_json::from_str(stderr.trim()).expect("single JSON diagnostic");
    assert_eq!(event["fields"]["event"], "process_start_failed");
    assert_eq!(event["fields"]["stage"], "configuration");
    assert_eq!(event["fields"]["setting"], "TOKENSTREAM_MASTER_KEY");
    assert!(stderr.contains("TOKENSTREAM_MASTER_KEY"));
    assert!(!stderr.contains(secret));
}

#[test]
fn invalid_log_filter_fails_with_a_sanitized_json_diagnostic() {
    let hostile = "authorization=Bearer-secret,payload=[";
    let output = Command::new(env!("CARGO_BIN_EXE_tokenstream"))
        .env_clear()
        .env("HOME", tempfile::tempdir().expect("home").path())
        .env("TOKENSTREAM_LOG_FILTER", hostile)
        .output()
        .expect("run tokenstream binary");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(stderr.lines().count(), 1);
    let event: Value = serde_json::from_str(stderr.trim()).expect("single JSON diagnostic");
    assert_eq!(event["level"], "ERROR");
    assert_eq!(event["target"], "tokenstream::process");
    assert_eq!(event["fields"]["event"], "process_start_failed");
    assert_eq!(event["fields"]["setting"], "TOKENSTREAM_LOG_FILTER");
    assert!(!stderr.contains(hostile));
    assert!(!stderr.contains("Bearer-secret"));
}

#[test]
fn explicit_filter_applies_to_structured_runtime_diagnostics() {
    let directory = tempfile::tempdir().expect("data directory");
    let secret_marker = "query-secret-must-not-appear";
    let missing_database = format!(
        "sqlite://{}/missing/tokenstream.db?mode=rwc&payload={secret_marker}",
        directory.path().display()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_tokenstream"))
        .env_clear()
        .env("HOME", directory.path())
        .env("TOKENSTREAM_DATA_DIR", directory.path())
        .env("TOKENSTREAM_DATABASE_URL", missing_database)
        .env("TOKENSTREAM_MASTER_KEY", "11".repeat(32))
        .env(
            "TOKENSTREAM_ADMIN_PASSWORD_HASH",
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
        )
        .env("TOKENSTREAM_LOG_FILTER", "warn")
        .output()
        .expect("run tokenstream binary");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(!stderr.contains(secret_marker));
    let events = stderr
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("JSON diagnostic"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1, "info events must be filtered out");
    let keys = events[0]
        .as_object()
        .expect("diagnostic object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(keys, ["fields", "level", "target", "timestamp"].into());
    assert_eq!(events[0]["level"], "ERROR");
    assert_eq!(events[0]["fields"]["event"], "process_start_failed");
    assert_eq!(events[0]["fields"]["error_kind"], "storage_unavailable");
    assert_eq!(
        events[0]["fields"]["message"],
        "Tokenstream failed to start."
    );
    assert!(events[0].get("span").is_none());
    assert!(events[0].get("spans").is_none());
}

#[test]
fn database_startup_emits_only_audited_diagnostics_for_permissive_filters() {
    for filter in [None, Some("trace"), Some("sqlx=trace,tokenstream=trace")] {
        let directory = tempfile::tempdir().expect("data directory");
        let database_path = directory.path().join("hostile-secret-marker.db");
        let data_address = unused_loopback_address();
        let admin_address = unused_loopback_address();
        let mut command = gateway_command(directory.path(), data_address, admin_address);
        command
            .env(
                "TOKENSTREAM_DATABASE_URL",
                format!("sqlite://{}?mode=rwc", database_path.display()),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(filter) = filter {
            command.env("TOKENSTREAM_LOG_FILTER", filter);
        }

        let mut child = command.spawn().expect("start gateway for filter check");
        // Derive readiness from the child's own final startup diagnostic instead
        // of probing the reserved port. A parallel test or process can take the
        // port after it is reserved, and a probe would then observe that foreign
        // listener and kill this child before it emits anything.
        let stderr = child.stderr.take().expect("diagnostic output");
        let stderr =
            capture_diagnostics_until(&mut child, stderr, "bootstrap_credential_delivered");

        assert!(!stderr.is_empty(), "expected diagnostics for {filter:?}");
        assert!(!stderr.contains("hostile-secret-marker"));
        assert!(!stderr.contains("db.statement"));
        assert!(!stderr.contains("CREATE TABLE"));
        assert!(!stderr.contains("SELECT "));
        for line in stderr.lines() {
            let event: Value = serde_json::from_str(line).expect("structured diagnostic");
            let keys = event
                .as_object()
                .expect("diagnostic object")
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(keys, ["fields", "level", "target", "timestamp"].into());
            assert!(event["fields"]["event"].is_string());
            assert!(event["fields"]["message"].is_string());
            assert!(
                event["target"]
                    .as_str()
                    .is_some_and(|target| target.starts_with("tokenstream::"))
            );
        }
    }
}

#[test]
fn fatal_startup_failure_is_not_silenced_by_a_disabling_filter() {
    let secret = "hostile-secret-marker";
    for filter in ["off", "tokenstream::process=off"] {
        let directory = tempfile::tempdir().expect("data directory");
        let output = Command::new(env!("CARGO_BIN_EXE_tokenstream"))
            .env_clear()
            .env("HOME", directory.path())
            .env("TOKENSTREAM_DATA_DIR", directory.path())
            .env(
                "TOKENSTREAM_DATABASE_URL",
                format!(
                    "sqlite://{}/{secret}/missing.db?mode=rwc",
                    directory.path().display()
                ),
            )
            .env("TOKENSTREAM_MASTER_KEY", "11".repeat(32))
            .env(
                "TOKENSTREAM_ADMIN_PASSWORD_HASH",
                "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
            )
            .env("TOKENSTREAM_LOG_FILTER", filter)
            .output()
            .expect("run tokenstream binary");

        assert!(
            !output.status.success(),
            "filter {filter:?} must not succeed"
        );
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
        assert_eq!(
            stderr.lines().count(),
            1,
            "filter {filter:?} must emit exactly one fatal diagnostic: {stderr:?}"
        );
        let event: Value = serde_json::from_str(stderr.trim()).expect("single JSON diagnostic");
        assert_eq!(event["level"], "ERROR");
        assert_eq!(event["target"], "tokenstream::process");
        assert_eq!(event["fields"]["event"], "process_start_failed");
        assert_eq!(event["fields"]["stage"], "database_connection");
        assert_eq!(event["fields"]["error_kind"], "storage_unavailable");
        assert!(
            !stderr.contains(filter),
            "filter value must not echo into the diagnostic: {stderr:?}"
        );
        assert!(
            !stderr.contains(secret),
            "failure context must not echo configuration: {stderr:?}"
        );
    }
}

#[test]
fn configured_and_default_admin_passwords_never_use_credential_output() {
    let explicit_dir = tempfile::tempdir().expect("explicit password directory");
    let explicit_password = "explicit-admin-secret-marker";
    let explicit_output = Command::new(env!("CARGO_BIN_EXE_tokenstream"))
        .env_clear()
        .env("HOME", explicit_dir.path())
        .env("TOKENSTREAM_DATA_DIR", explicit_dir.path())
        .env(
            "TOKENSTREAM_DATABASE_URL",
            format!(
                "sqlite://{}/missing/tokenstream.db?mode=rwc",
                explicit_dir.path().display()
            ),
        )
        .env("TOKENSTREAM_MASTER_KEY", "11".repeat(32))
        .env("TOKENSTREAM_ADMIN_PASSWORD", explicit_password)
        .output()
        .expect("run with explicit administrator password");
    assert!(!explicit_output.status.success());
    assert!(explicit_output.stdout.is_empty());
    assert!(
        !String::from_utf8(explicit_output.stderr)
            .expect("explicit stderr UTF-8")
            .contains(explicit_password)
    );

    let default_dir = tempfile::tempdir().expect("default password directory");
    let default_output = Command::new(env!("CARGO_BIN_EXE_tokenstream"))
        .env_clear()
        .env("HOME", default_dir.path())
        .env("TOKENSTREAM_DATA_DIR", default_dir.path())
        .env(
            "TOKENSTREAM_DATABASE_URL",
            format!(
                "sqlite://{}/missing/tokenstream.db?mode=rwc",
                default_dir.path().display()
            ),
        )
        .env("TOKENSTREAM_MASTER_KEY", "11".repeat(32))
        .output()
        .expect("run with default administrator password");
    assert!(!default_output.status.success());
    assert!(default_output.stdout.is_empty());
    let events = String::from_utf8(default_output.stderr)
        .expect("default stderr UTF-8")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("default JSON diagnostic"))
        .collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .any(|event| { event["fields"]["event"] == "default_admin_password_enabled" })
    );
    assert!(events.iter().all(|event| {
        !contains_exact_string(event, tokenstream::local_state::DEFAULT_ADMIN_PASSWORD)
    }));
}

#[test]
fn generated_bootstrap_password_is_output_only_for_the_first_creation() {
    let directory = tempfile::tempdir().expect("data directory");
    let data_address = unused_loopback_address();
    let admin_address = unused_loopback_address();
    let mut first = gateway_command(directory.path(), data_address, admin_address)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start first gateway");
    let stdout = first.stdout.take().expect("first stdout");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    let line = receiver
        .recv_timeout(Duration::from_secs(20))
        .expect("bootstrap credential output deadline")
        .expect("read bootstrap credential");
    let credential: Value = serde_json::from_str(line.trim()).expect("credential JSON");
    let password = credential["password"]
        .as_str()
        .expect("generated password")
        .to_owned();
    assert_eq!(credential["record"], "tokenstream_bootstrap_credential");
    assert!(!password.is_empty());
    wait_until_listening(&mut first, admin_address);
    assert_admin_login(admin_address, &password);
    let _ = first.kill();
    let first_output = first.wait_with_output().expect("finish first gateway");
    let first_stderr = String::from_utf8(first_output.stderr).expect("first stderr UTF-8");
    assert!(!first_stderr.contains(&password));

    let mut second = gateway_command(directory.path(), data_address, admin_address)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start second gateway");
    wait_until_listening(&mut second, admin_address);
    let _ = second.kill();
    let second_output = second.wait_with_output().expect("finish second gateway");
    assert!(second_output.stdout.is_empty());
    let second_stderr = String::from_utf8(second_output.stderr).expect("second stderr UTF-8");
    assert!(!second_stderr.contains(&password));
    for line in second_stderr.lines() {
        serde_json::from_str::<Value>(line).expect("structured stderr diagnostic");
    }
}

#[test]
fn bootstrap_stdout_failure_is_sanitized_and_not_replayed() {
    let directory = tempfile::tempdir().expect("data directory");
    let data_address = unused_loopback_address();
    let admin_address = unused_loopback_address();
    let mut first = gateway_command(directory.path(), data_address, admin_address)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start gateway with closed credential output");
    drop(first.stdout.take());
    let status = wait_until_exit(&mut first);
    assert!(!status.success());
    let mut stderr = String::new();
    first
        .stderr
        .take()
        .expect("failure stderr")
        .read_to_string(&mut stderr)
        .expect("read failure stderr");
    let events = stderr
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("structured failure diagnostic"))
        .collect::<Vec<_>>();
    assert!(events.iter().any(|event| {
        event["fields"]["event"] == "process_start_failed"
            && event["fields"]["stage"] == "bootstrap"
            && event["fields"]["error_kind"] == "credential_delivery_failed"
    }));
    assert!(!stderr.contains("password"));

    let mut second = gateway_command(directory.path(), data_address, admin_address)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("restart after credential delivery failure");
    wait_until_listening(&mut second, admin_address);
    let _ = second.kill();
    let output = second.wait_with_output().expect("finish restarted gateway");
    assert!(
        output.stdout.is_empty(),
        "a committed bootstrap credential cannot be replayed"
    );
}

fn unused_loopback_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback address")
        .local_addr()
        .expect("loopback address")
}

fn gateway_command(
    data_dir: &std::path::Path,
    data_address: SocketAddr,
    admin_address: SocketAddr,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tokenstream"));
    command
        .env_clear()
        .env("HOME", data_dir)
        .env("TOKENSTREAM_DATA_DIR", data_dir)
        .env("TOKENSTREAM_DATA_LISTEN_ADDR", data_address.to_string())
        .env("TOKENSTREAM_ADMIN_LISTEN_ADDR", admin_address.to_string())
        .env("TOKENSTREAM_MASTER_KEY", "11".repeat(32))
        .env(
            "TOKENSTREAM_ADMIN_PASSWORD_HASH",
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
        );
    command
}

fn wait_until_listening(child: &mut std::process::Child, address: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("gateway exited before listening: {status}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("gateway did not listen before the deadline");
}

fn capture_diagnostics_until(
    child: &mut std::process::Child,
    stderr: impl Read + Send + 'static,
    marker: &str,
) -> String {
    use std::sync::mpsc::RecvTimeoutError;

    let (sender, receiver) = mpsc::channel::<std::io::Result<String>>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if sender.send(Ok(line.clone())).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(error));
                    break;
                }
            }
        }
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut captured = String::new();
    let mut found = false;
    while std::time::Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(line)) => {
                found |= line.contains(marker);
                captured.push_str(&line);
                if found {
                    break;
                }
            }
            Ok(Err(error)) => panic!("failed to read gateway diagnostics: {error}"),
            Err(RecvTimeoutError::Timeout) => {
                if let Ok(Some(status)) = child.try_wait() {
                    panic!("gateway exited before emitting {marker}: {status}\n{captured}");
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    assert!(
        found,
        "gateway did not emit {marker} before the deadline\n{captured}"
    );
    let _ = child.kill();
    let _ = child.wait();
    captured
}

fn wait_until_exit(child: &mut std::process::Child) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll gateway") {
            return status;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("gateway did not exit after credential delivery failed");
}

fn assert_admin_login(address: SocketAddr, password: &str) {
    let body = serde_json::json!({"name": "admin", "password": password}).to_string();
    let mut stream = TcpStream::connect(address).expect("connect to control plane");
    write!(
        stream,
        "POST /admin/api/session HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write sign-in request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read sign-in response");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "generated password must authenticate: {response}"
    );
}

fn contains_exact_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value == needle,
        Value::Array(values) => values
            .iter()
            .any(|value| contains_exact_string(value, needle)),
        Value::Object(values) => values
            .values()
            .any(|value| contains_exact_string(value, needle)),
        _ => false,
    }
}
