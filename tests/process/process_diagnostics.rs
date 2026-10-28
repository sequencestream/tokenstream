use std::fs;
use std::path::Path;

const PRINT_MACROS: [&str; 5] = ["eprintln!", "println!", "dbg!", "eprint!(", "print!("];
const STANDARD_STREAM_ACCESS: [&str; 2] = ["io::stderr", "io::stdout"];

#[test]
fn production_rust_does_not_bypass_process_diagnostics() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![source];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).expect("read source directory") {
            let entry = entry.expect("source entry");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let body = fs::read_to_string(&path).expect("read Rust source");
                let production = body.split("#[cfg(test)]").next().unwrap_or(&body);
                for forbidden in PRINT_MACROS {
                    assert!(
                        !production.contains(forbidden),
                        "{} bypasses structured diagnostics with {forbidden}",
                        path.display()
                    );
                }
                // The diagnostics module owns the only audited writers that may
                // acquire the standard streams directly. Everywhere else must go
                // through the process-diagnostic contract.
                if path.file_name().and_then(|name| name.to_str()) != Some("diagnostics.rs") {
                    for forbidden in STANDARD_STREAM_ACCESS {
                        assert!(
                            !production.contains(forbidden),
                            "{} bypasses structured diagnostics with {forbidden}",
                            path.display()
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn global_diagnostic_install_reports_a_conflict_without_panicking() {
    tokenstream::diagnostics::install("info").expect("first subscriber installation");
    assert!(tokenstream::diagnostics::install("info").is_err());
}
