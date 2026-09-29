//! Compile the administration page before it is embedded in the binary.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let web = manifest.join("web");
    let dist_index = web.join("dist").join("index.html");

    println!("cargo:rerun-if-changed=web/src");
    println!("cargo:rerun-if-changed=web/index.html");
    println!("cargo:rerun-if-changed=web/package.json");
    println!("cargo:rerun-if-changed=web/package-lock.json");
    println!("cargo:rerun-if-changed=web/vite.config.ts");
    println!("cargo:rerun-if-changed=web/tsconfig.json");
    println!("cargo:rerun-if-env-changed=TOKENSTREAM_SKIP_FRONTEND_BUILD");

    let skip = env::var("TOKENSTREAM_SKIP_FRONTEND_BUILD")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !skip {
        build_frontend(&web);
    }
    if !dist_index.is_file() {
        panic!(
            "the administration page is missing at {}. Run `npm --prefix web ci && npm --prefix web run build`.",
            dist_index.display()
        );
    }
}

fn build_frontend(web: &Path) {
    if !web.join("node_modules").is_dir() {
        run_npm(web, &["ci"]);
    }
    run_npm(web, &["run", "build"]);
}

fn run_npm(web: &Path, args: &[&str]) {
    let mut command = npm_command();
    command.args(args).current_dir(web);
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to start npm {}: {error}", args.join(" ")));
    if !status.success() {
        panic!("npm {} failed with {status}", args.join(" "));
    }
}

fn npm_command() -> Command {
    if cfg!(windows) {
        Command::new("npm.cmd")
    } else {
        Command::new("npm")
    }
}
