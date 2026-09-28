//! Shared requirement for layers that need an external dependency.
//!
//! A layer that needs an external dependency must fail when the dependency is
//! missing. A silently skipped layer is indistinguishable from a passing one
//! in a test report, so absence is reported as a failure that names the
//! setting that supplies the dependency.

use std::env;

/// Returns the PostgreSQL connection string that every dual-backend layer
/// requires, failing rather than skipping when it is absent.
pub fn require_postgres_url(layer: &str) -> String {
    match env::var("TOKENSTREAM_TEST_POSTGRES_URL") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "{layer} requires a PostgreSQL server: set TOKENSTREAM_TEST_POSTGRES_URL, or run \
             scripts/release-gate.sh, which provisions one when it is not supplied"
        ),
    }
}
