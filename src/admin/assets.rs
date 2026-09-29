//! Read-only serving of the compiled administration page on the control plane.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue, X_CONTENT_TYPE_OPTIONS};
use hyper::{Response, StatusCode};
use include_dir::{Dir, include_dir};

/// Bytes a single administration asset may occupy once it has been read.
pub const MAX_ASSET_BYTES: u64 = 8 * 1024 * 1024;

/// Longest administration page path a request may address.
const MAX_PATH_LENGTH: usize = 512;

type AssetBody = Full<Bytes>;

static EMBEDDED_PAGE: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/web/dist");

/// Serves the compiled administration page from the process image.
///
/// The page and the administration API share one origin, so the session cookie
/// and the CSRF token keep working without cross-site exceptions. Only the
/// page's own assets are readable: session endpoints, the metrics endpoint and
/// every other API path keep their own behaviour.
#[derive(Clone, Debug)]
pub struct AdminAssets {
    inner: Inner,
}

#[derive(Clone, Debug)]
enum Inner {
    Embedded,
    Fixture(Arc<HashMap<String, Bytes>>),
}

impl AdminAssets {
    /// The administration page compiled into this binary.
    pub fn embedded() -> Self {
        Self {
            inner: Inner::Embedded,
        }
    }

    /// A closed set of page files for tests that must not use the compiled page.
    pub fn from_files<K, V>(files: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<Vec<u8>>,
    {
        let files = files
            .into_iter()
            .map(|(key, value)| (normalize_asset_key(&key.into()), Bytes::from(value.into())))
            .collect();
        Self {
            inner: Inner::Fixture(Arc::new(files)),
        }
    }

    /// Confirms the compiled page contains an entry document.
    ///
    /// Startup fails before any listener binds when the embedded page is empty,
    /// so a deployment cannot come up serving only API responses while claiming
    /// to serve the page.
    pub fn verify(&self) -> std::io::Result<()> {
        if self.lookup(INDEX_DOCUMENT).is_some() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the administration page has no built entry document",
            ))
        }
    }

    /// Resolves one page path to an asset inside the compiled page.
    ///
    /// Unreadable or escaping paths resolve to `None` rather than to an error
    /// response, so the caller decides whether a missing page asset is a 404 or
    /// an unknown API route.
    pub fn resolve(&self, path: &str) -> Option<Asset> {
        let relative = relative_path(path)?;
        let key = asset_key(&relative)?;
        if key == INDEX_DOCUMENT {
            // The entry document is served without a cache lifetime so a newly
            // deployed binary is picked up on the next navigation.
            return self.read(&key, NO_STORE);
        }
        if !key.starts_with("assets/") {
            return None;
        }
        self.read(&key, IMMUTABLE)
    }

    fn read(&self, relative: &str, cache_control: &'static str) -> Option<Asset> {
        let bytes = self.lookup(relative)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_ASSET_BYTES {
            return None;
        }
        Some(Asset {
            content_type: content_type(Path::new(relative)),
            cache_control,
            bytes,
        })
    }

    fn lookup(&self, relative: &str) -> Option<Bytes> {
        match &self.inner {
            Inner::Embedded => EMBEDDED_PAGE
                .get_file(relative)
                .map(|file| Bytes::from_static(file.contents())),
            Inner::Fixture(files) => files.get(relative).cloned(),
        }
    }
}

const INDEX_DOCUMENT: &str = "index.html";
const NO_STORE: &str = "no-store";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

pub struct Asset {
    content_type: &'static str,
    cache_control: &'static str,
    bytes: Bytes,
}

impl Asset {
    pub fn into_response(self) -> Response<AssetBody> {
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, self.content_type)
            .header(CACHE_CONTROL, self.cache_control)
            .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
            .header(REFERER_POLICY, "no-referrer")
            .body(Full::new(self.bytes))
            .expect("asset response is valid")
    }
}

/// Returns the asset-relative path for a request, or `None` when the path is
/// unusable, escapes the compiled page, or names a missing page file.
fn relative_path(path: &str) -> Option<PathBuf> {
    if path.len() > MAX_PATH_LENGTH {
        return None;
    }
    let trimmed = path.trim_start_matches('/');
    let candidate = if trimmed.is_empty() {
        INDEX_DOCUMENT
    } else {
        trimmed
    };
    let relative = Path::new(candidate);
    if relative.is_absolute() {
        return None;
    }
    for component in relative.components() {
        match component {
            Component::Normal(_) => {}
            _ => return None,
        }
    }
    Some(relative.to_path_buf())
}

fn asset_key(relative: &Path) -> Option<String> {
    let mut key = String::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        let part = part.to_str()?;
        if !key.is_empty() {
            key.push('/');
        }
        key.push_str(part);
    }
    Some(key)
}

fn normalize_asset_key(path: &str) -> String {
    path.trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

/// Chooses a content type from the file extension alone.
///
/// The administration page ships hashed asset names and plain text, styles and
/// scripts, so the mapping is closed and never guesses from file contents.
fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("webmanifest") => "application/manifest+json",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

const REFERER_POLICY: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("referrer-policy");

/// A strict policy for the page, allowing only its own scripts, styles and
/// images and forbidding any framing.
pub const PAGE_CONTENT_SECURITY_POLICY: HeaderValue = HeaderValue::from_static(
    "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
);

#[cfg(test)]
mod tests {
    use super::*;

    fn assets() -> AdminAssets {
        AdminAssets::from_files([
            ("index.html", b"<html>" as &[u8]),
            ("assets/index-abc123.js", b"console.log('page')"),
            ("secrets.txt", b"not page content"),
        ])
    }

    #[test]
    fn rejects_paths_that_leave_the_compiled_page() {
        let assets = assets();
        for path in [
            "/../secrets",
            "/assets/../../secrets",
            "/%2e%2e/secrets",
            "/./index.html",
            "/nested/../index.html",
            "/secrets.txt",
        ] {
            assert!(
                assets.resolve(path).is_none(),
                "{path} must not resolve to a file"
            );
        }
    }

    #[test]
    fn serves_the_entry_document_for_the_root() {
        let assets = assets();
        let asset = assets.resolve("/").expect("entry document");
        assert_eq!(asset.content_type, "text/html; charset=utf-8");
        assert_eq!(asset.cache_control, NO_STORE);
    }

    #[test]
    fn verify_rejects_a_page_without_a_built_entry() {
        let empty = AdminAssets::from_files::<&str, Vec<u8>>([]);
        assert!(empty.verify().is_err());
        assert!(assets().verify().is_ok());
    }

    #[test]
    fn embedded_page_contains_an_entry_document() {
        let assets = AdminAssets::embedded();
        assert!(assets.verify().is_ok());
        let asset = assets.resolve("/").expect("embedded entry document");
        assert_eq!(asset.content_type, "text/html; charset=utf-8");
        assert_eq!(asset.cache_control, NO_STORE);
    }
}
