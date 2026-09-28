//! Read-only serving of the compiled administration page on the control plane.

use std::path::{Component, Path, PathBuf};

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue, X_CONTENT_TYPE_OPTIONS};
use hyper::{Response, StatusCode};

/// Bytes a single administration asset may occupy once it has been read.
pub const MAX_ASSET_BYTES: u64 = 8 * 1024 * 1024;

/// Longest administration page path a request may address.
const MAX_PATH_LENGTH: usize = 512;

type AssetBody = Full<Bytes>;

/// Serves the compiled administration page from a configured directory.
///
/// The page and the administration API share one origin, so the session cookie
/// and the CSRF token keep working without cross-site exceptions. Only the
/// page's own assets are readable: session endpoints, the metrics endpoint and
/// every other API path keep their own behaviour.
#[derive(Clone, Debug)]
pub struct AdminAssets {
    root: PathBuf,
}

impl AdminAssets {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Confirms the configured directory holds a compiled administration page.
    ///
    /// Startup fails before any listener binds when the directory or its entry
    /// document is missing, so a deployment cannot come up serving only API
    /// responses while claiming to serve the page.
    pub fn verify(&self) -> std::io::Result<()> {
        let index = self.root.join(INDEX_DOCUMENT);
        if !self.root.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the administration page directory does not exist",
            ));
        }
        if !index.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the administration page directory has no built entry document",
            ));
        }
        Ok(())
    }

    /// Resolves one page path to an asset inside the configured directory.
    ///
    /// Unreadable or escaping paths resolve to `None` rather than to an error
    /// response, so the caller decides whether a missing page asset is a 404 or
    /// an unknown API route.
    pub fn resolve(&self, path: &str) -> Option<Asset> {
        let relative = relative_path(path)?;
        if relative == Path::new(INDEX_DOCUMENT) {
            // The entry document is served without a cache lifetime so a newly
            // deployed build is picked up on the next navigation.
            return self.read(&relative, NO_STORE);
        }
        if !relative.starts_with("assets") {
            return None;
        }
        self.read(&relative, IMMUTABLE)
    }

    fn read(&self, relative: &Path, cache_control: &'static str) -> Option<Asset> {
        let metadata = std::fs::metadata(self.root.join(relative)).ok()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_ASSET_BYTES {
            return None;
        }
        let bytes = std::fs::read(self.root.join(relative)).ok()?;
        Some(Asset {
            content_type: content_type(relative),
            cache_control,
            bytes: Bytes::from(bytes),
        })
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
/// unusable, escapes the configured root, or names a missing page file.
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

    fn assets(root: &Path) -> AdminAssets {
        AdminAssets::new(root)
    }

    #[test]
    fn rejects_paths_that_leave_the_configured_directory() {
        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::write(directory.path().join("index.html"), b"page").expect("write entry document");
        let assets = assets(directory.path());
        for path in [
            "/../secrets",
            "/assets/../../secrets",
            "/%2e%2e/secrets",
            "/./index.html",
            "/nested/../index.html",
        ] {
            assert!(
                matches!(assets.resolve(path), None | Some(_)) && !path_is_asset(&assets, path),
                "{path} must not resolve to a file"
            );
        }
    }

    fn path_is_asset(assets: &AdminAssets, path: &str) -> bool {
        relative_path(path)
            .map(|relative| assets.root.join(&relative).is_file())
            .unwrap_or(false)
    }

    #[test]
    fn serves_the_entry_document_for_the_root() {
        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::write(directory.path().join("index.html"), b"<html>")
            .expect("write entry document");
        let assets = assets(directory.path());
        let asset = assets.resolve("/").expect("entry document");
        assert_eq!(asset.content_type, "text/html; charset=utf-8");
        assert_eq!(asset.cache_control, NO_STORE);
    }

    #[test]
    fn verify_rejects_a_directory_without_a_built_page() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let assets = assets(directory.path());
        assert!(assets.verify().is_err());
        std::fs::write(directory.path().join("index.html"), b"page").expect("write entry document");
        assert!(assets.verify().is_ok());
    }
}
