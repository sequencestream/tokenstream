//! Process data directory, secret files, and the operator settings overlay.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};

use crate::config::ConfigError;

/// Documented first-run administrator password. Replace it after sign-in.
pub const DEFAULT_ADMIN_PASSWORD: &str = "tokenstream";

pub const DEFAULT_DATA_LISTEN_ADDR: &str = "127.0.0.1:3300";
pub const DEFAULT_ADMIN_LISTEN_ADDR: &str = "127.0.0.1:3301";

const OVERLAY_FILE: &str = "settings.json";
const MASTER_KEY_FILE: &str = "master.key";
const ADMIN_HASH_FILE: &str = "admin.hash";

/// One row in the administration settings table.
#[derive(Clone, Copy, Debug)]
pub struct SettingSpec {
    pub name: &'static str,
    pub label: &'static str,
    pub restart_required: bool,
    pub secret: bool,
}

/// Settings the administration page can list and change.
pub fn setting_catalog() -> &'static [SettingSpec] {
    &[
        SettingSpec {
            name: "TOKENSTREAM_DATA_LISTEN_ADDR",
            label: "Data-plane listen address",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_ADMIN_LISTEN_ADDR",
            label: "Control-plane listen address",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_DATABASE_URL",
            label: "Database URL",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_MASTER_KEY",
            label: "Master key",
            restart_required: false,
            secret: true,
        },
        SettingSpec {
            name: "TOKENSTREAM_ADMIN_PASSWORD",
            label: "Administrator password",
            restart_required: false,
            secret: true,
        },
        SettingSpec {
            name: "TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS",
            label: "Upstream connect timeout (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_UPSTREAM_HEADER_TIMEOUT_MS",
            label: "Upstream header timeout (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_STREAM_IDLE_TIMEOUT_MS",
            label: "Stream idle timeout (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_UPSTREAM_IDLE_PER_HOST",
            label: "Idle HTTP connections per origin",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_UPSTREAM_POOL_IDLE_TIMEOUT_MS",
            label: "Idle HTTP connection lifetime (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_SHUTDOWN_DRAIN_TIMEOUT_MS",
            label: "Shutdown drain timeout (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_LOG_FLUSH_TIMEOUT_MS",
            label: "Log flush timeout (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_DATABASE_MAX_CONNECTIONS",
            label: "Database pool size",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_MAX_PROXY_CONNECTIONS",
            label: "Proxy admission limit",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_PASSWORD_MAX_CONCURRENCY",
            label: "Password hashing ceiling",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_ADMIN_PASSWORD_CONCURRENCY",
            label: "Control-plane hashing slots",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_AUTH_DATABASE_CONNECTIONS",
            label: "Authentication database reservations",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_AUTH_DB_TIMEOUT_MS",
            label: "Authentication database timeout (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_ADMIN_DB_TIMEOUT_MS",
            label: "Administration database timeout (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_LOG_DB_TIMEOUT_MS",
            label: "Log database timeout (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_DATA_MAX_CONNECTIONS",
            label: "Data-plane connection cap",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_ADMIN_MAX_CONNECTIONS",
            label: "Control-plane connection cap",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS",
            label: "Downstream header timeout (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS",
            label: "Administration body timeout (ms)",
            restart_required: false,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_ADMIN_SESSION_TTL_MS",
            label: "Administration session lifetime (ms)",
            restart_required: false,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_HTTP_BUFFER_BYTES",
            label: "HTTP buffer size (bytes)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES",
            label: "WebSocket max frame (bytes)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES",
            label: "WebSocket max message (bytes)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_WEBSOCKET_QUEUE_CAPACITY",
            label: "WebSocket outbound queue",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_LOG_QUEUE_CAPACITY",
            label: "Log queue capacity",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_LOG_BATCH_SIZE",
            label: "Log batch size",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_LOG_BATCH_INTERVAL_MS",
            label: "Log batch interval (ms)",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_DEVELOPMENT_MODE",
            label: "Development mode",
            restart_required: false,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_ADMIN_STATIC_ROOT",
            label: "Administration page directory",
            restart_required: true,
            secret: false,
        },
        SettingSpec {
            name: "TOKENSTREAM_DATA_DIR",
            label: "Process data directory",
            restart_required: true,
            secret: false,
        },
    ]
}

pub fn spec_for(name: &str) -> Option<&'static SettingSpec> {
    setting_catalog().iter().find(|spec| spec.name == name)
}

/// Resolves `~/.tokenstream` or `TOKENSTREAM_DATA_DIR`.
pub fn resolve_data_dir(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
) -> Result<PathBuf, ConfigError> {
    match get("TOKENSTREAM_DATA_DIR") {
        Ok(Some(value)) if !value.is_empty() => expand_path(&value),
        Ok(Some(_)) => Err(ConfigError::Invalid {
            name: "TOKENSTREAM_DATA_DIR",
            requirement: "must be a non-empty path when present",
        }),
        Ok(None) => default_data_dir(),
        Err(()) => Err(ConfigError::Invalid {
            name: "TOKENSTREAM_DATA_DIR",
            requirement: "must contain valid Unicode",
        }),
    }
}

pub fn default_data_dir() -> Result<PathBuf, ConfigError> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or(ConfigError::Invalid {
            name: "TOKENSTREAM_DATA_DIR",
            requirement: "must be set when the home directory is unknown",
        })?;
    Ok(PathBuf::from(home).join(".tokenstream"))
}

pub fn default_sqlite_url(data_dir: &Path) -> String {
    format!("sqlite://{}", data_dir.join("tokenstream.db").display())
}

pub fn ensure_data_dir(data_dir: &Path) -> Result<(), ConfigError> {
    fs::create_dir_all(data_dir).map_err(|_| ConfigError::Invalid {
        name: "TOKENSTREAM_DATA_DIR",
        requirement: "must name a writable directory",
    })?;
    restrict_mode(data_dir, 0o700);
    Ok(())
}

pub fn expand_path(value: &str) -> Result<PathBuf, ConfigError> {
    if let Some(rest) = value.strip_prefix("~/") {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or(ConfigError::Invalid {
                name: "TOKENSTREAM_DATA_DIR",
                requirement: "must be set when expanding a home-relative path",
            })?;
        return Ok(PathBuf::from(home).join(rest));
    }
    if value == "~" {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or(ConfigError::Invalid {
                name: "TOKENSTREAM_DATA_DIR",
                requirement: "must be set when expanding a home-relative path",
            })?;
        return Ok(PathBuf::from(home));
    }
    Ok(PathBuf::from(value))
}

pub fn load_overlay(data_dir: &Path) -> Result<HashMap<String, String>, ConfigError> {
    let path = data_dir.join(OVERLAY_FILE);
    match fs::read_to_string(&path) {
        Ok(body) => serde_json::from_str(&body).map_err(|_| ConfigError::Invalid {
            name: "TOKENSTREAM_DATA_DIR",
            requirement: "must contain a valid settings overlay",
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(_) => Err(ConfigError::Invalid {
            name: "TOKENSTREAM_DATA_DIR",
            requirement: "must contain a readable settings overlay",
        }),
    }
}

pub fn save_overlay(data_dir: &Path, overlay: &HashMap<String, String>) -> Result<(), ConfigError> {
    ensure_data_dir(data_dir)?;
    let path = data_dir.join(OVERLAY_FILE);
    let body = serde_json::to_string_pretty(overlay).map_err(|_| ConfigError::Invalid {
        name: "TOKENSTREAM_DATA_DIR",
        requirement: "must contain a valid settings overlay",
    })?;
    write_restricted(&path, body.as_bytes())
}

pub fn load_master_key_file(data_dir: &Path) -> Result<Option<String>, ConfigError> {
    read_optional_secret(data_dir.join(MASTER_KEY_FILE), "TOKENSTREAM_MASTER_KEY")
}

pub fn save_master_key_file(data_dir: &Path, hex: &str) -> Result<(), ConfigError> {
    ensure_data_dir(data_dir)?;
    write_restricted(&data_dir.join(MASTER_KEY_FILE), hex.as_bytes())
}

pub fn load_admin_hash_file(data_dir: &Path) -> Result<Option<String>, ConfigError> {
    read_optional_secret(
        data_dir.join(ADMIN_HASH_FILE),
        "TOKENSTREAM_ADMIN_PASSWORD_HASH",
    )
}

pub fn save_admin_hash_file(data_dir: &Path, hash: &str) -> Result<(), ConfigError> {
    ensure_data_dir(data_dir)?;
    write_restricted(&data_dir.join(ADMIN_HASH_FILE), hash.as_bytes())
}

pub fn generate_master_key() -> Result<[u8; 32], ConfigError> {
    let mut key = [0_u8; 32];
    getrandom::getrandom(&mut key).map_err(|_| ConfigError::Invalid {
        name: "TOKENSTREAM_MASTER_KEY",
        requirement: "could not generate a master key",
    })?;
    Ok(key)
}

pub fn encode_master_key(key: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in key {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

pub fn hash_admin_password(password: &str) -> Result<String, ConfigError> {
    if password.is_empty() {
        return Err(ConfigError::Invalid {
            name: "TOKENSTREAM_ADMIN_PASSWORD",
            requirement: "must be a non-empty password",
        });
    }
    let mut salt_bytes = [0_u8; 16];
    getrandom::getrandom(&mut salt_bytes).map_err(|_| ConfigError::Invalid {
        name: "TOKENSTREAM_ADMIN_PASSWORD",
        requirement: "could not hash the administrator password",
    })?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| ConfigError::Invalid {
        name: "TOKENSTREAM_ADMIN_PASSWORD",
        requirement: "could not hash the administrator password",
    })?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| ConfigError::Invalid {
            name: "TOKENSTREAM_ADMIN_PASSWORD",
            requirement: "could not hash the administrator password",
        })
}

pub fn password_matches(password: &str, encoded_hash: &str) -> bool {
    let Ok(hash) = argon2::password_hash::PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

/// Finds a compiled administration page next to the executable or in a local build.
pub fn discover_admin_static_root() -> Option<PathBuf> {
    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        let beside = directory.join("admin");
        if beside.join("index.html").is_file() {
            return Some(beside);
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let dist = cwd.join("web").join("dist");
        if dist.join("index.html").is_file() {
            return Some(dist);
        }
        let admin = cwd.join("admin");
        if admin.join("index.html").is_file() {
            return Some(admin);
        }
    }
    None
}

fn read_optional_secret(path: PathBuf, name: &'static str) -> Result<Option<String>, ConfigError> {
    match fs::read_to_string(&path) {
        Ok(body) => {
            let value = body.trim().to_owned();
            if value.is_empty() {
                return Err(ConfigError::Invalid {
                    name,
                    requirement: "must contain a non-empty secret",
                });
            }
            Ok(Some(value))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ConfigError::Invalid {
            name,
            requirement: "must be a readable secret file",
        }),
    }
}

fn write_restricted(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    fs::write(path, bytes).map_err(|_| ConfigError::Invalid {
        name: "TOKENSTREAM_DATA_DIR",
        requirement: "must name a writable directory",
    })?;
    restrict_mode(path, 0o600);
    Ok(())
}

fn restrict_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    let _ = mode;
    let _ = path;
}
