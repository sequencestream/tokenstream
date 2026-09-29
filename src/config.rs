use std::env;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MIN_TIMEOUT_MS: u64 = 1;
const MAX_UPSTREAM_TIMEOUT_MS: u64 = 300_000;
const MAX_IDLE_TIMEOUT_MS: u64 = 3_600_000;
const MAX_SHUTDOWN_TIMEOUT_MS: u64 = 300_000;
const MAX_LOG_BATCH_INTERVAL_MS: u64 = 60_000;
const MAX_DATABASE_TIMEOUT_MS: u64 = 60_000;
const MAX_DATABASE_CONNECTIONS: usize = 1_024;
const MAX_PROXY_CONNECTIONS: usize = 1_000_000;
const MIN_HTTP_BUFFER_BYTES: usize = 1_024;
const MAX_HTTP_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_WEBSOCKET_BYTES: usize = 64 * 1024 * 1024;
const MAX_QUEUE_CAPACITY: usize = 1_000_000;

#[derive(Clone)]
pub struct DatabaseUrl(String);

impl DatabaseUrl {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseUrl([REDACTED])")
    }
}

#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey([REDACTED])")
    }
}

#[derive(Clone)]
pub struct AdminPasswordHash(String);

impl AdminPasswordHash {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdminPasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminPasswordHash([REDACTED])")
    }
}

/// The name of the account created from the configured administrator password.
#[derive(Clone)]
pub struct BootstrapAccount(String);

impl BootstrapAccount {
    fn new(value: &str) -> Result<Self, ConfigError> {
        let value = value.trim();
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            return Err(ConfigError::Invalid {
                name: "TOKENSTREAM_BOOTSTRAP_ACCOUNT",
                requirement: "must be a short, non-empty account name",
            });
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Debug for BootstrapAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapAccount([REDACTED])")
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    data_listen_addr: SocketAddr,
    admin_listen_addr: SocketAddr,
    database_url: DatabaseUrl,
    master_key: MasterKey,
    admin_password_hash: AdminPasswordHash,
    bootstrap_account: BootstrapAccount,
    upstream_connect_timeout: Duration,
    upstream_header_timeout: Duration,
    stream_idle_timeout: Duration,
    upstream_idle_per_host: usize,
    upstream_pool_idle_timeout: Duration,
    shutdown_drain_timeout: Duration,
    log_flush_timeout: Duration,
    database_max_connections: usize,
    max_proxy_connections: usize,
    http_buffer_bytes: usize,
    websocket_max_frame_bytes: usize,
    websocket_max_message_bytes: usize,
    websocket_queue_capacity: usize,
    log_queue_capacity: usize,
    log_batch_size: usize,
    log_batch_interval: Duration,
    password_max_concurrency: usize,
    data_password_concurrency: usize,
    admin_password_concurrency: usize,
    auth_database_connections: usize,
    auth_db_timeout: Duration,
    admin_db_timeout: Duration,
    log_db_timeout: Duration,
    data_max_connections: usize,
    admin_max_connections: usize,
    downstream_header_timeout: Duration,
    admin_body_timeout: Duration,
    admin_session_ttl: Duration,
    development_mode: bool,
    data_dir: Option<PathBuf>,
}

struct SourceOptions<'a> {
    data_dir: Option<&'a Path>,
    file_master: Option<&'a str>,
    file_hash: Option<&'a str>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut env_get = |name: &str| match env::var_os(name) {
            Some(value) => value.into_string().map(Some).map_err(|_| ()),
            None => Ok(None),
        };
        let data_dir = crate::local_state::resolve_data_dir(&mut env_get)?;
        crate::local_state::ensure_data_dir(&data_dir)?;
        let overlay = crate::local_state::load_overlay(&data_dir)?;
        let file_master = crate::local_state::load_master_key_file(&data_dir)?;
        let file_hash = crate::local_state::load_admin_hash_file(&data_dir)?;
        let mut persist_master = None;
        let mut persist_hash = None;
        let mut config = Self::from_source_with(
            |name| match env::var_os(name) {
                Some(value) => value.into_string().map(Some).map_err(|_| ()),
                None => Ok(overlay.get(name).cloned()),
            },
            SourceOptions {
                data_dir: Some(&data_dir),
                file_master: file_master.as_deref(),
                file_hash: file_hash.as_deref(),
            },
            &mut persist_master,
            &mut persist_hash,
        )?;
        if let Some(hex) = persist_master {
            crate::local_state::save_master_key_file(&data_dir, &hex)?;
        }
        if let Some(hash) = persist_hash {
            crate::local_state::save_admin_hash_file(&data_dir, &hash)?;
        }
        config.data_dir = Some(data_dir);
        Ok(config)
    }

    pub fn from_map(
        values: &std::collections::HashMap<String, String>,
    ) -> Result<Self, ConfigError> {
        Self::from_source(|name| Ok(values.get(name).cloned()))
    }

    pub fn with_data_dir(mut self, data_dir: Option<PathBuf>) -> Self {
        self.data_dir = data_dir;
        self
    }

    fn from_source(
        get: impl FnMut(&str) -> Result<Option<String>, ()>,
    ) -> Result<Self, ConfigError> {
        let mut persist_master = None;
        let mut persist_hash = None;
        Self::from_source_with(
            get,
            SourceOptions {
                data_dir: None,
                file_master: None,
                file_hash: None,
            },
            &mut persist_master,
            &mut persist_hash,
        )
    }

    fn from_source_with(
        mut get: impl FnMut(&str) -> Result<Option<String>, ()>,
        options: SourceOptions<'_>,
        persist_master: &mut Option<String>,
        persist_hash: &mut Option<String>,
    ) -> Result<Self, ConfigError> {
        let data_listen_addr: std::net::SocketAddr = parse_optional_value(
            &mut get,
            "TOKENSTREAM_DATA_LISTEN_ADDR",
            crate::local_state::DEFAULT_DATA_LISTEN_ADDR,
        )?;
        let admin_listen_addr: std::net::SocketAddr = parse_optional_value(
            &mut get,
            "TOKENSTREAM_ADMIN_LISTEN_ADDR",
            crate::local_state::DEFAULT_ADMIN_LISTEN_ADDR,
        )?;
        if data_listen_addr == admin_listen_addr {
            return Err(ConfigError::Invalid {
                name: "TOKENSTREAM_ADMIN_LISTEN_ADDR",
                requirement: "must differ from TOKENSTREAM_DATA_LISTEN_ADDR",
            });
        }

        let database_url_value = match optional(&mut get, "TOKENSTREAM_DATABASE_URL")? {
            Some(value) => value,
            None => match options.data_dir {
                Some(data_dir) => crate::local_state::default_sqlite_url(data_dir),
                None => "sqlite::memory:".to_owned(),
            },
        };
        validate_database_url(&database_url_value)?;
        let database_url = DatabaseUrl(database_url_value);

        let master_key_value = match optional(&mut get, "TOKENSTREAM_MASTER_KEY")? {
            Some(value) => value,
            None => {
                if let Some(file_value) = options.file_master {
                    file_value.to_owned()
                } else {
                    let generated = crate::local_state::generate_master_key()?;
                    let hex = crate::local_state::encode_master_key(&generated);
                    *persist_master = Some(hex.clone());
                    hex
                }
            }
        };
        let master_key = MasterKey(decode_master_key(&master_key_value)?);

        let env_password = optional(&mut get, "TOKENSTREAM_ADMIN_PASSWORD")?;
        let admin_hash_value = match optional(&mut get, "TOKENSTREAM_ADMIN_PASSWORD_HASH")? {
            Some(value) => value,
            None => {
                if let Some(password) = env_password {
                    let hash = crate::local_state::hash_admin_password(&password)?;
                    *persist_hash = Some(hash.clone());
                    hash
                } else if let Some(file_value) = options.file_hash {
                    file_value.to_owned()
                } else {
                    let hash = crate::local_state::hash_admin_password(
                        crate::local_state::DEFAULT_ADMIN_PASSWORD,
                    )?;
                    *persist_hash = Some(hash.clone());
                    hash
                }
            }
        };
        validate_admin_password_hash(&admin_hash_value)?;
        let admin_password_hash = AdminPasswordHash(admin_hash_value);
        let bootstrap_account = BootstrapAccount::new(&parse_optional_value::<String>(
            &mut get,
            "TOKENSTREAM_BOOTSTRAP_ACCOUNT",
            crate::admin::DEFAULT_BOOTSTRAP_ACCOUNT_NAME,
        )?)?;

        let upstream_connect_timeout = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS",
            5000,
            MAX_UPSTREAM_TIMEOUT_MS,
        )?;
        let upstream_header_timeout = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_UPSTREAM_HEADER_TIMEOUT_MS",
            30_000,
            MAX_UPSTREAM_TIMEOUT_MS,
        )?;
        let stream_idle_timeout = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_STREAM_IDLE_TIMEOUT_MS",
            60_000,
            MAX_IDLE_TIMEOUT_MS,
        )?;
        let upstream_idle_per_host =
            parse_optional(&mut get, "TOKENSTREAM_UPSTREAM_IDLE_PER_HOST", 8, 0, 64)?;
        let upstream_pool_idle_timeout = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_UPSTREAM_POOL_IDLE_TIMEOUT_MS",
            30_000,
            MAX_UPSTREAM_TIMEOUT_MS,
        )?;
        let shutdown_drain_timeout = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_SHUTDOWN_DRAIN_TIMEOUT_MS",
            30_000,
            MAX_SHUTDOWN_TIMEOUT_MS,
        )?;
        let log_flush_timeout = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_LOG_FLUSH_TIMEOUT_MS",
            5000,
            MAX_SHUTDOWN_TIMEOUT_MS,
        )?;
        let database_max_connections = parse_optional(
            &mut get,
            "TOKENSTREAM_DATABASE_MAX_CONNECTIONS",
            16,
            1,
            MAX_DATABASE_CONNECTIONS,
        )?;
        let max_proxy_connections = parse_optional(
            &mut get,
            "TOKENSTREAM_MAX_PROXY_CONNECTIONS",
            4096,
            1,
            MAX_PROXY_CONNECTIONS,
        )?;
        let password_max_concurrency =
            parse_optional(&mut get, "TOKENSTREAM_PASSWORD_MAX_CONCURRENCY", 4, 2, 64)?;
        let admin_password_concurrency = parse_optional(
            &mut get,
            "TOKENSTREAM_ADMIN_PASSWORD_CONCURRENCY",
            1,
            1,
            password_max_concurrency.saturating_sub(1),
        )?;
        let data_password_concurrency = password_max_concurrency - admin_password_concurrency;
        let auth_database_connections = parse_optional(
            &mut get,
            "TOKENSTREAM_AUTH_DATABASE_CONNECTIONS",
            database_max_connections.saturating_sub(1).clamp(1, 2),
            1,
            database_max_connections,
        )?;
        let auth_db_timeout = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_AUTH_DB_TIMEOUT_MS",
            1000,
            MAX_DATABASE_TIMEOUT_MS,
        )?;
        let admin_db_timeout = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_ADMIN_DB_TIMEOUT_MS",
            5000,
            MAX_DATABASE_TIMEOUT_MS,
        )?;
        let log_db_timeout = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_LOG_DB_TIMEOUT_MS",
            2000,
            MAX_DATABASE_TIMEOUT_MS,
        )?;
        let data_max_connections = parse_optional(
            &mut get,
            "TOKENSTREAM_DATA_MAX_CONNECTIONS",
            max_proxy_connections.saturating_add(64),
            max_proxy_connections.saturating_add(1),
            MAX_PROXY_CONNECTIONS + 1024,
        )?;
        let admin_max_connections = parse_optional(
            &mut get,
            "TOKENSTREAM_ADMIN_MAX_CONNECTIONS",
            128,
            1,
            MAX_PROXY_CONNECTIONS,
        )?;
        let downstream_header_timeout = Duration::from_millis(parse_optional(
            &mut get,
            "TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS",
            10000,
            1,
            300000,
        )? as u64);
        let admin_body_timeout = Duration::from_millis(parse_optional(
            &mut get,
            "TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS",
            30000,
            1,
            300000,
        )? as u64);
        let admin_session_ttl = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_ADMIN_SESSION_TTL_MS",
            15 * 60 * 1000,
            MAX_IDLE_TIMEOUT_MS,
        )?;
        let http_buffer_bytes = parse_optional(
            &mut get,
            "TOKENSTREAM_HTTP_BUFFER_BYTES",
            65_536,
            MIN_HTTP_BUFFER_BYTES,
            MAX_HTTP_BUFFER_BYTES,
        )?;
        let websocket_max_frame_bytes = parse_optional(
            &mut get,
            "TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES",
            1_048_576,
            1,
            MAX_WEBSOCKET_BYTES,
        )?;
        let websocket_max_message_bytes = parse_optional(
            &mut get,
            "TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES",
            8_388_608,
            1,
            MAX_WEBSOCKET_BYTES,
        )?;
        if websocket_max_frame_bytes > websocket_max_message_bytes {
            return Err(ConfigError::Invalid {
                name: "TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES",
                requirement: "must not exceed TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES",
            });
        }
        let websocket_queue_capacity = parse_optional(
            &mut get,
            "TOKENSTREAM_WEBSOCKET_QUEUE_CAPACITY",
            32,
            1,
            MAX_QUEUE_CAPACITY,
        )?;
        let log_queue_capacity = parse_optional(
            &mut get,
            "TOKENSTREAM_LOG_QUEUE_CAPACITY",
            8192,
            1,
            MAX_QUEUE_CAPACITY,
        )?;
        let log_batch_size = parse_optional(
            &mut get,
            "TOKENSTREAM_LOG_BATCH_SIZE",
            128,
            1,
            MAX_QUEUE_CAPACITY,
        )?;
        if log_batch_size > log_queue_capacity {
            return Err(ConfigError::Invalid {
                name: "TOKENSTREAM_LOG_BATCH_SIZE",
                requirement: "must not exceed TOKENSTREAM_LOG_QUEUE_CAPACITY",
            });
        }
        let log_batch_interval = parse_optional_duration(
            &mut get,
            "TOKENSTREAM_LOG_BATCH_INTERVAL_MS",
            100,
            MAX_LOG_BATCH_INTERVAL_MS,
        )?;

        let loopback_listeners =
            data_listen_addr.ip().is_loopback() && admin_listen_addr.ip().is_loopback();
        let development_mode =
            parse_optional_flag(&mut get, "TOKENSTREAM_DEVELOPMENT_MODE", loopback_listeners)?;

        Ok(Self {
            data_listen_addr,
            admin_listen_addr,
            database_url,
            master_key,
            admin_password_hash,
            bootstrap_account,
            upstream_connect_timeout,
            upstream_header_timeout,
            stream_idle_timeout,
            upstream_idle_per_host,
            upstream_pool_idle_timeout,
            shutdown_drain_timeout,
            log_flush_timeout,
            database_max_connections,
            max_proxy_connections,
            http_buffer_bytes,
            websocket_max_frame_bytes,
            websocket_max_message_bytes,
            websocket_queue_capacity,
            log_queue_capacity,
            log_batch_size,
            log_batch_interval,
            password_max_concurrency,
            data_password_concurrency,
            admin_password_concurrency,
            auth_database_connections,
            auth_db_timeout,
            admin_db_timeout,
            log_db_timeout,
            data_max_connections,
            admin_max_connections,
            downstream_header_timeout,
            admin_body_timeout,
            admin_session_ttl,
            development_mode,
            data_dir: options.data_dir.map(Path::to_path_buf),
        })
    }

    pub fn password_max_concurrency(&self) -> usize {
        self.password_max_concurrency
    }
    pub fn data_password_concurrency(&self) -> usize {
        self.data_password_concurrency
    }
    pub fn admin_password_concurrency(&self) -> usize {
        self.admin_password_concurrency
    }
    pub fn auth_database_connections(&self) -> usize {
        self.auth_database_connections
    }
    pub fn auth_db_timeout(&self) -> Duration {
        self.auth_db_timeout
    }
    pub fn admin_db_timeout(&self) -> Duration {
        self.admin_db_timeout
    }
    pub fn log_db_timeout(&self) -> Duration {
        self.log_db_timeout
    }
    pub fn data_max_connections(&self) -> usize {
        self.data_max_connections
    }
    pub fn admin_max_connections(&self) -> usize {
        self.admin_max_connections
    }
    pub fn downstream_header_timeout(&self) -> Duration {
        self.downstream_header_timeout
    }
    pub fn admin_body_timeout(&self) -> Duration {
        self.admin_body_timeout
    }

    pub fn admin_session_ttl(&self) -> Duration {
        self.admin_session_ttl
    }
    pub fn data_listen_addr(&self) -> SocketAddr {
        self.data_listen_addr
    }

    pub fn admin_listen_addr(&self) -> SocketAddr {
        self.admin_listen_addr
    }

    pub fn database_url(&self) -> &DatabaseUrl {
        &self.database_url
    }

    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    pub fn admin_password_hash(&self) -> &AdminPasswordHash {
        &self.admin_password_hash
    }

    /// The name given to the account created from the administrator password.
    pub fn bootstrap_account(&self) -> &BootstrapAccount {
        &self.bootstrap_account
    }

    pub fn bootstrap_account_name(&self) -> &str {
        &self.bootstrap_account.0
    }

    pub fn upstream_connect_timeout(&self) -> Duration {
        self.upstream_connect_timeout
    }

    pub fn upstream_header_timeout(&self) -> Duration {
        self.upstream_header_timeout
    }

    pub fn stream_idle_timeout(&self) -> Duration {
        self.stream_idle_timeout
    }

    pub fn upstream_idle_per_host(&self) -> usize {
        self.upstream_idle_per_host
    }

    pub fn upstream_pool_idle_timeout(&self) -> Duration {
        self.upstream_pool_idle_timeout
    }

    pub fn shutdown_drain_timeout(&self) -> Duration {
        self.shutdown_drain_timeout
    }

    pub fn log_flush_timeout(&self) -> Duration {
        self.log_flush_timeout
    }

    pub fn database_max_connections(&self) -> usize {
        self.database_max_connections
    }

    pub fn max_proxy_connections(&self) -> usize {
        self.max_proxy_connections
    }

    pub fn http_buffer_bytes(&self) -> usize {
        self.http_buffer_bytes
    }

    pub fn websocket_max_frame_bytes(&self) -> usize {
        self.websocket_max_frame_bytes
    }

    pub fn websocket_max_message_bytes(&self) -> usize {
        self.websocket_max_message_bytes
    }

    pub fn websocket_queue_capacity(&self) -> usize {
        self.websocket_queue_capacity
    }

    pub fn log_queue_capacity(&self) -> usize {
        self.log_queue_capacity
    }

    pub fn log_batch_size(&self) -> usize {
        self.log_batch_size
    }

    pub fn log_batch_interval(&self) -> Duration {
        self.log_batch_interval
    }

    /// True when non-HTTPS provider endpoints are explicitly permitted.
    ///
    /// This is an opt-in development setting; it is off unless the deployment
    /// sets it to `true`.
    pub fn development_mode(&self) -> bool {
        self.development_mode
    }

    pub fn data_dir(&self) -> Option<&Path> {
        self.data_dir.as_deref()
    }

    pub fn master_key_hex(&self) -> String {
        crate::local_state::encode_master_key(self.master_key.expose())
    }

    pub fn uses_default_admin_password(&self) -> bool {
        crate::local_state::password_matches(
            crate::local_state::DEFAULT_ADMIN_PASSWORD,
            self.admin_password_hash.expose(),
        )
    }

    pub fn to_env_map(&self) -> std::collections::HashMap<String, String> {
        let mut values = std::collections::HashMap::from([
            (
                "TOKENSTREAM_DATA_LISTEN_ADDR".to_owned(),
                self.data_listen_addr.to_string(),
            ),
            (
                "TOKENSTREAM_ADMIN_LISTEN_ADDR".to_owned(),
                self.admin_listen_addr.to_string(),
            ),
            (
                "TOKENSTREAM_DATABASE_URL".to_owned(),
                self.database_url.expose().to_owned(),
            ),
            ("TOKENSTREAM_MASTER_KEY".to_owned(), self.master_key_hex()),
            (
                "TOKENSTREAM_BOOTSTRAP_ACCOUNT".to_owned(),
                self.bootstrap_account_name().to_owned(),
            ),
            (
                "TOKENSTREAM_ADMIN_PASSWORD_HASH".to_owned(),
                self.admin_password_hash.expose().to_owned(),
            ),
            (
                "TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS".to_owned(),
                self.upstream_connect_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_UPSTREAM_HEADER_TIMEOUT_MS".to_owned(),
                self.upstream_header_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_STREAM_IDLE_TIMEOUT_MS".to_owned(),
                self.stream_idle_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_UPSTREAM_IDLE_PER_HOST".to_owned(),
                self.upstream_idle_per_host.to_string(),
            ),
            (
                "TOKENSTREAM_UPSTREAM_POOL_IDLE_TIMEOUT_MS".to_owned(),
                self.upstream_pool_idle_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_SHUTDOWN_DRAIN_TIMEOUT_MS".to_owned(),
                self.shutdown_drain_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_LOG_FLUSH_TIMEOUT_MS".to_owned(),
                self.log_flush_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_DATABASE_MAX_CONNECTIONS".to_owned(),
                self.database_max_connections.to_string(),
            ),
            (
                "TOKENSTREAM_MAX_PROXY_CONNECTIONS".to_owned(),
                self.max_proxy_connections.to_string(),
            ),
            (
                "TOKENSTREAM_PASSWORD_MAX_CONCURRENCY".to_owned(),
                self.password_max_concurrency.to_string(),
            ),
            (
                "TOKENSTREAM_ADMIN_PASSWORD_CONCURRENCY".to_owned(),
                self.admin_password_concurrency.to_string(),
            ),
            (
                "TOKENSTREAM_AUTH_DATABASE_CONNECTIONS".to_owned(),
                self.auth_database_connections.to_string(),
            ),
            (
                "TOKENSTREAM_AUTH_DB_TIMEOUT_MS".to_owned(),
                self.auth_db_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_ADMIN_DB_TIMEOUT_MS".to_owned(),
                self.admin_db_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_LOG_DB_TIMEOUT_MS".to_owned(),
                self.log_db_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_DATA_MAX_CONNECTIONS".to_owned(),
                self.data_max_connections.to_string(),
            ),
            (
                "TOKENSTREAM_ADMIN_MAX_CONNECTIONS".to_owned(),
                self.admin_max_connections.to_string(),
            ),
            (
                "TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS".to_owned(),
                self.downstream_header_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS".to_owned(),
                self.admin_body_timeout.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_ADMIN_SESSION_TTL_MS".to_owned(),
                self.admin_session_ttl.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_HTTP_BUFFER_BYTES".to_owned(),
                self.http_buffer_bytes.to_string(),
            ),
            (
                "TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES".to_owned(),
                self.websocket_max_frame_bytes.to_string(),
            ),
            (
                "TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES".to_owned(),
                self.websocket_max_message_bytes.to_string(),
            ),
            (
                "TOKENSTREAM_WEBSOCKET_QUEUE_CAPACITY".to_owned(),
                self.websocket_queue_capacity.to_string(),
            ),
            (
                "TOKENSTREAM_LOG_QUEUE_CAPACITY".to_owned(),
                self.log_queue_capacity.to_string(),
            ),
            (
                "TOKENSTREAM_LOG_BATCH_SIZE".to_owned(),
                self.log_batch_size.to_string(),
            ),
            (
                "TOKENSTREAM_LOG_BATCH_INTERVAL_MS".to_owned(),
                self.log_batch_interval.as_millis().to_string(),
            ),
            (
                "TOKENSTREAM_DEVELOPMENT_MODE".to_owned(),
                if self.development_mode {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                },
            ),
        ]);
        if let Some(data_dir) = &self.data_dir {
            values.insert(
                "TOKENSTREAM_DATA_DIR".to_owned(),
                data_dir.display().to_string(),
            );
        }
        values
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ConfigError {
    Missing {
        name: &'static str,
    },
    Invalid {
        name: &'static str,
        requirement: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { name } => write!(formatter, "required configuration {name} is missing"),
            Self::Invalid { name, requirement } => {
                write!(formatter, "configuration {name} is invalid: {requirement}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

fn optional(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
    name: &'static str,
) -> Result<Option<String>, ConfigError> {
    match get(name) {
        Ok(Some(value)) if value.is_empty() => Err(ConfigError::Invalid {
            name,
            requirement: "must be non-empty when present",
        }),
        Ok(value) => Ok(value),
        Err(()) => Err(ConfigError::Invalid {
            name,
            requirement: "must contain valid Unicode",
        }),
    }
}

fn parse_optional_value<T: std::str::FromStr>(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
    name: &'static str,
    default: &str,
) -> Result<T, ConfigError> {
    let raw = optional(get, name)?.unwrap_or_else(|| default.to_owned());
    raw.parse().map_err(|_| ConfigError::Invalid {
        name,
        requirement: "has an invalid format",
    })
}

fn parse_optional_flag(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
    name: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match optional(get, name)? {
        None => Ok(default),
        Some(value) => match value.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(ConfigError::Invalid {
                name,
                requirement: "must be either true or false",
            }),
        },
    }
}

fn required(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
    name: &'static str,
) -> Result<String, ConfigError> {
    match get(name) {
        Ok(Some(value)) if !value.is_empty() => Ok(value),
        Ok(Some(_)) | Ok(None) => Err(ConfigError::Missing { name }),
        Err(()) => Err(ConfigError::Invalid {
            name,
            requirement: "must contain valid Unicode",
        }),
    }
}

fn parse_bounded(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
    name: &'static str,
    minimum: usize,
    maximum: usize,
) -> Result<usize, ConfigError> {
    let value = required(get, name)?
        .parse::<usize>()
        .map_err(|_| ConfigError::Invalid {
            name,
            requirement: "must be a positive integer",
        })?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigError::Invalid {
            name,
            requirement: "is outside the supported range",
        });
    }
    Ok(value)
}

fn parse_optional_duration(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
    name: &'static str,
    default_ms: u64,
    maximum: u64,
) -> Result<Duration, ConfigError> {
    let value = get(name).map_err(|_| ConfigError::Invalid {
        name,
        requirement: "must contain valid Unicode",
    })?;
    match value {
        None => Ok(Duration::from_millis(default_ms)),
        Some(value) => {
            let milliseconds = value.parse::<u64>().map_err(|_| ConfigError::Invalid {
                name,
                requirement: "must be an integer number of milliseconds",
            })?;
            if !(MIN_TIMEOUT_MS..=maximum).contains(&milliseconds) {
                return Err(ConfigError::Invalid {
                    name,
                    requirement: "is outside the supported timeout range",
                });
            }
            Ok(Duration::from_millis(milliseconds))
        }
    }
}

fn parse_optional(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
    name: &'static str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, ConfigError> {
    let value = get(name).map_err(|_| ConfigError::Invalid {
        name,
        requirement: "must contain valid Unicode",
    })?;
    match value {
        None => Ok(default),
        Some(value) => parse_bounded(&mut |_| Ok(Some(value.clone())), name, minimum, maximum),
    }
}

fn validate_database_url(value: &str) -> Result<(), ConfigError> {
    const NAME: &str = "TOKENSTREAM_DATABASE_URL";
    if value == "sqlite::memory:" {
        return Ok(());
    }
    if let Some(path) = value.strip_prefix("sqlite://") {
        if !path.is_empty() && !path.chars().any(char::is_control) {
            return Ok(());
        }
        return Err(ConfigError::Invalid {
            name: NAME,
            requirement: "must contain a non-empty SQLite path",
        });
    }

    for prefix in ["postgres://", "postgresql://"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            let (authority, database) = rest.split_once('/').unwrap_or_default();
            let host = authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host);
            if !host.is_empty()
                && !host.starts_with(':')
                && !database.is_empty()
                && !value
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                return Ok(());
            }
        }
    }
    Err(ConfigError::Invalid {
        name: NAME,
        requirement: "must be a SQLite or PostgreSQL URL",
    })
}

fn decode_master_key(value: &str) -> Result<[u8; 32], ConfigError> {
    const NAME: &str = "TOKENSTREAM_MASTER_KEY";
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::Invalid {
            name: NAME,
            requirement: "must be exactly 32 bytes encoded as 64 hexadecimal characters",
        });
    }

    let mut key = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_digit(pair[0]);
        let low = hex_digit(pair[1]);
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

pub(crate) fn decode_master_key_for_admin(value: &str) -> Result<[u8; 32], ConfigError> {
    decode_master_key(value)
}

fn hex_digit(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => unreachable!("master key was validated as hexadecimal"),
    }
}

fn validate_admin_password_hash(value: &str) -> Result<(), ConfigError> {
    let parts: Vec<_> = value.split('$').collect();
    let (parameters, salt, hash) = match parts.as_slice() {
        ["", "argon2id", version, parameters, salt, hash] if *version == "v=19" => {
            (*parameters, *salt, *hash)
        }
        ["", "argon2id", parameters, salt, hash] => (*parameters, *salt, *hash),
        _ => return Err(invalid_admin_hash()),
    };
    let mut memory = None;
    let mut iterations = None;
    let mut parallelism = None;
    for parameter in parameters.split(',') {
        let (name, value) = parameter.split_once('=').ok_or_else(invalid_admin_hash)?;
        let value = value.parse::<u32>().map_err(|_| invalid_admin_hash())?;
        if value == 0 {
            return Err(invalid_admin_hash());
        }
        match name {
            "m" if memory.replace(value).is_none() => {}
            "t" if iterations.replace(value).is_none() => {}
            "p" if parallelism.replace(value).is_none() => {}
            _ => return Err(invalid_admin_hash()),
        }
    }
    if memory.is_none()
        || iterations.is_none()
        || parallelism.is_none()
        || !valid_phc_base64(salt)
        || !valid_phc_base64(hash)
    {
        return Err(invalid_admin_hash());
    }
    Ok(())
}

fn valid_phc_base64(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

fn invalid_admin_hash() -> ConfigError {
    ConfigError::Invalid {
        name: "TOKENSTREAM_ADMIN_PASSWORD_HASH",
        requirement: "must be a valid Argon2id password hash",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{Config, ConfigError};

    fn valid_values() -> HashMap<&'static str, String> {
        HashMap::from([
            ("TOKENSTREAM_DATA_LISTEN_ADDR", "127.0.0.1:3000".into()),
            ("TOKENSTREAM_ADMIN_LISTEN_ADDR", "127.0.0.1:3001".into()),
            ("TOKENSTREAM_DATABASE_URL", "sqlite://tokenstream.db".into()),
            ("TOKENSTREAM_MASTER_KEY", "11".repeat(32)),
            (
                "TOKENSTREAM_ADMIN_PASSWORD_HASH",
                "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA".into(),
            ),
            ("TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS", "5000".into()),
            ("TOKENSTREAM_UPSTREAM_HEADER_TIMEOUT_MS", "30000".into()),
            ("TOKENSTREAM_STREAM_IDLE_TIMEOUT_MS", "60000".into()),
            ("TOKENSTREAM_SHUTDOWN_DRAIN_TIMEOUT_MS", "30000".into()),
            ("TOKENSTREAM_LOG_FLUSH_TIMEOUT_MS", "5000".into()),
            ("TOKENSTREAM_DATABASE_MAX_CONNECTIONS", "16".into()),
            ("TOKENSTREAM_MAX_PROXY_CONNECTIONS", "4096".into()),
            ("TOKENSTREAM_HTTP_BUFFER_BYTES", "65536".into()),
            ("TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES", "1048576".into()),
            ("TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES", "8388608".into()),
            ("TOKENSTREAM_WEBSOCKET_QUEUE_CAPACITY", "32".into()),
            ("TOKENSTREAM_LOG_QUEUE_CAPACITY", "8192".into()),
            ("TOKENSTREAM_LOG_BATCH_SIZE", "128".into()),
            ("TOKENSTREAM_LOG_BATCH_INTERVAL_MS", "100".into()),
            ("TOKENSTREAM_DEVELOPMENT_MODE", "false".into()),
        ])
    }

    fn load(values: &HashMap<&'static str, String>) -> Result<Config, ConfigError> {
        Config::from_source(|name| Ok(values.get(name).cloned()))
    }

    #[test]
    fn loads_every_required_setting() {
        let config = load(&valid_values()).expect("valid configuration");

        assert_eq!(config.data_listen_addr().port(), 3000);
        assert_eq!(config.admin_listen_addr().port(), 3001);
        assert_eq!(config.database_url().expose(), "sqlite://tokenstream.db");
        assert_eq!(config.master_key().expose(), &[0x11; 32]);
        assert!(
            config
                .admin_password_hash()
                .expose()
                .starts_with("$argon2id$")
        );
        assert_eq!(config.upstream_connect_timeout().as_millis(), 5000);
        assert_eq!(config.upstream_header_timeout().as_millis(), 30000);
        assert_eq!(config.stream_idle_timeout().as_millis(), 60000);
        assert_eq!(config.upstream_idle_per_host(), 8);
        assert_eq!(config.upstream_pool_idle_timeout().as_millis(), 30_000);
        assert_eq!(config.shutdown_drain_timeout().as_millis(), 30000);
        assert_eq!(config.log_flush_timeout().as_millis(), 5000);
        assert_eq!(config.database_max_connections(), 16);
        assert_eq!(config.max_proxy_connections(), 4096);
        assert_eq!(config.http_buffer_bytes(), 65536);
        assert_eq!(config.websocket_max_frame_bytes(), 1048576);
        assert_eq!(config.websocket_max_message_bytes(), 8388608);
        assert_eq!(config.websocket_queue_capacity(), 32);
        assert_eq!(config.log_queue_capacity(), 8192);
        assert_eq!(config.log_batch_size(), 128);
        assert_eq!(config.log_batch_interval().as_millis(), 100);
        assert!(!config.development_mode());
    }

    #[test]
    fn absent_settings_use_compiled_defaults() {
        let config = load(&HashMap::new()).expect("defaulted configuration");
        assert_eq!(config.data_listen_addr().port(), 3300);
        assert_eq!(config.admin_listen_addr().port(), 3301);
        assert_eq!(config.database_url().expose(), "sqlite::memory:");
        assert_eq!(config.master_key().expose().len(), 32);
        assert!(
            config
                .admin_password_hash()
                .expose()
                .starts_with("$argon2id$")
        );
        assert_eq!(config.upstream_connect_timeout().as_millis(), 5000);
        assert_eq!(config.http_buffer_bytes(), 65536);
        assert!(config.development_mode());
        assert!(config.uses_default_admin_password());
    }

    #[test]
    fn development_mode_is_explicitly_opt_in() {
        let mut values = valid_values();
        values.insert("TOKENSTREAM_DEVELOPMENT_MODE", "true".into());
        assert!(
            load(&values)
                .expect("valid configuration")
                .development_mode()
        );
    }

    #[test]
    fn rejects_invalid_formats_without_echoing_values() {
        for (name, invalid) in [
            ("TOKENSTREAM_DATA_LISTEN_ADDR", "secret-address"),
            ("TOKENSTREAM_DATABASE_URL", "secret-database"),
            ("TOKENSTREAM_MASTER_KEY", "secret-master-key"),
            ("TOKENSTREAM_ADMIN_PASSWORD_HASH", "secret-password-hash"),
            ("TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS", "secret-timeout"),
            ("TOKENSTREAM_MAX_PROXY_CONNECTIONS", "secret-count"),
            ("TOKENSTREAM_DEVELOPMENT_MODE", "secret-mode"),
        ] {
            let mut values = valid_values();
            values.insert(name, invalid.into());
            let rendered = load(&values).unwrap_err().to_string();
            assert!(rendered.contains(name));
            assert!(!rendered.contains(invalid));
        }
    }

    #[test]
    fn rejects_values_outside_resource_bounds() {
        for (name, invalid) in [
            ("TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS", "0"),
            ("TOKENSTREAM_UPSTREAM_HEADER_TIMEOUT_MS", "300001"),
            ("TOKENSTREAM_STREAM_IDLE_TIMEOUT_MS", "3600001"),
            ("TOKENSTREAM_UPSTREAM_IDLE_PER_HOST", "65"),
            ("TOKENSTREAM_UPSTREAM_POOL_IDLE_TIMEOUT_MS", "0"),
            ("TOKENSTREAM_UPSTREAM_POOL_IDLE_TIMEOUT_MS", "300001"),
            ("TOKENSTREAM_SHUTDOWN_DRAIN_TIMEOUT_MS", "300001"),
            ("TOKENSTREAM_LOG_FLUSH_TIMEOUT_MS", "0"),
            ("TOKENSTREAM_DATABASE_MAX_CONNECTIONS", "0"),
            ("TOKENSTREAM_MAX_PROXY_CONNECTIONS", "1000001"),
            ("TOKENSTREAM_HTTP_BUFFER_BYTES", "1023"),
            ("TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES", "67108865"),
            ("TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES", "0"),
            ("TOKENSTREAM_WEBSOCKET_QUEUE_CAPACITY", "0"),
            ("TOKENSTREAM_LOG_QUEUE_CAPACITY", "1000001"),
            ("TOKENSTREAM_LOG_BATCH_SIZE", "0"),
            ("TOKENSTREAM_LOG_BATCH_INTERVAL_MS", "60001"),
            ("TOKENSTREAM_PASSWORD_MAX_CONCURRENCY", "1"),
            ("TOKENSTREAM_PASSWORD_MAX_CONCURRENCY", "65"),
            ("TOKENSTREAM_ADMIN_PASSWORD_CONCURRENCY", "0"),
            ("TOKENSTREAM_AUTH_DATABASE_CONNECTIONS", "0"),
            ("TOKENSTREAM_AUTH_DB_TIMEOUT_MS", "0"),
            ("TOKENSTREAM_ADMIN_DB_TIMEOUT_MS", "60001"),
            ("TOKENSTREAM_LOG_DB_TIMEOUT_MS", "0"),
            ("TOKENSTREAM_DATA_MAX_CONNECTIONS", "4096"),
            ("TOKENSTREAM_ADMIN_MAX_CONNECTIONS", "0"),
            ("TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS", "0"),
            ("TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS", "300001"),
            ("TOKENSTREAM_ADMIN_SESSION_TTL_MS", "0"),
            ("TOKENSTREAM_ADMIN_SESSION_TTL_MS", "3600001"),
        ] {
            let mut values = valid_values();
            values.insert(name, invalid.into());
            assert!(
                matches!(load(&values), Err(ConfigError::Invalid { name: actual, .. }) if actual == name)
            );
        }
    }

    #[test]
    fn derives_runtime_bounds_from_the_proxy_capacity() {
        let config = load(&valid_values()).expect("valid configuration");

        assert_eq!(config.password_max_concurrency(), 4);
        assert_eq!(config.data_password_concurrency(), 3);
        assert_eq!(config.admin_password_concurrency(), 1);
        assert_eq!(config.auth_database_connections(), 2);
        assert_eq!(config.auth_db_timeout().as_millis(), 1000);
        assert_eq!(config.admin_db_timeout().as_millis(), 5000);
        assert_eq!(config.log_db_timeout().as_millis(), 2000);
        assert_eq!(config.admin_max_connections(), 128);
        assert_eq!(config.downstream_header_timeout().as_millis(), 10000);
        assert_eq!(config.admin_body_timeout().as_millis(), 30000);
        assert_eq!(config.admin_session_ttl().as_millis(), 15 * 60 * 1000);
        assert_eq!(config.upstream_idle_per_host(), 8);
        assert_eq!(config.upstream_pool_idle_timeout().as_millis(), 30_000);
        assert!(
            config.data_max_connections() > config.max_proxy_connections(),
            "the data plane must keep room to reject overload before the proxy limit"
        );

        let mut explicit = valid_values();
        for (name, value) in [
            ("TOKENSTREAM_PASSWORD_MAX_CONCURRENCY", "12"),
            ("TOKENSTREAM_DATA_MAX_CONNECTIONS", "5000"),
            ("TOKENSTREAM_ADMIN_MAX_CONNECTIONS", "64"),
            ("TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS", "1500"),
            ("TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS", "2000"),
            ("TOKENSTREAM_UPSTREAM_IDLE_PER_HOST", "0"),
            ("TOKENSTREAM_UPSTREAM_POOL_IDLE_TIMEOUT_MS", "1500"),
            ("TOKENSTREAM_ADMIN_SESSION_TTL_MS", "2000"),
        ] {
            explicit.insert(name, value.into());
        }
        let config = load(&explicit).expect("valid configuration");
        assert_eq!(config.password_max_concurrency(), 12);
        assert_eq!(config.data_password_concurrency(), 11);
        assert_eq!(config.admin_password_concurrency(), 1);
        assert_eq!(config.data_max_connections(), 5000);
        assert_eq!(config.admin_max_connections(), 64);
        assert_eq!(config.downstream_header_timeout().as_millis(), 1500);
        assert_eq!(config.admin_body_timeout().as_millis(), 2000);
        assert_eq!(config.admin_session_ttl().as_millis(), 2000);
        assert_eq!(config.upstream_idle_per_host(), 0);
        assert_eq!(config.upstream_pool_idle_timeout().as_millis(), 1500);
    }

    #[test]
    fn rejects_conflicting_addresses_and_cross_field_limits() {
        let mut same_addresses = valid_values();
        same_addresses.insert("TOKENSTREAM_ADMIN_LISTEN_ADDR", "127.0.0.1:3000".into());
        assert!(load(&same_addresses).is_err());

        let mut oversized_frame = valid_values();
        oversized_frame.insert("TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES", "8388609".into());
        assert!(load(&oversized_frame).is_err());

        let mut oversized_batch = valid_values();
        oversized_batch.insert("TOKENSTREAM_LOG_BATCH_SIZE", "8193".into());
        assert!(load(&oversized_batch).is_err());
    }

    #[test]
    fn debug_output_redacts_secrets_and_database_credentials() {
        let mut values = valid_values();
        values.insert(
            "TOKENSTREAM_DATABASE_URL",
            "postgresql://secret-user:secret-password@localhost/tokenstream".into(),
        );
        let config = load(&values).expect("valid configuration");
        let rendered = format!("{config:?}");

        assert!(!rendered.contains("secret-user"));
        assert!(!rendered.contains("secret-password"));
        assert!(!rendered.contains("$argon2id$"));
        assert!(!rendered.contains(&"11".repeat(32)));
        assert!(rendered.contains("[REDACTED]"));
    }
}
