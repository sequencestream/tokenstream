use std::env;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

const MIN_TIMEOUT_MS: u64 = 1;
const MAX_UPSTREAM_TIMEOUT_MS: u64 = 300_000;
const MAX_IDLE_TIMEOUT_MS: u64 = 3_600_000;
const MAX_SHUTDOWN_TIMEOUT_MS: u64 = 300_000;
const MAX_LOG_BATCH_INTERVAL_MS: u64 = 60_000;
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

#[derive(Clone, Debug)]
pub struct Config {
    data_listen_addr: SocketAddr,
    admin_listen_addr: SocketAddr,
    database_url: DatabaseUrl,
    master_key: MasterKey,
    admin_password_hash: AdminPasswordHash,
    upstream_connect_timeout: Duration,
    upstream_header_timeout: Duration,
    stream_idle_timeout: Duration,
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
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(|name| match env::var_os(name) {
            Some(value) => value.into_string().map(Some).map_err(|_| ()),
            None => Ok(None),
        })
    }

    fn from_source(
        mut get: impl FnMut(&str) -> Result<Option<String>, ()>,
    ) -> Result<Self, ConfigError> {
        let data_listen_addr = parse_required(&mut get, "TOKENSTREAM_DATA_LISTEN_ADDR")?;
        let admin_listen_addr = parse_required(&mut get, "TOKENSTREAM_ADMIN_LISTEN_ADDR")?;
        if data_listen_addr == admin_listen_addr {
            return Err(ConfigError::Invalid {
                name: "TOKENSTREAM_ADMIN_LISTEN_ADDR",
                requirement: "must differ from TOKENSTREAM_DATA_LISTEN_ADDR",
            });
        }

        let database_url_value = required(&mut get, "TOKENSTREAM_DATABASE_URL")?;
        validate_database_url(&database_url_value)?;
        let database_url = DatabaseUrl(database_url_value);

        let master_key_value = required(&mut get, "TOKENSTREAM_MASTER_KEY")?;
        let master_key = MasterKey(decode_master_key(&master_key_value)?);

        let admin_hash_value = required(&mut get, "TOKENSTREAM_ADMIN_PASSWORD_HASH")?;
        validate_admin_password_hash(&admin_hash_value)?;
        let admin_password_hash = AdminPasswordHash(admin_hash_value);

        let upstream_connect_timeout = parse_duration(
            &mut get,
            "TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS",
            MAX_UPSTREAM_TIMEOUT_MS,
        )?;
        let upstream_header_timeout = parse_duration(
            &mut get,
            "TOKENSTREAM_UPSTREAM_HEADER_TIMEOUT_MS",
            MAX_UPSTREAM_TIMEOUT_MS,
        )?;
        let stream_idle_timeout = parse_duration(
            &mut get,
            "TOKENSTREAM_STREAM_IDLE_TIMEOUT_MS",
            MAX_IDLE_TIMEOUT_MS,
        )?;
        let shutdown_drain_timeout = parse_duration(
            &mut get,
            "TOKENSTREAM_SHUTDOWN_DRAIN_TIMEOUT_MS",
            MAX_SHUTDOWN_TIMEOUT_MS,
        )?;
        let log_flush_timeout = parse_duration(
            &mut get,
            "TOKENSTREAM_LOG_FLUSH_TIMEOUT_MS",
            MAX_SHUTDOWN_TIMEOUT_MS,
        )?;
        let database_max_connections = parse_bounded(
            &mut get,
            "TOKENSTREAM_DATABASE_MAX_CONNECTIONS",
            1,
            MAX_DATABASE_CONNECTIONS,
        )?;
        let max_proxy_connections = parse_bounded(
            &mut get,
            "TOKENSTREAM_MAX_PROXY_CONNECTIONS",
            1,
            MAX_PROXY_CONNECTIONS,
        )?;
        let http_buffer_bytes = parse_bounded(
            &mut get,
            "TOKENSTREAM_HTTP_BUFFER_BYTES",
            MIN_HTTP_BUFFER_BYTES,
            MAX_HTTP_BUFFER_BYTES,
        )?;
        let websocket_max_frame_bytes = parse_bounded(
            &mut get,
            "TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES",
            1,
            MAX_WEBSOCKET_BYTES,
        )?;
        let websocket_max_message_bytes = parse_bounded(
            &mut get,
            "TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES",
            1,
            MAX_WEBSOCKET_BYTES,
        )?;
        if websocket_max_frame_bytes > websocket_max_message_bytes {
            return Err(ConfigError::Invalid {
                name: "TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES",
                requirement: "must not exceed TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES",
            });
        }
        let websocket_queue_capacity = parse_bounded(
            &mut get,
            "TOKENSTREAM_WEBSOCKET_QUEUE_CAPACITY",
            1,
            MAX_QUEUE_CAPACITY,
        )?;
        let log_queue_capacity = parse_bounded(
            &mut get,
            "TOKENSTREAM_LOG_QUEUE_CAPACITY",
            1,
            MAX_QUEUE_CAPACITY,
        )?;
        let log_batch_size = parse_bounded(
            &mut get,
            "TOKENSTREAM_LOG_BATCH_SIZE",
            1,
            MAX_QUEUE_CAPACITY,
        )?;
        if log_batch_size > log_queue_capacity {
            return Err(ConfigError::Invalid {
                name: "TOKENSTREAM_LOG_BATCH_SIZE",
                requirement: "must not exceed TOKENSTREAM_LOG_QUEUE_CAPACITY",
            });
        }
        let log_batch_interval = parse_duration(
            &mut get,
            "TOKENSTREAM_LOG_BATCH_INTERVAL_MS",
            MAX_LOG_BATCH_INTERVAL_MS,
        )?;

        Ok(Self {
            data_listen_addr,
            admin_listen_addr,
            database_url,
            master_key,
            admin_password_hash,
            upstream_connect_timeout,
            upstream_header_timeout,
            stream_idle_timeout,
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
        })
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

    pub fn upstream_connect_timeout(&self) -> Duration {
        self.upstream_connect_timeout
    }

    pub fn upstream_header_timeout(&self) -> Duration {
        self.upstream_header_timeout
    }

    pub fn stream_idle_timeout(&self) -> Duration {
        self.stream_idle_timeout
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

fn parse_required<T: std::str::FromStr>(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
    name: &'static str,
) -> Result<T, ConfigError> {
    required(get, name)?
        .parse()
        .map_err(|_| ConfigError::Invalid {
            name,
            requirement: "has an invalid format",
        })
}

fn parse_duration(
    get: &mut impl FnMut(&str) -> Result<Option<String>, ()>,
    name: &'static str,
    maximum: u64,
) -> Result<Duration, ConfigError> {
    let milliseconds = required(get, name)?
        .parse::<u64>()
        .map_err(|_| ConfigError::Invalid {
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
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0]);
        let low = hex_digit(pair[1]);
        key[index] = (high << 4) | low;
    }
    Ok(key)
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
    }

    #[test]
    fn every_setting_is_required() {
        for name in valid_values().keys() {
            let mut values = valid_values();
            values.remove(name);
            assert_eq!(load(&values).unwrap_err(), ConfigError::Missing { name });
        }
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
        ] {
            let mut values = valid_values();
            values.insert(name, invalid.into());
            assert!(
                matches!(load(&values), Err(ConfigError::Invalid { name: actual, .. }) if actual == name)
            );
        }
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
