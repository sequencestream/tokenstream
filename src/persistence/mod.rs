use std::error::Error;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use url::Url;

use crate::domain::{
    EmptyOpaqueValueError, GatewayKeyId, PasswordHash, PositiveValueError, ProtocolType, Provider,
    ProviderCursor, ProviderId, ProviderStatus, RequestId, RequestLog, RequestLogCursor,
    RequestLogId, SecretCiphertext, TransportType,
};

pub mod postgres;
pub mod sqlite;
pub mod time;

use postgres::PostgresDatabase;
use sqlite::SqliteDatabase;

pub const MAX_PROVIDER_PAGE_SIZE: usize = 100;
pub const MAX_REQUEST_LOG_PAGE_SIZE: usize = 100;

/// Longest a storage operation waits for a pooled connection before failing closed.
///
/// The pool's connection count is the hard upper bound; this deadline keeps an
/// exhausted pool from blocking an authentication lookup indefinitely. Exhaustion
/// and execution deadlines surface as [`RepositoryError::Timeout`].
pub const DEFAULT_POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Connection split and execution deadlines for one database handle.
///
/// `auth_connections` smaller than `max_connections` reserves that many pooled
/// connections for credential lookup. The remainder serves administration and
/// logging. When the values are equal, both paths share one pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseBounds {
    pub max_connections: usize,
    pub auth_connections: usize,
    pub acquire_timeout: Duration,
    pub auth_timeout: Duration,
    pub admin_timeout: Duration,
    pub log_timeout: Duration,
}

impl DatabaseBounds {
    /// A single shared pool whose acquire and execution deadlines match the
    /// historical connection-wait bound. Tests that do not exercise isolation
    /// or per-class deadlines use this layout.
    pub fn for_tests(max_connections: usize) -> Self {
        Self {
            max_connections,
            auth_connections: max_connections,
            acquire_timeout: DEFAULT_POOL_ACQUIRE_TIMEOUT,
            auth_timeout: DEFAULT_POOL_ACQUIRE_TIMEOUT,
            admin_timeout: DEFAULT_POOL_ACQUIRE_TIMEOUT,
            log_timeout: DEFAULT_POOL_ACQUIRE_TIMEOUT,
        }
    }
}

/// Cancels `fut` when `deadline` elapses so a stuck query cannot occupy a
/// caller or a pool slot indefinitely.
pub(crate) async fn timed<T>(
    deadline: Duration,
    fut: impl Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, sqlx::Error> {
    match tokio::time::timeout(deadline, fut).await {
        Ok(result) => result,
        Err(_) => Err(sqlx::Error::PoolTimedOut),
    }
}

/// Storage backend selected from the configured database URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseBackend {
    Sqlite,
    Postgres,
}

impl DatabaseBackend {
    /// Selects a backend from a validated database URL.
    ///
    /// SQLite URLs use the `sqlite:` scheme; every other accepted URL targets
    /// PostgreSQL.
    pub fn from_url(database_url: &str) -> Self {
        if database_url.starts_with("sqlite:") {
            Self::Sqlite
        } else {
            Self::Postgres
        }
    }
}

/// One storage handle whose concrete backend is chosen from the database URL.
#[derive(Clone, Debug)]
pub enum Database {
    Sqlite(SqliteDatabase),
    Postgres(PostgresDatabase),
}

impl Database {
    /// Connects to the backend selected from `database_url` with a bounded pool.
    pub async fn connect(database_url: &str, max_connections: usize) -> Result<Self, sqlx::Error> {
        Self::connect_with_bounds(database_url, DatabaseBounds::for_tests(max_connections)).await
    }

    /// Connects with an explicit connection split and per-class execution deadlines.
    pub async fn connect_with_bounds(
        database_url: &str,
        bounds: DatabaseBounds,
    ) -> Result<Self, sqlx::Error> {
        match DatabaseBackend::from_url(database_url) {
            DatabaseBackend::Sqlite => Ok(Self::Sqlite(
                SqliteDatabase::connect_with_bounds(database_url, bounds).await?,
            )),
            DatabaseBackend::Postgres => Ok(Self::Postgres(
                PostgresDatabase::connect_with_bounds(database_url, bounds).await?,
            )),
        }
    }

    pub fn backend(&self) -> DatabaseBackend {
        match self {
            Self::Sqlite(_) => DatabaseBackend::Sqlite,
            Self::Postgres(_) => DatabaseBackend::Postgres,
        }
    }
}

impl crate::MigrationRunner for Database {
    async fn run(&self) -> std::io::Result<()> {
        match self {
            Self::Sqlite(database) => crate::MigrationRunner::run(database).await,
            Self::Postgres(database) => crate::MigrationRunner::run(database).await,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NewProvider {
    name: String,
    protocol_type: ProtocolType,
    endpoint: Url,
    upstream_api_key_ciphertext: SecretCiphertext,
    gateway_key_id: GatewayKeyId,
    gateway_api_key_hash: PasswordHash,
    status: ProviderStatus,
    created_at: DateTime<Utc>,
}

impl NewProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        protocol_type: ProtocolType,
        endpoint: Url,
        upstream_api_key_ciphertext: SecretCiphertext,
        gateway_key_id: GatewayKeyId,
        gateway_api_key_hash: PasswordHash,
        status: ProviderStatus,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            name,
            protocol_type,
            endpoint,
            upstream_api_key_ciphertext,
            gateway_key_id,
            gateway_api_key_hash,
            status,
            created_at,
        }
    }
}

/// A field-scoped provider change set.
///
/// Only the named fields are written. Every unnamed column keeps the value it
/// currently holds in the database, so an edit can never restore a rotated
/// gateway key, revoke a status transition it did not name, or reset an
/// unchanged configuration field. A change set with no named field matches
/// nothing and is rejected by the caller before it reaches storage.
#[derive(Clone, Debug, Default)]
pub struct ProviderUpdate {
    name: Option<String>,
    endpoint: Option<Url>,
    upstream_api_key_ciphertext: Option<SecretCiphertext>,
    status: Option<ProviderStatus>,
}

impl ProviderUpdate {
    /// Starts an empty change set that names no field.
    pub fn new() -> Self {
        Self::default()
    }

    /// Names the display name as a field to write.
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Names the upstream endpoint as a field to write.
    pub fn with_endpoint(mut self, endpoint: Url) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Names the encrypted upstream credential as a field to write.
    pub fn with_upstream_api_key_ciphertext(mut self, ciphertext: SecretCiphertext) -> Self {
        self.upstream_api_key_ciphertext = Some(ciphertext);
        self
    }

    /// Names the status as a field to write.
    pub fn with_status(mut self, status: ProviderStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Reports whether the change set names no field at all.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.endpoint.is_none()
            && self.upstream_api_key_ciphertext.is_none()
            && self.status.is_none()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn endpoint(&self) -> Option<&Url> {
        self.endpoint.as_ref()
    }

    pub fn upstream_api_key_ciphertext(&self) -> Option<&SecretCiphertext> {
        self.upstream_api_key_ciphertext.as_ref()
    }

    pub fn status(&self) -> Option<ProviderStatus> {
        self.status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderListRequest {
    after_id: Option<ProviderCursor>,
    limit: usize,
}

impl ProviderListRequest {
    pub fn new(
        after_id: Option<ProviderCursor>,
        limit: usize,
    ) -> Result<Self, ProviderListRequestError> {
        if !(1..=MAX_PROVIDER_PAGE_SIZE).contains(&limit) {
            return Err(ProviderListRequestError);
        }
        Ok(Self { after_id, limit })
    }

    pub fn after_id(self) -> Option<ProviderCursor> {
        self.after_id
    }

    pub fn limit(self) -> usize {
        self.limit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderListRequestError;

impl fmt::Display for ProviderListRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "provider page size must be between 1 and {MAX_PROVIDER_PAGE_SIZE}"
        )
    }
}

impl Error for ProviderListRequestError {}

#[derive(Clone, Debug)]
pub struct RequestLogStarted {
    request_id: RequestId,
    provider_id: ProviderId,
    protocol_type: ProtocolType,
    transport_type: TransportType,
    path: String,
    start_time: DateTime<Utc>,
}

impl RequestLogStarted {
    pub fn new(
        request_id: RequestId,
        provider_id: ProviderId,
        protocol_type: ProtocolType,
        transport_type: TransportType,
        path: String,
        start_time: DateTime<Utc>,
    ) -> Self {
        Self {
            request_id,
            provider_id,
            protocol_type,
            transport_type,
            path,
            start_time,
        }
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    pub fn protocol_type(&self) -> ProtocolType {
        self.protocol_type
    }

    pub fn transport_type(&self) -> TransportType {
        self.transport_type
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn start_time(&self) -> DateTime<Utc> {
        self.start_time
    }
}

#[derive(Clone, Debug)]
pub struct RequestLogCompleted {
    request_id: RequestId,
    status_code: Option<u16>,
    end_time: DateTime<Utc>,
    error_msg: Option<String>,
}

impl RequestLogCompleted {
    pub fn new(
        request_id: RequestId,
        status_code: Option<u16>,
        end_time: DateTime<Utc>,
        error_msg: Option<String>,
    ) -> Self {
        Self {
            request_id,
            status_code,
            end_time,
            error_msg,
        }
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    pub fn end_time(&self) -> DateTime<Utc> {
        self.end_time
    }

    pub fn error_msg(&self) -> Option<&str> {
        self.error_msg.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLogQuery {
    after_id: Option<RequestLogCursor>,
    limit: usize,
    provider_id: Option<ProviderId>,
    transport_type: Option<TransportType>,
    start_time_gte: Option<DateTime<Utc>>,
    start_time_lt: Option<DateTime<Utc>>,
}

impl RequestLogQuery {
    pub fn new(
        after_id: Option<RequestLogCursor>,
        limit: usize,
        provider_id: Option<ProviderId>,
        transport_type: Option<TransportType>,
        start_time_gte: Option<DateTime<Utc>>,
        start_time_lt: Option<DateTime<Utc>>,
    ) -> Result<Self, RequestLogQueryError> {
        if !(1..=MAX_REQUEST_LOG_PAGE_SIZE).contains(&limit) {
            return Err(RequestLogQueryError::InvalidLimit);
        }
        if matches!((start_time_gte, start_time_lt), (Some(start), Some(end)) if start >= end) {
            return Err(RequestLogQueryError::InvalidTimeRange);
        }
        Ok(Self {
            after_id,
            limit,
            provider_id,
            transport_type,
            start_time_gte,
            start_time_lt,
        })
    }

    pub fn after_id(self) -> Option<RequestLogCursor> {
        self.after_id
    }

    pub fn limit(self) -> usize {
        self.limit
    }

    pub fn provider_id(self) -> Option<ProviderId> {
        self.provider_id
    }

    pub fn transport_type(self) -> Option<TransportType> {
        self.transport_type
    }

    pub fn start_time_gte(self) -> Option<DateTime<Utc>> {
        self.start_time_gte
    }

    pub fn start_time_lt(self) -> Option<DateTime<Utc>> {
        self.start_time_lt
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestLogQueryError {
    InvalidLimit,
    InvalidTimeRange,
}

impl fmt::Display for RequestLogQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => write!(
                formatter,
                "request log page size must be between 1 and {MAX_REQUEST_LOG_PAGE_SIZE}"
            ),
            Self::InvalidTimeRange => {
                formatter.write_str("request log start time lower bound must precede upper bound")
            }
        }
    }
}

impl Error for RequestLogQueryError {}

#[derive(Clone, Debug)]
pub struct RequestLogPage {
    items: Vec<RequestLog>,
    has_more: bool,
}

impl RequestLogPage {
    fn new(items: Vec<RequestLog>, has_more: bool) -> Self {
        Self { items, has_more }
    }

    pub fn items(&self) -> &[RequestLog] {
        &self.items
    }

    pub fn into_items(self) -> Vec<RequestLog> {
        self.items
    }

    pub fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn next_after_id(&self) -> Option<RequestLogCursor> {
        self.items
            .last()
            .map(|log| RequestLogCursor::try_from(log.id().get()))
            .transpose()
            .expect("stored request log IDs are positive")
    }
}

#[derive(Debug)]
pub struct ProviderPage {
    items: Vec<Provider>,
    has_more: bool,
}

impl ProviderPage {
    fn new(items: Vec<Provider>, has_more: bool) -> Self {
        Self { items, has_more }
    }

    pub fn items(&self) -> &[Provider] {
        &self.items
    }

    pub fn into_items(self) -> Vec<Provider> {
        self.items
    }

    pub fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn next_after_id(&self) -> Option<ProviderCursor> {
        self.items
            .last()
            .map(|provider| ProviderCursor::try_from(provider.id().get()))
            .transpose()
            .expect("stored provider IDs are positive")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    Conflict,
    ProviderInUse,
    NotFound,
    /// A partial update named no writable field, so no statement was issued.
    NoFieldsToUpdate,
    InvalidStoredData,
    Storage,
    /// A pooled connection could not be acquired, or a query or transaction
    /// exceeded its execution deadline.
    Timeout,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Conflict => "record conflicts with existing data",
            Self::ProviderInUse => "provider is referenced by request logs",
            Self::NotFound => "referenced record was not found",
            Self::NoFieldsToUpdate => "the change set named no writable field",
            Self::InvalidStoredData => "stored data is invalid",
            Self::Storage => "storage operation failed",
            Self::Timeout => "storage operation timed out",
        };
        formatter.write_str(message)
    }
}

impl Error for RepositoryError {}

#[allow(async_fn_in_trait)]
pub trait ProviderRepository: Send + Sync {
    async fn find_by_key_id(
        &self,
        key_id: &GatewayKeyId,
    ) -> Result<Option<Provider>, RepositoryError>;

    async fn find_by_id(&self, id: ProviderId) -> Result<Option<Provider>, RepositoryError>;

    async fn list(&self, request: ProviderListRequest) -> Result<ProviderPage, RepositoryError>;

    async fn create(&self, provider: NewProvider) -> Result<Provider, RepositoryError>;

    async fn update(
        &self,
        id: ProviderId,
        update: ProviderUpdate,
    ) -> Result<Provider, RepositoryError>;

    async fn rotate_gateway_key(
        &self,
        id: ProviderId,
        key_id: GatewayKeyId,
        hash: PasswordHash,
    ) -> Result<Provider, RepositoryError>;

    async fn delete(&self, id: ProviderId) -> Result<(), RepositoryError>;
}

#[allow(async_fn_in_trait)]
pub trait RequestLogRepository: Send + Sync {
    async fn insert_started(&self, event: RequestLogStarted) -> Result<(), RepositoryError>;

    async fn apply_completed(&self, event: RequestLogCompleted) -> Result<(), RepositoryError>;

    async fn query(&self, query: RequestLogQuery) -> Result<RequestLogPage, RepositoryError>;
}

#[allow(async_fn_in_trait)]
impl ProviderRepository for Database {
    async fn find_by_key_id(
        &self,
        key_id: &GatewayKeyId,
    ) -> Result<Option<Provider>, RepositoryError> {
        match self {
            Self::Sqlite(database) => database.find_by_key_id(key_id).await,
            Self::Postgres(database) => database.find_by_key_id(key_id).await,
        }
    }

    async fn find_by_id(&self, id: ProviderId) -> Result<Option<Provider>, RepositoryError> {
        match self {
            Self::Sqlite(database) => database.find_by_id(id).await,
            Self::Postgres(database) => database.find_by_id(id).await,
        }
    }

    async fn list(&self, request: ProviderListRequest) -> Result<ProviderPage, RepositoryError> {
        match self {
            Self::Sqlite(database) => database.list(request).await,
            Self::Postgres(database) => database.list(request).await,
        }
    }

    async fn create(&self, provider: NewProvider) -> Result<Provider, RepositoryError> {
        match self {
            Self::Sqlite(database) => database.create(provider).await,
            Self::Postgres(database) => database.create(provider).await,
        }
    }

    async fn update(
        &self,
        id: ProviderId,
        update: ProviderUpdate,
    ) -> Result<Provider, RepositoryError> {
        match self {
            Self::Sqlite(database) => database.update(id, update).await,
            Self::Postgres(database) => database.update(id, update).await,
        }
    }

    async fn rotate_gateway_key(
        &self,
        id: ProviderId,
        key_id: GatewayKeyId,
        hash: PasswordHash,
    ) -> Result<Provider, RepositoryError> {
        match self {
            Self::Sqlite(database) => database.rotate_gateway_key(id, key_id, hash).await,
            Self::Postgres(database) => database.rotate_gateway_key(id, key_id, hash).await,
        }
    }

    async fn delete(&self, id: ProviderId) -> Result<(), RepositoryError> {
        match self {
            Self::Sqlite(database) => database.delete(id).await,
            Self::Postgres(database) => database.delete(id).await,
        }
    }
}

#[allow(async_fn_in_trait)]
impl RequestLogRepository for Database {
    async fn insert_started(&self, event: RequestLogStarted) -> Result<(), RepositoryError> {
        match self {
            Self::Sqlite(database) => database.insert_started(event).await,
            Self::Postgres(database) => database.insert_started(event).await,
        }
    }

    async fn apply_completed(&self, event: RequestLogCompleted) -> Result<(), RepositoryError> {
        match self {
            Self::Sqlite(database) => database.apply_completed(event).await,
            Self::Postgres(database) => database.apply_completed(event).await,
        }
    }

    async fn query(&self, query: RequestLogQuery) -> Result<RequestLogPage, RepositoryError> {
        match self {
            Self::Sqlite(database) => database.query(query).await,
            Self::Postgres(database) => database.query(query).await,
        }
    }
}

#[derive(FromRow)]
struct ProviderRow {
    id: i64,
    name: String,
    protocol_type: String,
    endpoint: String,
    upstream_api_key_ciphertext: String,
    gateway_key_id: String,
    gateway_api_key_hash: String,
    status: String,
    created_at: i64,
}

impl ProviderRow {
    fn into_provider(self) -> Result<Provider, RepositoryError> {
        let id = ProviderId::try_from(self.id).map_err(invalid_positive_value)?;
        let protocol_type = match self.protocol_type.as_str() {
            "openai" => ProtocolType::OpenAi,
            "anthropic" => ProtocolType::Anthropic,
            _ => return Err(RepositoryError::InvalidStoredData),
        };
        let endpoint =
            Url::parse(&self.endpoint).map_err(|_| RepositoryError::InvalidStoredData)?;
        let gateway_key_id =
            GatewayKeyId::new(self.gateway_key_id).map_err(invalid_opaque_value)?;
        let status = match self.status.as_str() {
            "enabled" => ProviderStatus::Enabled,
            "disabled" => ProviderStatus::Disabled,
            _ => return Err(RepositoryError::InvalidStoredData),
        };
        let created_at = time::from_epoch_micros(self.created_at)?;

        Ok(Provider::new(
            id,
            self.name,
            protocol_type,
            endpoint,
            SecretCiphertext::new(self.upstream_api_key_ciphertext),
            gateway_key_id,
            PasswordHash::new(self.gateway_api_key_hash),
            status,
            created_at,
        ))
    }
}

#[derive(FromRow)]
struct RequestLogRow {
    id: i64,
    request_id: String,
    provider_id: i64,
    protocol_type: String,
    transport_type: String,
    path: String,
    status_code: Option<i64>,
    start_time: i64,
    end_time: Option<i64>,
    error_msg: Option<String>,
}

impl RequestLogRow {
    fn into_request_log(self) -> Result<RequestLog, RepositoryError> {
        let id = RequestLogId::try_from(self.id).map_err(invalid_positive_value)?;
        let request_id = RequestId::new(self.request_id).map_err(invalid_opaque_value)?;
        let provider_id = ProviderId::try_from(self.provider_id).map_err(invalid_positive_value)?;
        let protocol_type = parse_protocol_value(&self.protocol_type)?;
        let transport_type = match self.transport_type.as_str() {
            "http" => TransportType::Http,
            "websocket" => TransportType::WebSocket,
            _ => return Err(RepositoryError::InvalidStoredData),
        };
        let status_code = self
            .status_code
            .map(|value| u16::try_from(value).map_err(|_| RepositoryError::InvalidStoredData))
            .transpose()?;
        let start_time = time::from_epoch_micros(self.start_time)?;
        let end_time = self.end_time.map(time::from_epoch_micros).transpose()?;

        Ok(RequestLog::new(
            id,
            request_id,
            provider_id,
            protocol_type,
            transport_type,
            self.path,
            status_code,
            start_time,
            end_time,
            self.error_msg,
        ))
    }
}

fn invalid_positive_value(_: PositiveValueError) -> RepositoryError {
    RepositoryError::InvalidStoredData
}

fn invalid_opaque_value(_: EmptyOpaqueValueError) -> RepositoryError {
    RepositoryError::InvalidStoredData
}

fn protocol_value(protocol_type: ProtocolType) -> &'static str {
    match protocol_type {
        ProtocolType::OpenAi => "openai",
        ProtocolType::Anthropic => "anthropic",
    }
}

fn parse_protocol_value(value: &str) -> Result<ProtocolType, RepositoryError> {
    match value {
        "openai" => Ok(ProtocolType::OpenAi),
        "anthropic" => Ok(ProtocolType::Anthropic),
        _ => Err(RepositoryError::InvalidStoredData),
    }
}

fn transport_value(transport_type: TransportType) -> &'static str {
    match transport_type {
        TransportType::Http => "http",
        TransportType::WebSocket => "websocket",
    }
}

fn status_value(status: ProviderStatus) -> &'static str {
    match status {
        ProviderStatus::Enabled => "enabled",
        ProviderStatus::Disabled => "disabled",
    }
}
