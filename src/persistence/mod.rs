use std::error::Error;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use url::Url;

use crate::domain::{
    Account, AccountCursor, AccountId, AccountRole, AccountStatus, ApiKey, ApiKeyBinding,
    ApiKeyCursor, ApiKeyId, ApiKeyStatus, ApiKeyWithBindings, EmptyOpaqueValueError, GatewayKeyId,
    PasswordHash, PositiveValueError, ProtocolType, Provider, ProviderCursor, ProviderId,
    ProviderStatus, RequestId, RequestLog, RequestLogCursor, RequestLogId, SecretCiphertext,
    TransportType,
};

pub mod postgres;
pub mod sqlite;
pub mod time;

use postgres::PostgresDatabase;
use sqlite::SqliteDatabase;

pub const MAX_PROVIDER_PAGE_SIZE: usize = 100;
pub const MAX_REQUEST_LOG_PAGE_SIZE: usize = 100;
pub const MAX_ACCOUNT_PAGE_SIZE: usize = 100;
pub const MAX_API_KEY_PAGE_SIZE: usize = 100;

/// Largest number of providers one credential may be bound to.
///
/// The bound keeps provider resolution off an unbounded scan: a request that
/// must pick one provider out of an allowed set reads at most this many rows.
pub const MAX_API_KEY_PROVIDERS: usize = 32;

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
    status: ProviderStatus,
    created_at: DateTime<Utc>,
}

impl NewProvider {
    pub fn new(
        name: String,
        protocol_type: ProtocolType,
        endpoint: Url,
        upstream_api_key_ciphertext: SecretCiphertext,
        status: ProviderStatus,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            name,
            protocol_type,
            endpoint,
            upstream_api_key_ciphertext,
            status,
            created_at,
        }
    }
}

/// A new account together with the single field set on creation.
///
/// The bootstrap administrator is created once, from the configured
/// administrator credentials, and is the only account that can carry the flag.
#[derive(Clone, Debug)]
pub struct NewAccount {
    name: String,
    password_hash: PasswordHash,
    role: AccountRole,
    status: AccountStatus,
    is_bootstrap: bool,
    created_at: DateTime<Utc>,
}

impl NewAccount {
    pub fn new(
        name: String,
        password_hash: PasswordHash,
        role: AccountRole,
        status: AccountStatus,
        is_bootstrap: bool,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            name,
            password_hash,
            role,
            status,
            is_bootstrap,
            created_at,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn password_hash(&self) -> &PasswordHash {
        &self.password_hash
    }

    pub fn role(&self) -> AccountRole {
        self.role
    }

    pub fn status(&self) -> AccountStatus {
        self.status
    }

    pub fn is_bootstrap(&self) -> bool {
        self.is_bootstrap
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

/// A field-scoped account change set.
///
/// Only the named fields are written. `role` and `status` are refused by the
/// service for the bootstrap administrator, so this type has no way to express
/// a lockout.
#[derive(Clone, Debug, Default)]
pub struct AccountUpdate {
    name: Option<String>,
    password_hash: Option<PasswordHash>,
    role: Option<AccountRole>,
    status: Option<AccountStatus>,
}

impl AccountUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_password_hash(mut self, password_hash: PasswordHash) -> Self {
        self.password_hash = Some(password_hash);
        self
    }

    pub fn with_role(mut self, role: AccountRole) -> Self {
        self.role = Some(role);
        self
    }

    pub fn with_status(mut self, status: AccountStatus) -> Self {
        self.status = Some(status);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.password_hash.is_none()
            && self.role.is_none()
            && self.status.is_none()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn password_hash(&self) -> Option<&PasswordHash> {
        self.password_hash.as_ref()
    }

    pub fn role(&self) -> Option<AccountRole> {
        self.role
    }

    pub fn status(&self) -> Option<AccountStatus> {
        self.status
    }
}

/// A new account-owned credential with its provider bindings.
///
/// The bindings are written in the same transaction as the credential, so a
/// stored credential always resolves to at least one provider.
#[derive(Clone, Debug)]
pub struct NewApiKey {
    account_id: AccountId,
    name: String,
    key_id: GatewayKeyId,
    secret_hash: PasswordHash,
    status: ApiKeyStatus,
    default_provider_id: Option<ProviderId>,
    expires_at: Option<DateTime<Utc>>,
    provider_ids: Vec<ProviderId>,
    created_at: DateTime<Utc>,
}

impl NewApiKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        name: String,
        key_id: GatewayKeyId,
        secret_hash: PasswordHash,
        status: ApiKeyStatus,
        default_provider_id: Option<ProviderId>,
        expires_at: Option<DateTime<Utc>>,
        provider_ids: Vec<ProviderId>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            account_id,
            name,
            key_id,
            secret_hash,
            status,
            default_provider_id,
            expires_at,
            provider_ids,
            created_at,
        }
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn key_id(&self) -> &GatewayKeyId {
        &self.key_id
    }

    pub fn default_provider_id(&self) -> Option<ProviderId> {
        self.default_provider_id
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    pub fn provider_ids(&self) -> &[ProviderId] {
        &self.provider_ids
    }
}

/// A field-scoped credential change set.
///
/// Naming the provider set replaces it wholesale and rewrites the default, so a
/// caller can never leave a stored default pointing outside the allowed set.
#[derive(Clone, Debug, Default)]
pub struct ApiKeyUpdate {
    name: Option<String>,
    status: Option<ApiKeyStatus>,
    expires_at: Option<Option<DateTime<Utc>>>,
    provider_ids: Option<Vec<ProviderId>>,
    default_provider_id: Option<Option<ProviderId>>,
}

impl ApiKeyUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_status(mut self, status: ApiKeyStatus) -> Self {
        self.status = Some(status);
        self
    }

    pub fn with_expires_at(mut self, expires_at: Option<DateTime<Utc>>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_provider_ids(mut self, provider_ids: Vec<ProviderId>) -> Self {
        self.provider_ids = Some(provider_ids);
        self
    }

    pub fn with_default_provider_id(mut self, default_provider_id: Option<ProviderId>) -> Self {
        self.default_provider_id = Some(default_provider_id);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.status.is_none()
            && self.expires_at.is_none()
            && self.provider_ids.is_none()
            && self.default_provider_id.is_none()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn status(&self) -> Option<ApiKeyStatus> {
        self.status
    }

    pub fn expires_at(&self) -> Option<Option<DateTime<Utc>>> {
        self.expires_at
    }

    pub fn provider_ids(&self) -> Option<&[ProviderId]> {
        self.provider_ids.as_deref()
    }

    pub fn default_provider_id(&self) -> Option<Option<ProviderId>> {
        self.default_provider_id
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

/// A field-scoped provider change set.
///
/// Only the named fields are written. Every unnamed column keeps the value it
/// currently holds, so an edit can never restore a value the caller did not
/// name.
#[derive(Clone, Debug, Default)]
pub struct ProviderUpdate {
    name: Option<String>,
    endpoint: Option<Url>,
    upstream_api_key_ciphertext: Option<SecretCiphertext>,
    status: Option<ProviderStatus>,
}

impl ProviderUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_endpoint(mut self, endpoint: Url) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn with_upstream_api_key_ciphertext(mut self, ciphertext: SecretCiphertext) -> Self {
        self.upstream_api_key_ciphertext = Some(ciphertext);
        self
    }

    pub fn with_status(mut self, status: ProviderStatus) -> Self {
        self.status = Some(status);
        self
    }

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
pub struct AccountListRequest {
    after_id: Option<AccountCursor>,
    limit: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyListRequest {
    after_id: Option<ApiKeyCursor>,
    limit: usize,
    account_id: Option<AccountId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountListRequestError {
    InvalidLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyListRequestError {
    InvalidLimit,
}

impl fmt::Display for AccountListRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "account page size must be between 1 and {MAX_ACCOUNT_PAGE_SIZE}"
        )
    }
}

impl Error for AccountListRequestError {}

impl fmt::Display for ApiKeyListRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "credential page size must be between 1 and {MAX_API_KEY_PAGE_SIZE}"
        )
    }
}

impl Error for ApiKeyListRequestError {}

impl AccountListRequest {
    pub fn new(
        after_id: Option<AccountCursor>,
        limit: usize,
    ) -> Result<Self, AccountListRequestError> {
        if !(1..=MAX_ACCOUNT_PAGE_SIZE).contains(&limit) {
            return Err(AccountListRequestError::InvalidLimit);
        }
        Ok(Self { after_id, limit })
    }

    pub fn after_id(self) -> Option<AccountCursor> {
        self.after_id
    }

    pub fn limit(self) -> usize {
        self.limit
    }
}

impl ApiKeyListRequest {
    pub fn new(
        after_id: Option<ApiKeyCursor>,
        limit: usize,
        account_id: Option<AccountId>,
    ) -> Result<Self, ApiKeyListRequestError> {
        if !(1..=MAX_API_KEY_PAGE_SIZE).contains(&limit) {
            return Err(ApiKeyListRequestError::InvalidLimit);
        }
        Ok(Self {
            after_id,
            limit,
            account_id,
        })
    }

    pub fn after_id(self) -> Option<ApiKeyCursor> {
        self.after_id
    }

    pub fn limit(self) -> usize {
        self.limit
    }

    pub fn account_id(self) -> Option<AccountId> {
        self.account_id
    }
}

#[derive(Clone, Debug)]
pub struct AccountPage {
    items: Vec<Account>,
    has_more: bool,
}

impl AccountPage {
    fn new(items: Vec<Account>, has_more: bool) -> Self {
        Self { items, has_more }
    }

    pub fn items(&self) -> &[Account] {
        &self.items
    }

    pub fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn next_after_id(&self) -> Option<AccountCursor> {
        self.items
            .last()
            .map(|account| AccountCursor::try_from(account.id().get()))
            .transpose()
            .expect("stored account IDs are positive")
    }
}

#[derive(Clone, Debug)]
pub struct ApiKeyPage {
    items: Vec<ApiKeyWithBindings>,
    has_more: bool,
}

impl ApiKeyPage {
    fn new(items: Vec<ApiKeyWithBindings>, has_more: bool) -> Self {
        Self { items, has_more }
    }

    pub fn items(&self) -> &[ApiKeyWithBindings] {
        &self.items
    }

    pub fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn next_after_id(&self) -> Option<ApiKeyCursor> {
        self.items
            .last()
            .map(|key| ApiKeyCursor::try_from(key.api_key().id().get()))
            .transpose()
            .expect("stored credential IDs are positive")
    }
}

#[derive(Clone, Debug)]
pub struct RequestLogStarted {
    request_id: RequestId,
    account_id: AccountId,
    api_key_id: ApiKeyId,
    provider_id: ProviderId,
    protocol_type: ProtocolType,
    transport_type: TransportType,
    path: String,
    start_time: DateTime<Utc>,
}

impl RequestLogStarted {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: RequestId,
        account_id: AccountId,
        api_key_id: ApiKeyId,
        provider_id: ProviderId,
        protocol_type: ProtocolType,
        transport_type: TransportType,
        path: String,
        start_time: DateTime<Utc>,
    ) -> Self {
        Self {
            request_id,
            account_id,
            api_key_id,
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

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub fn api_key_id(&self) -> ApiKeyId {
        self.api_key_id
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
    account_id: Option<AccountId>,
    provider_id: Option<ProviderId>,
    transport_type: Option<TransportType>,
    start_time_gte: Option<DateTime<Utc>>,
    start_time_lt: Option<DateTime<Utc>>,
}

impl RequestLogQuery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        after_id: Option<RequestLogCursor>,
        limit: usize,
        account_id: Option<AccountId>,
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
            account_id,
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

    /// Scopes the result set to one account, so a regular user can only ever
    /// read its own traffic.
    pub fn account_id(self) -> Option<AccountId> {
        self.account_id
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
    /// An account or credential referenced by request logs cannot be deleted.
    InUse,
    /// A provider named by a credential binding cannot be deleted.
    ProviderBound,
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
            Self::InUse => "record is referenced by request logs",
            Self::ProviderBound => "provider is bound to a credential",
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
    async fn find_by_id(&self, id: ProviderId) -> Result<Option<Provider>, RepositoryError>;

    async fn list(&self, request: ProviderListRequest) -> Result<ProviderPage, RepositoryError>;

    async fn create(&self, provider: NewProvider) -> Result<Provider, RepositoryError>;

    async fn update(
        &self,
        id: ProviderId,
        update: ProviderUpdate,
    ) -> Result<Provider, RepositoryError>;

    async fn delete(&self, id: ProviderId) -> Result<(), RepositoryError>;
}

/// Accounts, the principals that own credentials and sign into the control plane.
#[allow(async_fn_in_trait)]
pub trait AccountRepository: Send + Sync {
    /// Looks up the single bootstrap administrator, when one exists.
    async fn find_bootstrap(&self) -> Result<Option<Account>, RepositoryError>;

    async fn find_by_name(&self, name: &str) -> Result<Option<Account>, RepositoryError>;

    async fn find_by_id(&self, id: AccountId) -> Result<Option<Account>, RepositoryError>;

    async fn list(&self, request: AccountListRequest) -> Result<AccountPage, RepositoryError>;

    /// Creates an account, or adopts the staged legacy credentials into it.
    ///
    /// The legacy adoption runs only for the bootstrap administrator and only
    /// while staged rows remain, so it happens exactly once and never turns into
    /// a repeatable conversion.
    async fn create(&self, account: NewAccount) -> Result<Account, RepositoryError>;

    async fn update(
        &self,
        id: AccountId,
        update: AccountUpdate,
    ) -> Result<Account, RepositoryError>;

    async fn delete(&self, id: AccountId) -> Result<(), RepositoryError>;

    async fn count(&self) -> Result<i64, RepositoryError>;
}

/// Account-owned credentials and the providers each one may select.
#[allow(async_fn_in_trait)]
pub trait ApiKeyRepository: Send + Sync {
    /// The data-plane lookup: credential, its owning account, and its bindings.
    async fn find_by_key_id(
        &self,
        key_id: &GatewayKeyId,
    ) -> Result<Option<ApiKeyWithBindings>, RepositoryError>;

    async fn find_by_id(&self, id: ApiKeyId)
    -> Result<Option<ApiKeyWithBindings>, RepositoryError>;

    async fn list(&self, request: ApiKeyListRequest) -> Result<ApiKeyPage, RepositoryError>;

    async fn create(&self, api_key: NewApiKey) -> Result<ApiKeyWithBindings, RepositoryError>;

    async fn update(
        &self,
        id: ApiKeyId,
        update: ApiKeyUpdate,
    ) -> Result<ApiKeyWithBindings, RepositoryError>;

    async fn rotate(
        &self,
        id: ApiKeyId,
        key_id: GatewayKeyId,
        hash: PasswordHash,
    ) -> Result<ApiKeyWithBindings, RepositoryError>;

    async fn delete(&self, id: ApiKeyId) -> Result<(), RepositoryError>;
}

#[allow(async_fn_in_trait)]
pub trait RequestLogRepository: Send + Sync {
    async fn insert_started(&self, event: RequestLogStarted) -> Result<(), RepositoryError>;

    async fn apply_completed(&self, event: RequestLogCompleted) -> Result<(), RepositoryError>;

    async fn query(&self, query: RequestLogQuery) -> Result<RequestLogPage, RepositoryError>;
}

#[allow(async_fn_in_trait)]
impl ProviderRepository for Database {
    async fn find_by_id(&self, id: ProviderId) -> Result<Option<Provider>, RepositoryError> {
        match self {
            Self::Sqlite(database) => ProviderRepository::find_by_id(database, id).await,
            Self::Postgres(database) => ProviderRepository::find_by_id(database, id).await,
        }
    }

    async fn list(&self, request: ProviderListRequest) -> Result<ProviderPage, RepositoryError> {
        match self {
            Self::Sqlite(database) => ProviderRepository::list(database, request).await,
            Self::Postgres(database) => ProviderRepository::list(database, request).await,
        }
    }

    async fn create(&self, provider: NewProvider) -> Result<Provider, RepositoryError> {
        match self {
            Self::Sqlite(database) => ProviderRepository::create(database, provider).await,
            Self::Postgres(database) => ProviderRepository::create(database, provider).await,
        }
    }

    async fn update(
        &self,
        id: ProviderId,
        update: ProviderUpdate,
    ) -> Result<Provider, RepositoryError> {
        match self {
            Self::Sqlite(database) => ProviderRepository::update(database, id, update).await,
            Self::Postgres(database) => ProviderRepository::update(database, id, update).await,
        }
    }

    async fn delete(&self, id: ProviderId) -> Result<(), RepositoryError> {
        match self {
            Self::Sqlite(database) => ProviderRepository::delete(database, id).await,
            Self::Postgres(database) => ProviderRepository::delete(database, id).await,
        }
    }
}

#[allow(async_fn_in_trait)]
impl AccountRepository for Database {
    async fn find_bootstrap(&self) -> Result<Option<Account>, RepositoryError> {
        match self {
            Self::Sqlite(database) => AccountRepository::find_bootstrap(database).await,
            Self::Postgres(database) => AccountRepository::find_bootstrap(database).await,
        }
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<Account>, RepositoryError> {
        match self {
            Self::Sqlite(database) => AccountRepository::find_by_name(database, name).await,
            Self::Postgres(database) => AccountRepository::find_by_name(database, name).await,
        }
    }

    async fn find_by_id(&self, id: AccountId) -> Result<Option<Account>, RepositoryError> {
        match self {
            Self::Sqlite(database) => AccountRepository::find_by_id(database, id).await,
            Self::Postgres(database) => AccountRepository::find_by_id(database, id).await,
        }
    }

    async fn list(&self, request: AccountListRequest) -> Result<AccountPage, RepositoryError> {
        match self {
            Self::Sqlite(database) => AccountRepository::list(database, request).await,
            Self::Postgres(database) => AccountRepository::list(database, request).await,
        }
    }

    async fn create(&self, account: NewAccount) -> Result<Account, RepositoryError> {
        match self {
            Self::Sqlite(database) => AccountRepository::create(database, account).await,
            Self::Postgres(database) => AccountRepository::create(database, account).await,
        }
    }

    async fn update(
        &self,
        id: AccountId,
        update: AccountUpdate,
    ) -> Result<Account, RepositoryError> {
        match self {
            Self::Sqlite(database) => AccountRepository::update(database, id, update).await,
            Self::Postgres(database) => AccountRepository::update(database, id, update).await,
        }
    }

    async fn delete(&self, id: AccountId) -> Result<(), RepositoryError> {
        match self {
            Self::Sqlite(database) => AccountRepository::delete(database, id).await,
            Self::Postgres(database) => AccountRepository::delete(database, id).await,
        }
    }

    async fn count(&self) -> Result<i64, RepositoryError> {
        match self {
            Self::Sqlite(database) => AccountRepository::count(database).await,
            Self::Postgres(database) => AccountRepository::count(database).await,
        }
    }
}

#[allow(async_fn_in_trait)]
impl ApiKeyRepository for Database {
    async fn find_by_key_id(
        &self,
        key_id: &GatewayKeyId,
    ) -> Result<Option<ApiKeyWithBindings>, RepositoryError> {
        match self {
            Self::Sqlite(database) => ApiKeyRepository::find_by_key_id(database, key_id).await,
            Self::Postgres(database) => ApiKeyRepository::find_by_key_id(database, key_id).await,
        }
    }

    async fn find_by_id(
        &self,
        id: ApiKeyId,
    ) -> Result<Option<ApiKeyWithBindings>, RepositoryError> {
        match self {
            Self::Sqlite(database) => ApiKeyRepository::find_by_id(database, id).await,
            Self::Postgres(database) => ApiKeyRepository::find_by_id(database, id).await,
        }
    }

    async fn list(&self, request: ApiKeyListRequest) -> Result<ApiKeyPage, RepositoryError> {
        match self {
            Self::Sqlite(database) => ApiKeyRepository::list(database, request).await,
            Self::Postgres(database) => ApiKeyRepository::list(database, request).await,
        }
    }

    async fn create(&self, api_key: NewApiKey) -> Result<ApiKeyWithBindings, RepositoryError> {
        match self {
            Self::Sqlite(database) => ApiKeyRepository::create(database, api_key).await,
            Self::Postgres(database) => ApiKeyRepository::create(database, api_key).await,
        }
    }

    async fn update(
        &self,
        id: ApiKeyId,
        update: ApiKeyUpdate,
    ) -> Result<ApiKeyWithBindings, RepositoryError> {
        match self {
            Self::Sqlite(database) => ApiKeyRepository::update(database, id, update).await,
            Self::Postgres(database) => ApiKeyRepository::update(database, id, update).await,
        }
    }

    async fn rotate(
        &self,
        id: ApiKeyId,
        key_id: GatewayKeyId,
        hash: PasswordHash,
    ) -> Result<ApiKeyWithBindings, RepositoryError> {
        match self {
            Self::Sqlite(database) => ApiKeyRepository::rotate(database, id, key_id, hash).await,
            Self::Postgres(database) => ApiKeyRepository::rotate(database, id, key_id, hash).await,
        }
    }

    async fn delete(&self, id: ApiKeyId) -> Result<(), RepositoryError> {
        match self {
            Self::Sqlite(database) => ApiKeyRepository::delete(database, id).await,
            Self::Postgres(database) => ApiKeyRepository::delete(database, id).await,
        }
    }
}

#[allow(async_fn_in_trait)]
impl RequestLogRepository for Database {
    async fn insert_started(&self, event: RequestLogStarted) -> Result<(), RepositoryError> {
        match self {
            Self::Sqlite(database) => RequestLogRepository::insert_started(database, event).await,
            Self::Postgres(database) => RequestLogRepository::insert_started(database, event).await,
        }
    }

    async fn apply_completed(&self, event: RequestLogCompleted) -> Result<(), RepositoryError> {
        match self {
            Self::Sqlite(database) => RequestLogRepository::apply_completed(database, event).await,
            Self::Postgres(database) => {
                RequestLogRepository::apply_completed(database, event).await
            }
        }
    }

    async fn query(&self, query: RequestLogQuery) -> Result<RequestLogPage, RepositoryError> {
        match self {
            Self::Sqlite(database) => RequestLogRepository::query(database, query).await,
            Self::Postgres(database) => RequestLogRepository::query(database, query).await,
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
            status,
            created_at,
        ))
    }
}

#[derive(FromRow)]
pub(crate) struct AccountRow {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) password_hash: String,
    pub(crate) role: String,
    pub(crate) status: String,
    pub(crate) is_bootstrap: bool,
    pub(crate) created_at: i64,
}

impl AccountRow {
    pub(crate) fn into_account(self) -> Result<Account, RepositoryError> {
        let id = AccountId::try_from(self.id).map_err(invalid_positive_value)?;
        let role = match self.role.as_str() {
            "admin" => AccountRole::Admin,
            "user" => AccountRole::User,
            _ => return Err(RepositoryError::InvalidStoredData),
        };
        let status = match self.status.as_str() {
            "enabled" => AccountStatus::Enabled,
            "disabled" => AccountStatus::Disabled,
            _ => return Err(RepositoryError::InvalidStoredData),
        };
        Ok(Account::new(
            id,
            self.name,
            PasswordHash::new(self.password_hash),
            role,
            status,
            self.is_bootstrap,
            time::from_epoch_micros(self.created_at)?,
        ))
    }
}

#[derive(FromRow)]
pub(crate) struct ApiKeyRow {
    pub(crate) id: i64,
    pub(crate) account_id: i64,
    pub(crate) name: String,
    pub(crate) key_id: String,
    pub(crate) secret_hash: String,
    pub(crate) status: String,
    pub(crate) default_provider_id: Option<i64>,
    pub(crate) expires_at: Option<i64>,
    pub(crate) created_at: i64,
}

impl ApiKeyRow {
    pub(crate) fn into_api_key(self) -> Result<ApiKey, RepositoryError> {
        let status = match self.status.as_str() {
            "enabled" => ApiKeyStatus::Enabled,
            "disabled" => ApiKeyStatus::Disabled,
            _ => return Err(RepositoryError::InvalidStoredData),
        };
        Ok(ApiKey::new(
            ApiKeyId::try_from(self.id).map_err(invalid_positive_value)?,
            AccountId::try_from(self.account_id).map_err(invalid_positive_value)?,
            self.name,
            GatewayKeyId::new(self.key_id).map_err(invalid_opaque_value)?,
            PasswordHash::new(self.secret_hash),
            status,
            self.default_provider_id
                .map(ProviderId::try_from)
                .transpose()
                .map_err(invalid_positive_value)?,
            self.expires_at.map(time::from_epoch_micros).transpose()?,
            time::from_epoch_micros(self.created_at)?,
        ))
    }
}

#[derive(FromRow)]
pub(crate) struct ApiKeyBindingRow {
    pub(crate) api_key_id: i64,
    pub(crate) provider_id: i64,
    pub(crate) position: i64,
}

impl ApiKeyBindingRow {
    pub(crate) fn into_binding(self) -> Result<ApiKeyBinding, RepositoryError> {
        Ok(ApiKeyBinding {
            api_key_id: ApiKeyId::try_from(self.api_key_id).map_err(invalid_positive_value)?,
            provider_id: ProviderId::try_from(self.provider_id).map_err(invalid_positive_value)?,
            position: self.position,
        })
    }
}

#[derive(FromRow)]
struct RequestLogRow {
    id: i64,
    request_id: String,
    account_id: i64,
    api_key_id: i64,
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
        let account_id = AccountId::try_from(self.account_id).map_err(invalid_positive_value)?;
        let api_key_id = ApiKeyId::try_from(self.api_key_id).map_err(invalid_positive_value)?;
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
            account_id,
            api_key_id,
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

pub(crate) fn role_value(role: AccountRole) -> &'static str {
    match role {
        AccountRole::Admin => "admin",
        AccountRole::User => "user",
    }
}

pub(crate) fn account_status_value(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Enabled => "enabled",
        AccountStatus::Disabled => "disabled",
    }
}

pub(crate) fn api_key_status_value(status: ApiKeyStatus) -> &'static str {
    match status {
        ApiKeyStatus::Enabled => "enabled",
        ApiKeyStatus::Disabled => "disabled",
    }
}

fn status_value(status: ProviderStatus) -> &'static str {
    match status {
        ProviderStatus::Enabled => "enabled",
        ProviderStatus::Disabled => "disabled",
    }
}
