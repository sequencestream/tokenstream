use std::error::Error;
use std::fmt;

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use url::Url;

use crate::domain::{
    EmptyOpaqueValueError, GatewayKeyId, PasswordHash, PositiveValueError, ProtocolType, Provider,
    ProviderCursor, ProviderId, ProviderStatus, SecretCiphertext,
};

pub mod postgres;
pub mod sqlite;

pub const MAX_PROVIDER_PAGE_SIZE: usize = 100;

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

#[derive(Clone, Debug)]
pub struct ProviderUpdate {
    name: String,
    protocol_type: ProtocolType,
    endpoint: Url,
    upstream_api_key_ciphertext: SecretCiphertext,
    gateway_key_id: GatewayKeyId,
    gateway_api_key_hash: PasswordHash,
    status: ProviderStatus,
}

impl ProviderUpdate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        protocol_type: ProtocolType,
        endpoint: Url,
        upstream_api_key_ciphertext: SecretCiphertext,
        gateway_key_id: GatewayKeyId,
        gateway_api_key_hash: PasswordHash,
        status: ProviderStatus,
    ) -> Self {
        Self {
            name,
            protocol_type,
            endpoint,
            upstream_api_key_ciphertext,
            gateway_key_id,
            gateway_api_key_hash,
            status,
        }
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
    InvalidStoredData,
    Storage,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Conflict => "provider conflicts with an existing record",
            Self::ProviderInUse => "provider is referenced by request logs",
            Self::NotFound => "provider was not found",
            Self::InvalidStoredData => "stored provider data is invalid",
            Self::Storage => "provider storage operation failed",
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

    async fn list(&self, request: ProviderListRequest) -> Result<ProviderPage, RepositoryError>;

    async fn create(&self, provider: NewProvider) -> Result<Provider, RepositoryError>;

    async fn update(
        &self,
        id: ProviderId,
        update: ProviderUpdate,
    ) -> Result<Provider, RepositoryError>;

    async fn delete(&self, id: ProviderId) -> Result<(), RepositoryError>;
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
        let created_at = DateTime::from_timestamp_micros(self.created_at)
            .ok_or(RepositoryError::InvalidStoredData)?;

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

fn status_value(status: ProviderStatus) -> &'static str {
    match status {
        ProviderStatus::Enabled => "enabled",
        ProviderStatus::Disabled => "disabled",
    }
}
