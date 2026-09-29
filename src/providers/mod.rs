//! Provider administration service.
//!
//! The service validates provider configuration, encrypts the upstream
//! credential, issues a provider-scoped gateway credential, and persists the
//! complete record in one write. The generated gateway secret is handed back
//! only from the creation result; it is never stored, logged, or rendered by
//! diagnostics.

use crate::crypto::{PasswordWork, PasswordWorkError};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use chrono::Utc;
use url::Url;

use crate::crypto::{GatewaySecretVerifier, SecretCipher};
use crate::domain::{
    GatewayCredential, ProtocolType, Provider, ProviderId, ProviderStatus, SecretString,
};
use crate::persistence::{
    NewProvider, ProviderListRequest, ProviderPage, ProviderRepository, ProviderUpdate,
    RepositoryError,
};

/// Longest accepted provider name, counted in Unicode scalar values.
pub const MAX_PROVIDER_NAME_LEN: usize = 128;

/// Longest accepted upstream API key, counted in bytes.
pub const MAX_UPSTREAM_API_KEY_LEN: usize = 8192;

/// Provider configuration supplied when creating a provider.
///
/// The upstream API key is a write-only value: it is encrypted before storage
/// and never appears in the stored record or the creation result.
pub struct CreateProviderRequest {
    name: String,
    protocol_type: ProtocolType,
    endpoint: String,
    upstream_api_key: SecretString,
    status: ProviderStatus,
}

impl CreateProviderRequest {
    pub fn new(
        name: String,
        protocol_type: ProtocolType,
        endpoint: String,
        upstream_api_key: SecretString,
        status: ProviderStatus,
    ) -> Self {
        Self {
            name,
            protocol_type,
            endpoint,
            upstream_api_key,
            status,
        }
    }
}

impl fmt::Debug for CreateProviderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateProviderRequest")
            .field("name", &self.name)
            .field("protocol_type", &self.protocol_type)
            .field("endpoint", &"[REDACTED]")
            .field("upstream_api_key", &"[REDACTED]")
            .field("status", &self.status)
            .finish()
    }
}

/// Fields to change on an existing provider.
///
/// Every field is optional: an absent field keeps its stored value, so a caller
/// changes only what it names. The upstream API key stays write-only; it is
/// re-encrypted on edit and never returned. The protocol type and gateway
/// credential are not editable values.
#[derive(Default)]
pub struct UpdateProviderRequest {
    name: Option<String>,
    endpoint: Option<String>,
    upstream_api_key: Option<SecretString>,
    status: Option<ProviderStatus>,
}

impl UpdateProviderRequest {
    /// Starts an empty change that keeps every stored value.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn with_upstream_api_key(mut self, upstream_api_key: SecretString) -> Self {
        self.upstream_api_key = Some(upstream_api_key);
        self
    }

    pub fn with_status(mut self, status: ProviderStatus) -> Self {
        self.status = Some(status);
        self
    }
}

impl fmt::Debug for UpdateProviderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdateProviderRequest")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint.as_ref().map(|_| "[REDACTED]"))
            .field(
                "upstream_api_key",
                &self.upstream_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("status", &self.status)
            .finish()
    }
}

/// The stored provider record together with its one-time gateway credential.
///
/// The credential is returned here and only here; a caller that loses it must
/// rotate the credential because the secret cannot be recovered from storage.
#[derive(Debug)]
pub struct CreatedProvider {
    provider: Provider,
    gateway_credential: GatewayCredential,
}

impl CreatedProvider {
    fn new(provider: Provider, gateway_credential: GatewayCredential) -> Self {
        Self {
            provider,
            gateway_credential,
        }
    }

    pub fn provider(&self) -> &Provider {
        &self.provider
    }

    pub fn gateway_credential(&self) -> &GatewayCredential {
        &self.gateway_credential
    }

    pub fn into_parts(self) -> (Provider, GatewayCredential) {
        (self.provider, self.gateway_credential)
    }
}

/// The stored provider record together with its freshly rotated credential.
///
/// The new credential is returned here and only here. The previous credential
/// stops authenticating as soon as the replacement is committed, while any
/// snapshot already handed to an active stream or connection is unaffected.
#[derive(Debug)]
pub struct RotatedProvider {
    provider: Provider,
    gateway_credential: GatewayCredential,
}

impl RotatedProvider {
    fn new(provider: Provider, gateway_credential: GatewayCredential) -> Self {
        Self {
            provider,
            gateway_credential,
        }
    }

    pub fn provider(&self) -> &Provider {
        &self.provider
    }

    pub fn gateway_credential(&self) -> &GatewayCredential {
        &self.gateway_credential
    }

    pub fn into_parts(self) -> (Provider, GatewayCredential) {
        (self.provider, self.gateway_credential)
    }
}

/// A provider service failure that carries no name, endpoint, key, or hash.
///
/// Every variant renders as a stable, non-sensitive description so a failure
/// can be surfaced or logged without echoing secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderServiceError {
    /// The name is empty, too long, or contains control characters.
    InvalidName,
    /// The endpoint is not an absolute HTTP(S) origin with an optional base path.
    InvalidEndpoint,
    /// The endpoint is plain HTTP while insecure endpoints are not enabled.
    InsecureEndpoint,
    /// The upstream API key is empty, too long, or contains control characters.
    InvalidUpstreamApiKey,
    /// Gateway credential generation failed.
    Credential,
    /// Compute or database capacity for this change is exhausted.
    Busy,
    /// Upstream credential encryption failed.
    Cipher,
    /// A provider with the same name or gateway key identifier already exists.
    Conflict,
    /// No provider exists for the given identifier.
    NotFound,
    /// The provider is referenced by request logs and cannot be deleted.
    InUse,
    /// The edit named no writable field, so nothing was changed.
    NoFieldsToUpdate,
    /// The record could not be persisted.
    Storage,
}

impl fmt::Display for ProviderServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidName => "provider name is invalid",
            Self::InvalidEndpoint => "provider endpoint is invalid",
            Self::InsecureEndpoint => "provider endpoint must use HTTPS",
            Self::InvalidUpstreamApiKey => "upstream API key is invalid",
            Self::Credential => "gateway credential generation failed",
            Self::Busy => "provider service has no spare capacity",
            Self::Cipher => "upstream credential encryption failed",
            Self::Conflict => "provider conflicts with existing data",
            Self::NotFound => "provider was not found",
            Self::InUse => "provider is referenced by request logs",
            Self::NoFieldsToUpdate => "the edit named no writable field",
            Self::Storage => "provider could not be persisted",
        };
        formatter.write_str(message)
    }
}

impl Error for ProviderServiceError {}

/// Creates providers, encrypting upstream keys and issuing gateway credentials.
pub struct ProviderService<R, C, V> {
    repository: R,
    cipher: C,
    verifier: Arc<V>,
    password_work: PasswordWork,
    allow_insecure_endpoints: bool,
}

impl<R, C, V> ProviderService<R, C, V>
where
    R: ProviderRepository,
    C: SecretCipher,
    V: GatewaySecretVerifier + 'static,
{
    /// Returns one provider for administration without exposing stored secrets.
    pub async fn get(&self, id: ProviderId) -> Result<Provider, ProviderServiceError> {
        self.repository
            .find_by_id(id)
            .await
            .map_err(map_repository_error)?
            .ok_or(ProviderServiceError::NotFound)
    }

    /// Lists providers by their increasing database identifier.
    pub async fn list(
        &self,
        request: ProviderListRequest,
    ) -> Result<ProviderPage, ProviderServiceError> {
        self.repository
            .list(request)
            .await
            .map_err(map_repository_error)
    }

    /// Builds a service over the given storage and cryptographic collaborators.
    ///
    /// `allow_insecure_endpoints` admits plain-HTTP endpoints and must only be
    /// set from an explicit development mode.
    pub fn new(repository: R, cipher: C, verifier: V, allow_insecure_endpoints: bool) -> Self {
        Self {
            repository,
            cipher,
            verifier: Arc::new(verifier),
            password_work: PasswordWork::default(),
            allow_insecure_endpoints,
        }
    }

    pub fn set_password_work(&mut self, work: PasswordWork) {
        self.password_work = work;
    }

    pub fn with_password_work(mut self, password_work: PasswordWork) -> Self {
        self.password_work = password_work;
        self
    }

    /// Reports whether plain-HTTP provider endpoints are admitted.
    pub fn allows_insecure_endpoints(&self) -> bool {
        self.allow_insecure_endpoints
    }

    /// Validates the request, then encrypts and persists one complete record.
    ///
    /// Validation and secret derivation happen before the single storage write,
    /// so a rejected request leaves no row behind. On success the returned
    /// credential is the only copy of the gateway secret.
    pub async fn create(
        &self,
        request: CreateProviderRequest,
    ) -> Result<CreatedProvider, ProviderServiceError> {
        let name = validate_name(&request.name)?;
        let endpoint = validate_endpoint(&request.endpoint, self.allow_insecure_endpoints)?;
        validate_upstream_api_key(&request.upstream_api_key)?;

        let verifier = self.verifier.clone();
        let (gateway_credential, gateway_api_key_hash) =
            match self.password_work.run(move || verifier.issue()).await {
                Ok(Ok(issued)) => issued,
                Ok(Err(_)) | Err(PasswordWorkError::Failed) => {
                    return Err(ProviderServiceError::Credential);
                }
                Err(PasswordWorkError::Busy) => return Err(ProviderServiceError::Busy),
            };
        let upstream_api_key_ciphertext = self
            .cipher
            .encrypt(&request.upstream_api_key)
            .map_err(|_| ProviderServiceError::Cipher)?;

        let new_provider = NewProvider::new(
            name,
            request.protocol_type,
            endpoint,
            upstream_api_key_ciphertext,
            gateway_credential.key_id().clone(),
            gateway_api_key_hash,
            request.status,
            Utc::now(),
        );
        let provider = self
            .repository
            .create(new_provider)
            .await
            .map_err(map_repository_error)?;

        Ok(CreatedProvider::new(provider, gateway_credential))
    }

    /// Issues a new gateway credential and replaces the stored key material.
    ///
    /// The key identifier and its hash are replaced together in one storage
    /// write, so a concurrent reader never observes a half-rotated provider.
    /// The new credential is returned once; requests that used the previous
    /// one fail after the replacement is committed, while snapshots already
    /// held by active streams or connections keep working.
    pub async fn rotate_gateway_credential(
        &self,
        id: ProviderId,
    ) -> Result<RotatedProvider, ProviderServiceError> {
        let verifier = self.verifier.clone();
        let (gateway_credential, gateway_api_key_hash) =
            match self.password_work.run(move || verifier.issue()).await {
                Ok(Ok(issued)) => issued,
                Ok(Err(_)) | Err(PasswordWorkError::Failed) => {
                    return Err(ProviderServiceError::Credential);
                }
                Err(PasswordWorkError::Busy) => return Err(ProviderServiceError::Busy),
            };

        let provider = self
            .repository
            .rotate_gateway_key(
                id,
                gateway_credential.key_id().clone(),
                gateway_api_key_hash,
            )
            .await
            .map_err(map_repository_error)?;

        Ok(RotatedProvider::new(provider, gateway_credential))
    }

    /// Applies a partial edit, committing only the named fields.
    ///
    /// The change set names exactly the fields the caller supplied; storage
    /// writes those columns alone, so an edit can never restore a rotated
    /// gateway key, re-enable a provider, or rewrite a field it never named —
    /// even when a rotation or a status change was committed after this
    /// request began. Validation and re-encryption happen before the single
    /// write, so a rejected edit leaves the stored record untouched. The
    /// gateway credential is unchanged; rotating it is a separate operation.
    /// Requests admitted before the commit keep their immutable snapshot.
    pub async fn update(
        &self,
        id: ProviderId,
        request: UpdateProviderRequest,
    ) -> Result<Provider, ProviderServiceError> {
        let mut update = ProviderUpdate::new();
        if let Some(name) = request.name {
            update = update.with_name(validate_name(&name)?);
        }
        if let Some(endpoint) = request.endpoint.as_deref() {
            update =
                update.with_endpoint(validate_endpoint(endpoint, self.allow_insecure_endpoints)?);
        }
        if let Some(upstream_api_key) = request.upstream_api_key {
            validate_upstream_api_key(&upstream_api_key)?;
            let ciphertext = self
                .cipher
                .encrypt(&upstream_api_key)
                .map_err(|_| ProviderServiceError::Cipher)?;
            update = update.with_upstream_api_key_ciphertext(ciphertext);
        }
        if let Some(status) = request.status {
            update = update.with_status(status);
        }
        if update.is_empty() {
            return Err(ProviderServiceError::NoFieldsToUpdate);
        }
        self.repository
            .update(id, update)
            .await
            .map_err(map_repository_error)
    }

    /// Atomically sets a provider to enabled or disabled.
    ///
    /// A disabled provider rejects new requests while streams already admitted
    /// continue on their snapshot.
    pub async fn set_status(
        &self,
        id: ProviderId,
        status: ProviderStatus,
    ) -> Result<Provider, ProviderServiceError> {
        self.update(id, UpdateProviderRequest::new().with_status(status))
            .await
    }

    /// Deletes a provider that no request log references.
    ///
    /// A referenced provider is refused with [`ProviderServiceError::InUse`] so
    /// the administrator can disable it instead.
    pub async fn delete(&self, id: ProviderId) -> Result<(), ProviderServiceError> {
        self.repository
            .delete(id)
            .await
            .map_err(map_repository_error)
    }
}

fn validate_name(raw: &str) -> Result<String, ProviderServiceError> {
    let name = raw.trim();
    if name.is_empty()
        || name.chars().count() > MAX_PROVIDER_NAME_LEN
        || name.chars().any(char::is_control)
    {
        return Err(ProviderServiceError::InvalidName);
    }
    Ok(name.to_owned())
}

fn validate_upstream_api_key(key: &SecretString) -> Result<(), ProviderServiceError> {
    let value = key.expose();
    if value.is_empty()
        || value.len() > MAX_UPSTREAM_API_KEY_LEN
        || value.chars().any(char::is_control)
    {
        return Err(ProviderServiceError::InvalidUpstreamApiKey);
    }
    Ok(())
}

fn validate_endpoint(raw: &str, allow_insecure: bool) -> Result<Url, ProviderServiceError> {
    let endpoint = Url::parse(raw).map_err(|_| ProviderServiceError::InvalidEndpoint)?;
    let scheme = endpoint.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(ProviderServiceError::InvalidEndpoint);
    }
    if !endpoint.has_host() {
        return Err(ProviderServiceError::InvalidEndpoint);
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(ProviderServiceError::InvalidEndpoint);
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(ProviderServiceError::InvalidEndpoint);
    }
    if scheme == "http" && !allow_insecure {
        return Err(ProviderServiceError::InsecureEndpoint);
    }
    Ok(endpoint)
}

fn map_repository_error(error: RepositoryError) -> ProviderServiceError {
    match error {
        RepositoryError::Conflict => ProviderServiceError::Conflict,
        RepositoryError::ProviderInUse => ProviderServiceError::InUse,
        RepositoryError::NotFound => ProviderServiceError::NotFound,
        RepositoryError::NoFieldsToUpdate => ProviderServiceError::NoFieldsToUpdate,
        RepositoryError::Timeout => ProviderServiceError::Busy,
        _ => ProviderServiceError::Storage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(validate_name("  primary  ").expect("valid name"), "primary");
        assert_eq!(validate_name("   "), Err(ProviderServiceError::InvalidName));
        assert_eq!(validate_name(""), Err(ProviderServiceError::InvalidName));
        assert_eq!(
            validate_name("line\nbreak"),
            Err(ProviderServiceError::InvalidName)
        );
        assert_eq!(
            validate_name(&"n".repeat(MAX_PROVIDER_NAME_LEN + 1)),
            Err(ProviderServiceError::InvalidName)
        );
        assert!(validate_name(&"n".repeat(MAX_PROVIDER_NAME_LEN)).is_ok());
    }

    #[test]
    fn endpoints_require_https_unless_explicitly_allowed() {
        assert!(validate_endpoint("https://api.example.com/base", false).is_ok());
        assert_eq!(
            validate_endpoint("http://api.example.com", false),
            Err(ProviderServiceError::InsecureEndpoint)
        );
        assert!(validate_endpoint("http://api.example.com", true).is_ok());
        for invalid in [
            "ftp://api.example.com",
            "https://",
            "not a url",
            "https://api.example.com?token=1",
            "https://api.example.com#frag",
            "https://user:pass@api.example.com",
        ] {
            assert_eq!(
                validate_endpoint(invalid, true),
                Err(ProviderServiceError::InvalidEndpoint),
                "expected {invalid:?} to be rejected"
            );
        }
    }

    #[test]
    fn upstream_keys_reject_empty_and_control_characters() {
        assert!(validate_upstream_api_key(&SecretString::new("sk-key")).is_ok());
        assert_eq!(
            validate_upstream_api_key(&SecretString::new("")),
            Err(ProviderServiceError::InvalidUpstreamApiKey)
        );
        assert_eq!(
            validate_upstream_api_key(&SecretString::new("sk\nkey")),
            Err(ProviderServiceError::InvalidUpstreamApiKey)
        );
        assert_eq!(
            validate_upstream_api_key(&SecretString::new("k".repeat(MAX_UPSTREAM_API_KEY_LEN + 1))),
            Err(ProviderServiceError::InvalidUpstreamApiKey)
        );
    }

    #[test]
    fn request_debug_output_redacts_endpoint_and_key() {
        let request = CreateProviderRequest::new(
            "primary".to_owned(),
            ProtocolType::OpenAi,
            "https://api.example.com?token=hidden".to_owned(),
            SecretString::new("sk-secret"),
            ProviderStatus::Enabled,
        );
        let rendered = format!("{request:?}");
        assert!(rendered.contains("primary"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("hidden"));
        assert!(!rendered.contains("sk-secret"));
    }
}
