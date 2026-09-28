//! Provider administration service.
//!
//! The service validates provider configuration, encrypts the upstream
//! credential, issues a provider-scoped gateway credential, and persists the
//! complete record in one write. The generated gateway secret is handed back
//! only from the creation result; it is never stored, logged, or rendered by
//! diagnostics.

use std::error::Error;
use std::fmt;

use chrono::Utc;
use url::Url;

use crate::crypto::{GatewaySecretVerifier, SecretCipher};
use crate::domain::{GatewayCredential, ProtocolType, Provider, ProviderStatus, SecretString};
use crate::persistence::{NewProvider, ProviderRepository, RepositoryError};

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
    /// Upstream credential encryption failed.
    Cipher,
    /// A provider with the same name or gateway key identifier already exists.
    Conflict,
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
            Self::Cipher => "upstream credential encryption failed",
            Self::Conflict => "provider conflicts with existing data",
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
    verifier: V,
    allow_insecure_endpoints: bool,
}

impl<R, C, V> ProviderService<R, C, V>
where
    R: ProviderRepository,
    C: SecretCipher,
    V: GatewaySecretVerifier,
{
    /// Builds a service over the given storage and cryptographic collaborators.
    ///
    /// `allow_insecure_endpoints` admits plain-HTTP endpoints and must only be
    /// set from an explicit development mode.
    pub fn new(repository: R, cipher: C, verifier: V, allow_insecure_endpoints: bool) -> Self {
        Self {
            repository,
            cipher,
            verifier,
            allow_insecure_endpoints,
        }
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

        let (gateway_credential, gateway_api_key_hash) = self
            .verifier
            .issue()
            .map_err(|_| ProviderServiceError::Credential)?;
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
