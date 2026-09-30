//! Provider administration service.
//!
//! The service validates provider configuration, encrypts the upstream
//! credential, and persists the complete record in one write. A provider issues
//! no gateway credential: credentials belong to accounts and refer to a
//! provider through their bindings, so a provider record never holds credential
//! material at all.

use std::error::Error;
use std::fmt;

use chrono::Utc;
use url::Url;

use crate::crypto::SecretCipher;
use crate::domain::{
    ProtocolType, Provider, ProviderAdmission, ProviderHealthState, ProviderId, ProviderProbe,
    ProviderStatus, SecretString,
};
use crate::persistence::{
    HealthOutcome, NewProvider, ProviderListRequest, ProviderPage, ProviderRepository,
    ProviderUpdate, RepositoryError,
};
use crate::telemetry::{HealthTransition, Metrics};

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
    admission: ProviderAdmission,
    probe: Option<ProviderProbe>,
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
            admission: ProviderAdmission::default(),
            probe: None,
        }
    }

    /// Bounds this provider at admission, so one upstream cannot consume
    /// capacity that belongs to the providers around it.
    pub fn with_admission(mut self, admission: ProviderAdmission) -> Self {
        self.admission = admission;
        self
    }

    /// Watches this provider's health by probing it.
    ///
    /// Absent is the default and means the provider is never probed, so health is
    /// opt-in per provider rather than a reachability contract the gateway would
    /// otherwise assert on the operator's behalf.
    pub fn with_probe(mut self, probe: Option<ProviderProbe>) -> Self {
        self.probe = probe;
        self
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
    probe: Option<Option<ProviderProbe>>,
    name: Option<String>,
    endpoint: Option<String>,
    upstream_api_key: Option<SecretString>,
    status: Option<ProviderStatus>,
    admission: Option<ProviderAdmission>,
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

    /// The endpoint this edit would leave in place, if it names one.
    ///
    /// Exposed so a probe written in the same request can be validated against
    /// the endpoint it will actually run against, rather than against the one the
    /// provider happened to have when the request arrived.
    pub fn endpoint(&self) -> Option<&String> {
        self.endpoint.as_ref()
    }

    pub fn with_upstream_api_key(mut self, upstream_api_key: SecretString) -> Self {
        self.upstream_api_key = Some(upstream_api_key);
        self
    }

    /// Watches or stops watching this provider's health.
    ///
    /// The inner `None` clears the probe, so a provider can be taken out of
    /// health observation in one edit. Clearing it also means the provider can
    /// never be isolated again, so it is a deliberate act rather than a way to
    /// hide a failing upstream.
    pub fn with_probe(mut self, probe: Option<ProviderProbe>) -> Self {
        self.probe = Some(probe);
        self
    }

    pub fn with_status(mut self, status: ProviderStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Replaces both admission bounds. Naming the admission here is what makes
    /// the edit non-empty, and it names every bound at once, so a single edit
    /// can widen, narrow, or clear the provider's limits together.
    pub fn with_admission(mut self, admission: ProviderAdmission) -> Self {
        self.admission = Some(admission);
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
    /// An admission bound is zero or beyond the accepted ceiling.
    InvalidAdmissionBound,
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
    /// The provider is bound to a credential and cannot be deleted.
    Bound,
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
            Self::InvalidAdmissionBound => "an admission bound must be greater than zero",
            Self::Busy => "provider service has no spare capacity",
            Self::Cipher => "upstream credential encryption failed",
            Self::Conflict => "provider conflicts with existing data",
            Self::NotFound => "provider was not found",
            Self::InUse => "provider is referenced by request logs",
            Self::Bound => "provider is bound to a credential",
            Self::NoFieldsToUpdate => "the edit named no writable field",
            Self::Storage => "provider could not be persisted",
        };
        formatter.write_str(message)
    }
}

impl Error for ProviderServiceError {}

/// Creates providers and encrypts their upstream keys.
///
/// The service holds no credential verifier: a provider issues no credentials,
/// so there is nothing here that needs to hash or compare a secret.
pub struct ProviderService<R, C> {
    repository: R,
    cipher: C,
    allow_insecure_endpoints: bool,
    health_metrics: Metrics,
}

impl<R, C> ProviderService<R, C>
where
    R: ProviderRepository,
    C: SecretCipher,
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

    pub fn cipher(&self) -> &C {
        &self.cipher
    }

    /// Decrypts every stored upstream key with the current cipher and seals it with `next`.
    pub async fn reencrypt_upstream_keys<N: SecretCipher>(
        &self,
        next: &N,
    ) -> Result<(), ProviderServiceError> {
        let mut after_id = None;
        loop {
            let page = self
                .repository
                .list(
                    ProviderListRequest::new(after_id, crate::persistence::MAX_PROVIDER_PAGE_SIZE)
                        .expect("page size is in range"),
                )
                .await
                .map_err(map_repository_error)?;
            let has_more = page.has_more();
            let next_cursor = page.next_after_id();
            let items = page.into_items();
            if items.is_empty() {
                break;
            }
            for provider in items {
                let plaintext = self
                    .cipher
                    .decrypt(provider.upstream_api_key_ciphertext())
                    .map_err(|_| ProviderServiceError::Cipher)?;
                let ciphertext = next
                    .encrypt(&plaintext)
                    .map_err(|_| ProviderServiceError::Cipher)?;
                self.repository
                    .update(
                        provider.id(),
                        crate::persistence::ProviderUpdate::new()
                            .with_upstream_api_key_ciphertext(ciphertext),
                    )
                    .await
                    .map_err(map_repository_error)?;
            }
            if !has_more {
                break;
            }
            after_id = next_cursor;
        }
        Ok(())
    }

    /// Builds a service over the given storage and cryptographic collaborators.
    ///
    /// `allow_insecure_endpoints` admits plain-HTTP endpoints and must only be
    /// set from an explicit development mode.
    pub fn new(repository: R, cipher: C, allow_insecure_endpoints: bool) -> Self {
        Self {
            repository,
            cipher,
            allow_insecure_endpoints,
            health_metrics: Metrics::default(),
        }
    }

    /// Attaches the exposition a health transition is recorded in.
    ///
    /// A transition is a fact about the running process rather than about the
    /// stored row, so it belongs in the exposition the process already renders
    /// rather than in a new store. Absent means the service records into a
    /// private default, which keeps a caller that has no exposition — a
    /// one-shot script, a repository test — from having to know about it.
    pub fn with_health_metrics(mut self, metrics: Metrics) -> Self {
        self.health_metrics = metrics;
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
    ) -> Result<Provider, ProviderServiceError> {
        let name = validate_name(&request.name)?;
        let endpoint = validate_endpoint(&request.endpoint, self.allow_insecure_endpoints)?;
        validate_upstream_api_key(&request.upstream_api_key)?;

        let upstream_api_key_ciphertext = self
            .cipher
            .encrypt(&request.upstream_api_key)
            .map_err(|_| ProviderServiceError::Cipher)?;

        let new_provider = NewProvider::new(
            name,
            request.protocol_type,
            endpoint,
            upstream_api_key_ciphertext,
            request.status,
            Utc::now(),
        )
        .with_admission(request.admission)
        .with_probe(request.probe);
        self.repository
            .create(new_provider)
            .await
            .map_err(map_repository_error)
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
        if let Some(admission) = request.admission {
            update = update.with_admission(admission);
        }
        if let Some(probe) = request.probe {
            update = update.with_probe(probe);
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

    /// Moves a provider into or out of a maintenance window.
    ///
    /// Only an administrator reaches this, and it is the only way to return a
    /// provider to service without waiting for a probe. It is also the only way
    /// to say a provider is *expected* to be unavailable, which is why a
    /// provider in a window is not probed: probing something an operator is
    /// deliberately changing would isolate it for a condition already known.
    ///
    /// The write moves the provider only from the state it was read in, so an
    /// operator closing a window cannot silently discard an isolation a probe
    /// recorded a moment earlier; the caller re-reads and decides again.
    pub async fn set_health(
        &self,
        id: ProviderId,
        health: ProviderHealthState,
    ) -> Result<Provider, ProviderServiceError> {
        let current = self.get(id).await?;
        // The healthy edge exposed by the administration API means "leave
        // maintenance", not "override an isolation". If a probe isolated the
        // provider before this request observed it, keep that verdict and let a
        // successful probe recover it.
        if health == ProviderHealthState::Healthy
            && current.health() != ProviderHealthState::Maintenance
        {
            return Ok(current);
        }
        let outcome = self
            .repository
            .set_health(id, current.health(), health)
            .await
            .map_err(map_repository_error)?;
        if let HealthOutcome::Applied(_) = outcome {
            self.health_metrics
                .record_health_transition(HealthTransition {
                    from: current.health(),
                    to: health,
                });
        }
        // Either the move landed, the provider already held the requested state,
        // or a probe moved it first. Reporting what storage actually holds is
        // the honest answer in all three cases, and it is the same read.
        self.get(id).await
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

pub mod health;

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
