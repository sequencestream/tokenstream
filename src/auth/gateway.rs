//! Data-plane authentication of account-owned gateway credentials.
//!
//! Authentication reads the provider-native header, parses the external
//! `<key-id>.<secret>` credential under strict length and character bounds,
//! resolves the account that owns it, resolves exactly one provider from the
//! credential's own bindings, verifies the secret against the stored hash, and
//! decrypts the upstream key. The result is an immutable snapshot that a single
//! request or connection owns for its whole lifetime.
//!
//! Every call performs its own lookup: there is no application-level credential
//! cache, so an edit, disable, or key rotation is observed by the next request
//! while already admitted work keeps its snapshot. Failures are returned before
//! any upstream is contacted and never carry credential, hash, or ciphertext
//! material.
//!
//! Nothing here reads the request body. Provider selection reads only the
//! credential's bindings and one dedicated request header, so payload
//! transparency holds for a credential that reaches several upstreams.

use crate::crypto::{PasswordWork, PasswordWorkError};
use crate::persistence::{GatewayLookupRepository, RepositoryError};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use hyper::HeaderMap;
use hyper::header::AUTHORIZATION;

use crate::crypto::{GatewaySecretVerifier, SecretCipher};
use crate::domain::{
    AccountStatus, ApiKeyStatus, GatewayCredential, MAX_GATEWAY_CREDENTIAL_LEN, ModelAliasTable,
    ProtocolType, ProviderSnapshot, ProviderStatus,
};

/// Header carrying the gateway credential on Anthropic-native routes.
const ANTHROPIC_CREDENTIAL_HEADER: &str = "x-api-key";

/// Authorization scheme token that precedes an OpenAI-native gateway credential.
const BEARER_SCHEME: &str = "Bearer";

/// Dedicated non-payload header that selects one of a credential's providers.
///
/// This is the only field besides the credential that may influence routing. It
/// is read before route validation, is accepted only when it names a provider
/// the credential is bound to, and is never logged.
pub const PROVIDER_SELECTION_HEADER: &str = "x-tokenstream-provider";

/// Longest accepted Authorization header value, including the scheme token.
const MAX_AUTHORIZATION_LEN: usize = BEARER_SCHEME.len() + 1 + MAX_GATEWAY_CREDENTIAL_LEN;

/// Where a downstream credential was read from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialSource {
    /// `Authorization: Bearer <credential>`, the OpenAI-native header.
    Authorization,
    /// `x-api-key: <credential>`, the Anthropic-native header.
    ApiKey,
}

/// A data-plane authentication failure that carries no credential material.
///
/// Every variant renders as a stable, non-sensitive description, so a failure
/// can be surfaced to a client or written to a log without echoing the
/// credential, the stored hash, or the decrypted upstream key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayAuthError {
    /// No provider-native credential header was supplied.
    MissingCredential,
    /// A provider-native credential header appeared more than once.
    DuplicateCredential,
    /// Both provider-native credential headers, or the wrong one, were supplied.
    ConflictingCredential,
    /// The credential is not a well-formed `<key-id>.<secret>` value.
    MalformedCredential,
    /// The key identifier does not resolve to a provider.
    UnknownCredential,
    /// The secret does not match the stored hash.
    InvalidCredential,
    /// The resolved provider is disabled.
    ProviderDisabled,
    /// The resolved provider is isolated or in a maintenance window.
    ProviderUnhealthy,
    /// The account that owns the credential is disabled.
    AccountDisabled,
    /// The credential carries an expiration that has already passed.
    KeyExpired,
    /// The credential selected no provider and has no default binding.
    NoProviderSelected,
    /// Storage or cryptographic infrastructure failed; authentication fails closed.
    Unavailable,
    /// Compute or database capacity for this lookup is exhausted.
    Busy,
}

impl fmt::Display for GatewayAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MissingCredential => "gateway credential is missing",
            Self::DuplicateCredential => "gateway credential is duplicated",
            Self::ConflictingCredential => "gateway credential header is conflicting",
            Self::MalformedCredential => "gateway credential is malformed",
            Self::UnknownCredential => "gateway credential is not recognized",
            Self::InvalidCredential => "gateway credential is invalid",
            Self::ProviderDisabled => "provider is disabled",
            Self::ProviderUnhealthy => "provider is not available",
            Self::AccountDisabled => "account is disabled",
            Self::KeyExpired => "gateway credential has expired",
            Self::NoProviderSelected => "no provider is selected for this credential",
            Self::Unavailable => "gateway authentication is unavailable",
            Self::Busy => "gateway authentication is busy",
        };
        formatter.write_str(message)
    }
}

impl Error for GatewayAuthError {}

/// Resolves a downstream gateway credential into a request-local snapshot.
///
/// The authenticator owns its storage and cryptographic collaborators and holds
/// no per-request state, so it can be shared across connection tasks while each
/// call still performs its own fresh lookup.
pub struct GatewayAuthenticator<R, C, V> {
    repository: R,
    cipher: C,
    verifier: Arc<V>,
    password_work: PasswordWork,
}

impl<R, C, V> GatewayAuthenticator<R, C, V>
where
    R: GatewayLookupRepository,
    C: SecretCipher,
    V: GatewaySecretVerifier + 'static,
{
    /// Builds an authenticator over the given storage and cryptographic collaborators.
    pub fn new(repository: R, cipher: C, verifier: V) -> Self {
        Self {
            repository,
            cipher,
            verifier: Arc::new(verifier),
            password_work: PasswordWork::default(),
        }
    }

    pub fn with_password_work(mut self, password_work: PasswordWork) -> Self {
        self.password_work = password_work;
        self
    }

    /// Authenticates `headers` and returns an immutable request snapshot.
    ///
    /// Missing, duplicated, conflicting, malformed, unknown, wrong, disabled,
    /// and expired credentials all fail here, before any upstream is contacted.
    /// A successful result owns the account, the credential, and the decrypted
    /// upstream key for the lifetime of the request or connection.
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Arc<ProviderSnapshot>, GatewayAuthError> {
        self.prepare(headers).await.map(|(snapshot, _)| snapshot)
    }

    /// Produces separate transport and adapter contexts from one verified view.
    /// Only the orchestrator receives alias configuration; forwarding receives
    /// the transport snapshot and cannot consult model configuration.
    pub async fn prepare(
        &self,
        headers: &HeaderMap,
    ) -> Result<(Arc<ProviderSnapshot>, ModelAliasTable), GatewayAuthError> {
        let (source, raw) = extract_credential(headers)?;
        let credential =
            GatewayCredential::parse(raw).map_err(|_| GatewayAuthError::MalformedCredential)?;

        let _secret_reader = self.cipher.secret_reader().map_err(|error| match error {
            crate::crypto::CipherError::Busy => GatewayAuthError::Busy,
            _ => GatewayAuthError::Unavailable,
        })?;
        let configuration = self
            .repository
            .gateway_configuration(credential.key_id(), selection_header(headers))
            .await
            .map_err(|error| match error {
                RepositoryError::Timeout => GatewayAuthError::Busy,
                _ => GatewayAuthError::Unavailable,
            })?
            .ok_or(GatewayAuthError::UnknownCredential)?;
        let owned = &configuration.credential;
        let api_key = owned.api_key();

        if api_key.status() == ApiKeyStatus::Disabled {
            return Err(GatewayAuthError::InvalidCredential);
        }
        if api_key.is_expired_at(chrono::Utc::now()) {
            return Err(GatewayAuthError::KeyExpired);
        }

        let account = configuration
            .account
            .as_ref()
            .ok_or(GatewayAuthError::UnknownCredential)?;
        if account.status() == AccountStatus::Disabled {
            return Err(GatewayAuthError::AccountDisabled);
        }

        let provider = configuration.provider.as_ref().ok_or_else(|| {
            if owned.bindings().is_empty() && selection_header(headers).is_none() {
                GatewayAuthError::NoProviderSelected
            } else {
                GatewayAuthError::UnknownCredential
            }
        })?;

        if source != native_source(provider.protocol_type()) {
            return Err(GatewayAuthError::ConflictingCredential);
        }
        if provider.status() == ProviderStatus::Disabled {
            return Err(GatewayAuthError::ProviderDisabled);
        }

        // An unhealthy provider refuses new work here, before any upstream is
        // contacted and before admission consumes a slot. It never reroutes:
        // the request fails, and it is never sent to a different provider.
        if provider.health().refuses_new_requests() {
            return Err(GatewayAuthError::ProviderUnhealthy);
        }

        let verifier = self.verifier.clone();
        let secret = credential.secret().clone();
        let hash = api_key.secret_hash().clone();
        let verified = match self
            .password_work
            .run(move || verifier.verify(&secret, &hash))
            .await
        {
            Ok(Ok(verified)) => verified,
            Ok(Err(_)) | Err(PasswordWorkError::Failed) => {
                return Err(GatewayAuthError::Unavailable);
            }
            Err(PasswordWorkError::Busy) => return Err(GatewayAuthError::Busy),
        };
        if !verified {
            return Err(GatewayAuthError::InvalidCredential);
        }

        let upstream_api_key = self
            .cipher
            .decrypt(provider.upstream_api_key_ciphertext())
            .map_err(|_| GatewayAuthError::Unavailable)?;
        let aliases = configuration.aliases;

        // The admission bounds of both the credential and the selected provider
        // are frozen here, with the rest of the snapshot. A later limit edit
        // applies to new work and cannot reach what is already admitted. The
        // alias table is frozen the same way: it names models for the provider
        // already chosen and does not choose that provider.
        Ok((
            Arc::new(
                ProviderSnapshot::new(
                    account.id(),
                    api_key.id(),
                    provider.id(),
                    provider.protocol_type(),
                    provider.endpoint().clone(),
                    upstream_api_key,
                )
                .with_admission(provider.admission(), api_key.admission())
                .with_health(provider.health()),
            ),
            aliases,
        ))
    }
}

/// Reads a single non-empty text selection. Other header shapes retain the
/// existing no-selector behavior rather than choosing one repeated value.
fn selection_header(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(PROVIDER_SELECTION_HEADER).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok().filter(|value| !value.is_empty())
}

impl<R, C, V> fmt::Debug for GatewayAuthenticator<R, C, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayAuthenticator")
            .finish_non_exhaustive()
    }
}

/// Reads the single provider-native credential header from `headers`.
///
/// Exactly one of the two native headers must be present. A repeated header is a
/// duplicate; both headers together are a conflict. The returned value borrows
/// from `headers` and is not yet bounds-checked for character set.
fn extract_credential(headers: &HeaderMap) -> Result<(CredentialSource, &str), GatewayAuthError> {
    let authorization_count = headers.get_all(AUTHORIZATION).iter().count();
    let api_key_count = headers.get_all(ANTHROPIC_CREDENTIAL_HEADER).iter().count();

    match (authorization_count, api_key_count) {
        (0, 0) => return Err(GatewayAuthError::MissingCredential),
        (count, _) if count > 1 => return Err(GatewayAuthError::DuplicateCredential),
        (_, count) if count > 1 => return Err(GatewayAuthError::DuplicateCredential),
        (1, 1) => return Err(GatewayAuthError::ConflictingCredential),
        _ => {}
    }

    if authorization_count == 1 {
        let value = headers
            .get(AUTHORIZATION)
            .expect("authorization header is present exactly once");
        let rendered = value
            .to_str()
            .map_err(|_| GatewayAuthError::MalformedCredential)?;
        if rendered.len() > MAX_AUTHORIZATION_LEN {
            return Err(GatewayAuthError::MalformedCredential);
        }
        let (scheme, credential) = rendered
            .split_once(' ')
            .ok_or(GatewayAuthError::MalformedCredential)?;
        if !scheme.eq_ignore_ascii_case(BEARER_SCHEME) {
            return Err(GatewayAuthError::MalformedCredential);
        }
        Ok((CredentialSource::Authorization, credential))
    } else {
        let value = headers
            .get(ANTHROPIC_CREDENTIAL_HEADER)
            .expect("api key header is present exactly once");
        let rendered = value
            .to_str()
            .map_err(|_| GatewayAuthError::MalformedCredential)?;
        if rendered.len() > MAX_GATEWAY_CREDENTIAL_LEN {
            return Err(GatewayAuthError::MalformedCredential);
        }
        Ok((CredentialSource::ApiKey, rendered))
    }
}

/// The native credential header for a provider protocol.
fn native_source(protocol: ProtocolType) -> CredentialSource {
    match protocol {
        ProtocolType::OpenAi => CredentialSource::Authorization,
        ProtocolType::Anthropic => CredentialSource::ApiKey,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn credential() -> String {
        format!("{}.{}", "k".repeat(22), "A".repeat(43))
    }

    #[test]
    fn requires_exactly_one_native_header() {
        let value = credential();

        assert_eq!(
            extract_credential(&HeaderMap::new()),
            Err(GatewayAuthError::MissingCredential)
        );

        let mut duplicated_authorization = HeaderMap::new();
        duplicated_authorization.append(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {value}")).expect("valid header"),
        );
        duplicated_authorization.append(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {value}")).expect("valid header"),
        );
        assert_eq!(
            extract_credential(&duplicated_authorization),
            Err(GatewayAuthError::DuplicateCredential)
        );

        let mut duplicated_api_key = HeaderMap::new();
        duplicated_api_key.append(
            ANTHROPIC_CREDENTIAL_HEADER,
            HeaderValue::from_str(&value).expect("valid header"),
        );
        duplicated_api_key.append(
            ANTHROPIC_CREDENTIAL_HEADER,
            HeaderValue::from_str(&value).expect("valid header"),
        );
        assert_eq!(
            extract_credential(&duplicated_api_key),
            Err(GatewayAuthError::DuplicateCredential)
        );

        let mut conflicting = HeaderMap::new();
        conflicting.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {value}")).expect("valid header"),
        );
        conflicting.insert(
            ANTHROPIC_CREDENTIAL_HEADER,
            HeaderValue::from_str(&value).expect("valid header"),
        );
        assert_eq!(
            extract_credential(&conflicting),
            Err(GatewayAuthError::ConflictingCredential)
        );
    }

    #[test]
    fn reads_each_native_header_under_its_own_rule() {
        let value = credential();

        let mut authorization = HeaderMap::new();
        authorization.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("bearer {value}")).expect("valid header"),
        );
        assert_eq!(
            extract_credential(&authorization).expect("bearer is case-insensitive"),
            (CredentialSource::Authorization, value.as_str())
        );

        let mut api_key = HeaderMap::new();
        api_key.insert(
            ANTHROPIC_CREDENTIAL_HEADER,
            HeaderValue::from_str(&value).expect("valid header"),
        );
        assert_eq!(
            extract_credential(&api_key).expect("api key is read verbatim"),
            (CredentialSource::ApiKey, value.as_str())
        );
    }

    #[test]
    fn rejects_malformed_shapes_and_non_text_values() {
        for rendered in [
            format!("Basic {value}", value = credential()),
            "Bearer".to_owned(),
            format!("Bearer {}", "x".repeat(MAX_AUTHORIZATION_LEN)),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&rendered).expect("valid header"),
            );
            assert_eq!(
                extract_credential(&headers),
                Err(GatewayAuthError::MalformedCredential),
                "expected {rendered:?} to be rejected"
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            ANTHROPIC_CREDENTIAL_HEADER,
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("valid header bytes"),
        );
        assert_eq!(
            extract_credential(&headers),
            Err(GatewayAuthError::MalformedCredential)
        );
    }
}
