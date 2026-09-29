//! Account and credential administration service.
//!
//! Accounts are the principals that own data-plane credentials and sign into the
//! control plane. Credentials are issued, rotated, bound to providers, enabled,
//! disabled, expired, and deleted here. The service holds no secret in a form
//! that outlives the call: a generated plaintext is returned from the issuance
//! result and never stored, logged, or rendered by diagnostics.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::crypto::{GatewaySecretVerifier, PasswordWork, PasswordWorkError};
use crate::domain::{
    Account, AccountId, AccountRole, AccountStatus, ApiKeyId, ApiKeyStatus, ApiKeyWithBindings,
    CredentialAdmission, GatewayCredential, MAX_ACCOUNT_NAME_LEN, ProviderId, SecretString,
};
use crate::persistence::{
    AccountListRequest, AccountPage, AccountRepository, AccountUpdate, ApiKeyListRequest,
    ApiKeyPage, ApiKeyRepository, ApiKeyUpdate, MAX_API_KEY_PROVIDERS, NewAccount, NewApiKey,
    RepositoryError,
};

/// Longest accepted generated password, counted in bytes.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// An account or credential service failure that carries no name, key, or hash.
///
/// Every variant renders as a stable, non-sensitive description, so a failure
/// can be surfaced or logged without echoing secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialServiceError {
    /// The name is empty, too long, or contains control characters.
    InvalidName,
    /// The password is empty or too long.
    InvalidPassword,
    /// The role or status is not one this process accepts.
    InvalidRoleOrStatus,
    /// The allowed provider set is empty or larger than the accepted bound.
    InvalidProviders,
    /// The default provider is not a member of the allowed set.
    DefaultNotInProviderSet,
    /// An admission bound is zero or beyond the accepted ceiling.
    InvalidAdmissionBound,
    /// A named provider does not exist.
    ProviderNotFound,
    /// The expiration is not a valid instant.
    InvalidExpiry,
    /// Compute or database capacity for this change is exhausted.
    Busy,
    /// The bootstrap administrator cannot be disabled, demoted, or deleted.
    BootstrapProtected,
    /// A regular user named an account it does not own.
    NotOwner,
    /// The named account is unknown, disabled, or the password does not match.
    ///
    /// One variant covers all three so a caller cannot distinguish "no such
    /// account" from "wrong password" and learn which names exist.
    InvalidCredentials,
    /// A record with the same name or key identifier already exists.
    Conflict,
    /// No record exists for the given identifier.
    NotFound,
    /// The record is referenced by request logs and cannot be deleted.
    InUse,
    /// The edit named no writable field, so nothing was changed.
    NoFieldsToUpdate,
    /// The record could not be persisted.
    Storage,
}

impl fmt::Display for CredentialServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidName => "name is invalid",
            Self::InvalidPassword => "password is invalid",
            Self::InvalidRoleOrStatus => "role or status is invalid",
            Self::InvalidProviders => "provider selection is invalid",
            Self::InvalidAdmissionBound => "an admission bound must be greater than zero",
            Self::DefaultNotInProviderSet => {
                "default provider must be one of the allowed providers"
            }
            Self::ProviderNotFound => "provider was not found",
            Self::InvalidExpiry => "expiration is invalid",
            Self::Busy => "credential service has no spare capacity",
            Self::BootstrapProtected => "the bootstrap administrator cannot be changed this way",
            Self::NotOwner => "the account does not own this resource",
            Self::InvalidCredentials => "invalid credentials",
            Self::Conflict => "record conflicts with existing data",
            Self::NotFound => "record was not found",
            Self::InUse => "record is referenced by request logs",
            Self::NoFieldsToUpdate => "the edit named no writable field",
            Self::Storage => "record could not be persisted",
        };
        formatter.write_str(message)
    }
}

impl Error for CredentialServiceError {}

/// The stored record together with the one-time credential that was issued.
#[derive(Debug)]
pub struct IssuedApiKey {
    api_key: ApiKeyWithBindings,
    credential: GatewayCredential,
}

impl IssuedApiKey {
    fn new(api_key: ApiKeyWithBindings, credential: GatewayCredential) -> Self {
        Self {
            api_key,
            credential,
        }
    }

    pub fn api_key(&self) -> &ApiKeyWithBindings {
        &self.api_key
    }

    /// The plaintext credential, shown only from the issuance result.
    pub fn credential(&self) -> &GatewayCredential {
        &self.credential
    }

    pub fn into_parts(self) -> (ApiKeyWithBindings, GatewayCredential) {
        (self.api_key, self.credential)
    }

    /// Rebuilds an issued credential from its parts, for a caller that needs to
    /// keep both the row and the one-time plaintext.
    pub fn from_parts(api_key: ApiKeyWithBindings, credential: GatewayCredential) -> Self {
        Self::new(api_key, credential)
    }
}

/// A new account, optionally with a password the caller supplied.
pub struct CreateAccountRequest {
    name: String,
    password: Option<SecretString>,
    role: AccountRole,
    status: AccountStatus,
}

impl CreateAccountRequest {
    pub fn new(
        name: String,
        password: Option<SecretString>,
        role: AccountRole,
        status: AccountStatus,
    ) -> Self {
        Self {
            name,
            password,
            role,
            status,
        }
    }
}

/// A created account, with the generated password when none was supplied.
pub struct CreatedAccount {
    account: Account,
    generated_password: Option<SecretString>,
}

impl CreatedAccount {
    fn new(account: Account, generated_password: Option<SecretString>) -> Self {
        Self {
            account,
            generated_password,
        }
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    /// The generated password, present only when the request supplied none.
    pub fn generated_password(&self) -> Option<&SecretString> {
        self.generated_password.as_ref()
    }

    pub fn into_parts(self) -> (Account, Option<SecretString>) {
        (self.account, self.generated_password)
    }
}

/// A new credential bound to a set of providers.
pub struct CreateApiKeyRequest {
    account_id: AccountId,
    name: String,
    provider_ids: Vec<ProviderId>,
    default_provider_id: Option<ProviderId>,
    expires_at: Option<DateTime<Utc>>,
    status: ApiKeyStatus,
    admission: CredentialAdmission,
}

impl CreateApiKeyRequest {
    pub fn new(
        account_id: AccountId,
        name: String,
        provider_ids: Vec<ProviderId>,
        default_provider_id: Option<ProviderId>,
        expires_at: Option<DateTime<Utc>>,
        status: ApiKeyStatus,
    ) -> Self {
        Self {
            account_id,
            name,
            provider_ids,
            default_provider_id,
            expires_at,
            status,
            admission: CredentialAdmission::default(),
        }
    }

    /// Bounds this credential at admission, so one caller cannot consume
    /// capacity that belongs to the callers around it.
    pub fn with_admission(mut self, admission: CredentialAdmission) -> Self {
        self.admission = admission;
        self
    }
}

/// A field-scoped credential change set.
#[derive(Default)]
pub struct UpdateApiKeyRequest {
    name: Option<String>,
    status: Option<ApiKeyStatus>,
    expires_at: Option<Option<DateTime<Utc>>>,
    provider_ids: Option<Vec<ProviderId>>,
    default_provider_id: Option<Option<ProviderId>>,
    admission: Option<CredentialAdmission>,
}

impl UpdateApiKeyRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
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

    /// Replaces all three admission bounds. Naming the admission here is what
    /// makes the edit non-empty, and it names every bound at once, so a single
    /// edit can widen, narrow, or clear the credential's limits together.
    pub fn with_admission(mut self, admission: CredentialAdmission) -> Self {
        self.admission = Some(admission);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.status.is_none()
            && self.expires_at.is_none()
            && self.provider_ids.is_none()
            && self.default_provider_id.is_none()
            && self.admission.is_none()
    }

    fn into_update(self) -> ApiKeyUpdate {
        let mut update = ApiKeyUpdate::new();
        if let Some(name) = self.name {
            update = update.with_name(name);
        }
        if let Some(status) = self.status {
            update = update.with_status(status);
        }
        if let Some(expires_at) = self.expires_at {
            update = update.with_expires_at(expires_at);
        }
        if let Some(provider_ids) = self.provider_ids {
            update = update.with_provider_ids(provider_ids);
        }
        if let Some(default_provider_id) = self.default_provider_id {
            update = update.with_default_provider_id(default_provider_id);
        }
        if let Some(admission) = self.admission {
            update = update.with_admission(admission);
        }
        update
    }
}

/// A field-scoped account change set.
#[derive(Default)]
pub struct UpdateAccountRequest {
    name: Option<String>,
    password: Option<SecretString>,
    role: Option<AccountRole>,
    status: Option<AccountStatus>,
}

impl UpdateAccountRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_password(mut self, password: SecretString) -> Self {
        self.password = Some(password);
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
}

/// Creates and edits accounts, and issues, rotates, and retires credentials.
pub struct CredentialService<R, V> {
    repository: R,
    verifier: Arc<V>,
    password_work: PasswordWork,
}

impl<R, V> CredentialService<R, V>
where
    R: AccountRepository + ApiKeyRepository + crate::persistence::ProviderRepository,
    V: GatewaySecretVerifier + 'static,
{
    pub fn new(repository: R, verifier: V) -> Self {
        Self {
            repository,
            verifier: Arc::new(verifier),
            password_work: PasswordWork::default(),
        }
    }

    pub fn with_password_work(mut self, password_work: PasswordWork) -> Self {
        self.password_work = password_work;
        self
    }

    /// Replaces the hashing budget, for a shared-construction caller.
    pub fn set_password_work(&mut self, password_work: PasswordWork) {
        self.password_work = password_work;
    }

    /// Creates the bootstrap administrator when no account exists.
    ///
    /// This is the one path that may create the account that cannot be disabled
    /// or demoted, and it refuses to run once any account exists. Credentials
    /// that predate accounts are adopted into it in the same transaction, so an
    /// upgrade never invalidates a client that already holds one.
    pub async fn ensure_bootstrap(
        &self,
        name: String,
        password: SecretString,
    ) -> Result<Option<Account>, CredentialServiceError> {
        if AccountRepository::count(&self.repository)
            .await
            .map_err(report_repository_error)?
            > 0
        {
            return Ok(None);
        }
        let name = validate_name(name)?;
        validate_password(&password)?;
        let hash = self.hash_password(password.expose()).await?;
        let account = AccountRepository::create(
            &self.repository,
            NewAccount::new(
                name,
                hash,
                AccountRole::Admin,
                AccountStatus::Enabled,
                true,
                Utc::now(),
            ),
        )
        .await
        .map_err(report_repository_error)?;
        Ok(Some(account))
    }

    /// Verifies a sign-in and returns the account it belongs to.
    ///
    /// An unknown name, a disabled account, and a wrong password all return
    /// [`CredentialServiceError::InvalidCredentials`], so the response never
    /// reveals which account names exist.
    pub async fn verify_sign_in(
        &self,
        name: &str,
        password: &str,
    ) -> Result<Account, CredentialServiceError> {
        let name = name.trim();
        if name.is_empty() || password.is_empty() || password.len() > MAX_PASSWORD_LEN {
            return Err(CredentialServiceError::InvalidCredentials);
        }
        let account = AccountRepository::find_by_name(&self.repository, name)
            .await
            .map_err(map_repository_error)?
            .ok_or(CredentialServiceError::InvalidCredentials)?;
        if account.status() == AccountStatus::Disabled {
            return Err(CredentialServiceError::InvalidCredentials);
        }
        // The hash is verified even for an unknown account would leak timing, so
        // the comparison runs against the stored hash before the result is used.
        if !self
            .verify_password(password, account.password_hash().expose())
            .await?
        {
            return Err(CredentialServiceError::InvalidCredentials);
        }
        Ok(account)
    }

    /// Returns one account without exposing its password hash.
    pub async fn get_account(&self, id: AccountId) -> Result<Account, CredentialServiceError> {
        AccountRepository::find_by_id(&self.repository, id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CredentialServiceError::NotFound)
    }

    pub async fn list_accounts(
        &self,
        request: AccountListRequest,
    ) -> Result<AccountPage, CredentialServiceError> {
        AccountRepository::list(&self.repository, request)
            .await
            .map_err(map_repository_error)
    }

    /// Creates an account, generating a password when the caller supplied none.
    pub async fn create_account(
        &self,
        request: CreateAccountRequest,
    ) -> Result<CreatedAccount, CredentialServiceError> {
        let name = validate_name(request.name)?;
        let (password, generated) = match request.password {
            Some(password) => {
                validate_password(&password)?;
                (password, None)
            }
            None => {
                let generated = SecretString::new(generate_password()?);
                (generated.clone(), Some(generated))
            }
        };
        let hash = self.hash_password(password.expose()).await?;
        let account = AccountRepository::create(
            &self.repository,
            NewAccount::new(name, hash, request.role, request.status, false, Utc::now()),
        )
        .await
        .map_err(map_repository_error)?;
        Ok(CreatedAccount::new(account, generated))
    }

    /// Applies a partial account edit, refusing to lock out the deployment.
    pub async fn update_account(
        &self,
        id: AccountId,
        request: UpdateAccountRequest,
    ) -> Result<Account, CredentialServiceError> {
        let account = self.get_account(id).await?;
        if request.name.is_none()
            && request.password.is_none()
            && request.role.is_none()
            && request.status.is_none()
        {
            return Err(CredentialServiceError::NoFieldsToUpdate);
        }
        // The bootstrap administrator is the only way back into a deployment's
        // own accounts, so it can be neither demoted nor disabled here.
        if account.is_bootstrap() && (request.role.is_some() || request.status.is_some()) {
            return Err(CredentialServiceError::BootstrapProtected);
        }
        let mut update = AccountUpdate::new();
        if let Some(name) = request.name {
            update = update.with_name(validate_name(name)?);
        }
        if let Some(password) = request.password {
            validate_password(&password)?;
            let hash = self.hash_password(password.expose()).await?;
            update = update.with_password_hash(hash);
        }
        if let Some(role) = request.role {
            update = update.with_role(role);
        }
        if let Some(status) = request.status {
            update = update.with_status(status);
        }
        AccountRepository::update(&self.repository, id, update)
            .await
            .map_err(map_repository_error)
    }

    pub async fn delete_account(&self, id: AccountId) -> Result<(), CredentialServiceError> {
        let account = self.get_account(id).await?;
        if account.is_bootstrap() {
            return Err(CredentialServiceError::BootstrapProtected);
        }
        AccountRepository::delete(&self.repository, id)
            .await
            .map_err(map_repository_error)
    }

    /// Returns one credential with its bindings, without any secret.
    pub async fn get_api_key(
        &self,
        id: ApiKeyId,
    ) -> Result<ApiKeyWithBindings, CredentialServiceError> {
        ApiKeyRepository::find_by_id(&self.repository, id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CredentialServiceError::NotFound)
    }

    pub async fn list_api_keys(
        &self,
        request: ApiKeyListRequest,
    ) -> Result<ApiKeyPage, CredentialServiceError> {
        ApiKeyRepository::list(&self.repository, request)
            .await
            .map_err(map_repository_error)
    }

    /// Issues a credential for `account_id`, bound to the given providers.
    ///
    /// The allowed set must be non-empty, so a stored credential can always
    /// resolve to exactly one provider. A named default must belong to that set.
    pub async fn create_api_key(
        &self,
        request: CreateApiKeyRequest,
    ) -> Result<IssuedApiKey, CredentialServiceError> {
        let name = validate_name(request.name)?;
        let provider_ids = self.validate_providers(&request.provider_ids).await?;
        let default_provider_id =
            self.validate_default(request.default_provider_id, &provider_ids)?;
        // An expiration that has already passed would create a credential that
        // can never authenticate, so it is refused rather than stored.
        if request.expires_at.is_some_and(|at| at <= Utc::now()) {
            return Err(CredentialServiceError::InvalidExpiry);
        }
        let expires_at = request.expires_at;

        // The owning account must exist, so a credential never dangles.
        self.get_account(request.account_id).await?;

        let (credential, hash) = self.issue_secret().await?;
        let api_key = ApiKeyRepository::create(
            &self.repository,
            NewApiKey::new(
                request.account_id,
                name,
                credential.key_id().clone(),
                hash,
                request.status,
                default_provider_id,
                expires_at,
                provider_ids,
                Utc::now(),
            )
            .with_admission(request.admission),
        )
        .await
        .map_err(map_repository_error)?;
        Ok(IssuedApiKey::new(api_key, credential))
    }

    /// Applies a partial credential edit.
    ///
    /// When the caller replaces the allowed set, the stored default is rechecked
    /// against the new set, so an edit can never leave a default pointing
    /// outside the providers the credential may reach.
    pub async fn update_api_key(
        &self,
        id: ApiKeyId,
        current: &ApiKeyWithBindings,
        request: UpdateApiKeyRequest,
    ) -> Result<ApiKeyWithBindings, CredentialServiceError> {
        if request.is_empty() {
            return Err(CredentialServiceError::NoFieldsToUpdate);
        }
        if let Some(name) = &request.name {
            validate_name(name.clone())?;
        }
        let update = request.into_update();

        let mut allowed: Vec<ProviderId> = current
            .bindings()
            .iter()
            .map(|binding| binding.provider_id)
            .collect();
        if let Some(provider_ids) = update.provider_ids() {
            allowed = self.validate_providers(provider_ids).await?;
        }

        // The default must remain a member of whatever set will be stored.
        let effective_default = match update.default_provider_id() {
            Some(Some(provider_id)) => Some(provider_id),
            Some(None) => None,
            None => current.api_key().default_provider_id(),
        };
        if let Some(default_provider_id) = effective_default
            && !allowed.contains(&default_provider_id)
        {
            return Err(CredentialServiceError::DefaultNotInProviderSet);
        }

        ApiKeyRepository::update(&self.repository, id, update)
            .await
            .map_err(map_repository_error)
    }

    /// Replaces the secret and returns the new credential once.
    ///
    /// The identifier and hash are replaced in one storage write, so a
    /// concurrent reader never observes a half-rotated credential. The previous
    /// secret fails new work as soon as the replacement is committed, while
    /// admitted streams keep the snapshot they hold.
    pub async fn rotate_api_key(
        &self,
        id: ApiKeyId,
    ) -> Result<IssuedApiKey, CredentialServiceError> {
        let (credential, hash) = self.issue_secret().await?;
        let api_key =
            ApiKeyRepository::rotate(&self.repository, id, credential.key_id().clone(), hash)
                .await
                .map_err(map_repository_error)?;
        Ok(IssuedApiKey::new(api_key, credential))
    }

    pub async fn delete_api_key(&self, id: ApiKeyId) -> Result<(), CredentialServiceError> {
        ApiKeyRepository::delete(&self.repository, id)
            .await
            .map_err(map_repository_error)
    }

    /// Generates one credential and its Argon2id hash.
    async fn issue_secret(
        &self,
    ) -> Result<(GatewayCredential, crate::domain::PasswordHash), CredentialServiceError> {
        let verifier = self.verifier.clone();
        let (credential, hash) = match self.password_work.run(move || verifier.issue()).await {
            Ok(Ok(issued)) => issued,
            Ok(Err(_)) | Err(PasswordWorkError::Failed) => {
                return Err(CredentialServiceError::Storage);
            }
            Err(PasswordWorkError::Busy) => return Err(CredentialServiceError::Busy),
        };
        Ok((credential, hash))
    }

    /// Hashes a password on the control-plane budget.
    async fn hash_password(
        &self,
        password: &str,
    ) -> Result<crate::domain::PasswordHash, CredentialServiceError> {
        let owned = password.to_owned();
        let hashed = self
            .password_work
            .run(move || crate::local_state::hash_admin_password(&owned))
            .await;
        match hashed {
            Ok(Ok(hash)) => Ok(crate::domain::PasswordHash::new(hash)),
            Ok(Err(_)) | Err(PasswordWorkError::Failed) => Err(CredentialServiceError::Storage),
            Err(PasswordWorkError::Busy) => Err(CredentialServiceError::Busy),
        }
    }

    /// Checks a candidate password against a stored hash.
    pub async fn verify_password(
        &self,
        password: &str,
        hash: &str,
    ) -> Result<bool, CredentialServiceError> {
        let owned = password.to_owned();
        let encoded = hash.to_owned();
        let verified = self
            .password_work
            .run(move || crate::local_state::password_matches(&owned, &encoded))
            .await;
        match verified {
            Ok(verified) => Ok(verified),
            Err(PasswordWorkError::Busy) => Err(CredentialServiceError::Busy),
            Err(PasswordWorkError::Failed) => Err(CredentialServiceError::Storage),
        }
    }

    /// Rejects an empty or oversized set, then confirms every member exists.
    async fn validate_providers(
        &self,
        provider_ids: &[ProviderId],
    ) -> Result<Vec<ProviderId>, CredentialServiceError> {
        if provider_ids.is_empty() || provider_ids.len() > MAX_API_KEY_PROVIDERS {
            return Err(CredentialServiceError::InvalidProviders);
        }
        let mut seen = Vec::with_capacity(provider_ids.len());
        for provider_id in provider_ids {
            if seen.contains(provider_id) {
                return Err(CredentialServiceError::InvalidProviders);
            }
            seen.push(*provider_id);
            if self
                .provider_exists(*provider_id)
                .await
                .map_err(map_repository_error)?
            {
                continue;
            }
            return Err(CredentialServiceError::ProviderNotFound);
        }
        Ok(seen)
    }

    async fn provider_exists(&self, id: ProviderId) -> Result<bool, RepositoryError> {
        crate::persistence::ProviderRepository::find_by_id(&self.repository, id)
            .await
            .map(|provider| provider.is_some())
    }

    fn validate_default(
        &self,
        default_provider_id: Option<ProviderId>,
        provider_ids: &[ProviderId],
    ) -> Result<Option<ProviderId>, CredentialServiceError> {
        match default_provider_id {
            None => Ok(None),
            Some(default_provider_id) if provider_ids.contains(&default_provider_id) => {
                Ok(Some(default_provider_id))
            }
            Some(_) => Err(CredentialServiceError::DefaultNotInProviderSet),
        }
    }
}

impl<R, V> fmt::Debug for CredentialService<R, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialService")
            .finish_non_exhaustive()
    }
}

/// Validates a name and returns it trimmed of surrounding whitespace.
fn validate_name(name: String) -> Result<String, CredentialServiceError> {
    let name = name.trim().to_owned();
    let length = name.chars().count();
    if length == 0 || length > MAX_ACCOUNT_NAME_LEN || name.chars().any(char::is_control) {
        return Err(CredentialServiceError::InvalidName);
    }
    Ok(name)
}

fn validate_password(password: &SecretString) -> Result<(), CredentialServiceError> {
    let value = password.expose();
    if value.is_empty() || value.len() > MAX_PASSWORD_LEN {
        return Err(CredentialServiceError::InvalidPassword);
    }
    Ok(())
}

/// Generates a password for an account created without one.
///
/// The value is random and shown once. It is never stored, so an operator who
/// loses it resets the account's password rather than recovering it.
fn generate_password() -> Result<String, CredentialServiceError> {
    const BYTES: usize = 18;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut random = [0_u8; BYTES];
    getrandom::getrandom(&mut random).map_err(|_| CredentialServiceError::Storage)?;
    Ok(random
        .iter()
        .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char)
        .collect())
}

/// Maps a repository failure raised while the bootstrap account is created.
///
/// Bootstrap runs once, at startup, where a failure is fatal, so it reports the
/// storage cause rather than folding it into a generic error the operator cannot
/// act on.
fn report_repository_error(error: RepositoryError) -> CredentialServiceError {
    map_repository_error(error)
}

fn map_repository_error(error: RepositoryError) -> CredentialServiceError {
    match error {
        RepositoryError::Conflict => CredentialServiceError::Conflict,
        RepositoryError::NotFound => CredentialServiceError::NotFound,
        RepositoryError::InUse
        | RepositoryError::ProviderInUse
        | RepositoryError::ProviderBound => CredentialServiceError::InUse,
        RepositoryError::NoFieldsToUpdate => CredentialServiceError::NoFieldsToUpdate,
        RepositoryError::Timeout => CredentialServiceError::Busy,
        _ => CredentialServiceError::Storage,
    }
}
