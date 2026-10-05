//! Account-owned model alias configuration.
//!
//! Aliases are inert control-plane state. This module validates and persists
//! them, but it has no dependency on authentication snapshots or proxying.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use chrono::Utc;

use crate::domain::{AccountId, AccountStatus, ModelAliasId, ModelAliasWithTargets, ProviderId};
use crate::persistence::{
    AccountRepository, MAX_MODEL_ALIAS_TARGETS, ModelAliasListRequest, ModelAliasPage,
    ModelAliasRepository, ModelAliasUpdate, NewModelAlias, ProviderRepository, RepositoryError,
};

pub const MAX_MODEL_ALIAS_NAME_LEN: usize = 100;
pub const MAX_UPSTREAM_MODEL_NAME_LEN: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelAliasServiceError {
    InvalidName,
    InvalidTargets,
    AccountNotFound,
    AccountDisabled,
    ProviderNotFound,
    Conflict,
    NotFound,
    NoFieldsToUpdate,
    Busy,
    Storage,
}

impl fmt::Display for ModelAliasServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidName => "model alias name is invalid",
            Self::InvalidTargets => "model alias targets are invalid",
            Self::AccountNotFound => "account was not found",
            Self::AccountDisabled => "account is disabled",
            Self::ProviderNotFound => "provider was not found",
            Self::Conflict => "model alias name already exists for this account",
            Self::NotFound => "model alias was not found",
            Self::NoFieldsToUpdate => "the edit named no writable field",
            Self::Busy => "model alias service has no spare capacity",
            Self::Storage => "model alias could not be persisted",
        };
        formatter.write_str(message)
    }
}

impl Error for ModelAliasServiceError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelAliasTargetInput {
    provider_id: ProviderId,
    upstream_model: String,
}

impl ModelAliasTargetInput {
    pub fn new(provider_id: ProviderId, upstream_model: String) -> Self {
        Self {
            provider_id,
            upstream_model,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CreateModelAliasRequest {
    account_id: AccountId,
    name: String,
    targets: Vec<ModelAliasTargetInput>,
}

impl CreateModelAliasRequest {
    pub fn new(account_id: AccountId, name: String, targets: Vec<ModelAliasTargetInput>) -> Self {
        Self {
            account_id,
            name,
            targets,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct UpdateModelAliasRequest {
    name: Option<String>,
    targets: Option<Vec<ModelAliasTargetInput>>,
}

impl UpdateModelAliasRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_targets(mut self, targets: Vec<ModelAliasTargetInput>) -> Self {
        self.targets = Some(targets);
        self
    }
}

#[derive(Clone)]
pub struct ModelAliasService<R> {
    repository: R,
}

impl<R> ModelAliasService<R>
where
    R: ModelAliasRepository + AccountRepository + ProviderRepository,
{
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn get(
        &self,
        id: ModelAliasId,
    ) -> Result<ModelAliasWithTargets, ModelAliasServiceError> {
        self.repository
            .find_model_alias_by_id(id)
            .await
            .map_err(map_repository_error)?
            .ok_or(ModelAliasServiceError::NotFound)
    }

    pub async fn list(
        &self,
        request: ModelAliasListRequest,
    ) -> Result<ModelAliasPage, ModelAliasServiceError> {
        self.repository
            .list_model_aliases(request)
            .await
            .map_err(map_repository_error)
    }

    pub async fn create(
        &self,
        request: CreateModelAliasRequest,
    ) -> Result<ModelAliasWithTargets, ModelAliasServiceError> {
        let account = AccountRepository::find_by_id(&self.repository, request.account_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(ModelAliasServiceError::AccountNotFound)?;
        if account.status() != AccountStatus::Enabled {
            return Err(ModelAliasServiceError::AccountDisabled);
        }
        let name = validate_name(&request.name)?;
        let targets = self.validate_targets(request.targets).await?;
        self.repository
            .create_model_alias(NewModelAlias::new(
                request.account_id,
                name,
                targets,
                Utc::now(),
            ))
            .await
            .map_err(map_repository_error)
    }

    pub async fn update(
        &self,
        id: ModelAliasId,
        request: UpdateModelAliasRequest,
    ) -> Result<ModelAliasWithTargets, ModelAliasServiceError> {
        let mut update = ModelAliasUpdate::new();
        if let Some(name) = request.name {
            update = update.with_name(validate_name(&name)?);
        }
        if let Some(targets) = request.targets {
            update = update.with_targets(self.validate_targets(targets).await?);
        }
        self.repository
            .update_model_alias(id, update)
            .await
            .map_err(map_repository_error)
    }

    pub async fn delete(&self, id: ModelAliasId) -> Result<(), ModelAliasServiceError> {
        self.repository
            .delete_model_alias(id)
            .await
            .map_err(map_repository_error)
    }

    async fn validate_targets(
        &self,
        targets: Vec<ModelAliasTargetInput>,
    ) -> Result<Vec<(ProviderId, String)>, ModelAliasServiceError> {
        if targets.is_empty() || targets.len() > MAX_MODEL_ALIAS_TARGETS {
            return Err(ModelAliasServiceError::InvalidTargets);
        }
        let mut providers = HashSet::with_capacity(targets.len());
        let mut validated = Vec::with_capacity(targets.len());
        for target in targets {
            if !providers.insert(target.provider_id) {
                return Err(ModelAliasServiceError::InvalidTargets);
            }
            let upstream_model = validate_upstream_model(&target.upstream_model)?;
            if ProviderRepository::find_by_id(&self.repository, target.provider_id)
                .await
                .map_err(map_repository_error)?
                .is_none()
            {
                return Err(ModelAliasServiceError::ProviderNotFound);
            }
            validated.push((target.provider_id, upstream_model));
        }
        Ok(validated)
    }
}

fn validate_name(raw: &str) -> Result<String, ModelAliasServiceError> {
    validate_text(raw, MAX_MODEL_ALIAS_NAME_LEN).ok_or(ModelAliasServiceError::InvalidName)
}

fn validate_upstream_model(raw: &str) -> Result<String, ModelAliasServiceError> {
    validate_text(raw, MAX_UPSTREAM_MODEL_NAME_LEN).ok_or(ModelAliasServiceError::InvalidTargets)
}

fn validate_text(raw: &str, max_len: usize) -> Option<String> {
    let value = raw.trim();
    (!value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

fn map_repository_error(error: RepositoryError) -> ModelAliasServiceError {
    match error {
        RepositoryError::Conflict => ModelAliasServiceError::Conflict,
        RepositoryError::NotFound => ModelAliasServiceError::NotFound,
        RepositoryError::NoFieldsToUpdate => ModelAliasServiceError::NoFieldsToUpdate,
        RepositoryError::Timeout => ModelAliasServiceError::Busy,
        _ => ModelAliasServiceError::Storage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_validation_trims_and_bounds_bytes() {
        assert_eq!(validate_name("  coding  ").expect("valid name"), "coding");
        assert_eq!(
            validate_name("\n"),
            Err(ModelAliasServiceError::InvalidName)
        );
        assert_eq!(
            validate_upstream_model(&"x".repeat(MAX_UPSTREAM_MODEL_NAME_LEN + 1)),
            Err(ModelAliasServiceError::InvalidTargets)
        );
    }
}
