use std::fmt;

use tokenstream::admin::AdminApi;
use tokenstream::config::{Config, ConfigError};
use tokenstream::crypto::{Argon2GatewaySecretVerifier, SharedCipher};
use tokenstream::diagnostics::{ConfigFailure, StartupErrorKind, StartupStage};
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::proxy::gateway::Gateway;
use tokenstream::telemetry::Metrics;

#[derive(Clone, Copy, Debug)]
struct StartupFailure {
    stage: StartupStage,
    error_kind: StartupErrorKind,
}

impl StartupFailure {
    const fn new(stage: StartupStage, error_kind: StartupErrorKind) -> Self {
        Self { stage, error_kind }
    }
}

impl fmt::Display for StartupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Tokenstream startup failed")
    }
}

impl std::error::Error for StartupFailure {}

#[tokio::main]
async fn main() {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            write_config_failure(&error);
            std::process::exit(1);
        }
    };
    if tokenstream::diagnostics::install(config.log_filter()).is_err() {
        let _ = tokenstream::diagnostics::write_fatal(
            StartupStage::DiagnosticInitialization,
            StartupErrorKind::SubscriberUnavailable,
            None,
        );
        std::process::exit(1);
    }
    if let Err(failure) = run(config).await {
        let _ = tokenstream::diagnostics::write_fatal(failure.stage, failure.error_kind, None);
        std::process::exit(1);
    }
}

fn write_config_failure(error: &ConfigError) {
    let (kind, setting, requirement) = match error {
        ConfigError::Missing { name } => (StartupErrorKind::MissingSetting, *name, None),
        ConfigError::Invalid { name, requirement } => {
            (StartupErrorKind::InvalidSetting, *name, Some(*requirement))
        }
    };
    let _ = tokenstream::diagnostics::write_fatal(
        StartupStage::Configuration,
        kind,
        Some(ConfigFailure::sanitized(setting, requirement)),
    );
}

async fn run(config: Config) -> Result<(), StartupFailure> {
    tracing::info!(
        target: "tokenstream::process",
        event = "process_starting",
        message = "Tokenstream is starting.",
        data_address = config.data_listen_addr().to_string().as_str(),
        control_address = config.admin_listen_addr().to_string().as_str(),
    );
    tracing::info!(
        target: "tokenstream::process",
        event = "data_directory_resolved",
        message = "The process data directory is ready.",
        configured = config.data_dir().is_some(),
    );
    if config.uses_default_admin_password() {
        tracing::warn!(
            target: "tokenstream::process",
            event = "default_admin_password_enabled",
            message = "The documented default administrator password is enabled and should be changed.",
        );
    }
    let database = tokenstream::persistence::Database::connect_with_bounds(
        config.database_url().expose(),
        tokenstream::persistence::DatabaseBounds {
            max_connections: config.database_max_connections(),
            auth_connections: config.auth_database_connections(),
            acquire_timeout: tokenstream::persistence::DEFAULT_POOL_ACQUIRE_TIMEOUT,
            auth_timeout: config.auth_db_timeout(),
            admin_timeout: config.admin_db_timeout(),
            log_timeout: config.log_db_timeout(),
        },
    )
    .await
    .map_err(|_| {
        StartupFailure::new(
            StartupStage::DatabaseConnection,
            StartupErrorKind::StorageUnavailable,
        )
    })?;
    tokenstream::MigrationRunner::run(&database)
        .await
        .map_err(|_| {
            StartupFailure::new(StartupStage::Migration, StartupErrorKind::MigrationFailed)
        })?;
    let metrics = Metrics::default();
    let admission =
        AdmissionControl::with_metrics(ProxyLimits::from_config(&config), metrics.clone());
    let (events, log_worker) = tokenstream::logging::channel_with_metrics(
        std::sync::Arc::new(database.clone()),
        config.log_queue_capacity(),
        config.log_batch_size(),
        config.log_batch_interval(),
        metrics.clone(),
    );
    let data_password_work =
        tokenstream::crypto::PasswordWork::new(config.data_password_concurrency());
    let admin_password_work =
        tokenstream::crypto::PasswordWork::new(config.admin_password_concurrency());
    let cipher = SharedCipher::new(config.master_key().expose());
    let generated_password = std::env::var("TOKENSTREAM_ADMIN_PASSWORD").is_err()
        && !config.uses_default_admin_password();
    let bootstrap_password = match std::env::var("TOKENSTREAM_ADMIN_PASSWORD") {
        Ok(password) => password,
        Err(_) if config.uses_default_admin_password() => {
            tokenstream::local_state::DEFAULT_ADMIN_PASSWORD.to_owned()
        }
        Err(_) => tokenstream::local_state::generate_admin_password().map_err(|_| {
            StartupFailure::new(
                StartupStage::Bootstrap,
                StartupErrorKind::CredentialGenerationFailed,
            )
        })?,
    };
    let admin_api = AdminApi::new(
        database.clone(),
        cipher.clone(),
        Argon2GatewaySecretVerifier::new(),
        config.development_mode(),
        config.admin_password_hash().expose().to_owned(),
    )
    .with_runtime(&config, admin_password_work)
    .with_metrics(metrics.clone());
    admin_api.verify_assets().map_err(|_| {
        StartupFailure::new(
            StartupStage::AdministrationAssets,
            StartupErrorKind::AssetsUnavailable,
        )
    })?;
    if admin_api
        .ensure_bootstrap_account(config.bootstrap_account_name(), &bootstrap_password)
        .await
        .map_err(|_| {
            StartupFailure::new(
                StartupStage::Bootstrap,
                StartupErrorKind::AccountCreationFailed,
            )
        })?
    {
        tracing::info!(
            target: "tokenstream::process",
            event = "bootstrap_account_created",
            message = "The bootstrap administrator account was created.",
        );
        if generated_password {
            tokenstream::diagnostics::write_bootstrap_password(&bootstrap_password).map_err(
                |_| {
                    StartupFailure::new(
                        StartupStage::Bootstrap,
                        StartupErrorKind::CredentialDeliveryFailed,
                    )
                },
            )?;
            tracing::info!(
                target: "tokenstream::process",
                event = "bootstrap_credential_delivered",
                message = "The generated bootstrap credential was delivered on standard output.",
            );
        }
    }
    let gateway = Gateway::with_shared_cipher(
        &config,
        database.clone(),
        events.clone(),
        metrics.clone(),
        data_password_work,
        cipher,
    );
    let health = tokenstream::providers::health::HealthProber::new(
        database.clone(),
        config.upstream_connect_timeout(),
        metrics.clone(),
    );
    tokenstream::run_with_health(
        config.data_listen_addr(),
        config.admin_listen_addr(),
        tokenstream::RegisteredMigrations,
        gateway,
        admin_api,
        admission,
        metrics,
        tokenstream::wait_for_shutdown_signal(),
        config.shutdown_drain_timeout(),
        events,
        log_worker,
        config.log_flush_timeout(),
        health,
    )
    .await
    .map_err(|_| {
        StartupFailure::new(
            StartupStage::Runtime,
            StartupErrorKind::ListenerOrRuntimeFailed,
        )
    })?;
    Ok(())
}
