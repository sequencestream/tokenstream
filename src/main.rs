use tokenstream::admin::AdminApi;
use tokenstream::config::Config;
use tokenstream::crypto::{Argon2GatewaySecretVerifier, SharedCipher};
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};
use tokenstream::proxy::gateway::Gateway;
use tokenstream::telemetry::Metrics;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Tokenstream failed to start: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let data_address = config.data_listen_addr();
    let control_address = config.admin_listen_addr();
    eprintln!(
        "Tokenstream starting data plane on http://{data_address} and control plane on http://{control_address}"
    );
    if let Some(data_dir) = config.data_dir() {
        eprintln!("Data directory {}", data_dir.display());
    }
    if config.uses_default_admin_password() {
        eprintln!(
            "Default administrator password is {}; change it from the administration page.",
            tokenstream::local_state::DEFAULT_ADMIN_PASSWORD
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
    .await?;
    // Migrations run before anything reads or writes a row. The bootstrap
    // account below depends on the tables this process is about to create, so
    // an upgrade and a fresh deployment follow the same path.
    tokenstream::MigrationRunner::run(&database).await?;
    let metrics = Metrics::default();
    let admission =
        AdmissionControl::with_metrics(ProxyLimits::from_config(&config), metrics.clone());
    let (log_sink, log_worker) = tokenstream::logging::channel_with_metrics(
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
    // The bootstrap account is created from the password this process was
    // configured with. The plaintext is resolved once, here, and is never
    // persisted: it comes from the environment when the operator supplied one,
    // and otherwise from the documented default when the configured hash is
    // still that default's. A hash whose plaintext is genuinely unknown — a
    // hash supplied directly — gets a generated password shown once, because a
    // hash cannot be reversed and a guessed password would be worse.
    let bootstrap_password = match std::env::var("TOKENSTREAM_ADMIN_PASSWORD") {
        Ok(password) => password,
        Err(_) if config.uses_default_admin_password() => {
            tokenstream::local_state::DEFAULT_ADMIN_PASSWORD.to_owned()
        }
        Err(_) => tokenstream::local_state::generate_admin_password()?,
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
    // The compiled page is confirmed before either listener binds, so a
    // deployment never comes up claiming to serve a page it cannot serve.
    admin_api.verify_assets()?;
    // The first account is created from the configured administrator
    // credentials before the control plane starts serving, so a fresh
    // deployment can sign in immediately and an upgraded one adopts the
    // credentials it already has without operator action.
    if admin_api
        .ensure_bootstrap_account(config.bootstrap_account_name(), &bootstrap_password)
        .await?
    {
        eprintln!(
            "Created bootstrap account {}; change its password from the administration page.",
            config.bootstrap_account_name()
        );
        if !config.uses_default_admin_password()
            && std::env::var("TOKENSTREAM_ADMIN_PASSWORD").is_err()
        {
            eprintln!("Bootstrap account password: {bootstrap_password}");
        }
    }
    let gateway = Gateway::with_shared_cipher(
        &config,
        database.clone(),
        log_sink.clone(),
        metrics.clone(),
        data_password_work,
        cipher,
    );
    tokenstream::run_with_control_and_logging(
        config.data_listen_addr(),
        config.admin_listen_addr(),
        tokenstream::RegisteredMigrations,
        gateway,
        admin_api,
        admission,
        metrics,
        tokenstream::wait_for_shutdown_signal(),
        config.shutdown_drain_timeout(),
        log_sink,
        log_worker,
        config.log_flush_timeout(),
    )
    .await?;
    Ok(())
}
