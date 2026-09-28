use tokenstream::admin::AdminApi;
use tokenstream::config::Config;
use tokenstream::crypto::{AesGcmCipher, Argon2GatewaySecretVerifier};
use tokenstream::persistence::Database;
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
    let database = Database::connect(
        config.database_url().expose(),
        config.database_max_connections(),
    )
    .await?;
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
    let admin_api = AdminApi::new(
        database.clone(),
        AesGcmCipher::new(config.master_key().expose()),
        Argon2GatewaySecretVerifier::new(),
        config.development_mode(),
        config.admin_password_hash().expose().to_owned(),
    );
    let gateway = Gateway::new(&config, database.clone(), log_sink.clone(), metrics.clone());
    tokenstream::run_with_control_and_logging(
        config.data_listen_addr(),
        config.admin_listen_addr(),
        database,
        gateway,
        admin_api,
        admission,
        metrics,
        tokio::signal::ctrl_c(),
        config.shutdown_drain_timeout(),
        log_sink,
        log_worker,
        config.log_flush_timeout(),
    )
    .await?;
    Ok(())
}
