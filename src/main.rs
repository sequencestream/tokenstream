use tokenstream::RejectAll;
use tokenstream::config::Config;
use tokenstream::persistence::Database;
use tokenstream::proxy::admission::{AdmissionControl, ProxyLimits};

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
    let admission = AdmissionControl::new(ProxyLimits::from_config(&config));
    tokenstream::run(
        config.data_listen_addr(),
        config.admin_listen_addr(),
        database,
        RejectAll,
        RejectAll,
        admission,
        tokio::signal::ctrl_c(),
        config.shutdown_drain_timeout(),
    )
    .await?;
    Ok(())
}
