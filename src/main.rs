use tokenstream::RejectAll;
use tokenstream::config::Config;
use tokenstream::persistence::sqlite::SqliteDatabase;

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
    if !config.database_url().expose().starts_with("sqlite:") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "configured database backend is not available",
        )
        .into());
    }
    let database = SqliteDatabase::connect(
        config.database_url().expose(),
        config.database_max_connections(),
    )
    .await?;
    eprintln!(
        "Tokenstream starting data plane on http://{data_address} and control plane on http://{control_address}"
    );
    tokenstream::run(
        data_address,
        control_address,
        database,
        RejectAll,
        RejectAll,
        tokio::signal::ctrl_c(),
        config.shutdown_drain_timeout(),
    )
    .await?;
    Ok(())
}
