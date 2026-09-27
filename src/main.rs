use std::io;

use tokenstream::MigrationRunner;
use tokenstream::RejectAll;
use tokenstream::config::Config;
use tokenstream::persistence::postgres::PostgresDatabase;
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
    eprintln!(
        "Tokenstream starting data plane on http://{data_address} and control plane on http://{control_address}"
    );
    let database_url = config.database_url().expose();
    if database_url.starts_with("sqlite:") {
        let database =
            SqliteDatabase::connect(database_url, config.database_max_connections()).await?;
        run_with_database(&config, database).await?;
    } else {
        let database =
            PostgresDatabase::connect(database_url, config.database_max_connections()).await?;
        run_with_database(&config, database).await?;
    }
    Ok(())
}

async fn run_with_database<M>(config: &Config, database: M) -> io::Result<()>
where
    M: MigrationRunner,
{
    tokenstream::run(
        config.data_listen_addr(),
        config.admin_listen_addr(),
        database,
        RejectAll,
        RejectAll,
        tokio::signal::ctrl_c(),
        config.shutdown_drain_timeout(),
    )
    .await?;
    Ok(())
}
