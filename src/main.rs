use tokenstream::config::Config;
use tokenstream::serve;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Tokenstream failed to start: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let address = config.data_listen_addr();
    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!("Tokenstream scaffold listening on http://{address}");
    serve(listener, tokio::signal::ctrl_c()).await?;
    Ok(())
}
