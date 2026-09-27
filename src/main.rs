use std::net::SocketAddr;

use tokenstream::serve;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address: SocketAddr = "127.0.0.1:3000".parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!("Tokenstream scaffold listening on http://{address}");
    serve(listener, tokio::signal::ctrl_c()).await?;
    Ok(())
}
