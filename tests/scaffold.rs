use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn health_is_available_without_exposing_future_routes() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(tokenstream::serve(listener, std::future::pending()));

    async fn get(address: std::net::SocketAddr, path: &str) -> io::Result<String> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(response)
    }

    let health = get(address, "/healthz").await?;
    assert!(health.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(health.ends_with("\r\n\r\nok\n"));

    let future_route = get(address, "/v1/responses").await?;
    assert!(future_route.starts_with("HTTP/1.1 404 Not Found\r\n"));

    server.abort();
    Ok(())
}
