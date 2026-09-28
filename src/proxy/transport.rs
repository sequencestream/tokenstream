//! Bounded socket reads and progress deadlines shared by both HTTP planes.
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

pub struct BoundedIo<S> {
    inner: S,
    chunk: usize,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
}
impl<S> BoundedIo<S> {
    pub fn new(inner: S, chunk: usize, idle: Duration) -> Self {
        Self {
            inner,
            chunk,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
        }
    }
    fn progress(&mut self) {
        self.deadline.as_mut().reset(Instant::now() + self.idle);
    }
    fn pending<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        if self.deadline.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
        } else {
            Poll::Pending
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for BoundedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let size = this.chunk.min(buf.remaining());
        let mut limited = ReadBuf::new(&mut buf.initialize_unfilled()[..size]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
            Poll::Pending => this.pending(cx),
            Poll::Ready(Ok(())) => {
                let size = limited.filled().len();
                buf.advance(size);
                if size > 0 {
                    this.progress();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for BoundedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, &buf[..buf.len().min(this.chunk)]) {
            Poll::Pending => this.pending(cx),
            Poll::Ready(Ok(size)) => {
                if size > 0 {
                    this.progress();
                }
                Poll::Ready(Ok(size))
            }
            result => result,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => this.pending(cx),
            result => result,
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => this.pending(cx),
            result => result,
        }
    }
}

#[derive(Clone)]
pub struct UpstreamConnector {
    inner: hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    timeout: Duration,
}
pub type UpstreamStream =
    hyper_rustls::MaybeHttpsStream<hyper_util::rt::TokioIo<tokio::net::TcpStream>>;
impl UpstreamConnector {
    pub fn new(timeout: Duration) -> Self {
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(timeout));
        http.set_nodelay(true);
        let inner = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("system TLS trust roots must be available")
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);
        Self { inner, timeout }
    }
}
impl tower_service::Service<hyper::Uri> for UpstreamConnector {
    type Response = UpstreamStream;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: hyper::Uri) -> Self::Future {
        let future = self.inner.call(uri);
        let deadline = self.timeout;
        Box::pin(async move {
            tokio::time::timeout(deadline, future)
                .await
                .map_err(|_| Box::new(io::Error::from(io::ErrorKind::TimedOut)) as Self::Error)?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn configured_chunks_and_idle_deadline_affect_actual_io() {
        for limit in [1024, 4096] {
            let (mut writer, reader) = tokio::io::duplex(16384);
            writer.write_all(&vec![7; 8192]).await.unwrap();
            let mut reader = BoundedIo::new(reader, limit, Duration::from_millis(20));
            let mut buffer = vec![0; 16384];
            let mut total = 0;
            while total < 8192 {
                let read = reader.read(&mut buffer).await.unwrap();
                assert_eq!(read, limit);
                assert!(buffer[..read].iter().all(|byte| *byte == 7));
                total += read;
            }
            assert_eq!(
                reader.read(&mut buffer).await.unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }
}
