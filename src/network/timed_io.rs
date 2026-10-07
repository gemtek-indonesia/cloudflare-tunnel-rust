use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub(crate) struct TimedIo<T> {
    inner: T,
    timeout: Duration,
    pending: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl<T> TimedIo<T> {
    pub(crate) fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            pending: None,
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for TimedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for TimedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if result.is_ready() {
            self.pending = None;
            return result;
        }
        if !self.timeout.is_zero() {
            let timeout = self.timeout;
            let sleep = self
                .pending
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
            if std::future::Future::poll(sleep.as_mut(), cx).is_ready() {
                self.pending = None;
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }
        }
        Poll::Pending
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
