use bytes::{Buf, Bytes};
use hyper::body::{Body, Frame, SizeHint};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, ReadBuf},
    sync::mpsc,
    task::JoinHandle,
};

pub struct ChannelBody {
    receiver: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>,
    remaining: Option<u64>,
}

impl ChannelBody {
    pub fn empty() -> Self {
        let (_, receiver) = mpsc::channel(1);
        Self {
            receiver,
            remaining: Some(0),
        }
    }

    pub fn reader<R: AsyncRead + Unpin + Send + 'static>(
        mut reader: R,
        length: Option<u64>,
    ) -> (Self, AbortTask) {
        let (sender, receiver) = mpsc::channel(4);
        let task = tokio::spawn(async move {
            let mut remaining = length.unwrap_or(u64::MAX);
            while remaining > 0 {
                let mut data = vec![0; remaining.min(16 * 1024) as usize];
                match reader.read(&mut data).await {
                    Ok(0) => {
                        if length.is_some() {
                            let _ = sender
                                .send(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "request body shorter than Content-Length",
                                )))
                                .await;
                        }
                        break;
                    }
                    Ok(count) => {
                        data.truncate(count);
                        remaining -= count as u64;
                        if sender
                            .send(Ok(Frame::data(Bytes::from(data))))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        break;
                    }
                }
            }
        });
        (
            Self {
                receiver,
                remaining: length,
            },
            AbortTask(task),
        )
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && let Some(remaining) = &mut self.remaining
                {
                    *remaining = remaining.saturating_sub(data.len() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.remaining == Some(0) || (self.receiver.is_closed() && self.receiver.is_empty())
    }
    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        if let Some(remaining) = self.remaining {
            hint.set_exact(remaining);
        }
        hint
    }
}

pub struct AbortTask(pub JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct H2Reader {
    pub stream: h2::RecvStream,
    buffer: Bytes,
}
impl H2Reader {
    pub fn new(stream: h2::RecvStream) -> Self {
        Self {
            stream,
            buffer: Bytes::new(),
        }
    }
}
impl AsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while self.buffer.is_empty() {
            match std::task::ready!(self.stream.poll_data(cx)) {
                Some(Ok(data)) => self.buffer = data,
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => return Poll::Ready(Ok(())),
            }
        }
        let count = out.remaining().min(self.buffer.len());
        out.put_slice(&self.buffer[..count]);
        self.buffer.advance(count);
        self.stream
            .flow_control()
            .release_capacity(count)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}
