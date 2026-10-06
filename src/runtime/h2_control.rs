use bytes::Bytes;
use std::{io, task::Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

pub(crate) async fn send_data(
    stream: &mut h2::SendStream<Bytes>,
    mut bytes: Bytes,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len());
        let capacity = futures::future::poll_fn(|cx| match stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(size))) => Poll::Ready(Ok(size)),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        })
        .await?;
        if capacity == 0 {
            continue;
        }
        let part = bytes.split_to(capacity.min(bytes.len()));
        stream.send_data(part, false).map_err(io::Error::other)?;
    }
    Ok(())
}

pub(crate) fn bridge(
    mut receive: h2::RecvStream,
    mut send: h2::SendStream<Bytes>,
) -> (DuplexStream, JoinHandle<io::Result<()>>) {
    let (application, transport) = tokio::io::duplex(64 * 1024);
    let (mut read, mut write) = tokio::io::split(transport);
    let task = tokio::task::spawn_local(async move {
        let incoming = async {
            while let Some(bytes) = receive.data().await {
                let bytes = bytes.map_err(io::Error::other)?;
                write.write_all(&bytes).await?;
                receive
                    .flow_control()
                    .release_capacity(bytes.len())
                    .map_err(io::Error::other)?;
            }
            write.shutdown().await
        };
        let outgoing = async {
            let mut buf = [0; 16 * 1024];
            loop {
                let n = read.read(&mut buf).await?;
                if n == 0 {
                    send.send_data(Bytes::new(), true)
                        .map_err(io::Error::other)?;
                    break;
                }
                send_data(&mut send, Bytes::copy_from_slice(&buf[..n])).await?;
            }
            Ok::<_, io::Error>(())
        };
        tokio::try_join!(incoming, outgoing)?;
        Ok(())
    });
    (application, task)
}
