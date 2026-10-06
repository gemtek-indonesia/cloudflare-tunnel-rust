use super::quic_metadata_protocol_capnp as wire;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DATA_SIGNATURE: [u8; 6] = [0x0a, 0x36, 0xcd, 0x12, 0xa1, 0x3e];
pub const RPC_SIGNATURE: [u8; 6] = [0x52, 0xbb, 0x82, 0x5c, 0xdb, 0x65];
pub const VERSION: [u8; 2] = *b"01";
pub const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Data,
    Rpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Http,
    Websocket,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub destination: String,
    pub connection_type: ConnectionType,
    pub metadata: Vec<(String, String)>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResponse {
    pub error: String,
    pub metadata: Vec<(String, String)>,
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub async fn read_stream_kind<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<StreamKind> {
    let mut signature = [0; 6];
    reader.read_exact(&mut signature).await?;
    match signature {
        DATA_SIGNATURE => Ok(StreamKind::Data),
        RPC_SIGNATURE => Ok(StreamKind::Rpc),
        _ => Err(invalid("unknown QUIC stream signature")),
    }
}

// Read exactly one ordinary Cap'n Proto message; do not buffer trailing body bytes.
async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; 4];
    reader.read_exact(&mut bytes).await?;
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap())
        .checked_add(1)
        .ok_or_else(|| invalid("segment count overflow"))? as usize;
    if count > 512 {
        return Err(invalid("too many Cap'n Proto segments"));
    }
    let table_len = (count + 2) & !1;
    bytes.resize(table_len * 4, 0);
    reader.read_exact(&mut bytes[4..]).await?;
    let mut body_len = 0usize;
    for segment in 0..count {
        let offset = 4 + segment * 4;
        let words = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        body_len = body_len
            .checked_add(
                words
                    .checked_mul(8)
                    .ok_or_else(|| invalid("segment size overflow"))?,
            )
            .ok_or_else(|| invalid("message size overflow"))?;
    }
    if body_len > MAX_METADATA_BYTES {
        return Err(invalid("metadata exceeds limit"));
    }
    let table_size = bytes.len();
    bytes.resize(table_size + body_len, 0);
    reader.read_exact(&mut bytes[table_size..]).await?;
    Ok(bytes)
}

fn read_pairs(
    reader: capnp::struct_list::Reader<'_, wire::metadata::Owned>,
) -> io::Result<Vec<(String, String)>> {
    reader
        .iter()
        .map(|m| {
            Ok((
                m.get_key()
                    .map_err(invalid)?
                    .to_str()
                    .map_err(invalid)?
                    .into(),
                m.get_val()
                    .map_err(invalid)?
                    .to_str()
                    .map_err(invalid)?
                    .into(),
            ))
        })
        .collect()
}

fn set_pairs(
    mut list: capnp::struct_list::Builder<'_, wire::metadata::Owned>,
    pairs: &[(String, String)],
) {
    for (i, (key, value)) in pairs.iter().enumerate() {
        let mut item = list.reborrow().get(i as u32);
        item.set_key(key);
        item.set_val(value);
    }
}

pub async fn read_connect_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<ConnectRequest> {
    let mut version = [0; 2];
    reader.read_exact(&mut version).await?;
    // cloudflared accepts any two version bytes; retain that receive behavior.
    let bytes = read_message(reader).await?;
    let msg = capnp::serialize::read_message(&mut bytes.as_slice(), super::reader_options())
        .map_err(invalid)?;
    let root = msg
        .get_root::<wire::connect_request::Reader>()
        .map_err(invalid)?;
    let connection_type = match root.get_type().map_err(invalid)? {
        wire::ConnectionType::Http => ConnectionType::Http,
        wire::ConnectionType::Websocket => ConnectionType::Websocket,
        wire::ConnectionType::Tcp => ConnectionType::Tcp,
    };
    Ok(ConnectRequest {
        destination: root
            .get_dest()
            .map_err(invalid)?
            .to_str()
            .map_err(invalid)?
            .into(),
        connection_type,
        metadata: read_pairs(root.get_metadata().map_err(invalid)?)?,
    })
}

pub async fn write_connect_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request: &ConnectRequest,
) -> io::Result<()> {
    let bytes = {
        let mut msg = capnp::message::Builder::new_default();
        let mut root = msg.init_root::<wire::connect_request::Builder>();
        root.set_dest(&request.destination);
        root.set_type(match request.connection_type {
            ConnectionType::Http => wire::ConnectionType::Http,
            ConnectionType::Websocket => wire::ConnectionType::Websocket,
            ConnectionType::Tcp => wire::ConnectionType::Tcp,
        });
        set_pairs(
            root.init_metadata(request.metadata.len().try_into().map_err(invalid)?),
            &request.metadata,
        );
        message_bytes(&msg)?
    };
    write_data_message(writer, &bytes).await
}

fn message_bytes(
    msg: &capnp::message::Builder<capnp::message::HeapAllocator>,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, msg).map_err(invalid)?;
    Ok(bytes)
}
async fn write_data_message<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(&DATA_SIGNATURE).await?;
    writer.write_all(&VERSION).await?;
    writer.write_all(bytes).await?;
    writer.flush().await
}

pub async fn write_connect_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &ConnectResponse,
) -> io::Result<()> {
    let bytes = {
        let mut msg = capnp::message::Builder::new_default();
        let mut root = msg.init_root::<wire::connect_response::Builder>();
        root.set_error(&response.error);
        set_pairs(
            root.init_metadata(response.metadata.len().try_into().map_err(invalid)?),
            &response.metadata,
        );
        message_bytes(&msg)?
    };
    write_data_message(writer, &bytes).await
}

pub async fn read_connect_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<ConnectResponse> {
    if read_stream_kind(reader).await? != StreamKind::Data {
        return Err(invalid("expected data response"));
    }
    let mut version = [0; 2];
    reader.read_exact(&mut version).await?;
    let bytes = read_message(reader).await?;
    let msg = capnp::serialize::read_message(&mut bytes.as_slice(), super::reader_options())
        .map_err(invalid)?;
    let root = msg
        .get_root::<wire::connect_response::Reader>()
        .map_err(invalid)?;
    Ok(ConnectResponse {
        error: root
            .get_error()
            .map_err(invalid)?
            .to_str()
            .map_err(invalid)?
            .into(),
        metadata: read_pairs(root.get_metadata().map_err(invalid)?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn fragmented_metadata_preserves_body() {
        let (mut tx, mut rx) = tokio::io::duplex(1);
        let request = ConnectRequest {
            destination: "https://example.invalid/a".into(),
            connection_type: ConnectionType::Http,
            metadata: vec![
                ("HttpMethod".into(), "POST".into()),
                ("HttpHeader:X-Test".into(), "value".into()),
            ],
        };
        let sent = request.clone();
        let task = tokio::spawn(async move {
            write_connect_request(&mut tx, &sent).await.unwrap();
            tx.write_all(b"body").await.unwrap();
        });
        assert_eq!(read_stream_kind(&mut rx).await.unwrap(), StreamKind::Data);
        assert_eq!(read_connect_request(&mut rx).await.unwrap(), request);
        let mut body = [0; 4];
        rx.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"body");
        task.await.unwrap();
    }
}
