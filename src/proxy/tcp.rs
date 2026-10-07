use super::{BoxReader, EdgeSink, Origin, ProxyState, RequestHead, Service};
use anyhow::{Context, Result, bail};
use http::{HeaderMap, HeaderValue};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{handshake::derive_accept_key, protocol::Role},
};

#[derive(Clone, Deserialize)]
pub(super) struct Rule {
    prefix: ipnet::IpNet,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    allow: bool,
}
struct StreamTask(tokio::task::JoinHandle<Result<()>>);
impl Drop for StreamTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(super) fn rules(values: &[serde_json::Value]) -> Result<Vec<Rule>> {
    values
        .iter()
        .map(|value| {
            let rule: Rule = serde_json::from_value(value.clone())
                .map_err(|_| anyhow::anyhow!("invalid ingress IP rule"))?;
            if rule.ports.contains(&0) {
                bail!("invalid ingress IP rule port");
            }
            Ok(rule)
        })
        .collect()
}
fn allowed(rules: &[Rule], destination: SocketAddr) -> bool {
    rules
        .iter()
        .find(|rule| {
            rule.prefix.contains(&destination.ip())
                && (rule.ports.is_empty() || rule.ports.contains(&destination.port()))
        })
        .is_some_and(|rule| rule.allow)
}
async fn dial(destination: &str, settings: &crate::config::OriginRequest) -> Result<TcpStream> {
    let timeout = settings
        .connect_timeout
        .map_or(Duration::from_secs(30), |duration| duration.0);
    let dial = TcpStream::connect(destination);
    let socket = if timeout.is_zero() {
        dial.await
    } else {
        tokio::time::timeout(timeout, dial).await?
    }
    .context("Unable to establish TCP origin connection")?;
    socket.set_nodelay(true)?;
    let keepalive = settings
        .tcp_keep_alive
        .map_or(Duration::from_secs(30), |duration| duration.0);
    let keepalive = if keepalive.is_zero() {
        Duration::from_secs(15)
    } else {
        keepalive
    };
    socket2::SockRef::from(&socket)
        .set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(keepalive))?;
    Ok(socket)
}
pub(super) async fn proxy(
    origin: Arc<Origin>,
    head: RequestHead,
    mut reader: BoxReader,
    sink: &mut EdgeSink,
    state: &ProxyState,
) -> Result<()> {
    let started = Instant::now();
    let (socket, socks, policy) = match &origin.service {
        Service::Tcp { destination, socks } => (
            Some(dial(destination, &origin.settings).await?),
            *socks,
            None,
        ),
        Service::Bastion { socks } => {
            let destination = head
                .headers
                .get("cf-access-jump-destination")
                .and_then(|value| value.to_str().ok())
                .context("Did not receive final destination from client")?;
            let destination = if let Ok(url) = url::Url::parse(destination) {
                url[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
            } else {
                destination.split('/').next().unwrap_or("").into()
            };
            if destination.is_empty() {
                bail!("invalid bastion destination");
            }
            (
                Some(dial(&destination, &origin.settings).await?),
                *socks,
                None,
            )
        }
        Service::Socks(rules) => (None, true, Some(rules.clone())),
        _ => bail!("origin is not a TCP stream"),
    };
    let mut headers = HeaderMap::new();
    if let Some(key) = head
        .headers
        .get("sec-websocket-key")
        .and_then(|value| value.to_str().ok())
        .filter(|key| !key.is_empty())
    {
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
        headers.insert(
            "sec-websocket-accept",
            HeaderValue::from_str(&derive_accept_key(key.as_bytes()))?,
        );
    }
    sink.head(101, &headers).await?;
    state.observability.metrics.response(101);
    state
        .observability
        .metrics
        .connect_latency
        .observe(started.elapsed().as_millis() as f64);
    let _tcp = state.observability.metrics.begin_tcp();
    let (edge, worker) = tokio::io::duplex(16 * 1024);
    let settings = origin.settings.clone();
    let task = tokio::spawn(async move {
        let websocket = WebSocketStream::from_raw_socket(worker, Role::Server, None).await;
        if socks {
            let (bridge, mut plaintext) = tokio::io::duplex(16 * 1024);
            let (read, write) = tokio::io::split(bridge);
            let websocket_task = StreamTask(tokio::spawn(async move {
                crate::access::forward::pipe(websocket, read, write).await
            }));
            let result = socks_connect(&mut plaintext, socket, policy.as_deref(), &settings).await;
            drop(plaintext);
            drop(websocket_task);
            result
        } else {
            let (read, write) = socket.context("TCP origin socket missing")?.into_split();
            crate::access::forward::pipe(websocket, read, write).await
        }
    });
    let guard = StreamTask(task);
    let (mut edge_read, mut edge_write) = tokio::io::split(edge);
    let upload = async {
        tokio::io::copy(&mut reader, &mut edge_write).await?;
        edge_write.shutdown().await
    };
    let download = super::copy_response(&mut edge_read, sink);
    let result = tokio::select! {result=upload=>result,result=download=>result};
    drop(guard);
    result?;
    Ok(())
}
async fn reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u8,
    address: Option<SocketAddr>,
) -> Result<()> {
    let address = address.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    let mut bytes = vec![5, status, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend(ip.octets());
        }
    }
    bytes.extend(address.port().to_be_bytes());
    stream.write_all(&bytes).await?;
    Ok(())
}
async fn socks_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    fixed: Option<TcpStream>,
    policy: Option<&[Rule]>,
    settings: &crate::config::OriginRequest,
) -> Result<()> {
    if stream.read_u8().await? != 5 {
        bail!("unsupported SOCKS version");
    }
    let count = stream.read_u8().await? as usize;
    let mut methods = vec![0; count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255]).await?;
        bail!("SOCKS no-auth method not offered");
    }
    stream.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 {
        bail!("unsupported SOCKS request version");
    }
    let host = match header[3] {
        1 => {
            let mut address = [0; 4];
            stream.read_exact(&mut address).await?;
            std::net::Ipv4Addr::from(address).to_string()
        }
        4 => {
            let mut address = [0; 16];
            stream.read_exact(&mut address).await?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            let mut name = vec![0; length];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).context("invalid SOCKS hostname")?
        }
        _ => {
            reply(stream, 8, None).await?;
            bail!("unsupported SOCKS address type");
        }
    };
    let port = stream.read_u16().await?;
    if header[1] != 1 {
        reply(stream, 7, None).await?;
        return Ok(());
    }
    let socket = if let Some(socket) = fixed {
        socket
    } else {
        let destination = tokio::net::lookup_host((host.as_str(), port))
            .await?
            .next()
            .context("SOCKS destination did not resolve")?;
        if policy.is_some_and(|rules| !allowed(rules, destination)) {
            reply(stream, 2, Some(destination)).await?;
            return Ok(());
        }
        match dial(&destination.to_string(), settings).await {
            Ok(socket) => socket,
            Err(_) => {
                reply(stream, 4, None).await?;
                return Ok(());
            }
        }
    };
    reply(stream, 0, Some(socket.local_addr()?)).await?;
    let mut socket = socket;
    tokio::io::copy_bidirectional(stream, &mut socket).await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn socks_ordered_policy_and_connect_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            socket.write_all(b"pong").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let rules = rules(&[
            serde_json::json!({"prefix":"127.0.0.0/8","ports":[address.port()],"allow":true}),
            serde_json::json!({"prefix":"0.0.0.0/0","allow":false}),
        ])
        .unwrap();
        assert!(allowed(&rules, address));
        assert!(!allowed(&rules, "192.0.2.1:443".parse().unwrap()));
        let (mut client, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            socks_connect(&mut server, None, Some(&rules), &Default::default()).await
        });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut negotiation = [0; 2];
        client.read_exact(&mut negotiation).await.unwrap();
        assert_eq!(negotiation, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut response = [0; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0);
        client.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        origin.await.unwrap();
    }
}
