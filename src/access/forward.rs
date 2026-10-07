use super::{ApplicationUrl, application_url, open_browser, token::TokenClient};
use anyhow::{Context, Result, bail};
use futures::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Error, Message, client::IntoClientRequest},
};

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type Socket = Pin<Box<dyn Io>>;
pub(crate) type WebSocket = WebSocketStream<Socket>;

pub(super) struct Options {
    app: ApplicationUrl,
    endpoint: ApplicationUrl,
    sni: Option<String>,
    headers: HeaderMap,
    client: tokio::sync::OnceCell<TokenClient>,
    directory: std::path::PathBuf,
    fedramp: bool,
    auto_close: bool,
}
impl Options {
    fn new(invocation: &crate::cli::Invocation) -> Result<Self> {
        let app = application_url(invocation.string("hostname"))?;
        let mut endpoint = app.clone();
        let mut sni = None;
        if !invocation.string("connect-to").is_empty() {
            let parts: Vec<_> = invocation.string("connect-to").split(':').collect();
            endpoint = match parts.as_slice() {
                [host] => application_url(host)?,
                [host, port] => application_url(&format!("{host}:{port}"))?,
                [name, port, host] => {
                    sni = Some((*name).into());
                    eprintln!("Using insecure SSL connection because SNI was overridden");
                    application_url(&format!("{host}:{port}"))?
                }
                _ => bail!("invalid connection override"),
            };
        }
        let mut headers = HeaderMap::new();
        for header in invocation.list("header") {
            if let Some((name, value)) = header.split_once(':') {
                headers.append(
                    HeaderName::from_bytes(name.trim().as_bytes())?,
                    HeaderValue::from_str(value.trim())?,
                );
            }
        }
        for (flag, name) in [
            ("service-token-id", "cf-access-client-id"),
            ("service-token-secret", "cf-access-client-secret"),
            ("destination", "cf-access-jump-destination"),
        ] {
            if !invocation.string(flag).is_empty() {
                headers.insert(name, HeaderValue::from_str(invocation.string(flag))?);
            }
        }
        headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_str(&format!("cloudflared/{}", crate::config::UPSTREAM_VERSION))?,
        );
        Ok(Self {
            app,
            endpoint,
            sni,
            headers,
            client: tokio::sync::OnceCell::new(),
            directory: TokenClient::default_directory()?,
            fedramp: invocation.bool("fedramp"),
            auto_close: invocation.bool("auto-close"),
        })
    }
    pub(super) fn from_forwarder(
        forwarder: &super::watcher::Forwarder,
        directory: &std::path::Path,
    ) -> Result<Self> {
        // Configured forwarders pass their URL directly to the carrier, without CLI HTTPS upgrading.
        let app = ApplicationUrl::remote(&forwarder.url)?;
        let mut headers = HeaderMap::new();
        for (value, name) in [
            (&forwarder.token_client_id, "cf-access-client-id"),
            (&forwarder.token_secret, "cf-access-client-secret"),
            (&forwarder.destination, "cf-access-jump-destination"),
        ] {
            if !value.is_empty() {
                headers.insert(name, HeaderValue::from_str(value)?);
            }
        }
        headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_str(&format!("cloudflared/{}", crate::config::UPSTREAM_VERSION))?,
        );
        Ok(Self {
            endpoint: app.clone(),
            app,
            sni: None,
            headers,
            client: tokio::sync::OnceCell::new(),
            directory: directory.to_owned(),
            fedramp: forwarder.is_fedramp,
            auto_close: false,
        })
    }
    async fn dial(&self, token: Option<&str>) -> std::result::Result<WebSocket, Error> {
        let mut target = self
            .endpoint
            .request_uri()
            .map_err(|_| Error::Io(std::io::Error::other("invalid Access WebSocket URL")))?
            .into_parts();
        target.scheme = Some(match self.endpoint.scheme() {
            "https" | "wss" => "wss".parse().expect("static WebSocket scheme"),
            "http" | "ws" => "ws".parse().expect("static WebSocket scheme"),
            _ => {
                return Err(Error::Url(
                    tokio_tungstenite::tungstenite::error::UrlError::UnsupportedUrlScheme,
                ));
            }
        });
        let target = http::Uri::from_parts(target)
            .map_err(|_| Error::Io(std::io::Error::other("invalid Access WebSocket URI")))?;
        let mut request = target.into_client_request()?;
        for (name, value) in &self.headers {
            if ![
                "upgrade",
                "connection",
                "sec-websocket-key",
                "sec-websocket-version",
                "sec-websocket-extensions",
            ]
            .contains(&name.as_str())
            {
                request.headers_mut().append(name, value.clone());
            }
        }
        let authority = self.app.host().to_owned();
        self.app
            .basic_auth(request.headers_mut())
            .map_err(|_| Error::Io(std::io::Error::other("invalid Access authorization header")))?;
        request.headers_mut().insert(
            http::header::HOST,
            HeaderValue::from_str(&authority)
                .map_err(|error| Error::Io(std::io::Error::other(error)))?,
        );
        if let Some(token) = token {
            request.headers_mut().insert(
                "cf-access-token",
                HeaderValue::from_str(token)
                    .map_err(|error| Error::Io(std::io::Error::other(error)))?,
            );
        }
        let socket = dial_socket(&self.endpoint, self.sni.as_deref())
            .await
            .map_err(|_| {
                Error::Io(std::io::Error::other(
                    "Access connection or TLS handshake failed",
                ))
            })?;
        tokio::time::timeout(
            Duration::from_secs(45),
            tokio_tungstenite::client_async(request, socket),
        )
        .await
        .map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Access WebSocket handshake timed out",
            ))
        })?
        .map(|(socket, _)| socket)
    }
    pub(super) async fn connect(&self) -> Result<WebSocket> {
        match self.dial(None).await {
            Ok(socket) => return Ok(socket),
            Err(error) if is_login(&error) => {}
            Err(_) => bail!("Access WebSocket handshake failed"),
        }
        let client = self
            .client
            .get_or_try_init(|| async { TokenClient::new(self.directory.clone(), self.fedramp) })
            .await?;
        let info = client.discover(&self.app).await?;
        for _ in 0..2 {
            let token = client
                .fetch(&self.app, &info, false, self.auto_close, open_browser)
                .await?;
            match self.dial(Some(&token)).await {
                Ok(socket) => return Ok(socket),
                Err(error) if is_login(&error) => client.invalidate(&info, &token).await?,
                Err(_) => bail!("authenticated Access WebSocket handshake failed"),
            }
        }
        bail!("Access token rejected by application")
    }
}
fn is_login(error: &Error) -> bool {
    match error {
        Error::Http(response) if response.status() == 302 => response
            .headers()
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|location| location.contains("/cdn-cgi/access/login")),
        _ => false,
    }
}

pub(crate) async fn dial_socket(
    endpoint: &ApplicationUrl,
    insecure_sni: Option<&str>,
) -> Result<Socket> {
    let host = endpoint.hostname();
    let port = endpoint.port()?;
    let socket = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .context("Access connection timeout")??;
    socket.set_nodelay(true)?;
    if endpoint.scheme() == "http" || endpoint.scheme() == "ws" {
        return Ok(Box::pin(socket));
    }
    let mut connector = crate::administration::verified_tls_connector()?;
    if insecure_sni.is_some() {
        connector.set_verify(boring::ssl::SslVerifyMode::NONE);
    }
    let connector = connector.build();
    let mut config = connector.configure()?;
    config.set_verify_hostname(insecure_sni.is_none());
    let mut ssl = config.into_ssl(insecure_sni.unwrap_or(host))?;
    crate::crypto::configure_platform_trust(&mut ssl)?;
    let socket = tokio::time::timeout(
        Duration::from_secs(30),
        tokio_boring::SslStreamBuilder::new(ssl, socket).connect(),
    )
    .await
    .context("Access TLS handshake timeout")?
    .map_err(|_| anyhow::anyhow!("Access TLS verification or handshake failed"))?;
    Ok(Box::pin(socket))
}

pub(crate) async fn pipe<S, R, W>(
    socket: WebSocketStream<S>,
    mut reader: R,
    mut writer: W,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = socket.split();
    let result = {
        let upload = async {
            let mut buffer = [0; 16 * 1024];
            loop {
                let count = reader.read(&mut buffer).await?;
                if count == 0 {
                    let _ = sink.close().await;
                    return Ok::<_, anyhow::Error>(());
                }
                sink.send(Message::Binary(bytes::Bytes::copy_from_slice(
                    &buffer[..count],
                )))
                .await?;
            }
        };
        let download = async {
            while let Some(message) = stream.next().await {
                match message {
                    Ok(Message::Binary(bytes)) => writer.write_all(&bytes).await?,
                    Ok(Message::Text(text)) => writer.write_all(text.as_bytes()).await?,
                    Ok(Message::Ping(_) | Message::Pong(_)) => {}
                    Ok(Message::Close(_)) | Err(Error::ConnectionClosed | Error::AlreadyClosed) => {
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => bail!("Access WebSocket stream failed"),
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! {result=upload=>result,result=download=>result}
    };
    writer.shutdown().await?;
    result
}

pub async fn execute(invocation: crate::cli::Invocation) -> Result<()> {
    if invocation.is_set("debug-stream") {
        bail!("--debug-stream is not implemented");
    }
    let options = Arc::new(Options::new(&invocation)?);
    let listener = invocation
        .args
        .first()
        .map_or(invocation.string("url"), String::as_str);
    if listener.is_empty() {
        return pipe(
            options.connect().await?,
            tokio::io::stdin(),
            tokio::io::stdout(),
        )
        .await;
    }
    let address = super::watcher::listener_address(listener)?;
    let listener = super::watcher::bind_listener(&address)
        .await
        .context("cannot bind Access listener")?;
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let options = options.clone();
                tasks.spawn(async move {
                    let websocket = options.connect().await?;
                    let (reader, writer) = socket.into_split();
                    pipe(websocket, reader, writer).await
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if matches!(result, Some(Err(_) | Ok(Err(_)))) {
                    eprintln!("Access client connection failed");
                }
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stalled_websocket_sink_does_not_block_reverse_direction() {
        let (socket, peer) = tokio::io::duplex(64);
        let websocket = WebSocketStream::from_raw_socket(
            socket,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        let mut peer = WebSocketStream::from_raw_socket(
            peer,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        let (local, application) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(local);
        let bridge = tokio::spawn(pipe(websocket, reader, writer));
        let (mut receive, mut send) = tokio::io::split(application);
        let sending = tokio::spawn(async move { send.write_all(&vec![7; 64 * 1024]).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!sending.is_finished());
        peer.send(Message::Binary(bytes::Bytes::from_static(b"reverse")))
            .await
            .unwrap();
        let mut response = [0; 7];
        tokio::time::timeout(Duration::from_secs(2), receive.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"reverse");
        bridge.abort();
        sending.abort();
        let _ = bridge.await;
        let _ = sending.await;
    }

    #[tokio::test]
    async fn binary_text_ping_and_close_streaming() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let data = ws.next().await.unwrap().unwrap();
            assert_eq!(data.into_data(), b"hello".as_slice());
            ws.send(Message::Ping(bytes::Bytes::from_static(b"ping")))
                .await
                .unwrap();
            ws.send(Message::Text("world".into())).await.unwrap();
            assert!(matches!(
                ws.next().await.unwrap().unwrap(),
                Message::Pong(_)
            ));
            ws.close(None).await.unwrap();
        });
        let endpoint = ApplicationUrl::remote(&format!("http://{address}/")).unwrap();
        let stream = dial_socket(&endpoint, None).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async(format!("ws://{address}/"), stream)
            .await
            .unwrap();
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let bridge = tokio::spawn(pipe(ws, reader, writer));
        peer.write_all(b"hello").await.unwrap();
        let mut response = [0; 5];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");
        tokio::time::timeout(Duration::from_secs(2), bridge)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server.await.unwrap();
    }
}
