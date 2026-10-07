use super::{EnvironmentProxy, Proxy, transport};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use boring::ssl::{SslConnector, SslRef};
use http::{HeaderValue, Uri};
use hyper::body::{Body, Incoming};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection as ConnectedIo, HttpConnector, proxy::SocksV5},
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_service::Service;

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type Socket = Box<dyn Io>;

#[derive(Clone)]
enum Settings {
    Native,
    Fixed(Arc<EnvironmentProxy>),
}
impl Settings {
    fn get(&self) -> &EnvironmentProxy {
        match self {
            Self::Native => EnvironmentProxy::current(),
            Self::Fixed(settings) => settings,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Http,
    Http1,
    Carrier,
}

#[derive(Clone)]
struct Network {
    http: HttpConnector,
    unix: Option<(std::path::PathBuf, Option<std::time::Duration>)>,
}
impl Service<Uri> for Network {
    type Response = TokioIo<Connection>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;
    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut network = self.clone();
        Box::pin(async move {
            let socket: Socket = if let Some((path, timeout)) = network.unix {
                let connect = tokio::net::UnixStream::connect(path);
                Box::new(if let Some(timeout) = timeout {
                    tokio::time::timeout(timeout, connect).await??
                } else {
                    connect.await?
                })
            } else {
                Box::new(
                    network
                        .http
                        .call(uri)
                        .await
                        .map_err(io::Error::other)?
                        .into_inner(),
                )
            };
            Ok(TokioIo::new(Connection {
                socket,
                proxied: false,
                h2: false,
            }))
        })
    }
}

#[derive(Clone)]
pub struct Connector {
    settings: Settings,
    network: Network,
    tls: SslConnector,
    proxy_reference: Option<String>,
    tls_timeout: Option<std::time::Duration>,
    configure_tls: fn(&mut SslRef) -> Result<(), boring::error::ErrorStack>,
}
impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvironmentConnector")
            .finish_non_exhaustive()
    }
}
impl Connector {
    pub fn platform() -> Result<Self> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(std::time::Duration::from_secs(30)));
        http.set_keepalive(Some(std::time::Duration::from_secs(30)));
        http.set_nodelay(true);
        Ok(Self {
            settings: Settings::Native,
            network: Network { http, unix: None },
            proxy_reference: None,
            tls_timeout: Some(std::time::Duration::from_secs(10)),
            tls: crate::administration::verified_tls_connector()?.build(),
            configure_tls: crate::crypto::configure_platform_trust,
        })
    }
    pub fn with_settings(mut self, settings: Arc<EnvironmentProxy>) -> Self {
        self.settings = Settings::Fixed(settings);
        self
    }
    pub fn with_transport(
        mut self,
        http: HttpConnector,
        tls: SslConnector,
        configure_tls: fn(&mut SslRef) -> Result<(), boring::error::ErrorStack>,
    ) -> Self {
        self.network.http = http;
        self.tls = tls;
        self.configure_tls = configure_tls;
        self
    }
    pub fn with_unix(
        mut self,
        path: std::path::PathBuf,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        self.network.unix = Some((path, timeout));
        self
    }
    pub fn with_tls_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.tls_timeout = timeout;
        self
    }
    async fn tls(
        &self,
        socket: Socket,
        reference: &str,
        protocols: Option<&[u8]>,
    ) -> Result<tokio_boring::SslStream<Socket>> {
        let connect =
            transport::tls_connect(socket, reference, &self.tls, self.configure_tls, protocols);
        if let Some(timeout) = self.tls_timeout {
            tokio::time::timeout(timeout, connect)
                .await
                .context("TLS handshake timed out")?
        } else {
            connect.await
        }
    }
    pub fn with_proxy_reference(mut self, reference: Option<String>) -> Self {
        self.proxy_reference = reference;
        self
    }
    pub fn prepare_headers_for(&self, uri: &Uri, headers: &mut http::HeaderMap) -> Result<()> {
        if uri.scheme_str() == Some("http")
            && let Some(proxy) = self.selected(uri)?
            && !["socks5", "socks5h"].contains(&proxy.scheme.as_str())
            && let Some(auth) = authorization(proxy)
        {
            headers.insert(http::header::PROXY_AUTHORIZATION, auth);
        }
        Ok(())
    }
    pub(crate) fn proxy_scheme(&self, uri: &Uri) -> Result<Option<&str>> {
        Ok(self.selected(uri)?.map(|proxy| proxy.scheme.as_str()))
    }
    fn selected(&self, uri: &Uri) -> Result<Option<&Proxy>> {
        let authority = uri.authority().context("request requires an authority")?;
        let host = socket_hostname(authority.host());
        let suffix = authority
            .as_str()
            .rsplit('@')
            .next()
            .unwrap_or("")
            .strip_prefix(authority.host())
            .unwrap_or("");
        let port = suffix.strip_prefix(':');
        self.settings
            .get()
            .select(uri.scheme_str().unwrap_or(""), host, port)
            .map_err(Into::into)
    }
    pub fn prepare_request<B>(&self, request: &mut http::Request<B>) -> Result<()> {
        let uri = request.uri().clone();
        if !request.headers().contains_key(http::header::HOST) {
            let authority = uri.authority().context("request requires an authority")?;
            let host = authority.as_str().rsplit('@').next().unwrap_or("");
            request.headers_mut().insert(
                http::header::HOST,
                HeaderValue::from_str(host).context("invalid request Host authority")?,
            );
        }
        self.prepare_headers_for(&uri, request.headers_mut())
    }
    pub async fn dial(&self, destination: Uri) -> Result<Connection> {
        self.dial_with_reference(destination, Profile::Http, None)
            .await
    }
    pub async fn dial_with_reference(
        &self,
        destination: Uri,
        profile: Profile,
        reference: Option<&str>,
    ) -> Result<Connection> {
        let secure = destination.scheme_str() == Some("https");
        let Connection {
            mut socket,
            proxied,
            mut h2,
        } = self.dial_transport(destination.clone(), profile).await?;
        if secure {
            let stream = self
                .tls(
                    socket,
                    reference.unwrap_or(socket_hostname(
                        destination.host().context("request requires a hostname")?,
                    )),
                    if profile == Profile::Http {
                        Some(b"\x02h2\x08http/1.1")
                    } else {
                        None
                    },
                )
                .await?;
            h2 = stream.ssl().selected_alpn_protocol() == Some(b"h2".as_slice());
            socket = Box::new(stream);
        }
        Ok(Connection {
            socket,
            proxied,
            h2,
        })
    }
    pub async fn dial_transport(&self, destination: Uri, profile: Profile) -> Result<Connection> {
        let selected = self.selected(&destination)?.cloned();
        let secure = destination.scheme_str() == Some("https");
        let mut proxied = false;
        let mut h2 = false;
        let socket: Socket = if let Some(proxy) = &selected {
            if profile == Profile::Carrier && !["http", "socks5"].contains(&proxy.scheme.as_str()) {
                bail!("unsupported Access carrier proxy scheme");
            }
            let endpoint = proxy_uri(proxy)?;
            if ["socks5", "socks5h"].contains(&proxy.scheme.as_str()) {
                let target = transport::socks_destination(&destination)?;
                let mut socks = SocksV5::new(endpoint, self.network.clone());
                if let Some(user) = proxy.username()
                    && (profile != Profile::Carrier
                        || !user.is_empty()
                            && user.len() < 256
                            && proxy.password().unwrap_or_default().len() < 256)
                {
                    socks = socks
                        .with_auth_bytes(
                            user.to_vec(),
                            proxy.password().unwrap_or_default().to_vec(),
                        )
                        .allow_no_auth();
                }
                Box::new(
                    socks
                        .call(target)
                        .await
                        .context("SOCKS proxy connection failed")?
                        .into_inner()
                        .into_socket(),
                )
            } else {
                let mut network = self.network.clone();
                let plain = network
                    .call(endpoint.clone())
                    .await
                    .context("proxy TCP connection failed")?
                    .into_inner()
                    .into_socket();
                let outer: Socket = if proxy.scheme == "https" {
                    let stream = self
                        .tls(
                            plain,
                            self.proxy_reference
                                .as_deref()
                                .unwrap_or(socket_hostname(endpoint.host().unwrap())),
                            if profile == Profile::Http {
                                Some(b"\x02h2\x08http/1.1")
                            } else {
                                None
                            },
                        )
                        .await?;
                    h2 = stream.ssl().selected_alpn_protocol() == Some(b"h2".as_slice());
                    Box::new(stream)
                } else {
                    plain
                };
                if secure || profile == Profile::Carrier {
                    let auth = if profile == Profile::Carrier && proxy.password().is_none() {
                        None
                    } else {
                        authorization(proxy)
                    };
                    let authority = connect_authority(&destination)?;
                    let connect = transport::http_connect(outer, &authority, auth.as_ref());
                    Box::new(if profile == Profile::Carrier {
                        connect.await?
                    } else {
                        tokio::time::timeout(std::time::Duration::from_secs(60), connect)
                            .await
                            .context("proxy CONNECT timed out")??
                    })
                } else {
                    proxied = true;
                    outer
                }
            }
        } else {
            validate_explicit_port(&destination)?;
            let mut network = self.network.clone();
            network
                .call(destination.clone())
                .await
                .context("TCP connection failed")?
                .into_inner()
                .into_socket()
        };
        Ok(Connection {
            socket,
            proxied,
            h2,
        })
    }
}
pub fn socket_hostname(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}
fn validate_explicit_port(uri: &Uri) -> Result<()> {
    let authority = uri.authority().context("request requires an authority")?;
    let host_port = authority.as_str().rsplit('@').next().unwrap_or("");
    if let Some(raw) = host_port
        .strip_prefix(authority.host())
        .and_then(|suffix| suffix.strip_prefix(':'))
        .filter(|port| !port.is_empty())
    {
        raw.parse::<u16>().context("invalid target port")?;
    }
    Ok(())
}
fn connect_authority(uri: &Uri) -> Result<String> {
    let authority = uri.authority().context("CONNECT requires an authority")?;
    let host_port = authority.as_str().rsplit('@').next().unwrap_or("");
    let suffix = host_port
        .strip_prefix(authority.host())
        .context("invalid CONNECT authority")?;
    Ok(if suffix.is_empty() || suffix == ":" {
        format!(
            "{}:{}",
            authority.host(),
            if uri.scheme_str() == Some("http") {
                80
            } else {
                443
            }
        )
    } else {
        host_port.to_owned()
    })
}
fn proxy_uri(proxy: &Proxy) -> Result<Uri> {
    let authority =
        std::str::from_utf8(proxy.authority()).context("invalid proxy address encoding")?;
    let parsed: http::uri::Authority = if authority.is_ascii() {
        authority.parse().context("invalid proxy address")?
    } else {
        crate::access::ApplicationUrl::remote(&format!("http://{authority}/"))?
            .request_uri()?
            .authority()
            .context("invalid proxy address")?
            .clone()
    };
    let hostname = socket_hostname(parsed.host());
    let hostname = if authority.is_ascii() {
        hostname.to_owned()
    } else {
        // URI parsing encodes labels without mapping their Unicode case.
        // Go applies the IDNA lookup profile to the original dialing hostname.
        let unicode = hostname
            .split('.')
            .map(|label| {
                label
                    .strip_prefix("xn--")
                    .and_then(idna::punycode::decode_to_string)
                    .unwrap_or_else(|| label.to_owned())
            })
            .collect::<Vec<_>>()
            .join(".");
        idna::domain_to_ascii(&unicode).map_err(|_| anyhow::anyhow!("invalid proxy hostname"))?
    };
    let suffix = parsed
        .as_str()
        .strip_prefix(parsed.host())
        .context("invalid proxy address")?;
    let port = if let Some(raw) = suffix.strip_prefix(':').filter(|raw| !raw.is_empty()) {
        raw.parse::<u16>().context("invalid proxy port")?;
        raw.to_owned()
    } else {
        match proxy.scheme.as_str() {
            "http" => "80",
            "https" => "443",
            "socks5" | "socks5h" => "1080",
            _ => bail!("proxy scheme has no default port"),
        }
        .to_owned()
    };
    let host = if hostname.contains(':') {
        format!("[{hostname}]")
    } else {
        hostname
    };
    format!("http://{host}:{port}/")
        .parse()
        .context("invalid proxy endpoint")
}
fn authorization(proxy: &Proxy) -> Option<HeaderValue> {
    let user = proxy.username()?;
    let mut value = user.to_vec();
    value.push(b':');
    value.extend_from_slice(proxy.password().unwrap_or_default());
    let mut value = HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(value)))
        .expect("base64 header value");
    value.set_sensitive(true);
    Some(value)
}

pub struct Connection {
    socket: Socket,
    proxied: bool,
    h2: bool,
}
impl Connection {
    pub(crate) fn into_socket(self) -> Socket {
        self.socket
    }
    pub(crate) fn is_h2(&self) -> bool {
        self.h2
    }
    pub fn is_proxied(&self) -> bool {
        self.proxied
    }
}
impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("proxied", &self.proxied)
            .finish_non_exhaustive()
    }
}
impl ConnectedIo for Connection {
    fn connected(&self) -> Connected {
        if self.h2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new().proxy(self.proxied)
        }
    }
}
impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}
impl Service<Uri> for Connector {
    type Response = TokioIo<Connection>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;
    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = self.clone();
        Box::pin(async move {
            connector
                .dial(uri)
                .await
                .map(TokioIo::new)
                .map_err(io::Error::other)
        })
    }
}

pub struct HttpClient<B> {
    client: Client<Connector, B>,
    connector: Connector,
}
impl<B> Clone for HttpClient<B> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            connector: self.connector.clone(),
        }
    }
}
impl<B> HttpClient<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub fn new(connector: Connector) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new())
                .proxy_target_from_host(true)
                .pool_timer(TokioTimer::new())
                .pool_idle_timeout(std::time::Duration::from_secs(90))
                .pool_max_idle_per_host(2)
                .build(connector.clone()),
            connector,
        }
    }
    pub async fn get(&self, uri: Uri) -> Result<http::Response<Incoming>>
    where
        B: Default,
    {
        self.request(http::Request::builder().uri(uri).body(B::default())?)
            .await
    }
    pub async fn request(&self, mut request: http::Request<B>) -> Result<http::Response<Incoming>> {
        self.connector.prepare_request(&mut request)?;
        self.client
            .request(request)
            .await
            .context("HTTP request failed")
    }
}

#[cfg(test)]
mod tests;
