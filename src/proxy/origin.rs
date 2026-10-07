use super::{RequestHead, body::ChannelBody};
use crate::config::OriginRequest;
use anyhow::{Context, Result, bail};
use boring::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
use hyper::{Response, body::Incoming};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection, HttpConnector},
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use std::{
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UnixStream,
};
use tower_service::Service as ConnectorService;

trait Io: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Io for T {}

#[derive(Clone)]
pub enum Service {
    Http(url::Url),
    Unix { path: PathBuf, tls: bool },
    Status(u16),
    Tcp { destination: String, socks: bool },
    Bastion { socks: bool },
    Socks(Vec<super::tcp::Rule>),
}

pub struct Origin {
    pub service: Service,
    pub settings: OriginRequest,
    pub verifier: Option<std::sync::Arc<crate::access::jwt::JwtVerifier>>,
    client: Option<Client<OriginConnector, ChannelBody>>,
    websocket_client: Option<Client<OriginConnector, ChannelBody>>,
    _hello: Option<super::hello::Server>,
}

pub struct OriginResponse {
    pub response: Response<Incoming>,
}

impl Origin {
    pub fn new(service: &str, settings: OriginRequest) -> Result<Self> {
        let verifier = settings
            .access
            .as_ref()
            .filter(|access| access.required && !access.team_name.is_empty())
            .map(crate::access::jwt::JwtVerifier::access)
            .transpose()?;
        let socks = settings.proxy_type.as_deref() == Some("socks");
        let mut hello = None;
        let service = if let Some(status) = service.strip_prefix("http_status:") {
            Service::Status(status.parse()?)
        } else if let Some(path) = service.strip_prefix("unix+tls:") {
            Service::Unix {
                path: PathBuf::from(path),
                tls: true,
            }
        } else if let Some(path) = service.strip_prefix("unix:") {
            Service::Unix {
                path: PathBuf::from(path),
                tls: false,
            }
        } else if ["hello_world", "hello-world"].contains(&service) {
            let (url, server) = super::hello::start()?;
            hello = Some(server);
            Service::Http(url)
        } else if service == "socks-proxy" {
            Service::Socks(super::tcp::rules(&settings.ip_rules)?)
        } else if service == "bastion" || settings.bastion_mode == Some(true) {
            Service::Bastion { socks }
        } else {
            let url = url::Url::parse(service).context("invalid origin URL")?;
            if !["http", "https", "ws", "wss"].contains(&url.scheme()) {
                let host = crate::config::socket_host(&url)?;
                let port = url.port().unwrap_or(match url.scheme() {
                    "ssh" => 22,
                    "rdp" => 3389,
                    "smb" => 445,
                    _ => 7864,
                });
                let destination = if host.contains(':') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                };
                Service::Tcp { destination, socks }
            } else {
                Service::Http(url)
            }
        };
        let (client, websocket_client) =
            if matches!(service, Service::Http(_) | Service::Unix { .. }) {
                let connector = OriginConnector::new(service.clone(), settings.clone())?;
                let mut websocket = connector.clone();
                websocket.force_http1 = true;
                (
                    Some(build_client(connector, &settings)),
                    Some(build_client(websocket, &settings)),
                )
            } else {
                (None, None)
            };
        Ok(Self {
            service,
            settings,
            verifier,
            client,
            websocket_client,
            _hello: hello,
        })
    }

    pub async fn request(&self, head: &RequestHead, body: ChannelBody) -> Result<OriginResponse> {
        let secure = matches!(&self.service, Service::Unix { tls: true, .. })
            || matches!(&self.service, Service::Http(url) if ["https", "wss"].contains(&url.scheme()));
        let physical_authority = match &self.service {
            Service::Http(url) => {
                url[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
            }
            _ => head.authority.clone(),
        };
        let host = self
            .settings
            .http_host_header
            .as_deref()
            .filter(|host| !host.is_empty())
            .unwrap_or_else(|| {
                if head.authority.is_empty() {
                    &physical_authority
                } else {
                    &head.authority
                }
            });
        let authority = if self.settings.match_sni_to_host == Some(true) {
            host
        } else {
            &physical_authority
        };
        let path = head.uri.path_and_query().map_or("/", |path| path.as_str());
        let uri: http::Uri = format!(
            "{}://{authority}{path}",
            if secure { "https" } else { "http" }
        )
        .parse()
        .context("invalid origin request URI")?;
        let mut request = http::Request::builder()
            .method(head.method.clone())
            .uri(uri)
            .body(body)?;
        *request.headers_mut() = head.headers.clone();
        request.headers_mut().insert(
            http::header::HOST,
            http::HeaderValue::from_str(host).context("invalid origin Host header")?,
        );
        if self
            .settings
            .http_host_header
            .as_ref()
            .is_some_and(|host| !host.is_empty())
        {
            request.headers_mut().insert(
                "x-forwarded-host",
                http::HeaderValue::from_str(&head.authority)
                    .context("invalid original Host header")?,
            );
        }
        // The frozen Go RoundTrip copies Host/Scheme, not configured URL.User.
        request
            .headers_mut()
            .remove("cf-cloudflared-proxy-connection-upgrade");
        request
            .headers_mut()
            .remove("cf-cloudflared-request-headers");
        request
            .headers_mut()
            .remove(http::header::TRANSFER_ENCODING);
        if head.websocket {
            request.headers_mut().insert(
                http::header::CONNECTION,
                http::HeaderValue::from_static("Upgrade"),
            );
            request.headers_mut().insert(
                http::header::UPGRADE,
                http::HeaderValue::from_static("websocket"),
            );
            request.headers_mut().insert(
                "sec-websocket-version",
                http::HeaderValue::from_static("13"),
            );
            request.headers_mut().remove(http::header::CONTENT_LENGTH);
        } else {
            request.headers_mut().insert(
                http::header::CONNECTION,
                http::HeaderValue::from_static("keep-alive"),
            );
        }
        let client = if head.websocket {
            self.websocket_client.as_ref()
        } else {
            self.client.as_ref()
        }
        .context("origin has no HTTP transport")?;
        let response = client.request(request).await.map_err(|_| {
            anyhow::anyhow!("Unable to reach the origin service or complete its HTTP/TLS request")
        })?;
        Ok(OriginResponse { response })
    }
}

fn build_client(
    connector: OriginConnector,
    settings: &OriginRequest,
) -> Client<OriginConnector, ChannelBody> {
    let mut builder = Client::builder(TokioExecutor::new());
    let idle = settings
        .keep_alive_timeout
        .map_or(Duration::from_secs(90), |value| value.0);
    builder
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(if idle.is_zero() { None } else { Some(idle) });
    let cap = settings.keep_alive_connections.unwrap_or(100);
    // Go's MaxIdleConnsPerHost=0 means its default of two, not disabling keepalive.
    builder.pool_max_idle_per_host(if cap == 0 { 2 } else { cap as usize });
    builder.build(connector)
}

#[derive(Clone)]
struct OriginConnector {
    http: HttpConnector,
    service: Service,
    settings: OriginRequest,
    tls: Option<SslConnector>,
    force_http1: bool,
}

impl OriginConnector {
    fn new(service: Service, settings: OriginRequest) -> Result<Self> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let connect_timeout = settings
            .connect_timeout
            .map_or(Duration::from_secs(30), |value| value.0);
        http.set_connect_timeout(if connect_timeout.is_zero() {
            None
        } else {
            Some(connect_timeout)
        });
        let keepalive = settings
            .tcp_keep_alive
            .map_or(Duration::from_secs(30), |value| value.0);
        http.set_keepalive(Some(if keepalive.is_zero() {
            Duration::from_secs(15)
        } else {
            keepalive
        }));
        http.set_nodelay(true);
        if settings.no_happy_eyeballs == Some(true) {
            http.set_happy_eyeballs_timeout(None);
        }
        let secure = matches!(&service, Service::Unix { tls: true, .. })
            || matches!(&service, Service::Http(url) if ["https", "wss"].contains(&url.scheme()));
        let tls = if secure {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            let mut roots = X509StoreBuilder::new()?;
            if let Some(pool) = &settings.ca_pool {
                let pem = std::fs::read(pool).context("Cannot read origin CA pool")?;
                let certificates = X509::stack_from_pem(&pem).context("Invalid origin CA pool")?;
                if certificates.is_empty() {
                    bail!("Origin CA pool contains no certificates");
                }
                for certificate in certificates {
                    roots.add_cert(certificate)?;
                }
            } else {
                for certificate in crate::crypto::native_roots()? {
                    roots.add_cert(certificate)?;
                }
            }
            builder.set_cert_store_builder(roots);
            builder.set_verify(if settings.no_tls_verify == Some(true) {
                SslVerifyMode::NONE
            } else {
                SslVerifyMode::PEER
            });
            Some(builder.build())
        } else {
            None
        };
        Ok(Self {
            http,
            service,
            settings,
            tls,
            force_http1: false,
        })
    }
}

struct OriginConnection {
    io: Box<dyn Io>,
    h2: bool,
}
impl std::fmt::Debug for OriginConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginConnection")
            .field("h2", &self.h2)
            .finish_non_exhaustive()
    }
}
impl Connection for OriginConnection {
    fn connected(&self) -> Connected {
        if self.h2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}
impl AsyncRead for OriginConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buffer)
    }
}
impl AsyncWrite for OriginConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl ConnectorService<http::Uri> for OriginConnector {
    type Response = TokioIo<OriginConnection>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;
    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let mut connector = self.clone();
        Box::pin(async move {
            let socket: Box<dyn Io> = match &connector.service {
                Service::Http(url) => {
                    let scheme = if ["https", "wss"].contains(&url.scheme()) {
                        "https"
                    } else {
                        "http"
                    };
                    let dial_uri: http::Uri = format!(
                        "{scheme}://{}/",
                        &url[url::Position::BeforeHost..url::Position::AfterPort]
                    )
                    .parse()
                    .map_err(io::Error::other)?;
                    Box::new(
                        connector
                            .http
                            .call(dial_uri)
                            .await
                            .map_err(io::Error::other)?
                            .into_inner(),
                    )
                }
                Service::Unix { path, .. } => {
                    let connect = UnixStream::connect(path);
                    let timeout = connector
                        .settings
                        .connect_timeout
                        .map_or(Duration::from_secs(30), |value| value.0);
                    Box::new(if timeout.is_zero() {
                        connect.await?
                    } else {
                        tokio::time::timeout(timeout, connect).await??
                    })
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "origin has no socket",
                    ));
                }
            };
            let (io, h2): (Box<dyn Io>, bool) = if let Some(tls) = &connector.tls {
                let mut config = tls.configure().map_err(io::Error::other)?;
                config.set_verify_hostname(connector.settings.no_tls_verify != Some(true));
                let name = if connector.settings.match_sni_to_host == Some(true) {
                    uri.host().unwrap_or("")
                } else {
                    connector
                        .settings
                        .origin_server_name
                        .as_deref()
                        .filter(|name| !name.is_empty())
                        .unwrap_or_else(|| match &connector.service {
                            Service::Http(url) => url.host_str().unwrap_or(""),
                            _ => uri.host().unwrap_or(""),
                        })
                };
                let mut ssl = config
                    .into_ssl(name.trim_matches(['[', ']']))
                    .map_err(io::Error::other)?;
                if connector.settings.http2_origin == Some(true) && !connector.force_http1 {
                    ssl.set_alpn_protos(b"\x02h2\x08http/1.1")
                        .map_err(io::Error::other)?;
                } else {
                    ssl.set_alpn_protos(b"\x08http/1.1")
                        .map_err(io::Error::other)?;
                }
                let handshake = tokio_boring::SslStreamBuilder::new(ssl, socket).connect();
                let timeout = connector
                    .settings
                    .tls_timeout
                    .map_or(Duration::from_secs(10), |value| value.0);
                let stream = if timeout.is_zero() {
                    handshake.await
                } else {
                    tokio::time::timeout(timeout, handshake).await?
                }
                .map_err(|_| io::Error::other("origin TLS verification or handshake failed"))?;
                let h2 = stream.ssl().selected_alpn_protocol() == Some(b"h2".as_slice());
                (Box::new(stream), h2)
            } else {
                (socket, false)
            };
            Ok(TokioIo::new(OriginConnection { io, h2 }))
        })
    }
}
