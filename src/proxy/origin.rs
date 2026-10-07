use super::{RequestHead, body::ChannelBody};
use crate::config::OriginRequest;
use anyhow::{Context, Result};
use boring::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
use hyper::Response;
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
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_service::Service as ConnectorService;

#[cfg(test)]
mod ca_tests;
#[cfg(test)]
mod proxy_name_tests;

use crate::proxy_environment::client::{Connector as EnvironmentConnector, Profile, Socket};

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
    physical_uri: Option<http::Uri>,
    routed: Option<EnvironmentConnector>,
}

pub struct OriginResponse {
    pub response: Response<crate::http_body::ResponseBody>,
}

impl Origin {
    pub fn new(
        service: &str,
        settings: OriginRequest,
        observability: &crate::observability::Context,
    ) -> Result<Self> {
        let raw_service = service.to_owned();
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
        let physical_uri = match &service {
            Service::Http(url) => {
                let address = if ["hello_world", "hello-world"].contains(&raw_service.as_str()) {
                    url.as_str()
                } else {
                    raw_service.as_str()
                };
                let mut parts = crate::access::ApplicationUrl::remote(address)?
                    .request_uri()?
                    .into_parts();
                parts.scheme = Some(if ["https", "wss"].contains(&url.scheme()) {
                    http::uri::Scheme::HTTPS
                } else {
                    http::uri::Scheme::HTTP
                });
                Some(http::Uri::from_parts(parts)?)
            }
            _ => None,
        };
        let mut routed = None;
        let (client, websocket_client) =
            if matches!(service, Service::Http(_) | Service::Unix { .. }) {
                let connector = OriginConnector::new(
                    service.clone(),
                    settings.clone(),
                    physical_uri.clone(),
                    observability,
                )?;
                routed = Some(connector.routed.clone());
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
            physical_uri,
            routed,
        })
    }

    pub async fn request(&self, head: &RequestHead, body: ChannelBody) -> Result<OriginResponse> {
        let secure = matches!(&self.service, Service::Unix { tls: true, .. })
            || matches!(&self.service, Service::Http(url) if ["https", "wss"].contains(&url.scheme()));
        let physical_authority = match &self.service {
            Service::Http(_) => self
                .physical_uri
                .as_ref()
                .unwrap()
                .authority()
                .unwrap()
                .as_str()
                .to_owned(),
            _ => head.authority.clone(),
        };
        let host_override = if matches!(&self.service, Service::Http(_)) {
            self.settings
                .http_host_header
                .as_deref()
                .filter(|host| !host.is_empty())
        } else {
            None
        };
        let host = host_override.unwrap_or_else(|| {
            if head.authority.is_empty() {
                &physical_authority
            } else {
                &head.authority
            }
        });
        let authority = if matches!(&self.service, Service::Http(_))
            && self.settings.match_sni_to_host == Some(true)
        {
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
        if host_override.is_some() {
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
        if let Some(routed) = &self.routed {
            let physical = self
                .physical_uri
                .as_ref()
                .cloned()
                .unwrap_or_else(|| request.uri().clone());
            routed.prepare_headers_for(&physical, request.headers_mut())?;
        }
        let method = request.method().clone();
        let gzip = crate::http_body::prepare_gzip(&method, request.headers_mut());
        let response = client.request(request).await.map_err(|_| {
            anyhow::anyhow!("Unable to reach the origin service or complete its HTTP/TLS request")
        })?;
        Ok(OriginResponse {
            response: crate::http_body::response(response, gzip),
        })
    }
}

fn origin_host_flags(ssl: &mut boring::ssl::SslRef) -> Result<(), boring::error::ErrorStack> {
    crate::crypto::enforce_hostname_policy(ssl);
    Ok(())
}

fn build_client(
    connector: OriginConnector,
    settings: &OriginRequest,
) -> Client<OriginConnector, ChannelBody> {
    let mut builder = Client::builder(TokioExecutor::new());
    builder.request_target_from_host(true);
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
    routed: EnvironmentConnector,
    physical_uri: Option<http::Uri>,
    service: Service,
    settings: OriginRequest,
    tls: Option<SslConnector>,
    force_http1: bool,
}

fn origin_roots(
    path: Option<&Path>,
    observability: &crate::observability::Context,
) -> Result<Vec<X509>> {
    use crate::observability::logging::{Event, Level};
    let custom = path
        .filter(|path| !path.as_os_str().is_empty())
        .map(std::fs::read)
        .transpose()
        .context("Cannot read origin CA pool")?;
    let mut roots = match crate::crypto::native_roots() {
        Ok(roots) => roots,
        Err(error) => {
            let _ = observability.logger.log(
                Level::Error,
                Event::Cloudflared,
                "error obtaining the system certificates",
                serde_json::json!({"error":error.to_string()}),
            );
            Vec::new()
        }
    };
    roots.extend(X509::stack_from_pem(include_bytes!(
        "../crypto/cloudflare-roots.pem"
    ))?);
    roots.extend(X509::stack_from_pem(include_bytes!(
        "../crypto/hello-root.pem"
    ))?);
    if let Some(pem) = custom {
        let certs = crate::crypto::pem_certificates(&pem);
        if certs.is_empty() {
            let _ = observability.logger.log(
                Level::Info,
                Event::Cloudflared,
                "could not append the provided origin CA to the cloudflared certificate pool",
                serde_json::json!({}),
            );
        }
        roots.extend(certs);
    }
    Ok(roots)
}

impl OriginConnector {
    fn new(
        service: Service,
        settings: OriginRequest,
        physical_uri: Option<http::Uri>,
        observability: &crate::observability::Context,
    ) -> Result<Self> {
        let roots_certificates =
            origin_roots(settings.ca_pool.as_deref().map(Path::new), observability)?;
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
        let tls = {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            let mut roots = X509StoreBuilder::new()?;
            for certificate in roots_certificates {
                roots.add_cert(certificate)?;
            }
            builder.set_cert_store_builder(roots);
            builder.set_verify(if settings.no_tls_verify == Some(true) {
                SslVerifyMode::NONE
            } else {
                SslVerifyMode::PEER
            });
            Some(builder.build())
        };
        let mut routed = EnvironmentConnector::platform()?
            .with_transport(http, tls.as_ref().unwrap().clone(), origin_host_flags)
            .with_tls_timeout(
                match settings
                    .tls_timeout
                    .map_or(Duration::from_secs(10), |timeout| timeout.0)
                {
                    timeout if timeout.is_zero() => None,
                    timeout => Some(timeout),
                },
            )
            .with_proxy_reference(
                settings
                    .origin_server_name
                    .clone()
                    .filter(|name| !name.is_empty()),
            );
        if let Service::Unix { path, .. } = &service {
            routed = routed.with_unix(
                path.clone(),
                if connect_timeout.is_zero() {
                    None
                } else {
                    Some(connect_timeout)
                },
            );
        }

        Ok(Self {
            routed,
            physical_uri,
            service,
            settings,
            tls,
            force_http1: false,
        })
    }
}

struct OriginConnection {
    io: Socket,
    h2: bool,
    proxied: bool,
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
            Connected::new().proxy(self.proxied)
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
        let connector = self.clone();
        Box::pin(async move {
            let destination = connector
                .physical_uri
                .clone()
                .unwrap_or_else(|| uri.clone());
            let uses_proxy = connector
                .routed
                .proxy_scheme(&destination)
                .map_err(io::Error::other)?
                .is_some();
            let match_sni = matches!(&connector.service, Service::Http(_))
                && connector.settings.match_sni_to_host == Some(true);
            let routed = if match_sni {
                connector
                    .routed
                    .clone()
                    .with_proxy_reference(
                        uri.authority()
                            .map(|authority| authority.as_str().to_owned()),
                    )
                    .with_tls_timeout(None)
            } else {
                connector.routed.clone()
            };
            let connection = routed
                .dial_transport(
                    destination.clone(),
                    if connector.settings.http2_origin == Some(true)
                        && !connector.force_http1
                        && !match_sni
                    {
                        Profile::Http
                    } else {
                        Profile::Http1
                    },
                )
                .await
                .map_err(io::Error::other)?;
            let proxied = connection.is_proxied();
            let transport_h2 = connection.is_h2();
            let socket = connection.into_socket();
            let secure = matches!(&connector.service, Service::Unix { tls: true, .. })
                || destination.scheme_str() == Some("https");
            let (io, h2): (Socket, bool) = if secure {
                let tls = connector.tls.as_ref().unwrap();
                let name = if match_sni && !uses_proxy {
                    uri.authority().map_or("", |authority| authority.as_str())
                } else {
                    connector
                        .settings
                        .origin_server_name
                        .as_deref()
                        .filter(|name| !name.is_empty())
                        .unwrap_or_else(|| {
                            crate::proxy_environment::client::socket_hostname(
                                destination.host().unwrap_or(""),
                            )
                        })
                };
                let mut ssl = crate::crypto::ssl_for_name(tls, name).map_err(io::Error::other)?;
                if connector.settings.http2_origin == Some(true)
                    && !connector.force_http1
                    && (!match_sni || uses_proxy)
                {
                    ssl.set_alpn_protos(b"\x02h2\x08http/1.1")
                        .map_err(io::Error::other)?;
                }
                let handshake = tokio_boring::SslStreamBuilder::new(ssl, socket).connect();
                let timeout = connector
                    .settings
                    .tls_timeout
                    .map_or(Duration::from_secs(10), |value| value.0);
                let stream = if timeout.is_zero() || match_sni && !uses_proxy {
                    handshake.await
                } else {
                    tokio::time::timeout(timeout, handshake).await?
                }
                .map_err(|_| io::Error::other("origin TLS verification or handshake failed"))?;
                let h2 = stream.ssl().selected_alpn_protocol() == Some(b"h2".as_slice());
                (Box::new(stream), h2)
            } else {
                (socket, transport_h2)
            };
            Ok(TokioIo::new(OriginConnection { io, h2, proxied }))
        })
    }
}
