use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

struct Driver(tokio::task::JoinHandle<Result<(), hyper::Error>>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// TLS policy belongs to the caller: platform trust or a consumer-owned custom store.
pub async fn tls_connect<S>(
    stream: S,
    hostname: &str,
    connector: &boring::ssl::SslConnector,
    configure: fn(&mut boring::ssl::SslRef) -> Result<(), boring::error::ErrorStack>,
    protocols: Option<&[u8]>,
) -> Result<tokio_boring::SslStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ssl = crate::crypto::ssl_for_name(connector, hostname)
        .context("TLS peer name configuration failed")?;
    configure(&mut ssl).context("TLS trust configuration failed")?;
    if let Some(protocols) = protocols {
        ssl.set_alpn_protos(protocols)
            .context("TLS protocol configuration failed")?;
    }
    tokio_boring::SslStreamBuilder::new(ssl, stream)
        .connect()
        .await
        .map_err(|_| anyhow::anyhow!("TLS peer verification or handshake failed"))
}

/// SOCKS receives an explicit valid numeric port; invalid URI ports never become defaults.
pub fn socks_destination(uri: &http::Uri) -> Result<http::Uri> {
    let authority = uri
        .authority()
        .context("SOCKS destination requires an authority")?;
    let host = authority.host();
    let host_and_port = authority.as_str().rsplit('@').next().unwrap_or("");
    let suffix = host_and_port
        .strip_prefix(host)
        .context("invalid SOCKS destination authority")?;
    let default = match uri.scheme_str() {
        Some("http" | "ws") => 80,
        Some("https" | "wss") => 443,
        _ => bail!("SOCKS destination requires an HTTP or WebSocket scheme"),
    };
    let port = if let Some(port) = suffix.strip_prefix(':').filter(|port| !port.is_empty()) {
        port.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .context("invalid SOCKS destination port")?
    } else {
        default
    };
    let mut parts = uri.clone().into_parts();
    parts.authority = Some(
        format!("{host}:{port}")
            .parse()
            .context("invalid SOCKS destination authority")?,
    );
    http::Uri::from_parts(parts).context("invalid SOCKS destination URI")
}

/// CONNECT retains the supplied authority and uses Hyper's parser and buffered upgrade.
pub async fn http_connect<S>(
    stream: S,
    authority: &str,
    authorization: Option<&HeaderValue>,
) -> Result<TokioIo<hyper::upgrade::Upgraded>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let authority: http::uri::Authority = authority.parse().context("invalid CONNECT authority")?;
    let mut request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(authority.as_str())
        .header(http::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())?;
    if let Some(authorization) = authorization {
        let mut authorization = authorization.clone();
        authorization.set_sensitive(true);
        request
            .headers_mut()
            .insert(http::header::PROXY_AUTHORIZATION, authorization);
    }
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("proxy HTTP handshake failed")?;
    let mut driver = Driver(tokio::spawn(connection.with_upgrades()));
    let response = sender
        .send_request(request)
        .await
        .context("proxy CONNECT request failed")?;
    if response.status() != StatusCode::OK {
        bail!(
            "proxy CONNECT rejected with status {}",
            response.status().as_u16()
        );
    }
    let upgraded = hyper::upgrade::on(response)
        .await
        .context("proxy CONNECT upgrade failed")?;
    (&mut driver.0)
        .await
        .context("proxy CONNECT driver failed")?
        .context("proxy CONNECT connection failed")?;
    Ok(TokioIo::new(upgraded))
}

#[cfg(test)]
mod tests;
