mod body;
mod hello;
mod origin;
#[cfg(test)]
mod proxy_environment_tests;
#[cfg(test)]
pub(crate) mod tag_test_origin;
mod tcp;
#[cfg(test)]
mod tests;

use crate::{
    config::{IngressRule, LoadedConfig, RunConfig, validate_ingress_paths},
    protocol::{
        headers,
        metadata::{ConnectRequest, ConnectResponse, ConnectionType, write_connect_response},
    },
    transport::quic::QuicStream,
};
use anyhow::{Context, Result, bail};
use body::{ChannelBody, H2Reader};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use http_body_util::BodyExt;
use origin::{Origin, Service};
use std::{io, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::RwLock,
};

struct Snapshot {
    rules: Vec<IngressRule>,
    origins: Vec<Arc<Origin>>,
    configuration: LoadedConfig,
    normalize: bool,
    paths: Vec<Option<regex::Regex>>,
}

pub struct ProxyState {
    tags: Vec<(HeaderName, HeaderValue)>,
    snapshot: RwLock<Snapshot>,
    normalize: bool,
    observability: Arc<crate::observability::Context>,
    quick_authorizer: Option<Arc<crate::quick_tunnel::auth::Authorizer>>,
}

impl ProxyState {
    pub fn new(config: &RunConfig, connector_id: uuid::Uuid) -> Result<Self> {
        Self::with_context(
            config,
            crate::observability::Context::quiet()?,
            connector_id,
        )
    }

    pub fn with_context(
        config: &RunConfig,
        observability: Arc<crate::observability::Context>,
        connector_id: uuid::Uuid,
    ) -> Result<Self> {
        let mut configuration = config.configuration.clone();
        configuration.ingress = config.ingress.clone();
        configuration.origin_request = config.origin_request.clone();
        let mut tags = config.tags.clone();
        tags.push((
            HeaderName::from_static("cf-warp-tag-id"),
            HeaderValue::from_str(&connector_id.to_string())?,
        ));
        Ok(Self {
            tags,
            snapshot: RwLock::new(Self::build(configuration, &observability)?),
            normalize: !config.disable_path_normalization,
            observability,
            quick_authorizer: config.quick_authorizer.clone(),
        })
    }

    fn build(
        mut configuration: LoadedConfig,
        observability: &crate::observability::Context,
    ) -> Result<Snapshot> {
        if configuration.ingress.is_empty() {
            configuration.ingress.push(IngressRule {
                service: "http_status:503".into(),
                ..Default::default()
            });
        }
        let paths = validate_ingress_paths(&configuration.ingress)?;
        let origins = configuration
            .ingress
            .iter()
            .map(|rule| {
                let mut settings = configuration.origin_request.merged(&rule.origin_request);
                if rule.service == "socks-proxy" {
                    // Dedicated SOCKS access policy uses the rule's own IP rules.
                    settings.ip_rules = rule.origin_request.ip_rules.clone();
                }
                Origin::new(&rule.service, settings, observability).map(Arc::new)
            })
            .collect::<Result<Vec<_>>>()?;
        configuration.settings.clear();
        configuration.tunnel.clear();
        configuration.source = None;
        Ok(Snapshot {
            paths,
            normalize: crate::config::ingress_requires_normalization(&configuration),
            rules: configuration.ingress.clone(),
            origins,
            configuration,
        })
    }

    pub async fn replace(&self, configuration: LoadedConfig) -> Result<()> {
        let snapshot = Self::build(configuration, &self.observability)?;
        *self.snapshot.write().await = snapshot;
        Ok(())
    }

    pub async fn configuration(&self) -> LoadedConfig {
        self.snapshot.read().await.configuration.clone()
    }

    async fn select(&self, head: &RequestHead) -> Result<Arc<Origin>> {
        let snapshot = self.snapshot.read().await;
        let path = if self.normalize && snapshot.normalize {
            crate::config::canonical_path(&head.path)
        } else {
            head.path.clone()
        };
        for (index, rule) in snapshot.rules.iter().enumerate() {
            if rule.matches_hostname(&head.hostname)
                && snapshot.paths[index]
                    .as_ref()
                    .is_none_or(|expression| expression.is_match(&path))
            {
                return Ok(snapshot.origins[index].clone());
            }
        }
        bail!("No matching ingress rule")
    }
}

pub(super) struct RequestHead {
    method: Method,
    uri: Uri,
    hostname: String,
    authority: String,
    path: String,
    headers: HeaderMap,
    websocket: bool,
    body: BodyMode,
}

#[derive(Clone, Copy)]
enum BodyMode {
    Empty,
    Length(u64),
    Stream,
}

impl RequestHead {
    fn from_quic(request: &ConnectRequest) -> Result<Self> {
        if request.connection_type == ConnectionType::Tcp {
            bail!("Private TCP forwarding is not implemented yet");
        }
        let mut method = Method::GET;
        let uri = request
            .destination
            .parse::<Uri>()
            .context("invalid request destination")?;
        let mut headers = HeaderMap::new();
        let mut authority = String::new();
        for (key, value) in &request.metadata {
            match key.as_str() {
                "HttpMethod" if !value.is_empty() => {
                    method =
                        Method::from_bytes(value.as_bytes()).context("invalid request method")?
                }
                "HttpHost" => authority = value.clone(),
                key if key.starts_with("HttpHeader:") => {
                    headers.append(
                        HeaderName::from_bytes(&key.as_bytes()[11..])
                            .context("invalid request header name")?,
                        HeaderValue::from_bytes(value.as_bytes())
                            .context("invalid request header value")?,
                    );
                }
                _ => {}
            }
        }
        Self::new(
            method,
            uri,
            headers,
            authority,
            request.connection_type == ConnectionType::Websocket,
            false,
        )
    }

    fn new(
        method: Method,
        uri: Uri,
        mut headers: HeaderMap,
        authority: String,
        websocket: bool,
        stream_body: bool,
    ) -> Result<Self> {
        let authority = if authority.is_empty() {
            String::new()
        } else {
            authority
        };
        let hostname = if authority.is_empty() {
            String::new()
        } else {
            authority
                .parse::<http::uri::Authority>()
                .context("invalid HTTP host")?
                .host()
                .to_owned()
        };
        let path = crate::config::matcher_path(uri.path())?;
        let length = headers
            .get(http::header::CONTENT_LENGTH)
            .map(|value| {
                value
                    .to_str()
                    .context("invalid Content-Length")?
                    .parse::<u64>()
                    .context("invalid Content-Length")
            })
            .transpose()?;
        for value in headers.get_all(http::header::CONTENT_LENGTH) {
            if value.to_str()?.parse::<u64>()? != length.unwrap_or_default() {
                bail!("Conflicting Content-Length headers");
            }
        }
        let chunked = headers
            .get(http::header::TRANSFER_ENCODING)
            .is_some_and(|value| {
                value
                    .as_bytes()
                    .windows(7)
                    .any(|part| part.eq_ignore_ascii_case(b"chunked"))
            });
        if chunked && length.is_some() {
            bail!("Conflicting Content-Length and Transfer-Encoding");
        }
        headers.remove("cf-cloudflared-proxy-connection-upgrade");
        let body = if websocket || length == Some(0) {
            BodyMode::Empty
        } else if let Some(length) = length {
            BodyMode::Length(length)
        } else if stream_body || chunked {
            BodyMode::Stream
        } else {
            BodyMode::Empty
        };
        Ok(Self {
            method,
            uri,
            hostname,
            authority,
            path,
            headers,
            websocket,
            body,
        })
    }
}

pub async fn serve_quic(
    stream: QuicStream,
    request: ConnectRequest,
    state: Arc<ProxyState>,
) -> Result<()> {
    if RequestHead::from_quic(&request)
        .is_ok_and(|head| matches!(head.body, BodyMode::Empty) && !head.websocket)
    {
        stream.cancel_read();
    }
    serve_data(stream, request, state).await
}

pub async fn serve_data<S>(stream: S, request: ConnectRequest, state: Arc<ProxyState>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let mut sink = EdgeSink::Quic {
        writer: Box::new(writer),
        started: false,
        protected: state.quick_authorizer.is_some(),
    };
    let result = match RequestHead::from_quic(&request) {
        Ok(head) => proxy(head, Box::new(reader), &mut sink, &state).await,
        Err(error) => Err(error),
    };
    finish(&mut sink, result).await
}

pub async fn serve_h2(
    request: http::Request<h2::RecvStream>,
    response: h2::server::SendResponse<Bytes>,
    state: Arc<ProxyState>,
) -> Result<()> {
    let (parts, body) = request.into_parts();
    let mut sink = EdgeSink::H2 {
        responder: Some(response),
        stream: None,
        ended: false,
        protected: state.quick_authorizer.is_some(),
    };
    let result: Result<()> = async {
        let websocket = parts
            .headers
            .get("cf-cloudflared-proxy-connection-upgrade")
            .is_some_and(|value| value == "websocket");
        if parts
            .headers
            .get("cf-cloudflared-proxy-src")
            .is_some_and(|value| value == "tcp")
        {
            bail!("Private TCP forwarding is not implemented yet");
        }
        let mut headers = parts.headers;
        if let Some(encoded) = headers.remove(headers::REQUEST_HEADERS) {
            for (name, value) in
                headers::deserialize(encoded.to_str()?).map_err(anyhow::Error::msg)?
            {
                headers.append(
                    HeaderName::from_bytes(&name)?,
                    HeaderValue::from_bytes(&value)?,
                );
            }
        }
        let authority = headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .or_else(|| parts.uri.authority().map(|value| value.as_str().to_owned()))
            .unwrap_or_default();
        let stream_body = !body.is_end_stream();
        let head = RequestHead::new(
            parts.method,
            parts.uri,
            headers,
            authority,
            websocket,
            stream_body,
        )?;
        proxy(head, Box::new(H2Reader::new(body)), &mut sink, &state).await
    }
    .await;
    finish(&mut sink, result).await
}

async fn finish(sink: &mut EdgeSink, result: Result<()>) -> Result<()> {
    if result.is_err() {
        if sink.started() {
            sink.abort();
            return result;
        }
        sink.error().await?;
    }
    sink.close().await?;
    result
}

type BoxReader = Box<dyn AsyncRead + Unpin + Send>;
type BoxWriter = Box<dyn AsyncWrite + Unpin + Send>;

async fn proxy(
    head: RequestHead,
    reader: BoxReader,
    sink: &mut EdgeSink,
    state: &ProxyState,
) -> Result<()> {
    let mut request = state.observability.metrics.begin_request(false);
    let result = proxy_inner(head, reader, sink, state).await;
    if result.is_err() {
        request.failed();
        state.observability.logger.log(
            crate::observability::logging::Level::Error,
            crate::observability::logging::Event::Http,
            "Unable to proxy request to the origin service",
            serde_json::json!({}),
        )?;
    }
    result
}

async fn proxy_inner(
    mut head: RequestHead,
    mut reader: BoxReader,
    sink: &mut EdgeSink,
    state: &ProxyState,
) -> Result<()> {
    if let Some(authorizer) = &state.quick_authorizer
        && let Some(response) = authorizer
            .authorize(
                &head.method,
                &head.uri,
                &head.authority,
                &mut head.headers,
                &mut *reader,
            )
            .await?
    {
        state.observability.metrics.response(response.status);
        sink.head(response.status, &response.headers).await?;
        if head.method != Method::HEAD {
            sink.data(response.body).await?;
        }
        return Ok(());
    }
    for (name, value) in &state.tags {
        head.headers.append(name, value.clone());
    }
    let origin = state.select(&head).await?;
    if origin
        .settings
        .access
        .as_ref()
        .is_some_and(|access| access.required)
    {
        let token = head
            .headers
            .get("cf-access-jwt-assertion")
            .and_then(|value| value.to_str().ok());
        let Some((verifier, token)) = origin
            .verifier
            .as_ref()
            .zip(token)
            .filter(|(_, token)| !token.is_empty())
        else {
            sink.head(403, &HeaderMap::new()).await?;
            state.observability.metrics.response(403);
            return Ok(());
        };
        if let Err(error) = verifier.verify(token).await {
            if error
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .is_some_and(|error| {
                    matches!(
                        error.kind(),
                        jsonwebtoken::errors::ErrorKind::InvalidAudience
                    )
                })
            {
                sink.head(403, &HeaderMap::new()).await?;
                state.observability.metrics.response(403);
                return Ok(());
            }
            bail!("Access JWT verification failed");
        }
    }
    match &origin.service {
        Service::Tcp { .. } | Service::Bastion { .. } | Service::Socks(_) => {
            return tcp::proxy(origin, head, reader, sink, state).await;
        }
        Service::Status(status) => {
            sink.head(*status, &HeaderMap::new()).await?;
            state.observability.metrics.response(*status);
            return Ok(());
        }
        _ => {}
    }
    if origin.settings.disable_chunked_encoding == Some(true)
        && matches!(head.body, BodyMode::Stream)
    {
        bail!("no-chunked-encoding requires Content-Length for streamed requests");
    }
    if head.websocket {
        let mut origin_response = origin.request(&head, ChannelBody::empty()).await?;
        let status = origin_response.response.status();
        let response_headers = state.quick_authorizer.as_ref().map_or_else(
            || origin_response.response.headers().clone(),
            |authorizer| authorizer.response_headers(origin_response.response.headers()),
        );
        sink.head(status.as_u16(), &response_headers).await?;
        state.observability.metrics.response(status.as_u16());
        if status == StatusCode::SWITCHING_PROTOCOLS {
            let upgraded = hyper::upgrade::on(&mut origin_response.response).await?;
            let (origin_read, origin_write) = tokio::io::split(TokioIoAdapter::new(upgraded));
            let upload = async move {
                let mut reader = reader;
                let mut writer = origin_write;
                tokio::io::copy(&mut reader, &mut writer).await?;
                writer.shutdown().await
            };
            let download = copy_response(origin_read, sink);
            tokio::try_join!(upload, download)?;
            return Ok(());
        }
        stream_response(&mut origin_response.response, sink).await?;
    } else {
        let (body, _upload) = match head.body {
            BodyMode::Empty => (ChannelBody::empty(), None),
            BodyMode::Length(length) => {
                let (body, upload) = ChannelBody::reader(reader, Some(length));
                (body, Some(upload))
            }
            BodyMode::Stream => {
                let (body, upload) = ChannelBody::reader(reader, None);
                (body, Some(upload))
            }
        };
        let mut origin_response = origin.request(&head, body).await?;
        sink.head(
            origin_response.response.status().as_u16(),
            &state.quick_authorizer.as_ref().map_or_else(
                || origin_response.response.headers().clone(),
                |authorizer| authorizer.response_headers(origin_response.response.headers()),
            ),
        )
        .await?;
        state
            .observability
            .metrics
            .response(origin_response.response.status().as_u16());
        stream_response(&mut origin_response.response, sink).await?;
    }
    Ok(())
}

type TokioIoAdapter<T> = hyper_util::rt::TokioIo<T>;

async fn stream_response(
    response: &mut http::Response<crate::http_body::ResponseBody>,
    sink: &mut EdgeSink,
) -> Result<()> {
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(data) => sink.data(data).await?,
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    sink.trailers(trailers).await?;
                }
            }
        }
    }
    Ok(())
}

async fn copy_response<R: AsyncRead + Unpin>(mut reader: R, sink: &mut EdgeSink) -> io::Result<()> {
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            sink.close().await.map_err(io::Error::other)?;
            return Ok(());
        }
        sink.data(Bytes::copy_from_slice(&buffer[..count]))
            .await
            .map_err(io::Error::other)?;
    }
}

enum EdgeSink {
    Quic {
        writer: BoxWriter,
        started: bool,
        protected: bool,
    },
    H2 {
        responder: Option<h2::server::SendResponse<Bytes>>,
        stream: Option<h2::SendStream<Bytes>>,
        ended: bool,
        protected: bool,
    },
}

impl EdgeSink {
    fn abort(&mut self) {
        if let Self::H2 {
            stream: Some(stream),
            ended,
            ..
        } = self
        {
            stream.send_reset(h2::Reason::INTERNAL_ERROR);
            *ended = true;
        }
    }
    fn started(&self) -> bool {
        match self {
            Self::Quic { started, .. } => *started,
            Self::H2 { responder, .. } => responder.is_none(),
        }
    }

    async fn head(&mut self, status: u16, headers: &HeaderMap) -> Result<()> {
        let mut headers = headers.clone();
        if match self {
            Self::Quic { protected, .. } | Self::H2 { protected, .. } => *protected,
        } {
            crate::quick_tunnel::auth::protect(&mut headers);
        }
        match self {
            Self::Quic {
                writer, started, ..
            } => {
                let mut metadata = vec![("HttpStatus".into(), status.to_string())];
                metadata.extend(headers.iter().map(|(name, value)| {
                    (
                        format!("HttpHeader:{}", canonical_header(name.as_str())),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                }));
                write_connect_response(
                    writer,
                    &ConnectResponse {
                        error: String::new(),
                        metadata,
                    },
                )
                .await?;
                *started = true;
            }
            Self::H2 {
                responder, stream, ..
            } => {
                let mut response = http::Response::builder()
                    .status(if status == 101 { 200 } else { status })
                    .body(())?;
                let user_headers = headers
                    .iter()
                    .filter(|(name, _)| !is_control_header(name.as_str()))
                    .map(|(name, value)| {
                        (
                            canonical_header(name.as_str()).into_bytes(),
                            value.as_bytes().to_vec(),
                        )
                    })
                    .collect::<Vec<_>>();
                response.headers_mut().insert(
                    headers::RESPONSE_HEADERS,
                    HeaderValue::from_str(&headers::serialize(&user_headers))?,
                );
                response.headers_mut().insert(
                    headers::RESPONSE_META,
                    HeaderValue::from_static("{\"src\":\"origin\"}"),
                );
                if let Some(length) = headers.get(http::header::CONTENT_LENGTH) {
                    response
                        .headers_mut()
                        .insert(http::header::CONTENT_LENGTH, length.clone());
                }
                *stream = Some(
                    responder
                        .take()
                        .context("response headers already sent")?
                        .send_response(response, false)?,
                );
            }
        }
        Ok(())
    }

    async fn error(&mut self) -> Result<()> {
        match self {
            Self::Quic {
                writer, started, ..
            } => {
                write_connect_response(
                    writer,
                    &ConnectResponse {
                        error: "Unable to proxy request to the origin service".into(),
                        metadata: vec![("HttpStatus".into(), "502".into())],
                    },
                )
                .await?;
                *started = true;
            }
            Self::H2 {
                responder, stream, ..
            } => {
                let mut response = http::Response::builder().status(502).body(())?;
                response.headers_mut().insert(
                    headers::RESPONSE_META,
                    HeaderValue::from_static("{\"src\":\"cloudflared\"}"),
                );
                *stream = Some(
                    responder
                        .take()
                        .context("response headers already sent")?
                        .send_response(response, false)?,
                );
            }
        }
        Ok(())
    }

    async fn data(&mut self, mut data: Bytes) -> Result<()> {
        match self {
            Self::Quic { writer, .. } => writer.write_all(&data).await?,
            Self::H2 { stream, .. } => {
                let stream = stream.as_mut().context("response headers not sent")?;
                while !data.is_empty() {
                    stream.reserve_capacity(data.len());
                    let capacity = futures::future::poll_fn(|cx| stream.poll_capacity(cx))
                        .await
                        .context("H2 stream closed")??;
                    if capacity == 0 {
                        continue;
                    }
                    let count = capacity.min(data.len());
                    stream.send_data(data.split_to(count), false)?;
                }
            }
        }
        Ok(())
    }

    async fn trailers(&mut self, trailers: HeaderMap) -> Result<()> {
        if let Self::H2 { stream, ended, .. } = self {
            stream
                .as_mut()
                .context("response headers not sent")?
                .send_trailers(trailers)?;
            *ended = true;
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        match self {
            Self::Quic { writer, .. } => writer.shutdown().await?,
            Self::H2 { stream, ended, .. } if !*ended => {
                if let Some(stream) = stream {
                    stream.send_data(Bytes::new(), true)?;
                }
                *ended = true;
            }
            _ => {}
        }
        Ok(())
    }
}

fn is_control_header(name: &str) -> bool {
    [":", "cf-int-", "cf-cloudflared-", "cf-proxy-"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn canonical_header(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or(String::new(), |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join("-")
}
