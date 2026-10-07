mod dns;
mod icmp;
mod packet;
mod session;
mod timed_io;
pub(crate) mod tracing;
pub(crate) use icmp::determine_sources as determine_icmp_sources;

use crate::{
    config::{DurationValue, LoadedConfig, RunConfig},
    protocol::{
        callbacks::{UdpRegistration, UdpRegistrationResult},
        metadata::{self, ConnectRequest, ConnectResponse},
    },
    transport::quic::{QuicSender, QuicStream},
};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde::Deserialize;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DatagramVersion {
    V2,
    V3,
}
#[derive(Clone)]
pub(crate) struct PrivateConfig {
    connect_timeout: Duration,
    tcp_keep_alive: Duration,
    max_flows: u64,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConfig {
    connect_timeout: Option<DurationValue>,
    tcp_keep_alive: Option<DurationValue>,
    #[serde(alias = "MaxActiveFlows")]
    max_active_flows: Option<u64>,
}
impl PrivateConfig {
    pub(crate) fn parse(config: &LoadedConfig, override_limit: Option<u64>) -> Result<Self> {
        let value = serde_yaml_ng::to_value(&config.warp_routing)?;
        let raw: RawConfig = serde_yaml_ng::from_value(value)
            .map_err(|_| anyhow::anyhow!("invalid warp-routing configuration"))?;
        Ok(Self {
            connect_timeout: raw.connect_timeout.map_or(Duration::from_secs(5), |d| d.0),
            tcp_keep_alive: raw.tcp_keep_alive.map_or(Duration::from_secs(30), |d| d.0),
            max_flows: override_limit.or(raw.max_active_flows).unwrap_or(0),
        })
    }
}
pub(crate) struct Limiter {
    state: Mutex<(u64, u64)>,
}
impl Limiter {
    fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new((0, limit)),
        })
    }
    pub(crate) fn acquire(self: &Arc<Self>) -> Result<Permit> {
        let mut state = self.state.lock().unwrap();
        if state.1 != 0 && state.0 >= state.1 {
            bail!(TooManyFlows);
        }
        state.0 += 1;
        Ok(Permit(self.clone()))
    }
    fn set_limit(&self, limit: u64) {
        self.state.lock().unwrap().1 = limit;
    }
}
pub(crate) struct Permit(Arc<Limiter>);
impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.0 = state.0.saturating_sub(1);
    }
}
#[derive(Debug, thiserror::Error)]
#[error("too many active flows")]
pub(crate) struct TooManyFlows;

pub(crate) struct NetworkState {
    context: Arc<crate::observability::Context>,
    config: RwLock<PrivateConfig>,
    pub(crate) limiter: Arc<Limiter>,
    dns: Arc<dns::DnsService>,
    pub(crate) v3: Arc<session::Registry>,
    pub(crate) icmp: Arc<icmp::IcmpRouter>,
    override_limit: Option<u64>,
    write_timeout: Duration,
    icmp_enabled: bool,
}
impl NetworkState {
    #[cfg(test)]
    pub(crate) fn active_flows(&self) -> u64 {
        self.limiter.state.lock().unwrap().0
    }
    #[cfg(test)]
    pub(crate) fn new(config: &RunConfig) -> Result<Arc<Self>> {
        Self::with_context(config, crate::observability::Context::quiet()?)
    }
    pub(crate) fn with_context(
        config: &RunConfig,
        context: Arc<crate::observability::Context>,
    ) -> Result<Arc<Self>> {
        let settings = PrivateConfig::parse(&config.configuration, config.max_active_flows)?;
        Ok(Arc::new(Self {
            context,
            limiter: Limiter::new(settings.max_flows),
            config: RwLock::new(settings),
            dns: Arc::new(dns::DnsService::new(config.dns_resolver_addrs.clone())),
            v3: session::Registry::new(),
            icmp: icmp::IcmpRouter::new(config)?,
            override_limit: config.max_active_flows,
            write_timeout: config.write_stream_timeout,
            icmp_enabled: config.quick_hostname.is_empty(),
        }))
    }
    pub(crate) fn prepare(&self, config: &LoadedConfig) -> Result<PrivateConfig> {
        PrivateConfig::parse(config, self.override_limit)
    }
    pub(crate) fn replace(&self, config: PrivateConfig) {
        self.limiter.set_limit(config.max_flows);
        *self.config.write().unwrap() = config;
    }
    pub(crate) async fn refresh_dns(&self, cancel: CancellationToken) {
        self.dns.refresh_loop(cancel).await
    }
    pub(crate) fn icmp_sources(&self) -> Vec<String> {
        if self.icmp_enabled {
            self.icmp.sources()
        } else {
            vec![]
        }
    }
    pub(crate) async fn dial_udp(&self, address: SocketAddr) -> Result<tokio::net::UdpSocket> {
        let address = self.dns.destination(address);
        let socket = tokio::net::UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        socket.connect(address).await?;
        Ok(socket)
    }
    async fn dial_tcp(
        &self,
        address: SocketAddr,
    ) -> Result<timed_io::TimedIo<tokio::net::TcpStream>> {
        let virtual_dns = address == dns::VIRTUAL_DNS;
        let address = self.dns.destination(address);
        let config = self.config.read().unwrap().clone();
        let timeout = if virtual_dns {
            Duration::from_secs(5)
        } else {
            config.connect_timeout
        };
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address))
            .await
            .context("private TCP connect timeout")
            .and_then(|result| result.map_err(anyhow::Error::from));
        self.context
            .metrics
            .connect_latency
            .observe(started.elapsed().as_millis() as f64);
        if result.is_err() {
            self.context.metrics.connect_errors.inc();
        }
        let stream = result?;
        let socket = socket2::SockRef::from(&stream);
        if virtual_dns || config.tcp_keep_alive.is_zero() {
            socket.set_keepalive(false)?;
        } else {
            socket.set_tcp_keepalive(
                &socket2::TcpKeepalive::new().with_time(config.tcp_keep_alive),
            )?;
        }
        Ok(timed_io::TimedIo::new(stream, self.write_timeout))
    }
    pub(crate) async fn serve_quic_tcp(
        self: &Arc<Self>,
        mut stream: QuicStream,
        request: ConnectRequest,
    ) -> Result<()> {
        let mut request_metrics = self.context.metrics.begin_request(true);
        let trace_context = request
            .metadata
            .iter()
            .find(|(key, _)| key == "cf-trace-id")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let trace = tracing::Trace::new(trace_context, "stream-connect");
        let prepared = async {
            let permit = self.limiter.acquire()?;
            let address = request
                .destination
                .parse::<SocketAddr>()
                .context("invalid private TCP destination")?;
            let origin = self.dial_tcp(address).await?;
            Ok::<_, anyhow::Error>((permit, origin))
        }
        .await;
        match prepared {
            Ok((_permit, mut origin)) => {
                let spans = trace.finish(None);
                let metadata = if spans.is_empty() {
                    vec![]
                } else {
                    use base64::Engine;
                    vec![(
                        "Cf-Int-Cloudflared-Tracing".into(),
                        base64::engine::general_purpose::STANDARD.encode(spans),
                    )]
                };
                metadata::write_connect_response(
                    &mut stream,
                    &ConnectResponse {
                        error: String::new(),
                        metadata,
                    },
                )
                .await?;
                if let Err(error) = tokio::io::copy_bidirectional(&mut stream, &mut origin).await {
                    request_metrics.failed();
                    return Err(error.into());
                }
                Ok(())
            }
            Err(error) => {
                request_metrics.failed();
                let mut metadata = Vec::new();
                if error.downcast_ref::<TooManyFlows>().is_some() {
                    metadata.push(("FlowConnectRateLimited".into(), "true".into()));
                }
                metadata::write_connect_response(
                    &mut stream,
                    &ConnectResponse {
                        error: error.to_string(),
                        metadata,
                    },
                )
                .await?;
                Ok(())
            }
        }
    }
    pub(crate) async fn serve_h2_tcp(
        self: Arc<Self>,
        request: http::Request<h2::RecvStream>,
        mut response: h2::server::SendResponse<Bytes>,
    ) -> Result<()> {
        let mut request_metrics = self.context.metrics.begin_request(true);
        let destination = request
            .uri()
            .authority()
            .map(|a| a.as_str())
            .or_else(|| request.headers().get("host").and_then(|v| v.to_str().ok()))
            .context("host not set in incoming request")?;
        let trace = tracing::Trace::new(
            request
                .headers()
                .get("cf-trace-id")
                .and_then(|value| value.to_str().ok())
                .unwrap_or(""),
            "stream-connect",
        );
        let prepared = async {
            let permit = self.limiter.acquire()?;
            let origin = self
                .dial_tcp(
                    destination
                        .parse()
                        .context("invalid private TCP destination")?,
                )
                .await?;
            Ok::<_, anyhow::Error>((permit, origin))
        }
        .await;
        match prepared {
            Ok((_permit, mut origin)) => {
                use base64::Engine;
                let spans = trace.finish(None);
                let headers = if spans.is_empty() {
                    String::new()
                } else {
                    crate::protocol::headers::serialize(&[(
                        b"Cf-Int-Cloudflared-Tracing".to_vec(),
                        base64::engine::general_purpose::STANDARD
                            .encode(spans)
                            .into_bytes(),
                    )])
                };
                let send = response.send_response(
                    http::Response::builder()
                        .status(200)
                        .header("cf-cloudflared-response-headers", headers)
                        .header("cf-cloudflared-response-meta", r#"{"src":"origin"}"#)
                        .body(())?,
                    false,
                )?;
                let (mut stream, pump) =
                    crate::runtime::h2_control::bridge(request.into_body(), send);
                let mut pump = crate::runtime::AbortTask(pump);
                if let Err(error) = tokio::io::copy_bidirectional(&mut stream, &mut origin).await {
                    request_metrics.failed();
                    return Err(error.into());
                }
                (&mut pump.0).await??;
                Ok(())
            }
            Err(error) => {
                request_metrics.failed();
                let meta = if error.downcast_ref::<TooManyFlows>().is_some() {
                    r#"{"src":"cloudflared","flow_rate_limited":true}"#
                } else {
                    r#"{"src":"cloudflared"}"#
                };
                response.send_response(
                    http::Response::builder()
                        .status(502)
                        .header("cf-cloudflared-response-meta", meta)
                        .body(())?,
                    true,
                )?;
                Ok(())
            }
        }
    }
}

pub(crate) struct Connection {
    pub(crate) index: u8,
    pub(crate) generation: uuid::Uuid,
    pub(crate) version: DatagramVersion,
    pub(crate) sender: QuicSender,
    pub(crate) cancel: CancellationToken,
    pub(crate) state: Arc<NetworkState>,
    pub(crate) v2: Arc<session::Registry>,
    rpc_timeout: Duration,
    write_timeout: Duration,
}

pub(crate) async fn serve_datagrams(
    connection: Arc<Connection>,
    mut incoming: tokio::sync::mpsc::Receiver<Bytes>,
) -> Result<()> {
    const MAX_REGISTRATION_TASKS: usize = 16;
    let cancel = connection.cancel.clone();
    let mut registrations = tokio::task::JoinSet::new();
    let result = 'dispatch: loop {
        while let Some(completed) = registrations.try_join_next() {
            match completed {
                Ok(Err(error)) => warn_datagram(&connection, &error),
                Err(error) => break 'dispatch Err(error.into()),
                Ok(Ok(())) => {}
            }
        }
        let bytes = tokio::select! {
            _ = cancel.cancelled() => break Ok(()),
            completed = registrations.join_next(), if !registrations.is_empty() => {
                match completed {
                    Some(Ok(Err(error))) => warn_datagram(&connection, &error),
                    Some(Err(error)) => break Err(error.into()),
                    _ => {}
                }
                continue;
            }
            bytes = incoming.recv() => match bytes {
                Some(bytes) => bytes,
                None => break Err(anyhow::anyhow!("datagram manager closed")),
            },
        };
        if connection.version == DatagramVersion::V3 && bytes.first() == Some(&0) {
            if registrations.len() == MAX_REGISTRATION_TASKS {
                warn_datagram(
                    &connection,
                    &anyhow::anyhow!(
                        "UDPv3 registration dropped while prior responses are pending"
                    ),
                );
                continue;
            }
            let connection = connection.clone();
            let cancel = cancel.clone();
            registrations.spawn_local(async move {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => Ok(()),
                    result = connection.handle(bytes) => result,
                }
            });
            continue;
        }
        tokio::select! {
            _ = cancel.cancelled() => break Ok(()),
            result = connection.handle(bytes) => {
                if let Err(error) = result {
                    warn_datagram(&connection, &error);
                }
            }
        }
    };
    registrations.abort_all();
    while registrations.join_next().await.is_some() {}
    result
}
fn warn_datagram(connection: &Connection, error: &anyhow::Error) {
    let _ = connection.state.context.logger.log(
        crate::observability::logging::Level::Warn,
        crate::observability::logging::Event::Cloudflared,
        &format!("Failed to handle datagram: {error}"),
        serde_json::json!({}),
    );
}
impl Connection {
    pub(crate) fn new(
        state: Arc<NetworkState>,
        scope: &crate::runtime::scope::PendingSessionContext,
        sender: QuicSender,
        rpc_timeout: Duration,
        write_timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            state,
            index: scope.index(),
            generation: scope.generation(),
            version: scope.snapshot().version,
            sender,
            cancel: scope.cancellation(),
            v2: session::Registry::new(),
            rpc_timeout,
            write_timeout,
        })
    }
    pub(crate) async fn register_udp(
        self: &Arc<Self>,
        request: UdpRegistration,
    ) -> UdpRegistrationResult {
        if self.version == DatagramVersion::V3 {
            self.state
                .context
                .metrics
                .udp_unsupported_remote_commands
                .with_label_values(&[&self.index.to_string(), "register_udp_session"])
                .inc();
            return UdpRegistrationResult {
                error: "datagram v3 does not support RegisterUdpSession RPC".into(),
                spans: Vec::new(),
            };
        }
        use opentelemetry_proto::tonic::common::v1::any_value::Value;
        let trace = tracing::Trace::new(&request.trace_context, "register-session")
            .attribute(
                "session-id",
                Value::StringValue(request.session_id.to_string()),
            )
            .attribute(
                "dst",
                Value::StringValue(format!("{}:{}", request.destination, request.port)),
            );
        let result = self.v2.register_v2(self.clone(), request).await;
        let error = result.err().map(|e| e.to_string()).unwrap_or_default();
        let spans = trace.finish((!error.is_empty()).then_some(error.as_str()));
        UdpRegistrationResult { error, spans }
    }
    pub(crate) async fn unregister_udp(&self, id: uuid::Uuid) -> Result<()> {
        if self.version == DatagramVersion::V3 {
            self.state
                .context
                .metrics
                .udp_unsupported_remote_commands
                .with_label_values(&[&self.index.to_string(), "unregister_udp_session"])
                .inc();
            bail!("datagram v3 does not support UnregisterUdpSession RPC");
        }
        self.v2.remove(*id.as_bytes(), None).await;
        Ok(())
    }
    pub(crate) async fn handle(self: &Arc<Self>, bytes: Bytes) -> Result<()> {
        session::handle(self, bytes).await
    }
    pub(crate) async fn close_v2_session(&self, id: [u8; 16], message: String) {
        if self.cancel.is_cancelled() || self.sender.is_closed() {
            return;
        }
        let result = async {
            use tokio::io::AsyncWriteExt;
            use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
            let mut stream = self.sender.open_bi().await?;
            stream.set_write_timeout(self.write_timeout);
            stream.write_all(&metadata::RPC_SIGNATURE).await?;
            let (read, write) = tokio::io::split(stream);
            let network = capnp_rpc::twoparty::VatNetwork::new(
                read.compat(),
                write.compat_write(),
                capnp_rpc::rpc_twoparty_capnp::Side::Client,
                crate::protocol::reader_options(),
            );
            let mut rpc = capnp_rpc::RpcSystem::new(Box::new(network), None);
            let client: crate::protocol::tunnelrpc_capnp::session_manager::Client =
                rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
            let _driver = crate::runtime::AbortTask(tokio::task::spawn_local(rpc));
            let mut call = client.unregister_udp_session_request();
            call.get().set_session_id(&id);
            call.get().set_message(&message);
            let mut observed = self
                .state
                .context
                .metrics
                .rpc_client("session", "unregister_udp_session");
            let result = tokio::time::timeout(self.rpc_timeout, call.send().promise).await;
            if !matches!(&result, Ok(Ok(_))) {
                observed.failed();
            }
            result??;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            eprintln!("Failed to unregister UDP session with edge: {error}");
        }
    }
}
#[cfg(test)]
mod tests;
