use super::tunnelrpc_capnp as wire;
use crate::observability::metrics::Metrics;
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp::Side, twoparty};
use futures::future::LocalBoxFuture;
use std::{net::IpAddr, rc::Rc, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use uuid::Uuid;

pub struct ConfigurationResult {
    pub latest_applied_version: i32,
    pub error: String,
}
pub struct UdpRegistration {
    pub session_id: Uuid,
    pub destination: IpAddr,
    pub port: u16,
    pub idle_hint: Duration,
    pub trace_context: String,
}
pub struct UdpRegistrationResult {
    pub error: String,
    pub spans: Vec<u8>,
}

pub trait EdgeCallbacks {
    fn update_configuration(
        &self,
        version: i32,
        config: Vec<u8>,
    ) -> LocalBoxFuture<'static, ConfigurationResult>;
    fn register_udp_session(
        &self,
        request: UdpRegistration,
    ) -> LocalBoxFuture<'static, Result<UdpRegistrationResult, capnp::Error>>;
    fn unregister_udp_session(
        &self,
        id: Uuid,
        message: String,
    ) -> LocalBoxFuture<'static, Result<(), capnp::Error>>;
}

struct Server {
    callbacks: Rc<dyn EdgeCallbacks>,
    metrics: Arc<Metrics>,
}
impl wire::configuration_manager::Server for Server {
    async fn update_configuration(
        self: Rc<Self>,
        params: wire::configuration_manager::UpdateConfigurationParams,
        mut results: wire::configuration_manager::UpdateConfigurationResults,
    ) -> capnp::Result<()> {
        let mut observed = self.metrics.rpc_server("config", "update_configuration");
        let outcome = async {
            let p = params.get()?;
            let config = p.get_config()?;
            let result = self
                .callbacks
                .update_configuration(p.get_version(), config.to_vec())
                .await;
            let mut out = results.get().init_result();
            out.set_latest_applied_version(result.latest_applied_version);
            out.set_err(&result.error);
            Ok(())
        }
        .await;
        if outcome.is_err() {
            observed.failed();
        }
        outcome
    }
}
impl wire::session_manager::Server for Server {
    async fn register_udp_session(
        self: Rc<Self>,
        params: wire::session_manager::RegisterUdpSessionParams,
        mut results: wire::session_manager::RegisterUdpSessionResults,
    ) -> capnp::Result<()> {
        let mut observed = self.metrics.rpc_server("session", "register_udp_session");
        let outcome = async {
            let p = params.get()?;
            let session_id = Uuid::from_slice(p.get_session_id()?)
                .map_err(|_| capnp::Error::failed("invalid session UUID".into()))?;
            let raw = p.get_dst_ip()?;
            let destination = match raw.len() {
                4 => IpAddr::from(<[u8; 4]>::try_from(raw).unwrap()),
                16 => {
                    let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(raw).unwrap());
                    ip.to_ipv4_mapped()
                        .map(IpAddr::V4)
                        .unwrap_or(IpAddr::V6(ip))
                }
                _ => return Err(capnp::Error::failed("invalid destination IP".into())),
            };
            let req = UdpRegistration {
                session_id,
                destination,
                port: p.get_dst_port(),
                idle_hint: Duration::from_nanos(p.get_close_after_idle_hint().max(0) as u64),
                trace_context: p
                    .get_trace_context()?
                    .to_str()
                    .map_err(|e| capnp::Error::failed(e.to_string()))?
                    .into(),
            };
            let result = self.callbacks.register_udp_session(req).await?;
            let mut out = results.get().init_result();
            out.set_err(&result.error);
            out.set_spans(&result.spans);
            Ok(())
        }
        .await;
        if outcome.is_err() {
            observed.failed();
        }
        outcome
    }
    async fn unregister_udp_session(
        self: Rc<Self>,
        params: wire::session_manager::UnregisterUdpSessionParams,
        _results: wire::session_manager::UnregisterUdpSessionResults,
    ) -> capnp::Result<()> {
        let mut observed = self.metrics.rpc_server("session", "unregister_udp_session");
        let outcome = async {
            let p = params.get()?;
            let id = Uuid::from_slice(p.get_session_id()?)
                .map_err(|_| capnp::Error::failed("invalid session UUID".into()))?;
            let message = p
                .get_message()?
                .to_str()
                .map_err(|e| capnp::Error::failed(e.to_string()))?
                .into();
            self.callbacks.unregister_udp_session(id, message).await
        }
        .await;
        if outcome.is_err() {
            observed.failed();
        }
        outcome
    }
}
impl wire::cloudflared_server::Server for Server {}

/// Serve after the six-byte RPC signature has been consumed. Run on LocalSet.
pub async fn serve_callbacks<T: AsyncRead + AsyncWrite + Unpin + 'static>(
    io: T,
    callbacks: Rc<dyn EdgeCallbacks>,
    timeout: Duration,
    metrics: Arc<Metrics>,
) -> capnp::Result<()> {
    let (read, write) = tokio::io::split(io);
    let network = twoparty::VatNetwork::new(
        read.compat(),
        write.compat_write(),
        Side::Server,
        super::reader_options(),
    );
    let client: wire::cloudflared_server::Client =
        capnp_rpc::new_client(Server { callbacks, metrics });
    let rpc = RpcSystem::new(Box::new(network), Some(client.client));
    let _ = tokio::time::timeout(timeout, rpc).await;
    Ok(())
}

#[cfg(test)]
mod tests;
