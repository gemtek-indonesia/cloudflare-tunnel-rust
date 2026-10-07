use super::tunnelrpc_capnp as wire;
use crate::observability::metrics::Metrics;
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp::Side, twoparty};
use std::{fmt, net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    task::JoinHandle,
};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use uuid::Uuid;

pub struct TunnelAuth {
    pub account_tag: String,
    pub tunnel_secret: Vec<u8>,
}
impl fmt::Debug for TunnelAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TunnelAuth { credentials: [REDACTED] }")
    }
}

#[derive(Debug)]
pub struct RegistrationRequest {
    pub auth: TunnelAuth,
    pub tunnel_id: Uuid,
    pub connection_index: u8,
    pub client_id: Uuid,
    pub features: Vec<String>,
    pub version: String,
    pub arch: String,
    pub origin_ip: Option<IpAddr>,
    pub previous_attempts: u8,
}

#[derive(Debug)]
pub enum RegistrationError {
    Rejected { cause: String },
    RetryAfter { cause: String, delay: Duration },
    Rpc(capnp::Error),
    Timeout,
    Invalid(&'static str),
    Disconnected,
}
impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { cause } => write!(f, "registration rejected: {cause}"),
            Self::RetryAfter { cause, delay } => {
                write!(f, "registration retryable after {delay:?}: {cause}")
            }
            Self::Rpc(error) => write!(f, "registration RPC: {error}"),
            Self::Timeout => f.write_str("registration RPC timeout"),
            Self::Invalid(cause) => f.write_str(cause),
            Self::Disconnected => f.write_str("control RPC disconnected"),
        }
    }
}
impl std::error::Error for RegistrationError {}
impl From<capnp::Error> for RegistrationError {
    fn from(error: capnp::Error) -> Self {
        Self::Rpc(error)
    }
}

#[derive(Debug)]
pub struct ConnectionIdentity {
    tunnel_id: Uuid,
    client_id: Uuid,
    connection_index: u8,
    features: Vec<String>,
}
impl ConnectionIdentity {
    pub fn tunnel_id(&self) -> Uuid {
        self.tunnel_id
    }
    pub fn client_id(&self) -> Uuid {
        self.client_id
    }
    pub fn connection_index(&self) -> u8 {
        self.connection_index
    }
    pub fn features(&self) -> &[String] {
        &self.features
    }
}
#[derive(Debug)]
pub struct ConnectionDetails {
    pub uuid: Uuid,
    pub location: String,
    pub remotely_managed: bool,
}

struct Driver {
    task: JoinHandle<()>,
    status: watch::Receiver<Option<Result<(), String>>>,
    disconnect: Option<capnp_rpc::Disconnector<Side>>,
    cancel: tokio_util::sync::CancellationToken,
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

pub struct ConnectionLiveness {
    status: watch::Receiver<Option<Result<(), String>>>,
    task: tokio::task::AbortHandle,
    cancel: tokio_util::sync::CancellationToken,
}
impl ConnectionLiveness {
    pub fn is_ready(&self) -> bool {
        !self.cancel.is_cancelled() && self.status.borrow().is_none() && !self.task.is_finished()
    }
}

/// Constructed only by a successful edge RPC, bound to that control I/O and registration.
pub struct RegisteredConnection {
    client: wire::registration_server::Client,
    driver: Driver,
    identity: ConnectionIdentity,
    details: ConnectionDetails,
    timeout: Duration,
    metrics: Arc<Metrics>,
}
impl RegisteredConnection {
    pub fn identity(&self) -> &ConnectionIdentity {
        &self.identity
    }
    pub fn details(&self) -> &ConnectionDetails {
        &self.details
    }
    pub fn is_ready(&self) -> bool {
        self.driver.status.borrow().is_none() && !self.driver.task.is_finished()
    }
    pub fn liveness(&self) -> ConnectionLiveness {
        ConnectionLiveness {
            status: self.driver.status.clone(),
            task: self.driver.task.abort_handle(),
            cancel: self.driver.cancel.clone(),
        }
    }
    fn check_ready(&self) -> Result<(), RegistrationError> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(RegistrationError::Disconnected)
        }
    }
    pub async fn disconnected(&mut self) {
        while self.driver.status.borrow().is_none() {
            if self.driver.status.changed().await.is_err() {
                break;
            }
        }
    }
    pub fn send_local_configuration(
        &self,
        config: &[u8],
    ) -> futures::future::LocalBoxFuture<'static, Result<(), RegistrationError>> {
        let mut observed = self
            .metrics
            .rpc_client("registration", "update_local_configuration");
        if let Err(error) = self.check_ready() {
            observed.failed();
            return Box::pin(async move {
                drop(observed);
                Err(error)
            });
        }
        let mut request = self.client.update_local_configuration_request();
        request.get().set_config(config);
        let timeout = self.timeout;
        let pending = request.send().promise;
        let liveness = self.liveness();
        Box::pin(async move {
            let result = async {
                tokio::time::timeout(timeout, pending)
                    .await
                    .map_err(|_| RegistrationError::Timeout)??;
                if liveness.is_ready() {
                    Ok(())
                } else {
                    Err(RegistrationError::Disconnected)
                }
            }
            .await;
            if result.is_err() {
                observed.failed();
            }
            result
        })
    }
    pub async fn unregister(mut self, grace_period: Duration) -> Result<(), RegistrationError> {
        let mut observed = self
            .metrics
            .rpc_client("registration", "unregister_connection");
        let result = async {
            self.check_ready()?;
            let deadline = tokio::time::Instant::now() + grace_period;
            tokio::time::timeout_at(
                deadline,
                self.client.unregister_connection_request().send().promise,
            )
            .await
            .map_err(|_| RegistrationError::Timeout)??;
            Ok::<_, RegistrationError>(deadline)
        }
        .await;
        if result.is_err() {
            observed.failed();
        }
        drop(observed);
        let deadline = result?;
        if let Some(disconnect) = self.driver.disconnect.take() {
            tokio::time::timeout_at(deadline, disconnect)
                .await
                .map_err(|_| RegistrationError::Timeout)??;
        }
        Ok(())
    }
}

/// Requires a running LocalSet. Cancellation/drop closes the owned control transport.
pub async fn register_connection<T: AsyncRead + AsyncWrite + Unpin + 'static>(
    control: T,
    request: RegistrationRequest,
    timeout: Duration,
    metrics: Arc<Metrics>,
) -> Result<RegisteredConnection, RegistrationError> {
    if request.auth.account_tag.is_empty() || request.auth.tunnel_secret.is_empty() {
        return Err(RegistrationError::Invalid("empty tunnel credentials"));
    }
    if request.features.len() > 1024 || request.features.iter().any(|f| f.len() > 4096) {
        return Err(RegistrationError::Invalid("feature list exceeds limit"));
    }
    let (read, write) = tokio::io::split(control);
    let mut network = twoparty::VatNetwork::new(
        read.compat(),
        write.compat_write(),
        Side::Client,
        super::reader_options(),
    );
    network.set_window_size(1024 * 1024);
    let mut rpc = RpcSystem::new(Box::new(network), None);
    let client: wire::registration_server::Client = rpc.bootstrap(Side::Server);
    let disconnect = Some(rpc.get_disconnector());
    let (status_tx, status) = watch::channel(None);
    let task = tokio::task::spawn_local(async move {
        let result = rpc.await.map_err(|e| e.to_string());
        let _ = status_tx.send(Some(result));
    });
    let driver = Driver {
        task,
        status,
        disconnect,
        cancel: tokio_util::sync::CancellationToken::new(),
    };
    let mut call = client.register_connection_request();
    let mut observed = metrics.rpc_client("registration", "register_connection");
    {
        let mut params = call.get();
        params.set_tunnel_id(request.tunnel_id.as_bytes());
        params.set_conn_index(request.connection_index);
        let mut auth = params.reborrow().init_auth();
        auth.set_account_tag(&request.auth.account_tag);
        auth.set_tunnel_secret(&request.auth.tunnel_secret);
        let mut options = params.init_options();
        options.set_replace_existing(false);
        options.set_compression_quality(0);
        options.set_num_previous_attempts(request.previous_attempts);
        match request.origin_ip {
            Some(IpAddr::V4(ip)) => {
                let mut raw = [0u8; 16];
                raw[10] = 0xff;
                raw[11] = 0xff;
                raw[12..].copy_from_slice(&ip.octets());
                options.set_origin_local_ip(&raw);
            }
            Some(IpAddr::V6(ip)) => options.set_origin_local_ip(&ip.octets()),
            None => options.set_origin_local_ip(&[]),
        }
        let mut info = options.init_client();
        info.set_client_id(request.client_id.as_bytes());
        info.set_version(&request.version);
        info.set_arch(&request.arch);
        let mut features = info.init_features(request.features.len() as u32);
        for (i, feature) in request.features.iter().enumerate() {
            features.set(i as u32, feature);
        }
    }
    let outcome = async {
        let answer = tokio::time::timeout(timeout, call.send().promise)
            .await
            .map_err(|_| RegistrationError::Timeout)??;
        let result = answer.get()?.get_result()?.get_result();
        let details = match result.which().map_err(capnp::Error::from)? {
            wire::connection_response::result::Error(error) => {
                let error = error?;
                let cause = error
                    .get_cause()?
                    .to_str()
                    .map_err(|e| RegistrationError::Rpc(capnp::Error::failed(e.to_string())))?
                    .to_owned();
                return Err(if error.get_should_retry() {
                    RegistrationError::RetryAfter {
                        cause,
                        delay: Duration::from_nanos(error.get_retry_after().max(0) as u64),
                    }
                } else {
                    RegistrationError::Rejected { cause }
                });
            }
            wire::connection_response::result::ConnectionDetails(details) => {
                let details = details?;
                ConnectionDetails {
                    uuid: Uuid::from_slice(details.get_uuid()?)
                        .map_err(|_| RegistrationError::Invalid("invalid edge connection UUID"))?,
                    location: details
                        .get_location_name()?
                        .to_str()
                        .map_err(|e| RegistrationError::Rpc(capnp::Error::failed(e.to_string())))?
                        .into(),
                    remotely_managed: details.get_tunnel_is_remotely_managed(),
                }
            }
        };
        Ok::<_, RegistrationError>(details)
    }
    .await;
    if outcome.is_err() {
        observed.failed();
    }
    drop(observed);
    let details = outcome?;
    let registered = RegisteredConnection {
        client,
        driver,
        identity: ConnectionIdentity {
            tunnel_id: request.tunnel_id,
            client_id: request.client_id,
            connection_index: request.connection_index,
            features: request.features,
        },
        details,
        timeout,
        metrics,
    };
    registered.check_ready()?;
    Ok(registered)
}
