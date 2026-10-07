mod discovery;
mod features;
pub(crate) mod h2_control;
pub(crate) mod prechecks;
pub(crate) mod scope;
mod service;

use crate::{
    config::{LoadedConfig, Protocol, RunConfig, UPSTREAM_VERSION},
    crypto::{EdgeTls, TlsPolicy},
    protocol::{
        callbacks::{
            self, ConfigurationResult, EdgeCallbacks, UdpRegistration, UdpRegistrationResult,
        },
        metadata::{self, StreamKind},
        registration::{
            self, ConnectionLiveness, RegisteredConnection, RegistrationError, RegistrationRequest,
            TunnelAuth,
        },
    },
    proxy::{self, ProxyState},
    transport,
};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures::{FutureExt, future::LocalBoxFuture};
use std::{
    collections::HashMap,
    net::SocketAddr,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EdgeProtocol {
    Quic,
    Http2,
}
enum Event {
    Connected(u8, EdgeProtocol),
    Retry(oneshot::Sender<()>),
}

struct LiveSlot {
    generation: u64,
    liveness: ConnectionLiveness,
    details: serde_json::Value,
}
struct Readiness {
    slots: Mutex<HashMap<u8, LiveSlot>>,
    next: AtomicU64,
    shutting_down: AtomicBool,
}
impl Readiness {
    #[cfg(test)]
    fn ready(&self) -> bool {
        self.count() > 0
    }
    fn count(&self) -> usize {
        if self.shutting_down.load(Ordering::Acquire) {
            0
        } else {
            self.slots
                .lock()
                .unwrap()
                .values()
                .filter(|s| s.liveness.is_ready())
                .count()
        }
    }
    #[cfg(test)]
    fn response(&self, client_id: Uuid) -> (u16, Vec<u8>) {
        let count = self.count();
        let status = if count > 0 { 200 } else { 503 };
        (status,serde_json::to_vec(&serde_json::json!({"status":status,"readyConnections":count,"connectorId":client_id})).unwrap())
    }
    fn bind(
        self: &Arc<Self>,
        registered: &RegisteredConnection,
        metrics: Arc<crate::observability::metrics::Metrics>,
        details: serde_json::Value,
    ) -> Lease {
        let index = registered.identity().connection_index();
        let generation = self.next.fetch_add(1, Ordering::Relaxed);
        self.slots.lock().unwrap().insert(
            index,
            LiveSlot {
                generation,
                liveness: registered.liveness(),
                details,
            },
        );
        Lease {
            state: self.clone(),
            index,
            generation,
            metrics,
            location: registered.details().location.clone(),
        }
    }
}
struct Lease {
    state: Arc<Readiness>,
    index: u8,
    generation: u64,
    metrics: Arc<crate::observability::metrics::Metrics>,
    location: String,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut slots = self.state.slots.lock().unwrap();
        if slots
            .get(&self.index)
            .is_some_and(|s| s.generation == self.generation)
        {
            slots.remove(&self.index);
            self.metrics.ha_connections.set(
                slots
                    .values()
                    .filter(|slot| slot.liveness.is_ready())
                    .count() as i64,
            );
            self.metrics
                .server_locations
                .with_label_values(&[&self.index.to_string(), &self.location])
                .set(0);
        }
    }
}

struct ConfigurationState {
    version: i32,
    current: LoadedConfig,
}
struct Runtime {
    config: RunConfig,
    proxy: Arc<ProxyState>,
    context: Arc<crate::observability::Context>,
    network: Arc<crate::network::NetworkState>,
    features: Arc<features::FeatureSelector>,
    management: Arc<crate::observability::management::Service>,
    configuration: tokio::sync::Mutex<ConfigurationState>,
    readiness: Arc<Readiness>,
    client_id: Uuid,
    events: mpsc::UnboundedSender<Event>,
    shutdown: CancellationToken,
    force: CancellationToken,
    ever_quic: AtomicBool,
    notify_socket: Option<std::ffi::OsString>,
    startup_announced: AtomicBool,
}
impl Runtime {
    fn should_fallback(
        &self,
        protocol: EdgeProtocol,
        max_addresses: bool,
        exhausted: bool,
    ) -> bool {
        protocol == EdgeProtocol::Quic
            && self.config.protocol == Protocol::Auto
            && !self.ever_quic.load(Ordering::Acquire)
            && (max_addresses || exhausted)
    }
    fn registration_failure(&self, error: RegistrationError) -> RegistrationFailure {
        let label = if matches!(&error,RegistrationError::Rejected{cause} if cause=="EDUPCONN") {
            "dup_edge_conn"
        } else {
            "server_error"
        };
        self.context
            .metrics
            .register_fail
            .with_label_values(&[label, "registerConnection"])
            .inc();
        RegistrationFailure(error)
    }
    async fn diagnostic_snapshot(&self) -> crate::observability::diagnostics::Snapshot {
        let current = self.configuration.lock().await;
        let connections = if self.readiness.shutting_down.load(Ordering::Acquire) {
            vec![]
        } else {
            self.readiness
                .slots
                .lock()
                .unwrap()
                .values()
                .filter(|slot| slot.liveness.is_ready())
                .map(|slot| slot.details.clone())
                .collect()
        };
        crate::observability::diagnostics::Snapshot {
            tunnel_id: self.config.credentials.tunnel_id,
            connector_id: self.client_id,
            connections,
            icmp_sources: self.network.icmp_sources(),
            cli_flags: self.config.diagnostic_cli_flags.clone(),
            versioned_config: serde_json::json!({"version":current.version,"config":{"ingress":current.current.ingress,"warp-routing":current.current.warp_routing,"originRequest":current.current.origin_request}}),
            quick_hostname: self.config.quick_hostname.clone(),
        }
    }
    fn warn(&self, message: &str) {
        let _ = self.context.logger.log(
            crate::observability::logging::Level::Warn,
            crate::observability::logging::Event::Cloudflared,
            message,
            serde_json::json!({}),
        );
    }
    fn request(
        &self,
        index: u8,
        address: SocketAddr,
        previous_attempts: u32,
        snapshot: &features::FeatureSnapshot,
    ) -> RegistrationRequest {
        RegistrationRequest {
            auth: TunnelAuth {
                account_tag: self.config.credentials.account_tag.clone(),
                tunnel_secret: self.config.credentials.tunnel_secret.clone(),
            },
            tunnel_id: self.config.credentials.tunnel_id,
            connection_index: index,
            client_id: self.client_id,
            features: snapshot.features.clone(),
            version: UPSTREAM_VERSION.into(),
            arch: "linux_amd64".into(),
            origin_ip: Some(address.ip()),
            previous_attempts: previous_attempts as u8,
        }
    }
    async fn update(&self, version: i32, json: Vec<u8>) -> ConfigurationResult {
        let mut current = self.configuration.lock().await;
        if version <= current.version {
            return ConfigurationResult {
                latest_applied_version: current.version,
                error: String::new(),
            };
        }
        let next = match std::str::from_utf8(&json)
            .ok()
            .and_then(|text| LoadedConfig::from_json(text).ok())
        {
            Some(config) => config,
            None => {
                return ConfigurationResult {
                    latest_applied_version: current.version,
                    error: "invalid ingress JSON".into(),
                };
            }
        };
        let private = match self.network.prepare(&next) {
            Ok(config) => config,
            Err(error) => {
                return ConfigurationResult {
                    latest_applied_version: current.version,
                    error: error.to_string(),
                };
            }
        };
        if let Err(error) = self.proxy.replace(next.clone()).await {
            return ConfigurationResult {
                latest_applied_version: current.version,
                error: error.to_string(),
            };
        }
        self.network.replace(private);
        self.context.metrics.config_version.set(i64::from(version));
        current.version = version;
        current.current = next;
        ConfigurationResult {
            latest_applied_version: version,
            error: String::new(),
        }
    }
    async fn local_configuration(&self) -> Result<Vec<u8>> {
        let current = self.configuration.lock().await;
        Ok(serde_json::to_vec(
            &serde_json::json!({"ingress":current.current.ingress,"originRequest":current.current.origin_request,"warp-routing":current.current.warp_routing}),
        )?)
    }
    async fn registered(
        self: &Arc<Self>,
        index: u8,
        protocol: EdgeProtocol,
        address: SocketAddr,
        registered: &RegisteredConnection,
    ) -> Result<Lease> {
        if index != registered.identity().connection_index() {
            bail!("registration index does not match connection owner");
        }
        let mut details = serde_json::Map::new();
        details.insert("isConnected".into(), serde_json::json!(true));
        details.insert("edgeAddress".into(), serde_json::json!(address.ip()));
        if index != 0 {
            details.insert("index".into(), serde_json::json!(index));
        }
        if protocol == EdgeProtocol::Quic {
            details.insert("protocol".into(), serde_json::json!(1));
        }
        let lease = self.readiness.bind(
            registered,
            self.context.metrics.clone(),
            serde_json::Value::Object(details),
        );
        self.context
            .metrics
            .ha_connections
            .set(self.readiness.count() as i64);
        self.context
            .metrics
            .register_success
            .with_label_values(&["registerConnection"])
            .inc();
        self.context
            .metrics
            .server_locations
            .with_label_values(&[&index.to_string(), &registered.details().location])
            .set(1);
        if protocol == EdgeProtocol::Quic {
            self.ever_quic.store(true, Ordering::Release);
        }
        let _ = self.events.send(Event::Connected(index, protocol));
        if !self.startup_announced.swap(true, Ordering::AcqRel) {
            if let Err(error) = service::notify_ready(self.notify_socket.as_deref()) {
                eprintln!("systemd readiness notification failed: {error}");
            }
            if let Some(path) = &self.config.pidfile {
                let expanded = crate::config::expand_home(
                    &path.to_string_lossy(),
                    std::env::var_os("HOME")
                        .as_deref()
                        .map(std::path::Path::new),
                )?;
                if let Err(error) = service::write_pid(&expanded) {
                    eprintln!("Unable to write pid: {error}");
                }
            }
        }
        eprintln!(
            "Registered tunnel connection connIndex={index} connection={} location={} protocol={protocol:?}",
            registered.details().uuid,
            registered.details().location
        );
        Ok(lease)
    }
}
struct Callback {
    runtime: Arc<Runtime>,
    network: Option<Arc<crate::network::Connection>>,
}
impl EdgeCallbacks for Callback {
    fn update_configuration(
        &self,
        version: i32,
        config: Vec<u8>,
    ) -> LocalBoxFuture<'static, ConfigurationResult> {
        let runtime = self.runtime.clone();
        async move { runtime.update(version, config).await }.boxed_local()
    }
    fn register_udp_session(
        &self,
        request: UdpRegistration,
    ) -> LocalBoxFuture<'static, Result<UdpRegistrationResult, capnp::Error>> {
        let network = self.network.clone();
        async move {
            match network {
                Some(network) => Ok(network.register_udp(request).await),
                None => Ok(UdpRegistrationResult {
                    error: "UDP sessions require QUIC".into(),
                    spans: Vec::new(),
                }),
            }
        }
        .boxed_local()
    }
    fn unregister_udp_session(
        &self,
        id: Uuid,
        _message: String,
    ) -> LocalBoxFuture<'static, Result<(), capnp::Error>> {
        let network = self.network.clone();
        async move {
            match network {
                Some(network) => network
                    .unregister_udp(id)
                    .await
                    .map_err(|e| capnp::Error::failed(e.to_string())),
                None => Err(capnp::Error::unimplemented(
                    "UDP sessions require QUIC".into(),
                )),
            }
        }
        .boxed_local()
    }
}

pub(crate) struct AbortTask<T>(pub(crate) JoinHandle<T>);
impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn tls(config: &RunConfig) -> Result<EdgeTls> {
    let root = config
        .edge_ca
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("read edge CA certificate")?;
    EdgeTls::new(
        if config.post_quantum {
            TlsPolicy::RequirePostQuantum
        } else {
            TlsPolicy::PreferPostQuantum
        },
        root.as_deref(),
    )
}

pub async fn run(config: RunConfig) -> Result<()> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let shutdown = CancellationToken::new();
            let force = CancellationToken::new();
            let stop = shutdown.clone();
            let hard_stop = force.clone();
            let signals = AbortTask(tokio::task::spawn_local(async move {
                let mut interrupt =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
                let mut terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                tokio::select! {_=interrupt.recv()=>{},_=terminate.recv()=>{}}
                stop.cancel();
                tokio::select! {_=interrupt.recv()=>{},_=terminate.recv()=>{}}
                hard_stop.cancel();
                Ok::<_, std::io::Error>(())
            }));
            let result = run_with_shutdown(config, shutdown, force).await;
            drop(signals);
            result
        })
        .await
}

async fn run_with_shutdown(
    mut config: RunConfig,
    shutdown: CancellationToken,
    force: CancellationToken,
) -> Result<()> {
    let edge_tls = tls(&config)?;
    crate::network::determine_icmp_sources(&mut config)?;
    let pool = tokio::select! {_=shutdown.cancelled()=>return Ok(()),result=discovery::resolve(&config)=>result?};
    let count = usize::from(config.ha_connections).min(pool.available());
    if count == 0 {
        bail!("no HA connections available");
    }
    let pool = Arc::new(Mutex::new(pool));
    let context =
        crate::observability::Context::new(config.logging.clone(), config.known_secrets.clone())?;
    let proxy = Arc::new(ProxyState::with_context(&config, context.clone())?);
    let network = crate::network::NetworkState::with_context(&config, context.clone())?;
    let selector = Arc::new(features::FeatureSelector::new(
        &config.credentials.account_tag,
        config.features.clone(),
        config.post_quantum,
    ));
    tokio::select! {_=shutdown.cancelled()=>return Ok(()),result=selector.refresh()=>if let Err(error)=result{eprintln!("Failed to fetch features, default to disable: {error}");}}
    let mut random = [0; 16];
    boring::rand::rand_bytes(&mut random)?;
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    let (events, event_rx) = mpsc::unbounded_channel();
    let readiness = Arc::new(Readiness {
        slots: Mutex::new(HashMap::new()),
        next: AtomicU64::new(1),
        shutting_down: AtomicBool::new(false),
    });
    let mut configuration = config.configuration.clone();
    configuration.ingress = config.ingress.clone();
    configuration.origin_request = config.origin_request.clone();
    let client_id = Uuid::from_bytes(random);
    let management = Arc::new(crate::observability::management::Service::new(
        context.clone(),
        client_id,
        &config.connector_label,
        (!config.service_op_ip.is_empty()).then(|| config.service_op_ip.clone()),
        config.management_diagnostics,
    ));
    let runtime = Arc::new(Runtime {
        configuration: tokio::sync::Mutex::new(ConfigurationState {
            version: -1,
            current: configuration,
        }),
        config,
        proxy,
        context,
        network,
        features: selector,
        management,
        readiness: readiness.clone(),
        client_id,
        events,
        shutdown: shutdown.clone(),
        force: force.clone(),
        ever_quic: AtomicBool::new(false),
        notify_socket: std::env::var_os("NOTIFY_SOCKET"),
        startup_announced: AtomicBool::new(false),
    });
    let background = runtime.clone();
    let precheck_runtime = runtime.clone();
    let _prechecks = prechecks::spawn_if_enabled(
        &runtime.config,
        &runtime.features.snapshot(true),
        async move {
            prechecks::startup(
                &precheck_runtime.config,
                &precheck_runtime.context,
                precheck_runtime.shutdown.clone(),
            )
            .await;
        },
    );
    let _feature_refresh = AbortTask(tokio::task::spawn_local(async move {
        background
            .features
            .refresh_loop(background.shutdown.clone())
            .await
    }));
    let background = runtime.clone();
    let _dns_refresh = AbortTask(tokio::task::spawn_local(async move {
        background
            .network
            .refresh_dns(background.shutdown.clone())
            .await
    }));
    let health = if runtime.config.metrics.is_empty() {
        None
    } else {
        Some(health_server(&runtime.config.metrics, runtime.clone(), shutdown.clone()).await?)
    };
    let result = supervise(runtime.clone(), pool, edge_tls, count, event_rx).await;
    readiness.shutting_down.store(true, Ordering::Release);
    shutdown.cancel();
    drop(health);
    result
}

async fn health_server(
    address: &str,
    runtime: Arc<Runtime>,
    shutdown: CancellationToken,
) -> Result<AbortTask<()>> {
    let listener = metrics_listener(address).await?;
    health_server_on(listener, runtime, shutdown)
}

fn health_server_on(
    listener: tokio::net::TcpListener,
    runtime: Arc<Runtime>,
    shutdown: CancellationToken,
) -> Result<AbortTask<()>> {
    eprintln!(
        "Starting metrics server on {}/metrics",
        listener.local_addr()?
    );
    Ok(AbortTask(tokio::task::spawn_local(async move {
        let mut tasks = JoinSet::new();
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => break,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error))=result {runtime.warn(&format!("diagnostic HTTP task failed: {error}"));}
                    continue;
                }
                result = listener.accept() => result,
            };
            let Ok((socket, _)) = accepted else {
                break;
            };
            let runtime = runtime.clone();
            let cancel = shutdown.clone();
            tasks.spawn_local(async move {
                let service = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| {
                        let runtime = runtime.clone();
                        async move {
                            let snapshot = runtime.diagnostic_snapshot().await;
                            let response = crate::observability::diagnostics::handle(request.uri().path(), &runtime.context, snapshot).await.unwrap_or_else(|_| hyper::Response::builder().status(500).body(Bytes::from_static(b"diagnostic collection failed\n")).unwrap());
                            Ok::<_, std::convert::Infallible>(response.map(http_body_util::Full::new))
                        }
                    },
                );
                tokio::select! {
                    _ = cancel.cancelled() => {},
                    _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(socket),service) => {},
                }
            });
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    })))
}

async fn metrics_listener(address: &str) -> Result<tokio::net::TcpListener> {
    if address == "localhost:0" {
        for port in 20241..=20245 {
            if let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
                return Ok(listener);
            }
        }
    }
    let address = if address == "localhost:0" {
        "127.0.0.1:0"
    } else {
        address
    };
    tokio::net::TcpListener::bind(address)
        .await
        .context("bind metrics/readiness listener")
}

async fn supervise(
    runtime: Arc<Runtime>,
    pool: Arc<Mutex<discovery::EdgePool>>,
    tls: EdgeTls,
    count: usize,
    mut events: mpsc::UnboundedReceiver<Event>,
) -> Result<()> {
    let initial = match runtime.config.protocol {
        Protocol::Http2 => EdgeProtocol::Http2,
        _ => EdgeProtocol::Quic,
    };
    let mut tasks = JoinSet::new();
    tasks.spawn_local(lane(runtime.clone(), pool.clone(), tls.clone(), 0, initial));
    let mut first = false;
    let mut launches = None;
    let mut next_index = 1usize;
    let mut pending = Vec::new();
    let mut retry_deadline = None;
    let mut global_retries = 0u32;
    let mut global_reset_after = None;
    let mut terminal = None;
    loop {
        tokio::select! {
            _ = runtime.shutdown.cancelled() => break,
            event = events.recv() => match event {
                Some(Event::Connected(index, protocol)) => {
                    if index == 0 && !first {
                        first = true;
                        launches = Some((Instant::now(), protocol));
                    }
                    if runtime.readiness.count() == count && pending.is_empty() {
                        global_reset_after = Some(Instant::now() + Duration::from_secs(40 * (1u64 << global_retries.min(31))));
                    }
                }
                Some(Event::Retry(reply)) => {
                    pending.push(reply);
                    if retry_deadline.is_none() {
                        if global_reset_after.is_some_and(|deadline| Instant::now() > deadline) {
                            global_retries = 0;
                            global_reset_after = None;
                        }
                        retry_deadline = Some(Instant::now() + backoff(global_retries, 10, runtime.config.retries)?);
                        global_retries = global_retries.saturating_add(1);
                    }
                }
                None => break,
            },
            _ = async {
                if let Some((deadline, _)) = launches { tokio::time::sleep_until(deadline).await }
                else { futures::future::pending().await }
            } => {
                if next_index < count {
                    let protocol = launches.unwrap().1;
                    tasks.spawn_local(lane(runtime.clone(), pool.clone(), tls.clone(), next_index as u8, protocol));
                    next_index += 1;
                    launches = if next_index < count { Some((Instant::now() + Duration::from_secs(1), protocol)) } else { None };
                } else { launches = None; }
            },
            _ = async {
                if let Some(deadline) = retry_deadline { tokio::time::sleep_until(deadline).await }
                else { futures::future::pending().await }
            } => {
                retry_deadline = None;
                for reply in pending.drain(..) { let _ = reply.send(()); }
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                match completed {
                    Some(Err(error)) => { terminal = Some(error.into()); break; }
                    Some(Ok(Err(error))) => { terminal = Some(error); break; }
                    _ => {}
                }
                if tasks.is_empty() && launches.is_none() { break; }
            },
        }
    }
    runtime
        .readiness
        .shutting_down
        .store(true, Ordering::Release);
    runtime.shutdown.cancel();
    let deadline = Instant::now() + runtime.config.grace_period;
    tokio::select! {_=runtime.force.cancelled()=>{},_=tokio::time::sleep_until(deadline)=>{},_=async{while tasks.join_next().await.is_some(){}}=>{}}
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    if let Some(error) = terminal {
        Err(error)
    } else {
        Ok(())
    }
}

fn backoff(retry: u32, base_seconds: u64, max_retries: u32) -> Result<Duration> {
    let exponent = retry.saturating_add(1).min(max_retries).min(31);
    let max_ms = base_seconds
        .saturating_mul(1000)
        .saturating_mul(1u64 << exponent);
    Ok(Duration::from_millis(discovery::random_below(
        max_ms.max(1),
    )?))
}

#[derive(Debug)]
struct RegistrationFailure(RegistrationError);
impl std::fmt::Display for RegistrationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for RegistrationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RetryPolicy {
    stop_startup: bool,
    supervised: bool,
    allow_fallback: bool,
    rotate: bool,
    connectivity: bool,
}
fn retry_policy(error: &anyhow::Error, first_worker: bool, initialized: bool) -> RetryPolicy {
    let mut policy = RetryPolicy {
        stop_startup: false,
        supervised: !first_worker,
        allow_fallback: true,
        rotate: false,
        connectivity: false,
    };
    if let Some(failure) = error.downcast_ref::<RegistrationFailure>() {
        let cause = match &failure.0 {
            RegistrationError::Rejected { cause } | RegistrationError::RetryAfter { cause, .. } => {
                cause.clone()
            }
            RegistrationError::Rpc(error) => error.to_string(),
            other => other.to_string(),
        };
        let duplicate = cause == "EDUPCONN";
        let permanent = !matches!(failure.0, RegistrationError::RetryAfter { .. }) || duplicate;
        policy.allow_fallback = !permanent;
        policy.rotate = duplicate;
        if first_worker && permanent && !duplicate && !cause.contains("Unauthorized") {
            policy.stop_startup = !initialized;
            policy.supervised = initialized;
        }
    } else if error.downcast_ref::<DialFailure>().is_some() {
        policy.connectivity = true;
        policy.rotate = true;
        policy.allow_fallback = false;
    }
    policy
}

async fn lane(
    runtime: Arc<Runtime>,
    pool: Arc<Mutex<discovery::EdgePool>>,
    tls: EdgeTls,
    index: u8,
    mut protocol: EdgeProtocol,
) -> Result<()> {
    let mut retries = 0u32;
    let mut address_failures = 0u8;
    let mut rotate = false;
    let mut connectivity = false;
    let mut stable_since = None;
    let mut first_worker = index == 0;
    loop {
        if runtime.shutdown.is_cancelled() {
            return Ok(());
        }
        let address = match pool.lock().unwrap().address(index, rotate, connectivity) {
            Ok(address) => address,
            Err(error) => return Err(error),
        };
        let result = match protocol {
            EdgeProtocol::Quic => {
                serve_quic(
                    runtime.clone(),
                    &tls,
                    index,
                    address,
                    retries,
                    &mut stable_since,
                )
                .await
            }
            EdgeProtocol::Http2 => {
                serve_h2(
                    runtime.clone(),
                    &tls,
                    index,
                    address,
                    retries,
                    &mut stable_since,
                )
                .await
            }
        };
        if runtime.shutdown.is_cancelled() {
            return Ok(());
        }
        if let Err(error) = result {
            let policy = retry_policy(
                &error,
                first_worker,
                runtime.startup_announced.load(Ordering::Acquire),
            );
            eprintln!("Connection terminated connIndex={index} protocol={protocol:?}: {error}");
            connectivity = policy.connectivity;
            rotate = policy.rotate;
            if connectivity {
                address_failures = address_failures.saturating_add(1);
            }
            if stable_since.is_some_and(|deadline| Instant::now() > deadline) {
                retries = 0;
                stable_since = None;
            }
            let wait = match backoff(retries, 1, runtime.config.retries) {
                Ok(wait) => wait,
                Err(error) => return Err(error),
            };
            retries = retries.saturating_add(1);
            tokio::select! {_=runtime.shutdown.cancelled()=>return Ok(()),_=tokio::time::sleep(wait)=>{}}
            if policy.stop_startup {
                return Err(error);
            }
            let max_addresses = address_failures > runtime.config.max_edge_addr_retries;
            let exhausted = retries >= runtime.config.retries && policy.allow_fallback;
            if runtime.should_fallback(protocol, max_addresses, exhausted) {
                protocol = EdgeProtocol::Http2;
                retries = 0;
                address_failures = 0;
                eprintln!("Switching to fallback protocol http2 connIndex={index}");
            }
            if policy.supervised {
                first_worker = false;
                let (tx, rx) = oneshot::channel();
                let _ = runtime.events.send(Event::Retry(tx));
                tokio::select! {_=runtime.shutdown.cancelled()=>return Ok(()),_=rx=>{}}
            }
        } else {
            return Ok(());
        }
    }
}

#[derive(Debug)]
struct DialFailure(std::io::Error);
impl std::fmt::Display for DialFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "edge dial: {}", self.0)
    }
}
impl std::error::Error for DialFailure {}

async fn drain_registered(
    runtime: &Runtime,
    registered: RegisteredConnection,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<()> {
    let deadline = Instant::now() + runtime.config.grace_period;
    let unregister = registered.unregister(runtime.config.grace_period);
    tokio::select! {_=runtime.force.cancelled()=>{},result=unregister=>{if let Err(error)=result{eprintln!("Error shutting down control stream: {error}");}}}
    tokio::select! {_=runtime.force.cancelled()=>{},_=tokio::time::sleep_until(deadline)=>{},_=async{while tasks.join_next().await.is_some(){}}=>{}}
    tasks.abort_all();
    Ok(())
}

async fn serve_quic(
    runtime: Arc<Runtime>,
    tls: &EdgeTls,
    index: u8,
    address: SocketAddr,
    retries: u32,
    reset_after: &mut Option<Instant>,
) -> Result<()> {
    let options = edge_options(&runtime.config);
    let mut conn = tokio::select! {_=runtime.shutdown.cancelled()=>return Ok(()),result=transport::quic::dial_with_options(address,"quic.cftunnel.com",tls,&options)=>result.map_err(DialFailure)?};
    let snapshot = runtime.features.snapshot(true);
    let pending = scope::PendingSessionContext::new(
        &runtime.config,
        index,
        "quic",
        address,
        snapshot.clone(),
        runtime.config.management_hostname.clone(),
    );
    let requests = pending.requests();
    let connection = crate::network::Connection::new(
        runtime.network.clone(),
        &pending,
        conn.sender(),
        runtime.config.rpc_timeout,
        runtime.config.write_stream_timeout,
    );
    let control = conn.open_bi().await?;
    let registration = registration::register_connection(
        control,
        runtime.request(index, address, retries, &snapshot),
        runtime.config.rpc_timeout,
        runtime.context.metrics.clone(),
    );
    tokio::pin!(registration);
    let mut registered = None::<RegisteredConnection>;
    let mut _lease = None;
    let mut incoming = conn.take_incoming()?;
    let shared = runtime.clone();
    let datagram_connection = connection.clone();
    let cancel = pending.cancellation();
    let mut datagrams = AbortTask(tokio::task::spawn_local(async move {
        loop {
            let bytes = tokio::select! {
                _ = cancel.cancelled() => return Ok::<_,anyhow::Error>(()),
                bytes = incoming.datagrams.recv() => bytes.context("datagram manager closed")?,
            };
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = datagram_connection.handle(bytes) => {
                    if let Err(error)=result {shared.warn(&format!("Failed to handle datagram: {error}"));}
                }
            }
        }
    }));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = runtime.shutdown.cancelled() => {
                if let Some(registered) = registered { drain_registered(&runtime, registered, &mut tasks).await?; }
                conn.close();
                return Ok(());
            }
            result = &mut registration, if registered.is_none() => {
                let value = result.map_err(|error|runtime.registration_failure(error))?;
                _lease = Some(runtime.registered(index, EdgeProtocol::Quic, address, &value).await?);
                push_local_configuration(&runtime, index, &value, &mut tasks).await?;
                registered = Some(value);
                *reset_after = Some(Instant::now() + Duration::from_secs(4 * (1u64 << retries.min(31))));
            }
            _ = async {
                if let Some(registered) = registered.as_mut() { registered.disconnected().await }
                else { futures::future::pending().await }
            } => bail!(RegistrationError::Disconnected),
            stream = incoming.streams.recv() => {
                let stream = stream.context("failed to accept QUIC stream")?;
                let shared = runtime.clone();
                let requests = requests.clone();
                let network = connection.clone();
                tasks.spawn_local(async move {
                    let cancel = requests.cancellation();
                    tokio::select! {
                        _ = cancel.cancelled() => Ok(()),
                        result = handle_quic(shared, requests, network, stream) => result,
                    }
                });
            }
            result = &mut datagrams.0 => {
                result??;
                bail!("datagram worker stopped");
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Some(Ok(Err(error))) => runtime.warn(&format!("Failed to handle QUIC stream: {error}")),
                    Some(Err(error)) => runtime.warn(&format!("QUIC task: {error}")),
                    _ => {}
                }
            }
        }
    }
}

async fn handle_quic(
    runtime: Arc<Runtime>,
    requests: scope::RequestContext,
    network: Arc<crate::network::Connection>,
    mut stream: transport::quic::QuicStream,
) -> Result<()> {
    stream.set_write_timeout(runtime.config.write_stream_timeout);
    match metadata::read_stream_kind(&mut stream).await? {
        StreamKind::Data => {
            let request = metadata::read_connect_request(&mut stream).await?;
            let host = request
                .metadata
                .iter()
                .rev()
                .find(|(key, _)| key == "HttpHost")
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            if request.connection_type != metadata::ConnectionType::Tcp
                && let Some(receipt) = requests.management_request(host)
            {
                return management_quic(&runtime, receipt, stream, request).await;
            }
            if request.connection_type == metadata::ConnectionType::Tcp {
                if runtime.config.quick_authorizer.is_some() {
                    metadata::write_connect_response(
                        &mut stream,
                        &metadata::ConnectResponse {
                            error: "HTTP authorization does not support private TCP".into(),
                            metadata: vec![],
                        },
                    )
                    .await?;
                    return Ok(());
                }
                runtime.network.serve_quic_tcp(stream, request).await
            } else {
                proxy::serve_quic(stream, request, runtime.proxy.clone()).await
            }
        }
        StreamKind::Rpc => {
            callbacks::serve_callbacks(
                stream,
                Rc::new(Callback {
                    runtime: runtime.clone(),
                    network: Some(network),
                }),
                runtime.config.rpc_timeout,
                runtime.context.metrics.clone(),
            )
            .await?;
            Ok(())
        }
    }
}

async fn serve_h2(
    runtime: Arc<Runtime>,
    tls: &EdgeTls,
    index: u8,
    address: SocketAddr,
    retries: u32,
    reset_after: &mut Option<Instant>,
) -> Result<()> {
    let options = edge_options(&runtime.config);
    let (mut conn, local_address) = tokio::select! {_=runtime.shutdown.cancelled()=>return Ok(()),result=transport::h2::dial_with_options_and_addr(address,"h2.cftunnel.com",tls,&options)=>result.map_err(DialFailure)?};
    let snapshot = runtime.features.snapshot(true);
    let pending = scope::PendingSessionContext::new(
        &runtime.config,
        index,
        "http2",
        address,
        snapshot.clone(),
        runtime.config.management_hostname.clone(),
    );
    let requests = pending.requests();
    let mut registered = None::<RegisteredConnection>;
    let mut control_pending = false;
    let mut tasks = JoinSet::new();
    let (tx, mut rx) =
        mpsc::unbounded_channel::<std::result::Result<RegisteredConnection, RegistrationError>>();
    let mut _lease = None;
    let mut _control_pump = None;
    loop {
        tokio::select! {
            _ = runtime.shutdown.cancelled() => {
                if let Some(registered) = registered {
                    conn.graceful_shutdown();
                    let draining = drain_registered(&runtime, registered, &mut tasks);
                    tokio::pin!(draining);
                    tokio::select! {
                        result = &mut draining => result?,
                        _ = futures::future::poll_fn(|cx| conn.poll_closed(cx)) => { draining.await?; }
                    }
                }
                return Ok(());
            }
            _ = async {
                if let Some(registered) = registered.as_mut() { registered.disconnected().await }
                else { futures::future::pending().await }
            } => bail!(RegistrationError::Disconnected),
            result = rx.recv(), if control_pending => {
                let value = result.context("control registration task closed")?.map_err(|error|runtime.registration_failure(error))?;
                _lease = Some(runtime.registered(index, EdgeProtocol::Http2, address, &value).await?);
                push_local_configuration(&runtime, index, &value, &mut tasks).await?;
                registered = Some(value);
                control_pending = false;
                *reset_after = Some(Instant::now() + Duration::from_secs(4 * (1u64 << retries.min(31))));
            }
            incoming = conn.accept() => {
                let (request, mut response) = incoming.context("connection with edge closed")??;
                let upgrade = request.headers().get("cf-cloudflared-proxy-connection-upgrade")
                    .and_then(|value| value.to_str().ok()).unwrap_or("").to_owned();
                match upgrade.as_str() {
                    "control-stream" => {
                        if control_pending || registered.is_some() {
                            response.send_response(http::Response::builder().status(409).body(())?, true)?;
                            continue;
                        }
                        control_pending = true;
                        let send = response.send_response(http::Response::builder().status(200).body(())?, false)?;
                        let (control, pump) = h2_control::bridge(request.into_body(), send);
                        _control_pump = Some(AbortTask(pump));
                        let tx = tx.clone();
                        let shared = runtime.clone();
                        let snapshot = snapshot.clone();
                        tasks.spawn_local(async move {
                            let result = registration::register_connection(control, shared.request(index, local_address, retries, &snapshot), shared.config.rpc_timeout,shared.context.metrics.clone()).await;
                            let _ = tx.send(result);
                            Ok(())
                        });
                    }
                    "update-configuration" => { tasks.spawn_local(configuration_request(request, response, runtime.clone())); }
                    _ => {
                        let shared = runtime.clone();
                        let private_tcp=request.headers().get("cf-cloudflared-proxy-src").is_some_and(|value|!value.is_empty());
                        let receipt = if private_tcp {None}else{request.uri().authority().and_then(|authority| requests.management_request(authority.as_str()))};
                        let cancel = requests.cancellation();
                        tasks.spawn_local(async move {
                            tokio::select! {
                                _ = cancel.cancelled() => Ok(()),
                                result = async {
                                    if let Some(receipt) = receipt {
                                        management_h2(&shared, receipt, request, response).await
                                    } else if request.headers().get("cf-cloudflared-proxy-src").is_some_and(|value| !value.is_empty()) {
                                        if shared.config.quick_authorizer.is_some() {
                                            response.send_response(http::Response::builder().status(502).body(())?, true)?;
                                            return Ok(());
                                        }
                                        shared.network.clone().serve_h2_tcp(request, response).await
                                    } else {
                                        proxy::serve_h2(request, response, shared.proxy.clone()).await
                                    }
                                } => result,
                            }
                        });
                    }
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Some(Ok(Err(error))) => runtime.warn(&format!("Failed to serve incoming request: {error}")),
                    Some(Err(error)) => runtime.warn(&format!("H2 request task: {error}")),
                    _ => {}
                }
            }
        }
    }
}

async fn push_local_configuration(
    runtime: &Runtime,
    index: u8,
    registered: &RegisteredConnection,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<()> {
    if index == 0 && !registered.details().remotely_managed {
        let pending = registered.send_local_configuration(&runtime.local_configuration().await?);
        let context = runtime.context.clone();
        context.metrics.local_config_pushes.inc();
        tasks.spawn_local(async move {
            if let Err(error) = pending.await {
                context.metrics.local_config_pushes_errors.inc();
                let _ = context.logger.log(
                    crate::observability::logging::Level::Error,
                    crate::observability::logging::Event::Cloudflared,
                    &format!("unable to send local configuration: {error}"),
                    serde_json::json!({}),
                );
            }
            Ok(())
        });
    }
    Ok(())
}

fn log_management(runtime: &Runtime, receipt: &scope::EdgeManagementRequest) {
    let _=runtime.context.logger.log(crate::observability::logging::Level::Debug,crate::observability::logging::Event::Http,"Management request received",serde_json::json!({"connIndex":receipt.connection_index(),"protocol":receipt.transport(),"edgeAddress":receipt.peer().ip()}));
}

async fn management_quic(
    runtime: &Runtime,
    receipt: scope::EdgeManagementRequest,
    mut stream: transport::quic::QuicStream,
    request: metadata::ConnectRequest,
) -> Result<()> {
    log_management(runtime, &receipt);
    use tokio::io::AsyncWriteExt;
    let head = management_head(&request)?;
    let response = runtime.management.handle_http(&receipt, &head).await?;
    let status = response.status().as_u16();
    let mut headers = vec![("HttpStatus".into(), status.to_string())];
    for (name, value) in response.headers() {
        headers.push((
            format!("HttpHeader:{}", name.as_str()),
            value.to_str()?.into(),
        ));
    }
    metadata::write_connect_response(
        &mut stream,
        &metadata::ConnectResponse {
            error: String::new(),
            metadata: headers,
        },
    )
    .await?;
    if status == 101 {
        runtime
            .management
            .stream_logs(receipt, head.uri().query(), stream)
            .await
    } else {
        stream.write_all(response.body()).await?;
        stream.shutdown().await?;
        Ok(())
    }
}

fn management_head(request: &metadata::ConnectRequest) -> Result<http::Request<()>> {
    let method = request
        .metadata
        .iter()
        .rev()
        .find(|(key, _)| key == "HttpMethod")
        .map(|(_, value)| value.as_str())
        .filter(|method| !method.is_empty())
        .unwrap_or("GET");
    let host = request
        .metadata
        .iter()
        .rev()
        .find(|(key, _)| key == "HttpHost")
        .map(|(_, value)| value.as_str())
        .context("missing management request Host")?;
    let authority: http::uri::Authority =
        host.parse().context("invalid management request Host")?;
    let mut parts = request.destination.parse::<http::Uri>()?.into_parts();
    parts.authority = Some(authority.clone());
    if parts.scheme.is_none() {
        parts.scheme = Some(http::uri::Scheme::HTTPS);
    }
    let mut head = http::Request::builder()
        .method(method)
        .uri(http::Uri::from_parts(parts)?);
    for (key, value) in &request.metadata {
        if let Some(name) = key.strip_prefix("HttpHeader:") {
            head = head.header(name, value);
        }
    }
    let mut head = head.body(())?;
    head.headers_mut().insert(
        http::header::HOST,
        http::HeaderValue::from_str(authority.as_str())?,
    );
    Ok(head)
}

async fn management_h2(
    runtime: &Runtime,
    receipt: scope::EdgeManagementRequest,
    request: http::Request<h2::RecvStream>,
    mut response: h2::server::SendResponse<Bytes>,
) -> Result<()> {
    log_management(runtime, &receipt);
    let (parts, body) = request.into_parts();
    let head = http::Request::from_parts(parts, ());
    let result = runtime.management.handle_http(&receipt, &head).await?;
    let upgrade = result.status() == 101;
    let status = if upgrade {
        200
    } else {
        result.status().as_u16()
    };
    let mut output = http::Response::builder()
        .status(status)
        .header("cf-cloudflared-response-meta", r#"{"src":"origin"}"#);
    let headers = result
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    output = output.header(
        "cf-cloudflared-response-headers",
        crate::protocol::headers::serialize(&headers),
    );
    let mut send = response.send_response(output.body(())?, false)?;
    if upgrade {
        let (stream, pump) = h2_control::bridge(body, send);
        let _pump = AbortTask(pump);
        runtime
            .management
            .stream_logs(receipt, head.uri().query(), stream)
            .await
    } else {
        h2_control::send_data(&mut send, result.body().clone()).await?;
        send.send_data(Bytes::new(), true)?;
        Ok(())
    }
}

fn edge_options(config: &RunConfig) -> transport::EdgeDialOptions {
    transport::EdgeDialOptions {
        bind_ip: config.edge_bind_address,
        dial_timeout: config.dial_edge_timeout,
        quic_disable_pmtu_discovery: config.quic_disable_pmtu_discovery,
        connection_window: config.connection_window,
        stream_window: config.stream_window,
    }
}

async fn configuration_request(
    request: http::Request<h2::RecvStream>,
    mut response: h2::server::SendResponse<Bytes>,
    runtime: Arc<Runtime>,
) -> Result<()> {
    let mut receive = request.into_body();
    let mut body = Vec::new();
    while let Some(bytes) = receive.data().await {
        let bytes = bytes?;
        if body.len() + bytes.len() > 64 * 1024 * 1024 {
            response.send_response(
                http::Response::builder()
                    .status(502)
                    .header("cf-cloudflared-response-meta", r#"{"src":"cloudflared"}"#)
                    .body(())?,
                true,
            )?;
            return Ok(());
        }
        body.extend_from_slice(&bytes);
        receive.flow_control().release_capacity(bytes.len())?;
    }
    #[derive(serde::Deserialize)]
    struct Update {
        #[serde(default)]
        version: i32,
        #[serde(default)]
        config: serde_json::Value,
    }
    let update = match serde_json::from_slice::<Update>(&body) {
        Ok(update) => update,
        Err(_) => {
            response.send_response(
                http::Response::builder()
                    .status(502)
                    .header("cf-cloudflared-response-meta", r#"{"src":"cloudflared"}"#)
                    .body(())?,
                true,
            )?;
            return Ok(());
        }
    };
    let result = runtime
        .update(update.version, serde_json::to_vec(&update.config)?)
        .await;
    // Go's error interface serializes as an empty object on this HTTP endpoint.
    let error = if result.error.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::json!({})
    };
    let body = serde_json::to_vec(
        &serde_json::json!({"lastAppliedVersion":result.latest_applied_version,"err":error}),
    )?;
    let mut send =
        response.send_response(http::Response::builder().status(200).body(())?, false)?;
    h2_control::send_data(&mut send, Bytes::from(body)).await?;
    send.send_data(Bytes::new(), true)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
