mod discovery;
mod h2_control;
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

const FEATURES: &[&str] = &[
    "serialized_headers",
    "support_quic_eof",
    "allow_remote_config",
];

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
    fn response(&self, client_id: Uuid) -> (u16, Vec<u8>) {
        let count = self.count();
        let status = if count > 0 { 200 } else { 503 };
        (status,serde_json::to_vec(&serde_json::json!({"status":status,"readyConnections":count,"connectorId":client_id})).unwrap())
    }
    fn bind(self: &Arc<Self>, registered: &RegisteredConnection) -> Lease {
        let index = registered.identity().connection_index();
        let generation = self.next.fetch_add(1, Ordering::Relaxed);
        self.slots.lock().unwrap().insert(
            index,
            LiveSlot {
                generation,
                liveness: registered.liveness(),
            },
        );
        Lease {
            state: self.clone(),
            index,
            generation,
        }
    }
}
struct Lease {
    state: Arc<Readiness>,
    index: u8,
    generation: u64,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut slots = self.state.slots.lock().unwrap();
        if slots
            .get(&self.index)
            .is_some_and(|s| s.generation == self.generation)
        {
            slots.remove(&self.index);
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
    fn request(
        &self,
        index: u8,
        address: SocketAddr,
        previous_attempts: u32,
    ) -> RegistrationRequest {
        RegistrationRequest {
            auth: TunnelAuth {
                account_tag: self.config.credentials.account_tag.clone(),
                tunnel_secret: self.config.credentials.tunnel_secret.clone(),
            },
            tunnel_id: self.config.credentials.tunnel_id,
            connection_index: index,
            client_id: self.client_id,
            features: FEATURES.iter().map(|s| (*s).into()).collect(),
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
        if let Err(error) = self.proxy.replace(next.clone()).await {
            return ConfigurationResult {
                latest_applied_version: current.version,
                error: error.to_string(),
            };
        }
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
        registered: &RegisteredConnection,
    ) -> Result<Lease> {
        if index != registered.identity().connection_index() {
            bail!("registration index does not match connection owner");
        }
        let lease = self.readiness.bind(registered);
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
struct Callback(Arc<Runtime>);
impl EdgeCallbacks for Callback {
    fn update_configuration(
        &self,
        version: i32,
        config: Vec<u8>,
    ) -> LocalBoxFuture<'static, ConfigurationResult> {
        let runtime = self.0.clone();
        async move { runtime.update(version, config).await }.boxed_local()
    }
    fn register_udp_session(
        &self,
        _request: UdpRegistration,
    ) -> LocalBoxFuture<'static, Result<UdpRegistrationResult, capnp::Error>> {
        async {
            Err(capnp::Error::unimplemented(
                "UDP session support is not advertised".into(),
            ))
        }
        .boxed_local()
    }
    fn unregister_udp_session(
        &self,
        _id: Uuid,
        _message: String,
    ) -> LocalBoxFuture<'static, Result<(), capnp::Error>> {
        async {
            Err(capnp::Error::unimplemented(
                "UDP session support is not advertised".into(),
            ))
        }
        .boxed_local()
    }
}

struct AbortTask<T>(JoinHandle<T>);
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
    config: RunConfig,
    shutdown: CancellationToken,
    force: CancellationToken,
) -> Result<()> {
    let edge_tls = tls(&config)?;
    let pool = tokio::select! {_=shutdown.cancelled()=>return Ok(()),result=discovery::resolve(&config)=>result?};
    let count = usize::from(config.ha_connections).min(pool.available());
    if count == 0 {
        bail!("no HA connections available");
    }
    let pool = Arc::new(Mutex::new(pool));
    let proxy = Arc::new(ProxyState::new(&config)?);
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
    let runtime = Arc::new(Runtime {
        configuration: tokio::sync::Mutex::new(ConfigurationState {
            version: -1,
            current: configuration,
        }),
        config,
        proxy,
        readiness: readiness.clone(),
        client_id: Uuid::from_bytes(random),
        events,
        shutdown: shutdown.clone(),
        force: force.clone(),
        ever_quic: AtomicBool::new(false),
        notify_socket: std::env::var_os("NOTIFY_SOCKET"),
        startup_announced: AtomicBool::new(false),
    });
    let health = if runtime.config.metrics.is_empty() {
        None
    } else {
        Some(
            health_server(
                &runtime.config.metrics,
                readiness.clone(),
                runtime.client_id,
                shutdown.clone(),
            )
            .await?,
        )
    };
    let result = supervise(runtime.clone(), pool, edge_tls, count, event_rx).await;
    readiness.shutting_down.store(true, Ordering::Release);
    shutdown.cancel();
    drop(health);
    result
}

async fn health_server(
    address: &str,
    state: Arc<Readiness>,
    client_id: Uuid,
    shutdown: CancellationToken,
) -> Result<AbortTask<()>> {
    let listener = metrics_listener(address).await?;
    eprintln!(
        "Starting metrics server on {}/metrics",
        listener.local_addr()?
    );
    Ok(AbortTask(tokio::task::spawn_local(async move {
        loop {
            let accepted =
                tokio::select! {_=shutdown.cancelled()=>break,result=listener.accept()=>result};
            let Ok((socket, _)) = accepted else {
                break;
            };
            let state = state.clone();
            tokio::task::spawn_local(async move {
                let service = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| {
                        let state = state.clone();
                        async move {
                            let (status, body) = match request.uri().path() {
                                "/ready" => state.response(client_id),
                                "/healthcheck" => (200, b"OK\n".to_vec()),
                                "/debug/pprof/cmdline" => (403, b"forbidden\n".to_vec()),
                                path if path.starts_with("/debug/pprof/")
                                    || path.starts_with("/debug/requests")
                                    || path.starts_with("/debug/events") =>
                                {
                                    (501, b"Go runtime diagnostics are not available\n".to_vec())
                                }
                                "/metrics" => (501, b"metrics are not implemented\n".to_vec()),
                                _ => (404, b"not found\n".to_vec()),
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .body(http_body_util::Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .await;
            });
        }
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
            _=runtime.shutdown.cancelled()=>break,
            event=events.recv()=>match event{
                Some(Event::Connected(index,protocol))=>{
                    if index==0&&!first{first=true;launches=Some((Instant::now(),protocol));}
                    if runtime.readiness.slots.lock().unwrap().values().filter(|s|s.liveness.is_ready()).count()==count&&pending.is_empty(){global_reset_after=Some(Instant::now()+Duration::from_secs(40*(1u64<<global_retries.min(31))));}
                },
                Some(Event::Retry(reply))=>{pending.push(reply);if retry_deadline.is_none(){if global_reset_after.is_some_and(|deadline|Instant::now()>deadline){global_retries=0;global_reset_after=None;}retry_deadline=Some(Instant::now()+backoff(global_retries,10,runtime.config.retries)?);global_retries=global_retries.saturating_add(1);}},
                None=>break,
            },
            _=async{if let Some((deadline,_))=launches{tokio::time::sleep_until(deadline).await}else{futures::future::pending().await}}=>{
                if next_index<count{let protocol=launches.unwrap().1;tasks.spawn_local(lane(runtime.clone(),pool.clone(),tls.clone(),next_index as u8,protocol));next_index+=1;launches=if next_index<count{Some((Instant::now()+Duration::from_secs(1),protocol))}else{None};}else{launches=None;}
            },
            _=async{if let Some(deadline)=retry_deadline{tokio::time::sleep_until(deadline).await}else{futures::future::pending().await}}=>{retry_deadline=None;for reply in pending.drain(..){let _=reply.send(());}},
            completed=tasks.join_next(),if !tasks.is_empty()=>{
                match completed{Some(Err(error))=>{terminal=Some(error.into());break;},Some(Ok(Err(error)))=>{terminal=Some(error);break;},_=>{}}
                if tasks.is_empty()&&launches.is_none(){break;}
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
            if protocol == EdgeProtocol::Quic
                && runtime.config.protocol == Protocol::Auto
                && !runtime.ever_quic.load(Ordering::Acquire)
                && (max_addresses || exhausted)
            {
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
    let control = conn.open_bi().await?;
    let mut registered = tokio::select! {_=runtime.shutdown.cancelled()=>return Ok(()),result=registration::register_connection(control,runtime.request(index,address,retries),runtime.config.rpc_timeout)=>result.map_err(RegistrationFailure)?};
    let _lease = runtime
        .registered(index, EdgeProtocol::Quic, &registered)
        .await?;
    *reset_after = Some(Instant::now() + Duration::from_secs(4 * (1u64 << retries.min(31))));
    let mut tasks = JoinSet::new();
    push_local_configuration(&runtime, index, &registered, &mut tasks).await?;
    loop {
        tokio::select! {
            _=runtime.shutdown.cancelled()=>{drain_registered(&runtime,registered,&mut tasks).await?;conn.close();return Ok(());},
            _=registered.disconnected()=>bail!(RegistrationError::Disconnected),
            stream=conn.accept_bi()=>{let mut stream=stream?;stream.set_write_timeout(runtime.config.write_stream_timeout);let shared=runtime.clone();tasks.spawn_local(async move{
                match metadata::read_stream_kind(&mut stream).await?{
                    StreamKind::Data=>{let request=metadata::read_connect_request(&mut stream).await?;proxy::serve_quic(stream,request,shared.proxy.clone()).await},
                    StreamKind::Rpc=>{callbacks::serve_callbacks(stream,Rc::new(Callback(shared.clone())),shared.config.rpc_timeout).await?;Ok(())},
                }
            });},
            result=tasks.join_next(),if !tasks.is_empty()=>{if let Some(result)=result{match result{Ok(Err(error))=>eprintln!("Failed to handle QUIC stream connIndex={index}: {error}"),Err(error)=>eprintln!("QUIC stream task connIndex={index}: {error}"),_=>{}}}},
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
    let mut registered = None::<RegisteredConnection>;
    let mut control_pending = false;
    let mut tasks = JoinSet::new();
    let (tx, mut rx) =
        mpsc::unbounded_channel::<std::result::Result<RegisteredConnection, RegistrationError>>();
    let mut _lease = None;
    let mut _control_pump = None;
    loop {
        tokio::select! {
            _=runtime.shutdown.cancelled()=>{if let Some(registered)=registered{conn.graceful_shutdown();let draining=drain_registered(&runtime,registered,&mut tasks);tokio::pin!(draining);tokio::select!{result=&mut draining=>result?,_=futures::future::poll_fn(|cx|conn.poll_closed(cx))=>{draining.await?;}}}else{tasks.abort_all();}return Ok(());},
            _=async{if let Some(registered)=registered.as_mut(){registered.disconnected().await}else{futures::future::pending().await}}=>bail!(RegistrationError::Disconnected),
            result=rx.recv(),if control_pending=>{let result=result.context("control registration task closed")?;let value:RegisteredConnection=result.map_err(RegistrationFailure)?;_lease=Some(runtime.registered(index,EdgeProtocol::Http2,&value).await?);push_local_configuration(&runtime,index,&value,&mut tasks).await?;registered=Some(value);control_pending=false;*reset_after=Some(Instant::now()+Duration::from_secs(4*(1u64<<retries.min(31))));
            },
            incoming=conn.accept()=>{let (request,mut response)=incoming.context("connection with edge closed")??;
                let upgrade=request.headers().get("cf-cloudflared-proxy-connection-upgrade").and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();
                match upgrade.as_str(){
                    "control-stream"=>{if control_pending||registered.is_some(){response.send_response(http::Response::builder().status(409).body(())?,true)?;continue;}control_pending=true;
                        let send=response.send_response(http::Response::builder().status(200).body(())?,false)?;
                        let (control,pump)=h2_control::bridge(request.into_body(),send);_control_pump=Some(AbortTask(pump));let tx=tx.clone();let shared=runtime.clone();
                        tasks.spawn_local(async move{let result=registration::register_connection(control,shared.request(index,local_address,retries),shared.config.rpc_timeout).await;let _=tx.send(result);Ok(())});
                    },
                    "update-configuration"=>{tasks.spawn_local(configuration_request(request,response,runtime.clone()));},
                    _=>{let shared=runtime.clone();tasks.spawn_local(proxy::serve_h2(request,response,shared.proxy.clone()));},
                }
            },
            result=tasks.join_next(),if !tasks.is_empty()=>{if let Some(result)=result{match result{Ok(Err(error))=>eprintln!("failed to serve incoming request connIndex={index}: {error}"),Err(error)=>eprintln!("H2 request task connIndex={index}: {error}"),_=>{}}}},
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
        tasks.spawn_local(async move {
            if let Err(error) = pending.await {
                eprintln!("unable to send local configuration: {error}");
            }
            Ok(())
        });
    }
    Ok(())
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
mod tests;
