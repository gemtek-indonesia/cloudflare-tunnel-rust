use super::{Connection, DatagramVersion, Permit};
use crate::{
    protocol::{
        callbacks::UdpRegistration,
        datagram::{DatagramV2, DatagramV3},
    },
    transport::quic::QuicSender,
};
use anyhow::Result;
use bytes::Bytes;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct Route {
    index: u8,
    generation: uuid::Uuid,
    sender: QuicSender,
    cancel: CancellationToken,
}
struct MigrationRequest {
    route: Route,
    accepted: tokio::sync::oneshot::Sender<()>,
}
struct PendingMigration {
    requests: mpsc::Sender<MigrationRequest>,
    route: Route,
    session_cancel: CancellationToken,
    activity: watch::Sender<Instant>,
}
struct Session {
    generation: u64,
    creator_index: u8,
    socket: Arc<tokio::net::UdpSocket>,
    route: watch::Sender<Route>,
    activity: watch::Sender<Instant>,
    input: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    remote: AtomicBool,
    version: DatagramVersion,
    started: tokio::sync::Notify,
    metrics: Arc<crate::observability::metrics::Metrics>,
    migrations: Option<mpsc::Sender<MigrationRequest>>,
    #[cfg(test)]
    write_fault: Mutex<Option<OriginWriteFault>>,
}
#[cfg(test)]
pub(super) enum OriginWriteOutcome {
    Send,
    Short(usize),
    Error(std::io::Error),
}
#[cfg(test)]
struct OriginWriteFault {
    entered: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<OriginWriteOutcome>,
}
#[derive(Clone, Copy, PartialEq)]
enum RegistrationKind {
    New,
    Retry,
    Migration,
}
struct V3Registration {
    generation: u64,
    kind: RegistrationKind,
    registry: Weak<Registry>,
    id: [u8; 16],
    owns_pending_creation: bool,
    migration: Option<PendingMigration>,
}
impl V3Registration {
    async fn accept_migration(&mut self) -> Result<()> {
        let Some(migration) = self.migration.take() else {
            return Ok(());
        };
        let attempt_cancel = migration.route.cancel.clone();
        let (accepted, acceptance) = tokio::sync::oneshot::channel();
        tokio::select! {
            biased;
            _ = attempt_cancel.cancelled() => anyhow::bail!("migration attempt canceled"),
            _ = migration.session_cancel.cancelled() => anyhow::bail!("migration session closed"),
            result = migration.requests.send(MigrationRequest { route: migration.route, accepted }) => {
                result.map_err(|_| anyhow::anyhow!("migration session closed"))?;
            }
        }
        tokio::select! {
            biased;
            _ = attempt_cancel.cancelled() => anyhow::bail!("migration attempt canceled"),
            _ = migration.session_cancel.cancelled() => anyhow::bail!("migration session closed"),
            result = acceptance => result.map_err(|_| anyhow::anyhow!("migration session closed"))?,
        }
        migration.activity.send_replace(Instant::now());
        Ok(())
    }
}
impl Drop for V3Registration {
    fn drop(&mut self) {
        if self.owns_pending_creation
            && let Some(registry) = self.registry.upgrade()
        {
            registry.remove_now(self.id, Some(self.generation));
        }
    }
}
impl Session {
    async fn send_origin(&self, payload: &[u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        {
            let fault = self.write_fault.lock().unwrap().take();
            if let Some(fault) = fault {
                let _ = fault.entered.send(());
                match fault
                    .release
                    .await
                    .map_err(|_| std::io::Error::other("origin write gate closed"))?
                {
                    OriginWriteOutcome::Send => {}
                    OriginWriteOutcome::Short(n) => return Ok(n),
                    OriginWriteOutcome::Error(error) => return Err(error),
                }
            }
        }
        self.socket.send(payload).await
    }
    fn untrack(&self) {
        if self.version == DatagramVersion::V2 {
            self.metrics.udp_active_sessions.dec();
        } else {
            self.metrics
                .udp_active_flows
                .with_label_values(&[&self.creator_index.to_string()])
                .dec();
        }
    }
    fn dropped(&self, reason: &str) {
        let index = self.route.borrow().index;
        self.metrics
            .udp_dropped_datagrams
            .with_label_values(&[&index.to_string(), reason])
            .inc();
    }
}
pub(crate) struct Registry {
    sessions: Mutex<HashMap<[u8; 16], Arc<Session>>>,
    generation: AtomicU64,
    creation: tokio::sync::Mutex<()>,
}
impl Drop for Registry {
    fn drop(&mut self) {
        for session in self.sessions.get_mut().unwrap().values() {
            session.untrack();
            session.cancel.cancel();
        }
    }
}
impl Registry {
    #[cfg(test)]
    pub(super) fn gate_next_origin_write(
        &self,
        id: [u8; 16],
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<OriginWriteOutcome>,
    ) {
        let session = self.sessions.lock().unwrap().get(&id).cloned().unwrap();
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, outcome) = tokio::sync::oneshot::channel();
        let mut fault = session.write_fault.lock().unwrap();
        assert!(fault.is_none(), "origin write gate already armed");
        *fault = Some(OriginWriteFault {
            entered,
            release: outcome,
        });
        (observed, release)
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(1),
            creation: tokio::sync::Mutex::new(()),
        })
    }
    pub(crate) async fn remove(&self, id: [u8; 16], generation: Option<u64>) -> bool {
        self.remove_now(id, generation)
    }
    fn remove_now(&self, id: [u8; 16], generation: Option<u64>) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions
            .get(&id)
            .is_some_and(|s| generation.is_none_or(|g| s.generation == g))
        {
            if let Some(session) = sessions.remove(&id) {
                session.untrack();
                session.remote.store(true, Ordering::Release);
                session.cancel.cancel();
            }
            true
        } else {
            false
        }
    }
    async fn create(
        self: &Arc<Self>,
        connection: Arc<Connection>,
        id: [u8; 16],
        address: std::net::SocketAddr,
        idle: Duration,
        start_immediately: bool,
    ) -> Result<Arc<Session>> {
        let permit = connection.state.limiter.acquire()?;
        let socket = Arc::new(connection.state.dial_udp(address).await?);
        let (input, receiver) = mpsc::channel(512);
        let (route, _) = watch::channel(Route {
            index: connection.index,
            generation: connection.generation,
            sender: connection.sender.clone(),
            cancel: connection.cancel.clone(),
        });
        let (activity, _) = watch::channel(Instant::now());
        let (migrations, migration_requests) = if connection.version == DatagramVersion::V3 {
            let (sender, receiver) = mpsc::channel(1);
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        let session = Arc::new(Session {
            generation: self.generation.fetch_add(1, Ordering::Relaxed),
            creator_index: connection.index,
            socket,
            route,
            activity,
            input,
            cancel: CancellationToken::new(),
            remote: AtomicBool::new(false),
            version: connection.version,
            started: tokio::sync::Notify::new(),
            metrics: connection.state.context.metrics.clone(),
            migrations,
            #[cfg(test)]
            write_fault: Mutex::new(None),
        });
        let previous = {
            let mut sessions = self.sessions.lock().unwrap();
            if session.version == DatagramVersion::V2 {
                session.metrics.udp_total_sessions.inc();
                session.metrics.udp_active_sessions.inc();
            } else {
                session
                    .metrics
                    .udp_total_flows
                    .with_label_values(&[&session.creator_index.to_string()])
                    .inc();
                session
                    .metrics
                    .udp_active_flows
                    .with_label_values(&[&session.creator_index.to_string()])
                    .inc();
            }
            let previous = sessions.insert(id, session.clone());
            if let Some(previous) = &previous {
                previous.untrack();
            }
            previous
        };
        if let Some(previous) = previous {
            previous.remote.store(true, Ordering::Release);
            previous.cancel.cancel();
        }
        let registry = Arc::downgrade(self);
        let weak = Arc::downgrade(&connection);
        let context = connection.state.context.clone();
        let actor = session.clone();
        let initial_route = session.route.borrow().clone();
        tokio::task::spawn_local(async move {
            if !start_immediately {
                let started = tokio::select! {
                    _ = actor.started.notified() => true,
                    _ = actor.cancel.cancelled() => false,
                    _ = initial_route.cancel.cancelled() => false,
                };
                if !started {
                    if let Some(registry) = registry.upgrade() {
                        registry.remove(id, Some(actor.generation)).await;
                    }
                    return;
                }
            }
            if actor.version == DatagramVersion::V3 {
                let result = V3Lifecycle {
                    registry,
                    id,
                    session: actor,
                    input: receiver,
                    migrations: migration_requests.expect("V3 session owns migration receiver"),
                    permit,
                    idle,
                    target: initial_route,
                }
                .run()
                .await;
                if let Err(failure) = result {
                    let _ = context.logger.log(
                        crate::observability::logging::Level::Error,
                        crate::observability::logging::Event::Udp,
                        "UDP flow closed with an error",
                        serde_json::json!({
                            "error": failure.error.to_string(),
                            "connIndex": failure.index,
                            "flowID": uuid::Uuid::from_bytes(id).simple().to_string(),
                        }),
                    );
                }
            } else {
                serve(registry, weak, id, actor, receiver, permit, idle).await;
            }
        });
        Ok(session)
    }
    pub(crate) async fn register_v2(
        self: &Arc<Self>,
        connection: Arc<Connection>,
        request: UdpRegistration,
    ) -> Result<()> {
        self.create(
            connection,
            *request.session_id.as_bytes(),
            std::net::SocketAddr::new(request.destination, request.port),
            request.idle_hint,
            true,
        )
        .await?;
        Ok(())
    }
    async fn register_v3(
        self: &Arc<Self>,
        connection: Arc<Connection>,
        id: [u8; 16],
        address: std::net::SocketAddr,
        idle: Duration,
    ) -> Result<V3Registration> {
        let _creation = self.creation.lock().await;
        let existing = self.sessions.lock().unwrap().get(&id).cloned();
        if let Some(session) = existing {
            let current = session.route.borrow().clone();
            let migrating =
                current.index != connection.index || current.generation != connection.generation;
            let migration = if migrating {
                let route = Route {
                    index: connection.index,
                    generation: connection.generation,
                    sender: connection.sender.clone(),
                    cancel: connection.cancel.clone(),
                };
                session.route.send_replace(route.clone());
                Some(PendingMigration {
                    requests: session
                        .migrations
                        .as_ref()
                        .expect("V3 session owns migration sender")
                        .clone(),
                    route,
                    session_cancel: session.cancel.clone(),
                    activity: session.activity.clone(),
                })
            } else {
                None
            };
            return Ok(V3Registration {
                generation: session.generation,
                kind: if migrating {
                    RegistrationKind::Migration
                } else {
                    RegistrationKind::Retry
                },
                registry: Arc::downgrade(self),
                id,
                owns_pending_creation: false,
                migration,
            });
        }
        let session = self.create(connection, id, address, idle, false).await?;
        Ok(V3Registration {
            generation: session.generation,
            kind: RegistrationKind::New,
            registry: Arc::downgrade(self),
            id,
            owns_pending_creation: true,
            migration: None,
        })
    }
    async fn response_completed(
        &self,
        id: [u8; 16],
        mut registration: V3Registration,
        sent: bool,
        index: u8,
    ) {
        registration.owns_pending_creation = false;
        if !sent && registration.kind == RegistrationKind::New {
            self.remove_now(id, Some(registration.generation));
            return;
        }
        if !sent {
            return;
        }
        let sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions
            .get(&id)
            .filter(|session| session.generation == registration.generation)
        {
            match registration.kind {
                RegistrationKind::New => session.started.notify_one(),
                RegistrationKind::Retry => {
                    session.activity.send_replace(Instant::now());
                    session
                        .metrics
                        .udp_retry_flow_responses
                        .with_label_values(&[&index.to_string()])
                        .inc();
                }
                RegistrationKind::Migration => {}
            }
        }
    }
    async fn payload(&self, id: [u8; 16], payload: Vec<u8>, connection: &Connection) {
        let session = self.sessions.lock().unwrap().get(&id).cloned();
        let Some(session) = session else {
            if connection.version == DatagramVersion::V3 {
                connection
                    .state
                    .context
                    .metrics
                    .udp_dropped_datagrams
                    .with_label_values(&[&connection.index.to_string(), "write_flow_unknown"])
                    .inc();
            }
            return;
        };
        if session.version == DatagramVersion::V2 {
            session.activity.send_replace(Instant::now());
            if let Err(error) =
                tokio::time::timeout(Duration::from_millis(200), session.socket.send(&payload))
                    .await
            {
                eprintln!("UDP origin write deadline exceeded: {error}");
            }
        } else {
            if matches!(
                session.input.try_send(payload),
                Err(mpsc::error::TrySendError::Full(_))
            ) {
                session.dropped("write_full");
            }
        }
    }
}

struct V3Lifecycle {
    registry: Weak<Registry>,
    id: [u8; 16],
    session: Arc<Session>,
    input: mpsc::Receiver<Vec<u8>>,
    migrations: mpsc::Receiver<MigrationRequest>,
    permit: Permit,
    idle: Duration,
    target: Route,
}
struct V3Failure {
    index: u8,
    error: anyhow::Error,
}
impl V3Lifecycle {
    async fn run(mut self) -> Result<(), V3Failure> {
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn_local(v3_read(self.id, self.session.clone()));
        workers.spawn_local(v3_write(self.session.clone(), self.input));
        let mut activity = self.session.activity.subscribe();
        let mut idle = IdleTimeout::new(DatagramVersion::V3, self.idle);
        let outcome = loop {
            tokio::select! {
                _ = self.session.cancel.cancelled() => break Ok(()),
                _ = self.target.cancel.cancelled() => break Ok(()),
                _ = idle.expired() => break Ok(()),
                completed = workers.join_next() => break match completed {
                    Some(Ok(result)) => result,
                    Some(Err(error)) => Err(error.into()),
                    None => Ok(()),
                },
                result = activity.changed() => {
                    if result.is_err() {
                        break Ok(());
                    }
                    idle.mark_active(Instant::now());
                }
                request = self.migrations.recv() => {
                    let Some(request) = request else {
                        break Ok(());
                    };
                    if request.accepted.is_closed() || request.route.cancel.is_cancelled() {
                        continue;
                    }
                    if request.accepted.send(()).is_ok() {
                        self.target = request.route;
                        self.session.metrics.udp_migrated_flows.with_label_values(&[&self.target.index.to_string()]).inc();
                    }
                }
            }
        };
        self.session.cancel.cancel();
        let index = self.session.route.borrow().index;
        if outcome.is_err() {
            self.session
                .metrics
                .udp_failed_flows
                .with_label_values(&[&index.to_string()])
                .inc();
        }
        drop(self.migrations);
        while workers.join_next().await.is_some() {}
        if let Some(registry) = self.registry.upgrade() {
            registry.remove_now(self.id, Some(self.session.generation));
        }
        drop(self.session);
        drop(self.permit);
        outcome.map_err(|error| V3Failure { index, error })
    }
}
async fn v3_read(id: [u8; 16], session: Arc<Session>) -> Result<()> {
    let mut buffer = [0; 1500];
    loop {
        let n = tokio::select! {
            _ = session.cancel.cancelled() => return Ok(()),
            result = session.socket.recv(&mut buffer) => result?,
        };
        if n > 1280 {
            session.dropped("read_too_large");
            continue;
        }
        let bytes = DatagramV3::Payload {
            id,
            payload: buffer[..n].to_vec(),
        }
        .encode()
        .map_err(anyhow::Error::msg)?;
        let sender = session.route.borrow().sender.clone();
        tokio::select! {
            _ = session.cancel.cancelled() => return Ok(()),
            result = sender.send_datagram(Bytes::from(bytes)) => result?,
        }
        session.activity.send_replace(Instant::now());
    }
}
async fn v3_write(session: Arc<Session>, mut input: mpsc::Receiver<Vec<u8>>) -> Result<()> {
    loop {
        let payload = tokio::select! {
            _ = session.cancel.cancelled() => return Ok(()),
            payload = input.recv() => match payload {
                Some(payload) => payload,
                None => return Ok(()),
            },
        };
        let sent = tokio::select! {
            _ = session.cancel.cancelled() => return Ok(()),
            result = tokio::time::timeout(Duration::from_millis(200), session.send_origin(&payload)) => result,
        };
        match sent {
            Ok(Ok(n)) if n == payload.len() => {
                session.activity.send_replace(Instant::now());
            }
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(_)) => session.dropped("write_failed"),
            Err(_) => session.dropped("write_deadline_exceeded"),
        }
    }
}

async fn serve(
    registry: Weak<Registry>,
    connection: Weak<Connection>,
    id: [u8; 16],
    session: Arc<Session>,
    mut input: mpsc::Receiver<Vec<u8>>,
    _permit: Permit,
    idle: Duration,
) {
    let mut route = session.route.subscribe();
    let mut activity = session.activity.subscribe();
    let mut idle = IdleTimeout::new(session.version, idle);
    let mut buffer = [0; 1500];
    let mut reason = "terminated without error".to_owned();
    loop {
        let target = route.borrow().clone();
        tokio::select! {
            result = route.changed() => {
                if result.is_err() {
                    break;
                }
                idle.mark_active(Instant::now());
            }
            result = activity.changed() => {
                if result.is_err() {
                    break;
                }
                idle.mark_active(*activity.borrow());
            }
            _ = session.cancel.cancelled() => break,
            _ = target.cancel.cancelled() => {
                if route.borrow().generation == target.generation {
                    break;
                }
            }
            _ = idle.expired() => {
                reason = idle_message(idle.duration);
                break;
            }
            result = session.socket.recv(&mut buffer) => {
                if session.version == DatagramVersion::V2 {
                    session.activity.send_replace(Instant::now());
                }
                match result {
                    Ok(n) if n <= 1280 => {
                        let payload = buffer[..n].to_vec();
                        let packet = match session.version {
                            DatagramVersion::V2 => DatagramV2::Udp { session_id: id, payload }.encode(),
                            DatagramVersion::V3 => DatagramV3::Payload { id, payload }.encode(),
                        };
                        if let Ok(packet) = packet {
                            let sender = route.borrow().sender.clone();
                            let sent = tokio::select! {
                                _ = session.cancel.cancelled() => break,
                                result = sender.send_datagram(Bytes::from(packet)) => result,
                            };
                            if let Err(error) = sent {
                                if session.version == DatagramVersion::V2 {
                                    log_send_error(&connection, error.to_string());
                                } else {
                                    reason = error.to_string();
                                    break;
                                }
                            }
                        }
                        if session.version == DatagramVersion::V3 {
                            session.activity.send_replace(Instant::now());
                        }
                    }
                    Ok(n) => {
                        if session.version == DatagramVersion::V2 {
                            session.metrics.packet_too_big_dropped.inc();
                            log_send_error(&connection, format!("origin UDP payload has {n} bytes, which exceeds transport MTU 1280"));
                        }
                    }
                    Err(error) => {
                        reason = error.to_string();
                        break;
                    }
                }
            }
            Some(payload) = input.recv(), if session.version == DatagramVersion::V3 => {
                match tokio::time::timeout(Duration::from_millis(200), session.socket.send(&payload)).await {
                    Ok(Ok(n)) if n == payload.len() => {
                        session.activity.send_replace(Instant::now());
                    }
                    Err(_) => {}
                    Ok(Err(error)) => {
                        reason = error.to_string();
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    let remote = session.remote.load(Ordering::Acquire);
    let version = session.version;
    let removed = if let Some(registry) = registry.upgrade() {
        registry.remove(id, Some(session.generation)).await
    } else {
        false
    };
    drop(session);
    if removed
        && version == DatagramVersion::V2
        && !remote
        && let Some(connection) = connection.upgrade()
    {
        connection.close_v2_session(id, reason).await;
    }
}

fn log_send_error(connection: &Weak<Connection>, error: String) {
    if let Some(connection) = connection.upgrade() {
        let _ = connection.state.context.logger.log(
            crate::observability::logging::Level::Error,
            crate::observability::logging::Event::Udp,
            "Failed to send session payload from destination to transport",
            serde_json::json!({"error": error}),
        );
    }
}

struct IdleTimeout {
    duration: Duration,
    deadline: Instant,
    ticks: Option<tokio::time::Interval>,
}
impl IdleTimeout {
    fn new(version: DatagramVersion, duration: Duration) -> Self {
        let duration = if duration.is_zero() {
            Duration::from_secs(210)
        } else {
            duration
        };
        let now = Instant::now();
        let ticks = if version == DatagramVersion::V2 {
            let frequency = (duration / 8).max(Duration::from_nanos(1));
            let mut ticks = tokio::time::interval_at(now + frequency, frequency);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            Some(ticks)
        } else {
            None
        };
        Self {
            duration,
            deadline: now + duration,
            ticks,
        }
    }
    fn mark_active(&mut self, at: Instant) {
        let active_at = if self.ticks.is_some() {
            at
        } else {
            Instant::now()
        };
        self.deadline = active_at + self.duration;
    }
    async fn expired(&mut self) {
        if let Some(ticks) = &mut self.ticks {
            loop {
                if ticks.tick().await > self.deadline {
                    return;
                }
            }
        } else {
            tokio::time::sleep_until(self.deadline).await;
        }
    }
}

fn idle_message(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    let decimal = |whole, fraction, width, unit: &str| {
        if fraction == 0 {
            format!("{whole}{unit}")
        } else {
            let fraction = format!("{fraction:0width$}");
            format!("{whole}.{}{unit}", fraction.trim_end_matches('0'))
        }
    };
    let value = if nanos == 0 {
        "0s".into()
    } else if nanos < 1_000 {
        format!("{nanos}ns")
    } else if nanos < 1_000_000 {
        decimal(nanos / 1_000, nanos % 1_000, 3, "µs")
    } else if nanos < 1_000_000_000 {
        decimal(nanos / 1_000_000, nanos % 1_000_000, 6, "ms")
    } else {
        let seconds = nanos / 1_000_000_000;
        let tail = decimal(seconds % 60, nanos % 1_000_000_000, 9, "s");
        if seconds >= 3_600 {
            format!("{}h{}m{tail}", seconds / 3_600, seconds / 60 % 60)
        } else if seconds >= 60 {
            format!("{}m{tail}", seconds / 60)
        } else {
            tail
        }
    };
    format!("session idle for {value}")
}

pub(crate) async fn handle(connection: &Arc<Connection>, bytes: Bytes) -> Result<()> {
    match connection.version {
        DatagramVersion::V2 => match DatagramV2::decode(&bytes).map_err(anyhow::Error::msg)? {
            DatagramV2::Udp {
                session_id,
                payload,
            } => connection.v2.payload(session_id, payload, connection).await,
            DatagramV2::Ip(packet) => {
                connection
                    .state
                    .icmp
                    .handle(connection.clone(), packet, None)
                    .await?
            }
            DatagramV2::TracedIp { identity, payload } => {
                connection
                    .state
                    .icmp
                    .handle(connection.clone(), payload, Some(identity))
                    .await?
            }
            DatagramV2::TraceSpans { .. } => {
                anyhow::bail!("unexpected incoming tracing-span datagram")
            }
        },
        DatagramVersion::V3 => match DatagramV3::decode(&bytes).map_err(anyhow::Error::msg)? {
            DatagramV3::Registration {
                id,
                destination,
                idle_seconds,
                ..
            } => {
                let mut result = connection
                    .state
                    .v3
                    .register_v3(
                        connection.clone(),
                        id,
                        destination,
                        Duration::from_secs(u64::from(idle_seconds)),
                    )
                    .await;
                if let Ok(registration) = &mut result {
                    registration.accept_migration().await?;
                }
                let response_type = match &result {
                    Ok(_) => 0,
                    Err(error) if error.downcast_ref::<super::TooManyFlows>().is_some() => 3,
                    Err(_) => 2,
                };
                let sent = connection
                    .sender
                    .send_datagram(Bytes::from(
                        DatagramV3::Response {
                            id,
                            response_type,
                            error: String::new(),
                        }
                        .encode()
                        .map_err(anyhow::Error::msg)?,
                    ))
                    .await;
                if let Ok(registration) = result {
                    connection
                        .state
                        .v3
                        .response_completed(id, registration, sent.is_ok(), connection.index)
                        .await;
                }
                sent?;
            }
            DatagramV3::Payload { id, payload } => {
                connection.state.v3.payload(id, payload, connection).await
            }
            DatagramV3::Icmp(packet) => {
                connection
                    .state
                    .icmp
                    .handle(connection.clone(), packet, None)
                    .await?
            }
            DatagramV3::Response { .. } => {}
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;

    #[tokio::test(start_paused = true)]
    async fn v3_idle_refresh_uses_consumed_activity_time() {
        let mut idle = IdleTimeout::new(DatagramVersion::V3, Duration::from_millis(100));
        let recorded = Instant::now() + Duration::from_millis(10);
        tokio::time::advance(Duration::from_millis(70)).await;
        idle.mark_active(recorded);
        tokio::time::advance(Duration::from_millis(60)).await;
        assert!(idle.expired().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(40)).await;
        assert!(idle.expired().now_or_never().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn v2_idle_uses_strict_periodic_checks_and_source_default() {
        for hint in [Duration::ZERO, Duration::from_millis(80)] {
            let mut idle = IdleTimeout::new(DatagramVersion::V2, hint);
            let duration = if hint.is_zero() {
                Duration::from_secs(210)
            } else {
                hint
            };
            for _ in 0..8 {
                tokio::time::advance(duration / 8).await;
                assert!(idle.expired().now_or_never().is_none());
            }
            tokio::time::advance(duration / 8).await;
            assert!(idle.expired().now_or_never().is_some());
        }
        for nanos in [1, 7, 8] {
            let mut idle = IdleTimeout::new(DatagramVersion::V2, Duration::from_nanos(nanos));
            tokio::time::advance(Duration::from_millis(2)).await;
            assert!(idle.expired().now_or_never().is_some());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn v2_activity_moves_expiry_without_resetting_tick_cadence() {
        let mut idle = IdleTimeout::new(DatagramVersion::V2, Duration::from_millis(80));
        for _ in 0..7 {
            tokio::time::advance(Duration::from_millis(10)).await;
            assert!(idle.expired().now_or_never().is_none());
        }
        idle.mark_active(Instant::now());
        for _ in 0..8 {
            tokio::time::advance(Duration::from_millis(10)).await;
            assert!(idle.expired().now_or_never().is_none());
        }
        tokio::time::advance(Duration::from_millis(10)).await;
        assert!(idle.expired().now_or_never().is_some());
    }

    #[test]
    fn idle_reason_matches_go_duration_string_contract() {
        for (nanos, expected) in [
            (0, "0s"),
            (7, "7ns"),
            (1_001, "1.001µs"),
            (1_500_001, "1.500001ms"),
            (1_500_000_001, "1.500000001s"),
            (60_000_000_000, "1m0s"),
            (3_600_000_000_000, "1h0m0s"),
            (3_661_123_000_000, "1h1m1.123s"),
            (i64::MAX as u64, "2562047h47m16.854775807s"),
        ] {
            assert_eq!(
                idle_message(Duration::from_nanos(nanos)),
                format!("session idle for {expected}")
            );
        }
    }
}
