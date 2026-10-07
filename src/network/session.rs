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
struct Session {
    generation: u64,
    socket: Arc<tokio::net::UdpSocket>,
    route: watch::Sender<Route>,
    activity: watch::Sender<Instant>,
    input: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    remote: AtomicBool,
    version: DatagramVersion,
    started: tokio::sync::Notify,
}
pub(crate) struct Registry {
    sessions: Mutex<HashMap<[u8; 16], Arc<Session>>>,
    generation: AtomicU64,
    creation: tokio::sync::Mutex<()>,
}
impl Drop for Registry {
    fn drop(&mut self) {
        for session in self.sessions.get_mut().unwrap().values() {
            session.cancel.cancel();
        }
    }
}
impl Registry {
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
        let mut sessions = self.sessions.lock().unwrap();
        if sessions
            .get(&id)
            .is_some_and(|s| generation.is_none_or(|g| s.generation == g))
        {
            if let Some(session) = sessions.remove(&id) {
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
        let session = Arc::new(Session {
            generation: self.generation.fetch_add(1, Ordering::Relaxed),
            socket,
            route,
            activity,
            input,
            cancel: CancellationToken::new(),
            remote: AtomicBool::new(false),
            version: connection.version,
            started: tokio::sync::Notify::new(),
        });
        if let Some(previous) = self.sessions.lock().unwrap().insert(id, session.clone()) {
            previous.remote.store(true, Ordering::Release);
            previous.cancel.cancel();
        }
        let registry = Arc::downgrade(self);
        let weak = Arc::downgrade(&connection);
        let actor = session.clone();
        tokio::task::spawn_local(async move {
            if !start_immediately {
                let mut pending_route = actor.route.subscribe();
                let started = loop {
                    let target = pending_route.borrow().clone();
                    tokio::select! {
                        _ = actor.started.notified() => break true,
                        _ = actor.cancel.cancelled() => break false,
                        result = pending_route.changed() => {if result.is_err(){break false;}},
                        _ = target.cancel.cancelled() => {
                            if pending_route.borrow().generation==target.generation {break false;}
                        }
                    }
                };
                if !started {
                    if let Some(registry) = registry.upgrade() {
                        registry.remove(id, Some(actor.generation)).await;
                    }
                    return;
                }
            }
            serve(
                registry,
                weak,
                id,
                actor,
                receiver,
                permit,
                if idle.is_zero() {
                    Duration::from_secs(210)
                } else {
                    idle
                },
            )
            .await;
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
    ) -> Result<(Arc<Session>, bool)> {
        let _creation = self.creation.lock().await;
        let existing = self.sessions.lock().unwrap().get(&id).cloned();
        if let Some(session) = existing {
            let current = session.route.borrow().clone();
            if current.index != connection.index || current.generation != connection.generation {
                session.route.send_replace(Route {
                    index: connection.index,
                    generation: connection.generation,
                    sender: connection.sender.clone(),
                    cancel: connection.cancel.clone(),
                });
            }
            session.activity.send_replace(Instant::now());
            return Ok((session, false));
        }
        let session = self.create(connection, id, address, idle, false).await?;
        Ok((session, true))
    }
    async fn payload(&self, id: [u8; 16], payload: Vec<u8>) {
        let session = self.sessions.lock().unwrap().get(&id).cloned();
        let Some(session) = session else {
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
            let _ = session.input.try_send(payload);
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
    let mut deadline = Instant::now() + idle;
    let mut buffer = [0; 1500];
    let mut reason = "terminated without error".to_owned();
    loop {
        let target = route.borrow().clone();
        tokio::select! {
            result = route.changed() => {
                if result.is_err() { break; }
                deadline = Instant::now() + idle;
            }
            result = activity.changed() => {
                if result.is_err() { break; }
                deadline = *activity.borrow() + idle;
            }
            _ = session.cancel.cancelled() => break,
            _ = target.cancel.cancelled() => {
                if route.borrow().generation == target.generation { break; }
            }
            _ = tokio::time::sleep_until(deadline) => {
                reason = format!("session idle for {idle:?}");
                break;
            }
            result = session.socket.recv(&mut buffer) => {
                match result {
                    Ok(n) if n <= 1280 => {
                        let payload = buffer[..n].to_vec();
                        let packet = match session.version {
                            DatagramVersion::V2 => DatagramV2::Udp { session_id: id, payload }.encode(),
                            DatagramVersion::V3 => DatagramV3::Payload { id, payload }.encode(),
                        };
                        if let Ok(packet) = packet {
                            let sender = route.borrow().sender.clone();
                            if let Err(error) = sender.send_datagram(Bytes::from(packet)).await {
                                reason = error.to_string();
                                break;
                            }
                        }
                        session.activity.send_replace(Instant::now());
                    }
                    Ok(_) => {}
                    Err(error) => { reason = error.to_string(); break; }
                }
            }
            Some(payload) = input.recv(), if session.version == DatagramVersion::V3 => {
                match tokio::time::timeout(Duration::from_millis(200), session.socket.send(&payload)).await {
                    Ok(Ok(n)) if n == payload.len() => { session.activity.send_replace(Instant::now()); }
                    Err(_) => {}
                    Ok(Err(error)) => { reason = error.to_string(); break; }
                    _ => {}
                }
            }
        }
    }
    let remote = session.remote.load(Ordering::Acquire);
    let removed = if let Some(registry) = registry.upgrade() {
        registry.remove(id, Some(session.generation)).await
    } else {
        false
    };
    if removed
        && session.version == DatagramVersion::V2
        && !remote
        && let Some(connection) = connection.upgrade()
    {
        connection.close_v2_session(id, reason).await;
    }
}

pub(crate) async fn handle(connection: &Arc<Connection>, bytes: Bytes) -> Result<()> {
    match connection.version {
        DatagramVersion::V2 => match DatagramV2::decode(&bytes).map_err(anyhow::Error::msg)? {
            DatagramV2::Udp {
                session_id,
                payload,
            } => connection.v2.payload(session_id, payload).await,
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
                let result = connection
                    .state
                    .v3
                    .register_v3(
                        connection.clone(),
                        id,
                        destination,
                        Duration::from_secs(u64::from(idle_seconds)),
                    )
                    .await;
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
                if let Ok((session, new)) = result {
                    if sent.is_ok() {
                        session.started.notify_one();
                    } else if new {
                        connection
                            .state
                            .v3
                            .remove(id, Some(session.generation))
                            .await;
                    }
                }
                sent?;
            }
            DatagramV3::Payload { id, payload } => connection.state.v3.payload(id, payload).await,
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
