use crate::crypto::EdgeTls;
use bytes::{Buf, Bytes};
use futures::task::AtomicWaker;
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    net::UdpSocket,
    sync::{Notify, mpsc, oneshot},
    time::Instant,
};
use tokio_quiche::{
    ApplicationOverQuic, QuicResult,
    quic::{HandshakeInfo, Incoming, QuicheConnection},
    socket::Socket,
};
use tokio_util::sync::CancellationToken;

const BUFFER: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
const QUEUE: usize = 32;
const READ_FIN: u8 = 1;
const WRITE_FIN: u8 = 2;
const DROPPED: u8 = 4;
const CLOSED: u8 = 8;
const CANCEL_WRITE: u8 = 16;

struct StreamStatus {
    flags: AtomicU8,
    shutdown_waker: AtomicWaker,
    notify: Arc<Notify>,
}

pub struct QuicStream {
    id: u64,
    io: DuplexStream,
    status: Arc<StreamStatus>,
    write_timeout: Duration,
    write_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl QuicStream {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn cancel_read(&self) {
        self.status.flags.fetch_or(READ_FIN, Ordering::Release);
        self.status.notify.notify_one();
    }
    pub fn set_write_timeout(&mut self, timeout: Duration) {
        self.write_timeout = timeout;
        self.write_deadline = None;
    }
    fn write_timed_out(&mut self, cx: &mut Context<'_>) -> bool {
        use std::future::Future;
        if self.write_timeout.is_zero() {
            return false;
        }
        let deadline = self
            .write_deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(self.write_timeout)));
        if deadline.as_mut().poll(cx).is_pending() {
            return false;
        }
        self.status.flags.fetch_or(CANCEL_WRITE, Ordering::Release);
        self.status.notify.notify_one();
        true
    }
}

impl Drop for QuicStream {
    fn drop(&mut self) {
        self.status.flags.fetch_or(DROPPED, Ordering::Release);
        self.status.notify.notify_one();
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && before == buf.filled().len()
            && self.status.flags.load(Ordering::Acquire) & (READ_FIN | CLOSED) == CLOSED
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "QUIC connection closed",
            )));
        }
        result
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.status.flags.load(Ordering::Acquire) & CANCEL_WRITE != 0 {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        let result = Pin::new(&mut self.io).poll_write(cx, buf);
        if result.is_ready() {
            self.write_deadline = None;
        } else if self.write_timed_out(cx) {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(Pin::new(&mut self.io).poll_shutdown(cx))?;
        self.status.shutdown_waker.register(cx.waker());
        let flags = self.status.flags.load(Ordering::Acquire);
        if flags & WRITE_FIN != 0 {
            return Poll::Ready(Ok(()));
        }
        if flags & CLOSED != 0 {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        if self.write_timed_out(cx) {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Poll::Pending
    }
}

enum Command {
    Open(oneshot::Sender<io::Result<QuicStream>>),
    Datagram(Bytes, oneshot::Sender<io::Result<()>>),
}

#[derive(Clone)]
pub struct QuicSender {
    commands: mpsc::Sender<Command>,
    notify: Arc<Notify>,
    cancel: CancellationToken,
    #[cfg(test)]
    datagram_fault: Arc<std::sync::Mutex<Option<DatagramFault>>>,
}
#[cfg(test)]
struct DatagramFault {
    kind: u8,
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<io::Result<()>>,
}
impl QuicSender {
    #[cfg(test)]
    pub(crate) fn gate_next_registration_datagram(
        &mut self,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<io::Result<()>>) {
        self.gate_next_datagram(3)
    }
    #[cfg(test)]
    pub(crate) fn gate_next_payload_datagram(
        &mut self,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<io::Result<()>>) {
        self.gate_next_datagram(1)
    }
    #[cfg(test)]
    fn gate_next_datagram(
        &mut self,
        kind: u8,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<io::Result<()>>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let mut fault = self.datagram_fault.lock().unwrap();
        assert!(fault.is_none(), "datagram fault already armed");
        *fault = Some(DatagramFault {
            kind,
            entered: entered_tx,
            release: release_rx,
        });
        (entered_rx, release_tx)
    }
    pub async fn open_bi(&self) -> io::Result<QuicStream> {
        if self.cancel.is_cancelled() {
            return Err(closed());
        }
        let (tx, rx) = oneshot::channel();
        tokio::select! { _=self.cancel.cancelled()=>return Err(closed()), result=self.commands.send(Command::Open(tx))=>result.map_err(|_|closed())? }
        self.notify.notify_one();
        tokio::select! { _=self.cancel.cancelled()=>Err(closed()), result=rx=>result.map_err(|_|closed())? }
    }
    pub async fn send_datagram(&self, payload: Bytes) -> io::Result<()> {
        if payload.len() > 1350 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        #[cfg(test)]
        {
            let fault = {
                let mut slot = self.datagram_fault.lock().unwrap();
                if slot
                    .as_ref()
                    .is_some_and(|fault| payload.first() == Some(&fault.kind))
                {
                    slot.take()
                } else {
                    None
                }
            };
            if let Some(fault) = fault {
                let _ = fault.entered.send(());
                tokio::select! {
                    biased;
                    _ = self.cancel.cancelled() => return Err(closed()),
                    result = fault.release => result.map_err(|_| closed())??,
                }
            }
        }
        let (tx, rx) = oneshot::channel();
        tokio::select! {_=self.cancel.cancelled()=>return Err(closed()),result=self.commands.send(Command::Datagram(payload,tx))=>result.map_err(|_|closed())?}
        self.notify.notify_one();
        tokio::select! {_=self.cancel.cancelled()=>Err(closed()),result=rx=>result.map_err(|_|closed())?}
    }
    pub fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }
}
pub struct IncomingStreams {
    receiver: mpsc::Receiver<QuicStream>,
    notify: Arc<Notify>,
}
impl IncomingStreams {
    pub async fn recv(&mut self) -> Option<QuicStream> {
        let stream = self.receiver.recv().await;
        self.notify.notify_one();
        stream
    }
}
pub struct QuicIncoming {
    pub streams: IncomingStreams,
    pub datagrams: mpsc::Receiver<Bytes>,
}

#[derive(Clone)]
pub(crate) struct QuicLiveness {
    cancel: CancellationToken,
}

impl QuicLiveness {
    pub(crate) fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub(crate) async fn closed(&self) {
        self.cancel.cancelled().await;
    }
}

pub struct QuicConnection {
    commands: mpsc::Sender<Command>,
    incoming: Option<QuicIncoming>,
    notify: Arc<Notify>,
    cancel: CancellationToken,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    _connection: tokio_quiche::QuicConnection,
}

impl QuicConnection {
    pub(crate) fn liveness(&self) -> QuicLiveness {
        QuicLiveness {
            cancel: self.cancel.clone(),
        }
    }

    pub fn sender(&self) -> QuicSender {
        QuicSender {
            commands: self.commands.clone(),
            notify: self.notify.clone(),
            cancel: self.cancel.clone(),
            #[cfg(test)]
            datagram_fault: Arc::new(std::sync::Mutex::new(None)),
        }
    }
    pub fn take_incoming(&mut self) -> io::Result<QuicIncoming> {
        self.incoming.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "incoming receivers already taken",
            )
        })
    }
    pub async fn open_bi(&self) -> io::Result<QuicStream> {
        self.sender().open_bi().await
    }
    pub async fn accept_bi(&mut self) -> io::Result<QuicStream> {
        self.incoming
            .as_mut()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "incoming receivers already taken",
                )
            })?
            .streams
            .recv()
            .await
            .ok_or_else(closed)
    }
    pub async fn send_datagram(&self, payload: Bytes) -> io::Result<()> {
        self.sender().send_datagram(payload).await
    }
    pub async fn recv_datagram(&mut self) -> io::Result<Bytes> {
        self.incoming
            .as_mut()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "incoming receivers already taken",
                )
            })?
            .datagrams
            .recv()
            .await
            .ok_or_else(closed)
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
    pub fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }
    pub fn close(&self) {
        self.cancel.cancel();
        self.notify.notify_one();
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        self.close();
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "QUIC connection closed")
}

struct CancelOnDrop(Option<CancellationToken>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(token) = &self.0 {
            token.cancel();
        }
    }
}

pub async fn dial(
    address: SocketAddr,
    server_name: &str,
    tls: &EdgeTls,
) -> io::Result<QuicConnection> {
    dial_with_options(
        address,
        server_name,
        tls,
        &super::EdgeDialOptions::default(),
    )
    .await
}

pub async fn dial_with_options(
    address: SocketAddr,
    server_name: &str,
    tls: &EdgeTls,
    options: &super::EdgeDialOptions,
) -> io::Result<QuicConnection> {
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let bind = options
        .bind_ip
        .map(|ip| SocketAddr::new(ip, 0))
        .unwrap_or_else(|| bind.parse().expect("constant UDP bind address"));
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(address).await?;
    let local_addr = socket.local_addr()?;
    let socket = Arc::new(socket);
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(
        quiche::PROTOCOL_VERSION,
        tls.quic_builder().map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    config
        .set_application_protos(&[b"argotunnel"])
        .map_err(io::Error::other)?;
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(1452);
    config.set_max_send_udp_payload_size(1452);
    config.discover_pmtu(!options.quic_disable_pmtu_discovery);
    config.set_initial_max_data(options.connection_window);
    config.set_max_connection_window(options.connection_window);
    config.set_initial_max_stream_data_bidi_local(options.stream_window);
    config.set_initial_max_stream_data_bidi_remote(options.stream_window);
    config.set_initial_max_stream_data_uni(options.stream_window);
    config.set_max_stream_window(options.stream_window);
    config.set_initial_max_streams_bidi(1 << 60);
    config.set_initial_max_streams_uni(1 << 60);
    config.enable_dgram(true, QUEUE, QUEUE);
    config.verify_peer(true);
    let mut cid = [0; 20];
    boring::rand::rand_bytes(&mut cid).map_err(io::Error::other)?;
    let mut conn: QuicheConnection = quiche::connect_with_buffer_factory(
        crate::crypto::tls_server_name(server_name).map_err(io::Error::other)?,
        &quiche::ConnectionId::from_ref(&cid),
        local_addr,
        address,
        &mut config,
    )
    .map_err(io::Error::other)?;
    crate::crypto::set_tls_name(conn.as_mut(), server_name).map_err(io::Error::other)?;
    attach_connection(conn, socket, address, local_addr, None).await
}

#[cfg(test)]
pub(crate) async fn attach_server(
    conn: QuicheConnection,
    socket: Arc<UdpSocket>,
    initial: Incoming,
) -> io::Result<QuicConnection> {
    let peer_addr = initial.peer_addr;
    let local_addr = initial.local_addr;
    socket.connect(peer_addr).await?;
    attach_connection(conn, socket, peer_addr, local_addr, Some(initial)).await
}

async fn attach_connection(
    conn: QuicheConnection,
    socket: Arc<UdpSocket>,
    address: SocketAddr,
    local_addr: SocketAddr,
    initial: Option<Incoming>,
) -> io::Result<QuicConnection> {
    let next_id = if conn.is_server() { 1 } else { 0 };
    let socket_wrapper = Socket {
        send: socket.clone(),
        recv: socket.clone(),
        local_addr,
        peer_addr: address,
        capabilities: Default::default(),
    };
    let wrapped = tokio_quiche::quic::raw::wrap_quiche_conn(
        conn,
        socket_wrapper,
        tokio_quiche::metrics::DefaultMetrics,
    );
    let cancel = CancellationToken::new();
    let mut guard = CancelOnDrop(Some(cancel.clone()));
    let notify = Arc::new(Notify::new());
    let (commands_tx, commands) = mpsc::channel(QUEUE);
    let (incoming_tx, incoming) = mpsc::channel(QUEUE);
    let (datagrams_tx, datagrams) = mpsc::channel(QUEUE);
    let driver = Driver {
        commands,
        incoming: incoming_tx,
        datagrams: datagrams_tx,
        streams: BTreeMap::new(),
        next_id,
        notify: notify.clone(),
        cancel: cancel.clone(),
        next_ping: Instant::now() + Duration::from_secs(1),
    };
    let (connection, handshake) = wrapped.conn.handshake_fut(driver);
    let recv_cancel = cancel.clone();
    let incoming_tx = wrapped.incoming_tx;
    if let Some(packet) = initial {
        incoming_tx.send(packet).await.map_err(|_| closed())?;
    }
    tokio::spawn(async move {
        let mut buf = vec![0; 65527];
        loop {
            let n = tokio::select! { _ = recv_cancel.cancelled() => break, result = socket.recv(&mut buf) => match result { Ok(n) => n, Err(_) => break } };
            let packet = Incoming {
                peer_addr: address,
                local_addr,
                rx_time: None,
                buf: buf[..n].to_vec(),
                gro: None,
                so_mark_data: None,
            };
            tokio::select! { _ = recv_cancel.cancelled() => break, result = incoming_tx.send(packet) => if result.is_err() { break; } }
        }
        recv_cancel.cancel();
    });
    let running = tokio::time::timeout(Duration::from_secs(5), handshake).await??;
    tokio_quiche::InitialQuicConnection::resume(running);
    guard.0 = None;
    Ok(QuicConnection {
        commands: commands_tx,
        incoming: Some(QuicIncoming {
            streams: IncomingStreams {
                receiver: incoming,
                notify: notify.clone(),
            },
            datagrams,
        }),
        notify,
        cancel,
        local_addr,
        peer_addr: address,
        _connection: connection,
    })
}

struct StreamState {
    io: DuplexStream,
    status: Arc<StreamStatus>,
    recv: Bytes,
    send: Bytes,
    recv_fin: bool,
    send_fin: bool,
}

struct Driver {
    commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<QuicStream>,
    datagrams: mpsc::Sender<Bytes>,
    streams: BTreeMap<u64, StreamState>,
    next_id: u64,
    notify: Arc<Notify>,
    cancel: CancellationToken,
    next_ping: Instant,
}

struct DriverWake(Arc<Notify>);
impl Wake for DriverWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

impl Driver {
    fn stream(&mut self, id: u64) -> QuicStream {
        let (io, app) = tokio::io::duplex(BUFFER);
        let status = Arc::new(StreamStatus {
            flags: AtomicU8::new(0),
            shutdown_waker: AtomicWaker::new(),
            notify: self.notify.clone(),
        });
        self.streams.insert(
            id,
            StreamState {
                io,
                status: status.clone(),
                recv: Bytes::new(),
                send: Bytes::new(),
                recv_fin: false,
                send_fin: false,
            },
        );
        QuicStream {
            id,
            io: app,
            status,
            write_timeout: Duration::ZERO,
            write_deadline: None,
        }
    }

    fn drive(&mut self, conn: &mut QuicheConnection) -> QuicResult<()> {
        if self.cancel.is_cancelled() {
            let _ = conn.close(true, 0, b"");
            return Err(closed().into());
        }
        while let Ok(cmd) = self.commands.try_recv() {
            match cmd {
                Command::Open(reply) => {
                    let id = self.next_id;
                    self.next_id += 4;
                    let stream = self.stream(id);
                    let _ = reply.send(Ok(stream));
                }
                Command::Datagram(data, reply) => {
                    let _ = reply.send(conn.dgram_send(&data).map_err(io::Error::other));
                }
            }
        }
        for id in conn.readable() {
            if id & 3 != ((self.next_id & 3) ^ 1) || self.streams.contains_key(&id) {
                continue;
            }
            let Ok(permit) = self.incoming.clone().try_reserve_owned() else {
                break;
            };
            let stream = self.stream(id);
            permit.send(stream);
        }
        let waker = Waker::from(Arc::new(DriverWake(self.notify.clone())));
        let mut cx = Context::from_waker(&waker);
        self.streams.retain(|&id, stream| {
            let flags = stream.status.flags.load(Ordering::Acquire);
            if flags & DROPPED != 0 {
                let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
                let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, 0);
                return false;
            }
            if flags & READ_FIN != 0 && !stream.recv_fin {
                let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
                stream.recv_fin = true;
                stream.recv = Bytes::new();
            }
            if flags & CANCEL_WRITE != 0 && flags & WRITE_FIN == 0 {
                let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, 0);
                stream.send = Bytes::new();
                stream.send_fin = true;
                stream.status.flags.fetch_or(WRITE_FIN, Ordering::Release);
                stream.status.shutdown_waker.wake();
            }
            if stream.recv.is_empty() && !stream.recv_fin && conn.stream_readable(id) {
                let mut buf = [0; CHUNK];
                match conn.stream_recv(id, &mut buf) {
                    Ok((n, fin)) => {
                        stream.recv = Bytes::copy_from_slice(&buf[..n]);
                        stream.recv_fin = fin;
                    }
                    Err(quiche::Error::Done) => {}
                    Err(_) => {
                        stream.status.flags.fetch_or(CLOSED, Ordering::Release);
                        return false;
                    }
                }
            }
            if !stream.recv.is_empty() {
                match Pin::new(&mut stream.io).poll_write(&mut cx, &stream.recv) {
                    Poll::Ready(Ok(n)) => {
                        stream.recv.advance(n);
                        if stream.recv.is_empty() {
                            self.notify.notify_one();
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
                        stream.recv = Bytes::new();
                        stream.recv_fin = true;
                    }
                    Poll::Pending => {}
                }
            }
            if stream.recv_fin && stream.recv.is_empty() {
                stream.status.flags.fetch_or(READ_FIN, Ordering::Release);
                let _ = Pin::new(&mut stream.io).poll_shutdown(&mut cx);
            }
            if stream.send.is_empty() && !stream.send_fin {
                let mut buf = [0; CHUNK];
                let mut read = ReadBuf::new(&mut buf);
                match Pin::new(&mut stream.io).poll_read(&mut cx, &mut read) {
                    Poll::Ready(Ok(())) => {
                        stream.send_fin = read.filled().is_empty();
                        stream.send = Bytes::copy_from_slice(read.filled());
                    }
                    Poll::Ready(Err(_)) => stream.send_fin = true,
                    Poll::Pending => {}
                }
            }
            if flags & CANCEL_WRITE == 0
                && (!stream.send.is_empty() || stream.send_fin && flags & WRITE_FIN == 0)
            {
                match conn.stream_send(id, &stream.send, stream.send_fin) {
                    Ok(n) => {
                        stream.send.advance(n);
                        if stream.send_fin && stream.send.is_empty() {
                            stream.status.flags.fetch_or(WRITE_FIN, Ordering::Release);
                            stream.status.shutdown_waker.wake();
                        }
                        if !stream.send_fin {
                            self.notify.notify_one();
                        }
                    }
                    Err(quiche::Error::Done) => {}
                    Err(_) => {
                        stream.status.flags.fetch_or(CLOSED, Ordering::Release);
                        stream.status.shutdown_waker.wake();
                        return false;
                    }
                }
            }
            stream.status.flags.load(Ordering::Acquire) & (READ_FIN | WRITE_FIN)
                != READ_FIN | WRITE_FIN
        });
        loop {
            let mut buf = [0; 1452];
            match conn.dgram_recv(&mut buf) {
                Ok(n) => {
                    if n <= 1350 {
                        let _ = self.datagrams.try_send(Bytes::copy_from_slice(&buf[..n]));
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(_) => break,
            }
        }
        if Instant::now() >= self.next_ping {
            let _ = conn.send_ack_eliciting();
            self.next_ping = Instant::now() + Duration::from_secs(1);
        }
        Ok(())
    }
}

impl ApplicationOverQuic for Driver {
    fn on_conn_established(
        &mut self,
        _conn: &mut QuicheConnection,
        _info: &HandshakeInfo,
    ) -> QuicResult<()> {
        Ok(())
    }
    fn should_act(&self) -> bool {
        true
    }
    async fn wait_for_data(&mut self, conn: &mut QuicheConnection) -> QuicResult<()> {
        tokio::select! {
            _ = self.notify.notified() => {},
            _ = self.cancel.cancelled() => {
                let _=conn.close(true,0,b"");
                return Err(closed().into());
            },
            _ = tokio::time::sleep_until(self.next_ping) => {}
        }
        Ok(())
    }
    fn process_reads(&mut self, conn: &mut QuicheConnection) -> QuicResult<()> {
        self.drive(conn)
    }
    fn process_writes(&mut self, conn: &mut QuicheConnection) -> QuicResult<()> {
        self.drive(conn)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.cancel.cancel();
        for stream in self.streams.values() {
            stream.status.flags.fetch_or(CLOSED, Ordering::Release);
            stream.status.shutdown_waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{TlsPolicy, tests::certificate};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn echo_peer(
        socket: UdpSocket,
        mut config: quiche::Config,
        initial_streams: usize,
        reset_first: bool,
    ) -> Option<(bool, u64)> {
        let local = socket.local_addr().unwrap();
        let mut packet = [0; 65527];
        let (n, remote) = socket.recv_from(&mut packet).await.unwrap();
        let header = quiche::Header::from_slice(&mut packet[..n], 20).unwrap();
        let mut cid = [0; 20];
        boring::rand::rand_bytes(&mut cid).unwrap();
        let mut conn = quiche::accept(
            &quiche::ConnectionId::from_ref(&cid),
            None,
            local,
            remote,
            &mut config,
        )
        .unwrap();
        conn.recv(
            &mut packet[..n],
            quiche::RecvInfo {
                from: remote,
                to: local,
            },
        )
        .unwrap();
        let mut pending: BTreeMap<u64, (Bytes, bool)> = BTreeMap::new();
        let mut edge_stream_sent = false;
        let _original_destination = header.dcid;
        loop {
            if conn.is_established() && !edge_stream_sent {
                for index in 0..initial_streams {
                    let id = 1 + 4 * index as u64;
                    conn.stream_send(id, b"edge", initial_streams > 1).unwrap();
                    if reset_first && index == 0 {
                        conn.stream_shutdown(id, quiche::Shutdown::Write, 77)
                            .unwrap();
                    }
                }
                edge_stream_sent = true;
            }
            for id in conn.readable() {
                if pending.contains_key(&id) {
                    continue;
                }
                let mut data = [0; CHUNK];
                if let Ok((n, fin)) = conn.stream_recv(id, &mut data) {
                    pending.insert(id, (Bytes::copy_from_slice(&data[..n]), fin));
                }
            }
            pending.retain(|&id, (data, fin)| match conn.stream_send(id, data, *fin) {
                Ok(n) => {
                    data.advance(n);
                    !data.is_empty()
                }
                Err(quiche::Error::Done) => true,
                Err(_) => false,
            });
            let mut data = [0; 1350];
            while let Ok(n) = conn.dgram_recv(&mut data) {
                let _ = conn.dgram_send(&data[..n]);
            }
            let mut out = [0; 65527];
            while let Ok((n, info)) = conn.send(&mut out) {
                socket.send_to(&out[..n], info.to).await.unwrap();
            }
            if conn.is_closed() {
                return conn
                    .peer_error()
                    .map(|error| (error.is_app, error.error_code));
            }
            let deadline = conn.timeout().unwrap_or(Duration::from_millis(50));
            tokio::select! {
                _ = tokio::time::sleep(deadline) => conn.on_timeout(),
                result = socket.recv_from(&mut packet) => {
                    let (n, from) = result.unwrap();
                    let _ = conn.recv(&mut packet[..n], quiche::RecvInfo { from, to: local });
                }
            }
        }
    }

    fn peer_config(
        cert: &boring::x509::X509,
        key: &boring::pkey::PKey<boring::pkey::Private>,
    ) -> quiche::Config {
        peer_config_with_sni(cert, key, None)
    }

    fn peer_config_with_sni(
        cert: &boring::x509::X509,
        key: &boring::pkey::PKey<boring::pkey::Private>,
        sni: Option<Arc<std::sync::Mutex<String>>>,
    ) -> quiche::Config {
        let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
        ssl.set_certificate(cert).unwrap();
        ssl.set_private_key(key).unwrap();
        if let Some(sni) = sni {
            ssl.set_servername_callback(move |ssl, _| {
                *sni.lock().unwrap() = ssl
                    .servername(boring::ssl::NameType::HOST_NAME)
                    .unwrap_or("")
                    .into();
                Ok(())
            });
        }
        ssl.set_curves_list("X25519MLKEM768").unwrap();
        let mut config =
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
        config.set_application_protos(&[b"argotunnel"]).unwrap();
        config.set_max_idle_timeout(5000);
        config.set_initial_max_data(1024 * 1024);
        config.set_initial_max_stream_data_bidi_remote(64 * 1024);
        config.set_initial_max_stream_data_bidi_local(64 * 1024);
        config.set_initial_max_streams_bidi(128);
        config.enable_dgram(true, 32, 32);
        config
    }

    #[tokio::test]
    async fn quic_reference_names_sni_and_ip_sans() {
        let (cert, key) = crate::crypto::tests::certificate_for_sans(
            "localhost",
            &["localhost"],
            &["127.0.0.1", "::1"],
        );
        for (name, succeeds, expected_sni, ipv6) in [
            ("localhost.", true, "localhost", false),
            ("[localhost]", false, "[localhost]", false),
            ("[127.0.0.1]", true, "", false),
            ("[[127.0.0.1]]", false, "[[127.0.0.1]]", false),
            ("[::1]", true, "", true),
            ("127.0.0.1.", false, "127.0.0.1", false),
        ] {
            let sni = Arc::new(std::sync::Mutex::new(String::new()));
            let socket = UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
                .await
                .unwrap();
            let address = socket.local_addr().unwrap();
            let peer = tokio::spawn(echo_peer(
                socket,
                peer_config_with_sni(&cert, &key, Some(sni.clone())),
                0,
                false,
            ));
            let tls =
                EdgeTls::new(TlsPolicy::RequirePostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
            let client = tokio::time::timeout(Duration::from_secs(6), dial(address, name, &tls))
                .await
                .unwrap();
            assert_eq!(client.is_ok(), succeeds, "{name:?}");
            if let Ok(client) = client {
                client.close();
            }
            tokio::time::timeout(Duration::from_secs(6), peer)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(sni.lock().unwrap().as_str(), expected_sni, "{name:?}");
        }
    }

    #[tokio::test]
    async fn quic_requires_san_even_when_common_name_matches() {
        for (names, succeeds) in [(vec![], false), (vec!["edge.test"], true)] {
            let (cert, key) = crate::crypto::tests::certificate_for_names("edge.test", &names);
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let peer = tokio::spawn(echo_peer(socket, peer_config(&cert, &key), 0, false));
            let tls =
                EdgeTls::new(TlsPolicy::RequirePostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
            let client =
                tokio::time::timeout(Duration::from_secs(6), dial(addr, "edge.test", &tls))
                    .await
                    .unwrap();
            assert_eq!(client.is_ok(), succeeds);
            if let Ok(client) = client {
                client.close();
            }
            tokio::time::timeout(Duration::from_secs(6), peer)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn raw_loopback_stream_backpressure_half_close_and_datagram() {
        let (cert, key) = certificate();
        let config = peer_config(&cert, &key);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let peer = tokio::spawn(echo_peer(socket, config, 1, false));
        let tls =
            EdgeTls::new(TlsPolicy::RequirePostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
        let mut conn = dial(addr, "edge.test", &tls).await.unwrap();
        let sender = conn.sender();
        let mut incoming = conn.take_incoming().unwrap();
        assert!(
            matches!(conn.take_incoming(),Err(error) if error.kind()==io::ErrorKind::AlreadyExists)
        );
        let mut inbound = incoming.streams.recv().await.unwrap();
        assert_eq!(inbound.id(), 1);
        let mut edge_payload = [0; 4];
        inbound.read_exact(&mut edge_payload).await.unwrap();
        assert_eq!(&edge_payload, b"edge");
        inbound.write_all(b"return").await.unwrap();
        inbound.shutdown().await.unwrap();
        let mut returned = Vec::new();
        inbound.read_to_end(&mut returned).await.unwrap();
        assert_eq!(&returned, b"return");
        let stream = sender.open_bi().await.unwrap();
        assert_eq!(stream.id(), 0);
        let (mut read, mut write) = tokio::io::split(stream);
        let payload = vec![0x5a; 512 * 1024];
        let send = async {
            write.write_all(&payload).await.unwrap();
            write.shutdown().await.unwrap();
        };
        let recv = async {
            let mut output = Vec::new();
            read.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, payload);
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(send, recv);
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(
            !conn.is_closed(),
            "keepalive must prevent five-second idle expiry"
        );
        sender
            .send_datagram(Bytes::from_static(b"datagram"))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), incoming.datagrams.recv())
                .await
                .unwrap()
                .unwrap(),
            "datagram"
        );
        let source = conn.local_addr();
        drop(conn);
        assert!(sender.is_closed());
        assert!(sender.open_bi().await.is_err());
        assert!(
            sender
                .send_datagram(Bytes::from_static(b"after close"))
                .await
                .is_err()
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), peer)
                .await
                .unwrap()
                .unwrap(),
            Some((true, 0)),
            "peer must observe application close code zero"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(socket) = UdpSocket::bind(source).await {
                    drop(socket);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(
            Duration::from_millis(100),
            tokio::time::sleep(Duration::from_millis(5)),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn incoming_queue_saturation_reset_and_later_streams_preserve_progress() {
        let (cert, key) = certificate();
        let config = peer_config(&cert, &key);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let peer = tokio::spawn(echo_peer(socket, config, QUEUE + 8, true));
        let tls =
            EdgeTls::new(TlsPolicy::RequirePostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
        let mut connection = dial(address, "edge.test", &tls).await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            connection.incoming.as_ref().unwrap().streams.receiver.len(),
            QUEUE
        );
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..QUEUE + 8 {
            let mut stream = tokio::time::timeout(Duration::from_secs(1), connection.accept_bi())
                .await
                .unwrap()
                .unwrap();
            assert!(seen.insert(stream.id()), "peer stream admitted only once");
            let mut body = Vec::new();
            let result =
                tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut body))
                    .await
                    .unwrap();
            if stream.id() == 1 {
                assert!(result.is_err(), "peer reset must close its read side");
            } else {
                result.unwrap();
                assert_eq!(body, b"edge");
                stream.shutdown().await.unwrap();
            }
        }
        assert_eq!(seen.len(), QUEUE + 8);
        let mut later = connection.open_bi().await.unwrap();
        later.write_all(b"later").await.unwrap();
        later.shutdown().await.unwrap();
        let mut body = Vec::new();
        later.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"later");
        drop(connection);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), peer)
                .await
                .unwrap()
                .unwrap(),
            Some((true, 0))
        );
        tokio::time::timeout(
            Duration::from_millis(100),
            tokio::time::sleep(Duration::from_millis(5)),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_handshake_releases_udp_socket() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let tls = EdgeTls::new(TlsPolicy::default(), None).unwrap();
        let dial_task = tokio::spawn(async move { dial(address, "edge.test", &tls).await });
        let mut packet = [0; 1500];
        let (_, source) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        dial_task.abort();
        assert!(matches!(dial_task.await, Err(error) if error.is_cancelled()));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(socket) = UdpSocket::bind(source).await {
                    drop(socket);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn write_timeout_preserves_read_side() {
        let (io, mut peer) = tokio::io::duplex(8);
        let status = Arc::new(StreamStatus {
            flags: AtomicU8::new(0),
            shutdown_waker: AtomicWaker::new(),
            notify: Arc::new(Notify::new()),
        });
        let mut stream = QuicStream {
            id: 0,
            io,
            status: status.clone(),
            write_timeout: Duration::ZERO,
            write_deadline: None,
        };
        stream.set_write_timeout(Duration::from_millis(5));
        let error = stream.write_all(&[0; 9]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_ne!(status.flags.load(Ordering::Acquire) & CANCEL_WRITE, 0);
        peer.write_all(b"response").await.unwrap();
        let mut response = [0; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
    }
}
