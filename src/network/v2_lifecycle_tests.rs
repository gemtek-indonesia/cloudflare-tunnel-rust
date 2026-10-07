use super::*;
use crate::protocol::{metadata, tunnelrpc_capnp as wire};
use std::rc::Rc;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

struct CloseCall {
    id: uuid::Uuid,
    reason: String,
}
struct ClosePeer {
    calls: tokio::sync::mpsc::UnboundedSender<CloseCall>,
    hold: bool,
}
impl wire::session_manager::Server for ClosePeer {
    async fn register_udp_session(
        self: Rc<Self>,
        _: wire::session_manager::RegisterUdpSessionParams,
        _: wire::session_manager::RegisterUdpSessionResults,
    ) -> capnp::Result<()> {
        Err(capnp::Error::failed(
            "unexpected registration on edge peer".into(),
        ))
    }
    async fn unregister_udp_session(
        self: Rc<Self>,
        params: wire::session_manager::UnregisterUdpSessionParams,
        _: wire::session_manager::UnregisterUdpSessionResults,
    ) -> capnp::Result<()> {
        let params = params.get()?;
        self.calls
            .send(CloseCall {
                id: uuid::Uuid::from_slice(params.get_session_id()?).unwrap(),
                reason: params.get_message()?.to_str()?.into(),
            })
            .unwrap();
        if self.hold {
            futures::future::pending::<()>().await;
        }
        Ok(())
    }
}
async fn close_peer(
    pair: &mut Pair,
    hold: bool,
) -> (
    crate::runtime::AbortTask<capnp::Result<()>>,
    tokio::sync::mpsc::UnboundedReceiver<CloseCall>,
) {
    let mut stream = timeout(Duration::from_secs(2), pair.incoming.streams.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        stream.id() >= 4 && stream.id().is_multiple_of(4),
        "session RPC must follow the owned client control stream"
    );
    assert!(matches!(
        metadata::read_stream_kind(&mut stream).await.unwrap(),
        metadata::StreamKind::Rpc
    ));
    let (calls, received) = tokio::sync::mpsc::unbounded_channel();
    let client: wire::session_manager::Client = capnp_rpc::new_client(ClosePeer { calls, hold });
    let (read, write) = tokio::io::split(stream);
    let network = capnp_rpc::twoparty::VatNetwork::new(
        read.compat(),
        write.compat_write(),
        capnp_rpc::rpc_twoparty_capnp::Side::Server,
        crate::protocol::reader_options(),
    );
    let rpc = capnp_rpc::RpcSystem::new(Box::new(network), Some(client.client));
    (
        crate::runtime::AbortTask(tokio::task::spawn_local(rpc)),
        received,
    )
}
async fn register(
    pair: &Pair,
    id: uuid::Uuid,
    destination: SocketAddr,
    idle: Duration,
) -> UdpRegistrationResult {
    pair.connection
        .register_udp(UdpRegistration {
            session_id: id,
            destination: destination.ip(),
            port: destination.port(),
            idle_hint: idle,
            trace_context: String::new(),
        })
        .await
}
async fn learn_origin_port(
    pair: &mut Pair,
    origin: &tokio::net::UdpSocket,
    id: uuid::Uuid,
) -> SocketAddr {
    pair.send(
        DatagramV2::Udp {
            session_id: *id.as_bytes(),
            payload: b"learn socket".to_vec(),
        }
        .encode()
        .unwrap(),
    )
    .await;
    let mut buffer = [0; 64];
    let (n, source) = timeout(Duration::from_secs(1), origin.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..n], b"learn socket");
    source
}

#[tokio::test(flavor = "current_thread")]
async fn idle_unregister_is_real_rpc_and_stall_or_peer_close_releases_owned_resources() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for (hold, close_transport) in [(false, false), (true, false), (true, true)] {
                let mut config = crate::runtime::tests::config();
                config.max_active_flows = Some(1);
                let state = NetworkState::new(&config).unwrap();
                let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
                if close_transport {
                    Arc::get_mut(&mut pair.connection).unwrap().rpc_timeout =
                        Duration::from_secs(2);
                }
                let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let destination = origin.local_addr().unwrap();
                let id = uuid::Uuid::from_bytes([31; 16]);
                assert!(
                    register(&pair, id, destination, Duration::from_millis(80))
                        .await
                        .error
                        .is_empty()
                );
                let source = learn_origin_port(&mut pair, &origin, id).await;
                let (mut rpc, mut calls) = close_peer(&mut pair, hold).await;
                let call = timeout(Duration::from_secs(1), calls.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(call.id, id);
                assert_eq!(call.reason, "session idle for 80ms");
                assert_eq!(pair.connection.v2.len(), 0);
                assert_eq!(state.context.metrics.udp_active_sessions.get(), 0);
                assert_eq!(state.context.metrics.udp_total_sessions.get(), 1);
                assert!(
                    tokio::net::UdpSocket::bind(source).await.is_ok(),
                    "origin socket must close before waiting for edge unregister response"
                );
                if hold {
                    assert_eq!(
                        state.active_flows(),
                        1,
                        "outgoing RPC still owns the source flow slot"
                    );
                    assert!(
                        !register(
                            &pair,
                            uuid::Uuid::from_bytes([32; 16]),
                            destination,
                            Duration::from_secs(1)
                        )
                        .await
                        .error
                        .is_empty()
                    );
                }
                if close_transport {
                    pair.peer.close();
                }
                let _ = timeout(Duration::from_secs(1), &mut rpc.0)
                    .await
                    .unwrap()
                    .unwrap();
                drained(&state).await;
                assert_eq!(state.active_flows(), 0);
                let labels = ["session", "unregister_udp_session"];
                assert_eq!(
                    state
                        .context
                        .metrics
                        .rpc_client_operations
                        .with_label_values(&labels)
                        .get(),
                    1
                );
                assert_eq!(
                    state
                        .context
                        .metrics
                        .rpc_client_failures
                        .with_label_values(&labels)
                        .get(),
                    u64::from(hold)
                );
                if !close_transport {
                    let replacement = uuid::Uuid::from_bytes([33; 16]);
                    assert!(
                        register(&pair, replacement, destination, Duration::from_secs(1))
                            .await
                            .error
                            .is_empty()
                    );
                    pair.connection.unregister_udp(replacement).await.unwrap();
                    drained(&state).await;
                }
                pair.client.close();
                pair.peer.close();
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn remote_unregister_and_replacement_suppress_retired_owner_rpc() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let id = uuid::Uuid::from_bytes([41; 16]);
            assert!(
                register(&pair, id, destination, Duration::from_millis(80))
                    .await
                    .error
                    .is_empty()
            );
            let retired = learn_origin_port(&mut pair, &origin, id).await;
            assert!(
                register(&pair, id, destination, Duration::from_secs(1))
                    .await
                    .error
                    .is_empty()
            );
            let current = learn_origin_port(&mut pair, &origin, id).await;
            assert_ne!(retired, current);
            assert!(
                timeout(Duration::from_millis(200), pair.incoming.streams.recv())
                    .await
                    .is_err(),
                "retired actor's expiry must emit no stale unregister RPC"
            );
            assert_eq!(state.active_flows(), 1);
            assert_eq!(pair.connection.v2.len(), 1);
            origin.send_to(b"replacement alive", current).await.unwrap();
            assert_eq!(
                DatagramV2::decode(&pair.receive().await).unwrap(),
                DatagramV2::Udp {
                    session_id: *id.as_bytes(),
                    payload: b"replacement alive".to_vec()
                }
            );
            assert!(tokio::net::UdpSocket::bind(retired).await.is_ok());
            pair.connection.unregister_udp(id).await.unwrap();
            drained(&state).await;
            assert_eq!(pair.connection.v2.len(), 0);
            assert!(tokio::net::UdpSocket::bind(current).await.is_ok());
            assert!(
                timeout(Duration::from_millis(100), pair.incoming.streams.recv())
                    .await
                    .is_err(),
                "remote unregister must not echo a close RPC"
            );
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

struct NetworkCallbacks(Arc<Connection>);
impl crate::protocol::callbacks::EdgeCallbacks for NetworkCallbacks {
    fn update_configuration(
        &self,
        _: i32,
        _: Vec<u8>,
    ) -> futures::future::LocalBoxFuture<'static, crate::protocol::callbacks::ConfigurationResult>
    {
        Box::pin(async {
            crate::protocol::callbacks::ConfigurationResult {
                latest_applied_version: 0,
                error: "configuration is outside this session fixture".into(),
            }
        })
    }
    fn register_udp_session(
        &self,
        request: UdpRegistration,
    ) -> futures::future::LocalBoxFuture<'static, capnp::Result<UdpRegistrationResult>> {
        let connection = self.0.clone();
        Box::pin(async move { Ok(connection.register_udp(request).await) })
    }
    fn unregister_udp_session(
        &self,
        id: uuid::Uuid,
        _: String,
    ) -> futures::future::LocalBoxFuture<'static, capnp::Result<()>> {
        let connection = self.0.clone();
        Box::pin(async move {
            connection
                .unregister_udp(id)
                .await
                .map_err(|error| capnp::Error::failed(error.to_string()))
        })
    }
}
struct IncomingRpc {
    client: wire::session_manager::Client,
    _client_driver: crate::runtime::AbortTask<capnp::Result<()>>,
    _server: crate::runtime::AbortTask<capnp::Result<()>>,
}
async fn incoming_rpc(pair: &mut Pair) -> IncomingRpc {
    use tokio::io::AsyncWriteExt;
    let mut stream = pair.peer.open_bi().await.unwrap();
    stream.write_all(&metadata::RPC_SIGNATURE).await.unwrap();
    let (read, write) = tokio::io::split(stream);
    let network = capnp_rpc::twoparty::VatNetwork::new(
        read.compat(),
        write.compat_write(),
        capnp_rpc::rpc_twoparty_capnp::Side::Client,
        crate::protocol::reader_options(),
    );
    let mut rpc = capnp_rpc::RpcSystem::new(Box::new(network), None);
    let client = rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
    let driver = crate::runtime::AbortTask(tokio::task::spawn_local(rpc));
    let mut stream = pair.received.streams.recv().await.unwrap();
    assert!(matches!(
        metadata::read_stream_kind(&mut stream).await.unwrap(),
        metadata::StreamKind::Rpc
    ));
    let callbacks = Rc::new(NetworkCallbacks(pair.connection.clone()));
    let metrics = pair.connection.state.context.metrics.clone();
    let server = crate::runtime::AbortTask(tokio::task::spawn_local(
        crate::protocol::callbacks::serve_callbacks(
            stream,
            callbacks,
            Duration::from_secs(5),
            metrics,
        ),
    ));
    IncomingRpc {
        client,
        _client_driver: driver,
        _server: server,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_idle_hints_do_not_crash_real_session_rpc_or_leak_slots() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let rpc = incoming_rpc(&mut pair).await;
            for hint in [-1, 0, 1, 7, 8] {
                let id = uuid::Uuid::new_v4();
                let mut call = rpc.client.register_udp_session_request();
                call.get().set_session_id(id.as_bytes());
                call.get().set_dst_ip(&[127, 0, 0, 1]);
                call.get().set_dst_port(destination.port());
                call.get().set_close_after_idle_hint(hint);
                call.get().set_trace_context("");
                let response = call.send().promise.await.unwrap();
                assert!(
                    response
                        .get()
                        .unwrap()
                        .get_result()
                        .unwrap()
                        .get_err()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .is_empty()
                );
                if hint <= 0 {
                    assert!(
                        timeout(Duration::from_millis(100), pair.incoming.streams.recv())
                            .await
                            .is_err(),
                        "negative and zero must use the source default, not immediate expiry"
                    );
                    let mut close = rpc.client.unregister_udp_session_request();
                    close.get().set_session_id(id.as_bytes());
                    close.get().set_message("synthetic remote close");
                    close.send().promise.await.unwrap();
                    drained(&state).await;
                } else {
                    let (mut peer, mut calls) = close_peer(&mut pair, false).await;
                    let call = calls.recv().await.unwrap();
                    assert_eq!(call.id, id);
                    assert_eq!(call.reason, format!("session idle for {hint}ns"));
                    let _ = timeout(Duration::from_secs(1), &mut peer.0)
                        .await
                        .unwrap()
                        .unwrap();
                    drained(&state).await;
                }
                assert_eq!(state.active_flows(), 0);
                assert_eq!(pair.connection.v2.len(), 0);
            }
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_origin_packets_mark_activity_and_transport_send_errors_do_not_close_session() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut pair =
                pair_with_packet_limit(state.clone(), &config, 0, DatagramVersion::V2, Some(1200))
                    .await;
            assert!(
                pair.client
                    .send_datagram(Bytes::from(vec![0; 1297]))
                    .await
                    .is_err(),
                "negotiated peer packet limit must actually reject this transport send"
            );
            assert!(!pair.client.is_closed());
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let id = uuid::Uuid::from_bytes([51; 16]);
            assert!(
                register(&pair, id, destination, Duration::from_millis(80))
                    .await
                    .error
                    .is_empty()
            );
            let source = learn_origin_port(&mut pair, &origin, id).await;
            let now = tokio::time::Instant::now();
            let mut cadence = tokio::time::interval_at(
                now + Duration::from_millis(40),
                Duration::from_millis(40),
            );
            for (index, size) in [1281, 1500, 1600].into_iter().enumerate() {
                cadence.tick().await;
                origin.send_to(&vec![0; size], source).await.unwrap();
                timeout(Duration::from_secs(1), async {
                    while state.context.metrics.packet_too_big_dropped.get() < index as u64 + 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            }
            assert!(now.elapsed() >= Duration::from_millis(120));
            assert_eq!(
                pair.connection.v2.len(),
                1,
                "oversized reads must refresh idle activity"
            );
            assert_eq!(state.context.metrics.udp_active_sessions.get(), 1);
            assert_eq!(state.context.metrics.udp_total_sessions.get(), 1);
            assert_eq!(state.context.metrics.packet_too_big_dropped.get(), 3);
            assert!(
                timeout(Duration::from_millis(20), pair.incoming.datagrams.recv())
                    .await
                    .is_err(),
                "oversized payloads must be dropped"
            );
            origin.send_to(&vec![0; 1280], source).await.unwrap();
            origin.send_to(&[], source).await.unwrap();
            assert_eq!(
                DatagramV2::decode(&pair.receive().await).unwrap(),
                DatagramV2::Udp {
                    session_id: *id.as_bytes(),
                    payload: vec![]
                }
            );
            assert_eq!(
                pair.connection.v2.len(),
                1,
                "MTU transport failure must drop only that packet"
            );
            origin.send_to(b"later packet", source).await.unwrap();
            assert_eq!(
                DatagramV2::decode(&pair.receive().await).unwrap(),
                DatagramV2::Udp {
                    session_id: *id.as_bytes(),
                    payload: b"later packet".to_vec()
                }
            );
            pair.connection.unregister_udp(id).await.unwrap();
            drained(&state).await;
            assert_eq!(state.context.metrics.udp_active_sessions.get(), 0);
            assert!(
                timeout(Duration::from_millis(100), pair.incoming.streams.recv())
                    .await
                    .is_err()
            );
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn loopback_udp_socket_error_sends_close_rpc_and_releases_socket_and_slot() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let id = uuid::Uuid::from_bytes([61; 16]);
            assert!(
                register(&pair, id, destination, Duration::from_secs(2))
                    .await
                    .error
                    .is_empty()
            );
            let source = learn_origin_port(&mut pair, &origin, id).await;
            drop(origin);
            pair.send(
                DatagramV2::Udp {
                    session_id: *id.as_bytes(),
                    payload: b"closed destination".to_vec(),
                }
                .encode()
                .unwrap(),
            )
            .await;
            let (mut peer, mut calls) = close_peer(&mut pair, false).await;
            let call = calls.recv().await.unwrap();
            assert_eq!(call.id, id);
            assert!(
                call.reason
                    .to_ascii_lowercase()
                    .contains("connection refused")
            );
            assert!(tokio::net::UdpSocket::bind(source).await.is_ok());
            let _ = timeout(Duration::from_secs(1), &mut peer.0)
                .await
                .unwrap()
                .unwrap();
            drained(&state).await;
            assert_eq!(pair.connection.v2.len(), 0);
            assert_eq!(state.context.metrics.udp_active_sessions.get(), 0);
            assert_eq!(state.context.metrics.udp_total_sessions.get(), 1);
            pair.client.close();
            pair.peer.close();
        })
        .await;
}
