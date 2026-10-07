use super::*;
use crate::{
    crypto::{EdgeTls, TlsPolicy},
    protocol::datagram::{DatagramV2, DatagramV3},
    runtime::scope,
    transport::quic::{self, QuicConnection, QuicIncoming},
};
use tokio::time::timeout;

#[path = "v2_lifecycle_tests.rs"]
mod v2_lifecycle;

#[path = "v3_ack_tests.rs"]
mod v3_ack;

#[path = "v3_duplex_tests.rs"]
mod v3_duplex;

#[path = "v3_metrics_tests.rs"]
mod v3_metrics;

#[path = "icmp_tests.rs"]
mod icmp_lifecycle;

#[path = "../proxy/tracing_wire_tests.rs"]
mod http_tracing;

struct Pair {
    client: QuicConnection,
    peer: QuicConnection,
    incoming: QuicIncoming,
    received: QuicIncoming,
    scope: scope::PendingSessionContext,
    connection: Arc<Connection>,
    _control: quic::QuicStream,
}
impl Pair {
    async fn send(&mut self, bytes: Vec<u8>) {
        self.try_send(bytes).await.unwrap();
    }
    async fn try_send(&mut self, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.peer.send_datagram(Bytes::from(bytes)).await?;
        let bytes = timeout(Duration::from_secs(2), self.received.datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        self.connection.handle(bytes).await
    }
    async fn receive(&mut self) -> Bytes {
        timeout(Duration::from_secs(2), self.incoming.datagrams.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

fn icmp_unavailable(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| matches!(error.raw_os_error(), Some(1 | 13 | 97 | 99)))
}
async fn assert_unavailable_icmp_cleanup(
    pair: &mut Pair,
    state: &NetworkState,
    error: &anyhow::Error,
) {
    assert!(icmp_unavailable(error));
    assert_eq!(state.icmp.len(), 0);
    assert!(
        timeout(Duration::from_millis(100), pair.incoming.datagrams.recv())
            .await
            .is_err(),
        "denied ping socket must emit no reply or successful tracing datagram"
    );
}
async fn pair(
    state: Arc<NetworkState>,
    config: &RunConfig,
    index: u8,
    version: DatagramVersion,
) -> Pair {
    pair_with_packet_limit(state, config, index, version, None).await
}
async fn pair_with_packet_limit(
    state: Arc<NetworkState>,
    config: &RunConfig,
    index: u8,
    version: DatagramVersion,
    packet_limit: Option<usize>,
) -> Pair {
    let (cert, key) = crate::runtime::tests::certificate();
    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
    ssl.set_certificate(&cert).unwrap();
    ssl.set_private_key(&key).unwrap();
    ssl.set_curves_list("X25519MLKEM768").unwrap();
    let mut peer_config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
    peer_config
        .set_application_protos(&[b"argotunnel"])
        .unwrap();
    peer_config.set_max_idle_timeout(5000);
    if let Some(limit) = packet_limit {
        peer_config.set_max_recv_udp_payload_size(limit);
    }
    peer_config.set_initial_max_data(1024 * 1024);
    peer_config.set_initial_max_stream_data_bidi_local(64 * 1024);
    peer_config.set_initial_max_stream_data_bidi_remote(64 * 1024);
    peer_config.set_initial_max_streams_bidi(128);
    peer_config.enable_dgram(true, 128, 128);
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let server = async move {
        let mut packet = vec![0; 65527];
        let (n, peer) = socket.recv_from(&mut packet).await.unwrap();
        let header = quiche::Header::from_slice(&mut packet[..n], 20).unwrap();
        let conn: tokio_quiche::quic::QuicheConnection =
            quiche::accept_with_buf_factory(&header.dcid, None, address, peer, &mut peer_config)
                .unwrap();
        let initial = tokio_quiche::quic::Incoming {
            peer_addr: peer,
            local_addr: address,
            rx_time: None,
            buf: packet[..n].to_vec(),
            gro: None,
            so_mark_data: None,
        };
        quic::attach_server(conn, socket, initial).await.unwrap()
    };
    let tls = EdgeTls::new(TlsPolicy::RequirePostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
    let options = crate::transport::EdgeDialOptions {
        bind_ip: Some("127.0.0.1".parse().unwrap()),
        quic_disable_pmtu_discovery: packet_limit.is_some(),
        ..Default::default()
    };
    let (client, peer) = tokio::join!(
        quic::dial_with_options(address, "quic.cftunnel.com", &tls, &options),
        server
    );
    let mut client = client.unwrap();
    let mut peer = peer;
    let control = client.open_bi().await.unwrap();
    assert_eq!(control.id(), 0);
    let incoming = peer.take_incoming().unwrap();
    let received = client.take_incoming().unwrap();
    let scope = scope::fixture_scope(config, index, version);
    let connection = Connection::new(
        state,
        &scope,
        client.sender(),
        Duration::from_millis(100),
        Duration::ZERO,
    );
    Pair {
        client,
        peer,
        incoming,
        received,
        scope,
        connection,
        _control: control,
    }
}
async fn drained(state: &NetworkState) {
    timeout(Duration::from_secs(2), async {
        while state.limiter.state.lock().unwrap().0 != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn echo_origin() -> (SocketAddr, crate::runtime::AbortTask<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::task::spawn_local(async move {
        let mut bytes = [0; 1500];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            socket.send_to(&bytes[..n], peer).await.unwrap();
        }
    });
    (address, crate::runtime::AbortTask(task))
}

#[tokio::test(flavor = "current_thread")]
async fn udp_v2_loopback_echo_duplicate_unregister_and_virtual_dns() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (destination, _origin) = echo_origin().await;
            let mut config = crate::runtime::tests::config();
            config.dns_resolver_addrs = vec![destination];
            let state = NetworkState::new(&config).unwrap();
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
            let id = uuid::Uuid::new_v4();
            let request = || UdpRegistration {
                session_id: id,
                destination: dns::VIRTUAL_DNS.ip(),
                port: 53,
                idle_hint: Duration::from_secs(5),
                trace_context: String::new(),
            };
            assert!(
                pair.connection
                    .register_udp(request())
                    .await
                    .error
                    .is_empty()
            );
            pair.send(
                DatagramV2::Udp {
                    session_id: *id.as_bytes(),
                    payload: b"dns-query".to_vec(),
                }
                .encode()
                .unwrap(),
            )
            .await;
            assert_eq!(
                DatagramV2::decode(&pair.receive().await).unwrap(),
                DatagramV2::Udp {
                    session_id: *id.as_bytes(),
                    payload: b"dns-query".to_vec()
                }
            );
            assert!(
                pair.connection
                    .register_udp(request())
                    .await
                    .error
                    .is_empty()
            );
            timeout(Duration::from_secs(2), async {
                while state.limiter.state.lock().unwrap().0 != 1 {
                    tokio::task::yield_now().await
                }
            })
            .await
            .unwrap();
            assert_eq!(pair.connection.v2.len(), 1);
            pair.send(
                DatagramV2::Udp {
                    session_id: *id.as_bytes(),
                    payload: b"replacement".to_vec(),
                }
                .encode()
                .unwrap(),
            )
            .await;
            assert_eq!(
                DatagramV2::decode(&pair.receive().await).unwrap(),
                DatagramV2::Udp {
                    session_id: *id.as_bytes(),
                    payload: b"replacement".to_vec()
                }
            );
            pair.connection.unregister_udp(id).await.unwrap();
            drained(&state).await;
            assert_eq!(pair.connection.v2.len(), 0);
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn udp_v3_migrates_same_index_attempt_preserves_origin_and_releases_limits() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (destination, _origin) = echo_origin().await;
            let mut config = crate::runtime::tests::config();
            config.max_active_flows = Some(1);
            let state = NetworkState::new(&config).unwrap();
            let mut first = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let mut second = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            assert_ne!(first.connection.generation, second.connection.generation);
            let id = [8; 16];
            let registration = |id, destination| {
                DatagramV3::Registration {
                    id,
                    destination,
                    idle_seconds: 1,
                    payload: vec![],
                    traced: false,
                }
                .encode()
                .unwrap()
            };
            first.send(registration(id, destination)).await;
            assert!(matches!(
                DatagramV3::decode(&first.receive().await).unwrap(),
                DatagramV3::Response {
                    response_type: 0,
                    ..
                }
            ));
            first.send(registration([9; 16], destination)).await;
            assert!(matches!(
                DatagramV3::decode(&first.receive().await).unwrap(),
                DatagramV3::Response {
                    response_type: 3,
                    ..
                }
            ));
            second
                .send(registration(id, "127.0.0.1:1".parse().unwrap()))
                .await;
            assert!(matches!(
                DatagramV3::decode(&second.receive().await).unwrap(),
                DatagramV3::Response {
                    response_type: 0,
                    ..
                }
            ));
            first.scope.cancellation().cancel();
            tokio::task::yield_now().await;
            second
                .send(
                    DatagramV3::Payload {
                        id,
                        payload: b"migrated".to_vec(),
                    }
                    .encode()
                    .unwrap(),
                )
                .await;
            assert_eq!(
                DatagramV3::decode(&second.receive().await).unwrap(),
                DatagramV3::Payload {
                    id,
                    payload: b"migrated".to_vec()
                }
            );
            assert_eq!(state.v3.len(), 1);
            assert_eq!(state.limiter.state.lock().unwrap().0, 1);
            second.scope.cancellation().cancel();
            drained(&state).await;
            assert_eq!(state.v3.len(), 0);
            first.client.close();
            first.peer.close();
            second.client.close();
            second.peer.close();
        })
        .await;
}
#[test]
fn flow_permits_release_after_failure_and_remote_limits_preserve_cli_zero() {
    let limiter = Limiter::new(1);
    let permit = limiter.acquire().unwrap();
    assert!(limiter.acquire().is_err());
    drop(permit);
    assert!(limiter.acquire().is_ok());
    limiter.set_limit(0);
    let first = limiter.acquire().unwrap();
    let second = limiter.acquire().unwrap();
    drop((first, second));
    let config =
        LoadedConfig::from_json(r#"{"warp-routing":{"maxActiveFlows":1,"connectTimeout":7}}"#)
            .unwrap();
    assert_eq!(PrivateConfig::parse(&config, Some(0)).unwrap().max_flows, 0);
    assert_eq!(
        PrivateConfig::parse(&config, None).unwrap().connect_timeout,
        Duration::from_secs(7)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn udp_v3_real_idle_expiry_releases_flow_slot() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (destination, _origin) = echo_origin().await;
            let mut config = crate::runtime::tests::config();
            config.max_active_flows = Some(1);
            let state = NetworkState::new(&config).unwrap();
            let mut pair = pair(state.clone(), &config, 1, DatagramVersion::V3).await;
            pair.send(
                DatagramV3::Registration {
                    id: [6; 16],
                    destination,
                    idle_seconds: 1,
                    traced: false,
                    payload: vec![],
                }
                .encode()
                .unwrap(),
            )
            .await;
            assert!(matches!(
                DatagramV3::decode(&pair.receive().await).unwrap(),
                DatagramV3::Response {
                    response_type: 0,
                    ..
                }
            ));
            assert_eq!(state.limiter.state.lock().unwrap().0, 1);
            drained(&state).await;
            assert_eq!(state.v3.len(), 0);
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn icmp_loopback_kernel_translation_reconnect_or_unavailable_socket_cleanup() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for ipv4 in [true, false] {
                let mut config = crate::runtime::tests::config();
                config.icmpv4_src = Some("127.0.0.1".parse().unwrap());
                config.icmpv6_src = Some("::1".into());
                let state = NetworkState::new(&config).unwrap();
                if !state.icmp.supports(ipv4) {
                    eprintln!("ICMP family unavailable at startup; disabled cleanup verified");
                    assert_eq!(state.icmp.len(), 0);
                    continue;
                }
                let mut first = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
                let mut second = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
                let destination: std::net::IpAddr =
                    if ipv4 { "127.0.0.1" } else { "::1" }.parse().unwrap();
                let packet = |sequence| {
                    packet::IcmpPacket {
                        source: destination,
                        destination,
                        ttl: 64,
                        message: vec![
                            if ipv4 { 8 } else { 128 },
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            sequence,
                            4,
                            5,
                            6,
                        ],
                    }
                    .encode()
                    .unwrap()
                };
                let bytes = DatagramV2::Ip(packet(1)).encode().unwrap();
                first.peer.send_datagram(Bytes::from(bytes)).await.unwrap();
                let bytes = timeout(Duration::from_secs(2), first.received.datagrams.recv())
                    .await
                    .unwrap()
                    .unwrap();
                if let Err(error) = first.connection.handle(bytes).await {
                    if icmp_unavailable(&error) {
                        assert_unavailable_icmp_cleanup(&mut first, &state, &error).await;
                        eprintln!(
                            "ICMP{} kernel proof unavailable; denial cleanup verified: {error}",
                            if ipv4 { 4 } else { 6 }
                        );
                        continue;
                    }
                    panic!("ICMP loopback error: {error}");
                }
                let DatagramV2::Ip(reply) = DatagramV2::decode(&first.receive().await).unwrap()
                else {
                    panic!("expected ICMP reply")
                };
                let reply = packet::IcmpPacket::decode(&reply).unwrap();
                assert_eq!(
                    u16::from_be_bytes(reply.message[4..6].try_into().unwrap()),
                    0
                );
                assert_eq!(reply.message[7], 1);
                assert_eq!(reply.message[0], if ipv4 { 0 } else { 129 });
                assert_eq!(reply.ttl, 255);
                assert_eq!(reply.source, destination);
                assert!(state.icmp.kernel_ids().iter().all(|id| *id != 0));
                assert_eq!(state.icmp.len(), 1);
                second
                    .send(DatagramV2::Ip(packet(2)).encode().unwrap())
                    .await;
                first.scope.cancellation().cancel();
                let DatagramV2::Ip(reply) = DatagramV2::decode(&second.receive().await).unwrap()
                else {
                    panic!("expected replacement reply")
                };
                let reply = packet::IcmpPacket::decode(&reply).unwrap();
                assert_eq!(
                    u16::from_be_bytes(reply.message[4..6].try_into().unwrap()),
                    0
                );
                assert_eq!(reply.message[7], 2);
                assert_eq!(state.icmp.len(), 1);
                second.scope.cancellation().cancel();
                timeout(Duration::from_secs(2), async {
                    while state.icmp.len() != 0 {
                        tokio::task::yield_now().await
                    }
                })
                .await
                .unwrap();
                first.client.close();
                first.peer.close();
                second.client.close();
                second.peer.close();
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn icmp_v2_kernel_correlated_otlp_or_unavailable_socket_cleanup() {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use prost::Message;
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut config = crate::runtime::tests::config();
            config.icmpv4_src = Some("127.0.0.1".parse().unwrap());
            let state = NetworkState::new(&config).unwrap();
            if !state.icmp.supports(true) {
                eprintln!("ICMPv4 kernel/OTLP proof unavailable at startup; disabled cleanup verified");
                assert_eq!(state.icmp.len(), 0);
                return;
            }
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
            let mut identity = [0x11; 25];
            identity[16..24].fill(0x22);
            identity[24] = 1;
            let request = packet::IcmpPacket {
                source: "127.0.0.1".parse().unwrap(),
                destination: "127.0.0.1".parse().unwrap(),
                ttl: 64,
                message: vec![8, 0, 0, 0, 0, 0, 0, 1],
            }
            .encode()
            .unwrap();
            let encoded=DatagramV2::TracedIp{identity,payload:request}.encode().unwrap();
            if let Err(error)=pair.try_send(encoded).await {
                if icmp_unavailable(&error) {
                    assert_unavailable_icmp_cleanup(&mut pair,&state,&error).await;
                    eprintln!("ICMPv2 kernel/OTLP proof unavailable; denial cleanup and absence of replies verified: {error}");
                    pair.scope.cancellation().cancel();pair.client.close();pair.peer.close();
                    return;
                }
                panic!("unexpected ICMPv2 trace error: {error}");
            }
            let mut names = Vec::new();
            let mut replies = 0;
            for _ in 0..3 {
                match DatagramV2::decode(&pair.receive().await).unwrap() {
                    DatagramV2::Ip(_) => replies += 1,
                    DatagramV2::TraceSpans {
                        identity: received,
                        payload,
                    } => {
                        assert_eq!(received, identity);
                        let export = ExportTraceServiceRequest::decode(payload.as_slice()).unwrap();
                        let span = &export.resource_spans[0].scope_spans[0].spans[0];
                        assert_eq!(span.trace_id, [0x11; 16]);
                        assert_eq!(span.parent_span_id, [0x22; 8]);
                        assert_eq!(span.kind, 1);
                        names.push(span.name.clone());
                    }
                    other => panic!("unexpected ICMP datagram: {other:?}"),
                }
            }
            names.sort();
            assert_eq!(names, ["icmp-echo-reply", "icmp-echo-request"]);
            assert_eq!(replies, 1);
            pair.scope.cancellation().cancel();
            timeout(Duration::from_secs(2), async {
                while state.icmp.len() != 0 {
                    tokio::task::yield_now().await
                }
            })
            .await
            .unwrap();
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn private_quic_tcp_half_close_virtual_dns_ack_trace_and_metrics_lifetime() {
    use crate::protocol::metadata::{self, ConnectRequest, ConnectionType, StreamKind};
    use base64::Engine;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::task::LocalSet::new()
        .run_until(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = listener.local_addr().unwrap();
            let origin = crate::runtime::AbortTask(tokio::task::spawn_local(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut body = Vec::new();
                socket.read_to_end(&mut body).await.unwrap();
                socket.write_all(&body).await.unwrap();
                socket.write_all(b"origin-after-eof").await.unwrap();
                socket.shutdown().await.unwrap();
            }));
            let mut config = crate::runtime::tests::config();
            config.dns_resolver_addrs = vec![destination];
            let state = NetworkState::new(&config).unwrap();
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
            let mut stream = pair.peer.open_bi().await.unwrap();
            metadata::write_connect_request(
                &mut stream,
                &ConnectRequest {
                    destination: dns::VIRTUAL_DNS.to_string(),
                    connection_type: ConnectionType::Tcp,
                    metadata: vec![(
                        "cf-trace-id".into(),
                        "11111111111111111111111111111111:2222222222222222:0:1".into(),
                    )],
                },
            )
            .await
            .unwrap();
            let worker = async {
                let mut incoming = pair.received.streams.recv().await.unwrap();
                assert_eq!(
                    metadata::read_stream_kind(&mut incoming).await.unwrap(),
                    StreamKind::Data
                );
                let request = metadata::read_connect_request(&mut incoming).await.unwrap();
                state.serve_quic_tcp(incoming, request).await.unwrap();
            };
            let client = async {
                let response = metadata::read_connect_response(&mut stream).await.unwrap();
                assert!(response.error.is_empty());
                let (_, encoded) = response
                    .metadata
                    .iter()
                    .find(|(key, _)| key == "Cf-Int-Cloudflared-Tracing")
                    .unwrap();
                let data = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap();
                let export = ExportTraceServiceRequest::decode(data.as_slice()).unwrap();
                assert_eq!(
                    export.resource_spans[0].scope_spans[0].spans[0].name,
                    "stream-connect"
                );
                assert_eq!(state.context.metrics.tcp_active.get(), 1);
                assert_eq!(state.context.metrics.tcp_total.get(), 1);
                let payload = vec![0x5a; 128 * 1024];
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut returned = Vec::new();
                stream.read_to_end(&mut returned).await.unwrap();
                assert_eq!(&returned[..payload.len()], payload);
                assert_eq!(&returned[payload.len()..], b"origin-after-eof");
            };
            timeout(Duration::from_secs(5), async {
                tokio::join!(worker, client);
            })
            .await
            .unwrap();
            assert_eq!(state.context.metrics.tcp_active.get(), 0);
            assert_eq!(state.limiter.state.lock().unwrap().0, 0);
            assert!(state.context.metrics.connect_latency.get_sample_count() > 0);
            assert_eq!(state.context.metrics.connect_errors.get(), 0);
            drop(origin);
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn private_h2_tcp_streams_response_tail_before_end_and_exports_ack_trace() {
    use base64::Engine;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::task::LocalSet::new()
        .run_until(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = listener.local_addr().unwrap();
            let _origin = crate::runtime::AbortTask(tokio::task::spawn_local(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut body = Vec::new();
                socket.read_to_end(&mut body).await.unwrap();
                socket.write_all(&body).await.unwrap();
                socket.write_all(b"response-tail").await.unwrap();
                socket.shutdown().await.unwrap();
            }));
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let (client, server) = tokio::io::duplex(64 * 1024);
            let shared = state.clone();
            let server = async move {
                let mut server = h2::server::handshake(server).await.unwrap();
                let (request, response) = server.accept().await.unwrap().unwrap();
                let mut task = crate::runtime::AbortTask(tokio::task::spawn_local(
                    shared.serve_h2_tcp(request, response),
                ));
                tokio::select! {
                    result = &mut task.0 => {
                        result.unwrap().unwrap();
                        server.graceful_shutdown();
                        let closed=futures::future::poll_fn(|cx|server.poll_closed(cx)).await;
                        assert!(closed.is_ok()||closed.unwrap_err().is_io(),"unexpected H2 shutdown protocol error");
                    }
                    incoming = server.accept() => {
                        assert!(incoming.is_none());
                    }
                }
            };
            let client = async {
                let (mut client, driver) = h2::client::handshake(client).await.unwrap();
                let _driver = crate::runtime::AbortTask(tokio::task::spawn_local(driver));
                let (response, mut send) = client
                    .send_request(
                        http::Request::builder()
                            .method("POST")
                            .uri(format!("https://{destination}/"))
                            .header("cf-cloudflared-proxy-src", "tcp")
                            .header(
                                "cf-trace-id",
                                "11111111111111111111111111111111:2222222222222222:0:1",
                            )
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), 200);
                assert_eq!(state.context.metrics.tcp_active.get(), 1);
                let headers = crate::protocol::headers::deserialize(
                    response.headers()["cf-cloudflared-response-headers"]
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                let data = base64::engine::general_purpose::STANDARD
                    .decode(&headers[0].1)
                    .unwrap();
                let export = ExportTraceServiceRequest::decode(data.as_slice()).unwrap();
                assert_eq!(
                    export.resource_spans[0].scope_spans[0].spans[0].name,
                    "stream-connect"
                );
                let payload = vec![0x5a; 128 * 1024];
                let mut body = response.into_body();
                let upload = async {
                    crate::runtime::h2_control::send_data(
                        &mut send,
                        Bytes::copy_from_slice(&payload),
                    )
                    .await
                    .unwrap();
                    send.send_data(Bytes::new(), true).unwrap();
                };
                let download = async {
                    let mut returned = Vec::new();
                    while let Some(bytes) = body.data().await {
                        let bytes = bytes.unwrap();
                        returned.extend_from_slice(&bytes);
                        body.flow_control().release_capacity(bytes.len()).unwrap();
                    }
                    assert_eq!(&returned[..payload.len()], payload);
                    assert_eq!(&returned[payload.len()..], b"response-tail");
                };
                tokio::join!(upload, download);
            };
            timeout(Duration::from_secs(5), async {
                tokio::join!(server, client);
            })
            .await
            .unwrap();
            assert_eq!(state.context.metrics.tcp_active.get(), 0);
            assert_eq!(state.limiter.state.lock().unwrap().0, 0);
        })
        .await;
}
