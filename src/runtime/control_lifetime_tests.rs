use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct LifetimeOracle {
    inner: Rc<Oracle>,
    configured: Arc<tokio::sync::Notify>,
}

enum EndControl {
    Fin,
    Reset,
}
impl wire::registration_server::Server for LifetimeOracle {
    async fn register_connection(
        self: Rc<Self>,
        params: wire::registration_server::RegisterConnectionParams,
        results: wire::registration_server::RegisterConnectionResults,
    ) -> capnp::Result<()> {
        self.inner
            .clone()
            .register_connection(params, results)
            .await
    }
    async fn unregister_connection(
        self: Rc<Self>,
        params: wire::registration_server::UnregisterConnectionParams,
        results: wire::registration_server::UnregisterConnectionResults,
    ) -> capnp::Result<()> {
        self.inner
            .clone()
            .unregister_connection(params, results)
            .await
    }
    async fn update_local_configuration(
        self: Rc<Self>,
        params: wire::registration_server::UpdateLocalConfigurationParams,
        results: wire::registration_server::UpdateLocalConfigurationResults,
    ) -> capnp::Result<()> {
        self.inner
            .clone()
            .update_local_configuration(params, results)
            .await?;
        self.configured.notify_one();
        Ok(())
    }
}

fn oracle(
    configured: Arc<tokio::sync::Notify>,
    origin_ip: std::net::Ipv4Addr,
) -> wire::registration_server::Client {
    capnp_rpc::new_client(LifetimeOracle {
        inner: Rc::new(Oracle {
            registered: Arc::new(tokio::sync::Notify::new()),
            unregistered: Arc::new(AtomicBool::new(false)),
            observed: Arc::new(Mutex::new(Vec::new())),
            local_configuration: Arc::new(AtomicBool::new(false)),
            origin_ip,
            reject: false,
            acknowledgement: None,
            timestamps: None,
            unregister_count: None,
        }),
        configured,
    })
}

async fn connected(events: &mut mpsc::UnboundedReceiver<Event>, protocol: EdgeProtocol) {
    assert!(matches!(events.recv().await, Some(Event::Connected(0, value)) if value == protocol));
}

#[tokio::test(flavor = "current_thread")]
async fn h2_control_fin_keeps_admission_and_reset_revokes_only_admission() {
    for (reset, late_reset) in [(false, false), (true, false), (false, true)] {
        tokio::task::LocalSet::new()
            .run_until(h2_control_case(reset, late_reset))
            .await;
    }
}

async fn h2_control_case(reset: bool, late_reset: bool) {
    let (cert, key) = certificate();
    let mut acceptor =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.set_private_key(&key).unwrap();
    let acceptor = acceptor.build();
    let tls = EdgeTls::new(TlsPolicy::PreferPostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut runtime = runtime(config());
    let (events, mut received) = mpsc::unbounded_channel();
    Arc::get_mut(&mut runtime).unwrap().events = events;
    let shared = runtime.clone();
    let edge = tokio::task::spawn_local(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let tls = tokio_boring::accept(&acceptor, socket).await.unwrap();
        let (mut client, driver) = h2::client::handshake(tls).await.unwrap();
        let driver = AbortTask(tokio::task::spawn_local(driver));
        let (answer, mut send) = client
            .send_request(
                http::Request::builder()
                    .method("POST")
                    .uri("https://synthetic.invalid/control")
                    .header("cf-cloudflared-proxy-connection-upgrade", "control-stream")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let mut receive = answer.await.unwrap().into_body();
        let (control, transport) = tokio::io::duplex(64 * 1024);
        let (mut read, mut write) = tokio::io::split(transport);
        let (end, mut ending) = mpsc::unbounded_channel();
        let (ended, mut end_received) = mpsc::unbounded_channel();
        let pump = AbortTask(tokio::task::spawn_local(async move {
            let incoming = async {
                while let Some(bytes) = receive.data().await {
                    let bytes = bytes.map_err(std::io::Error::other)?;
                    write.write_all(&bytes).await?;
                    receive
                        .flow_control()
                        .release_capacity(bytes.len())
                        .map_err(std::io::Error::other)?;
                }
                write.shutdown().await
            };
            let outgoing = async {
                let mut sent_fin = false;
                let mut bytes = [0; 16384];
                loop {
                    tokio::select! {
                        command = ending.recv() => {
                            match command {
                                Some(EndControl::Fin) => {
                                    send.send_data(Bytes::new(), true)
                                        .map_err(std::io::Error::other)?;
                                    sent_fin = true;
                                }
                                Some(EndControl::Reset) => {
                                    send.send_reset(h2::Reason::CANCEL);
                                    let _ = ended.send(());
                                    return Ok::<_, std::io::Error>(());
                                }
                                None => return Ok(()),
                            }
                            let _ = ended.send(());
                        }
                        count = read.read(&mut bytes), if !sent_fin => {
                            let count = count?;
                            if count == 0 {
                                return Ok(());
                            }
                            h2_control::send_data(&mut send, Bytes::copy_from_slice(&bytes[..count])).await?;
                        }
                    }
                }
            };
            tokio::try_join!(incoming, outgoing)
        }));
        let (read, write) = tokio::io::split(control);
        let network = capnp_rpc::twoparty::VatNetwork::new(
            read.compat(),
            write.compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            crate::protocol::reader_options(),
        );
        let configured = Arc::new(tokio::sync::Notify::new());
        let service = oracle(configured.clone(), "127.0.0.2".parse().unwrap());
        let rpc = AbortTask(tokio::task::spawn_local(capnp_rpc::RpcSystem::new(
            Box::new(network),
            Some(service.client),
        )));
        connected(&mut received, EdgeProtocol::Http2).await;
        configured.notified().await;
        assert_eq!(shared.readiness.count(), 1);
        let admission = {
            let slots = shared.readiness.slots.lock().unwrap();
            match &slots[&0].liveness {
                SessionLiveness::Http2 { control } => control.clone(),
                SessionLiveness::Quic { .. } => {
                    panic!("H2 admission needs its actual control scope")
                }
            }
        };
        end.send(if reset {
            EndControl::Reset
        } else {
            EndControl::Fin
        })
        .unwrap();
        end_received.recv().await.unwrap();
        if reset {
            admission.cancelled().await;
            assert_eq!(shared.readiness.count(), 0);
            assert_eq!(shared.context.metrics.ha_connections.get(), 0);
        }
        let updated = update_request(
            &mut client,
            9,
            serde_json::json!({"ingress":[{"service":"http_status:204"}]}),
        )
        .await;
        assert_eq!(updated["lastAppliedVersion"], 9);
        let (answer, _) = client
            .send_request(
                http::Request::builder()
                    .uri("https://synthetic.invalid/after-control-end")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(answer.await.unwrap().status(), 204);
        // An idle observation interval verifies timer progress and stable admission,
        // rather than delaying a prerequisite event.
        if !reset {
            assert!(
                tokio::time::timeout(Duration::from_millis(25), admission.cancelled())
                    .await
                    .is_err()
            );
        }
        assert_eq!(shared.readiness.count(), usize::from(!reset));
        assert_eq!(
            shared
                .context
                .metrics
                .register_success
                .with_label_values(&["registerConnection"])
                .get(),
            1
        );
        assert_eq!(
            shared
                .context
                .metrics
                .register_fail
                .with_label_values(&["server_error", "registerConnection"])
                .get(),
            0
        );
        if late_reset {
            end.send(EndControl::Reset).unwrap();
            tokio::time::timeout(Duration::from_secs(1), end_received.recv())
                .await
                .expect("peer must retain reset sender after FIN")
                .unwrap();
            tokio::time::timeout(Duration::from_secs(1), admission.cancelled())
                .await
                .expect("actual H2 reset after FIN must revoke admission");
            assert_eq!(shared.readiness.count(), 0);
            let updated = update_request(
                &mut client,
                10,
                serde_json::json!({"ingress":[{"service":"http_status:205"}]}),
            )
            .await;
            assert_eq!(updated["lastAppliedVersion"], 10);
            let (answer, _) = client
                .send_request(
                    http::Request::builder()
                        .uri("https://synthetic.invalid/after-late-reset")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            assert_eq!(answer.await.unwrap().status(), 205);
        }
        drop(rpc);
        drop(pump);
        drop(driver);
    });
    let mut retry = None;
    let connector = serve_h2(runtime.clone(), &tls, 0, address, 0, &mut retry);
    tokio::time::timeout(Duration::from_secs(5), async {
        let (result, peer) = tokio::join!(connector, edge);
        assert!(result.is_err());
        peer.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(runtime.readiness.count(), 0);
    assert_eq!(runtime.context.metrics.ha_connections.get(), 0);
    assert!(runtime.readiness.slots.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn quic_control_fin_keeps_transport_admission_http_and_callbacks() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (cert, key) = certificate();
            let mut ssl =
                boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
            ssl.set_certificate(&cert).unwrap();
            ssl.set_private_key(&key).unwrap();
            ssl.set_curves_list("X25519MLKEM768").unwrap();
            let mut config =
                quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
            config.set_application_protos(&[b"argotunnel"]).unwrap();
            config.set_max_idle_timeout(5000);
            config.set_initial_max_data(1024 * 1024);
            config.set_initial_max_stream_data_bidi_local(65536);
            config.set_initial_max_stream_data_bidi_remote(65536);
            config.set_initial_max_streams_bidi(128);
            config.enable_dgram(true, 32, 32);
            let tls =
                EdgeTls::new(TlsPolicy::RequirePostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
            let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let address = socket.local_addr().unwrap();
            let mut run = super::config();
            run.protocol = Protocol::Auto;
            let mut runtime = runtime(run);
            let (events, mut received) = mpsc::unbounded_channel();
            Arc::get_mut(&mut runtime).unwrap().events = events;
            let shared = runtime.clone();
            let edge = tokio::task::spawn_local(async move {
                let mut packet = vec![0; 65527];
                let (n, peer) = socket.recv_from(&mut packet).await.unwrap();
                let header = quiche::Header::from_slice(&mut packet[..n], 20).unwrap();
                let conn: tokio_quiche::quic::QuicheConnection =
                    quiche::accept_with_buf_factory(&header.dcid, None, address, peer, &mut config)
                        .unwrap();
                let initial = tokio_quiche::quic::Incoming {
                    peer_addr: peer,
                    local_addr: address,
                    rx_time: None,
                    buf: packet[..n].to_vec(),
                    gro: None,
                    so_mark_data: None,
                };
                let mut conn = transport::quic::attach_server(conn, socket, initial)
                    .await
                    .unwrap();
                let observer = conn.liveness();
                let control_stream = conn.accept_bi().await.unwrap();
                assert_eq!(control_stream.id(), 0);
                let (mut stream_read, mut stream_write) = tokio::io::split(control_stream);
                let (control, transport) = tokio::io::duplex(65536);
                let (mut read, mut write) = tokio::io::split(transport);
                let (end, ending) = oneshot::channel();
                let (ended, end_received) = oneshot::channel();
                let pump = AbortTask(tokio::task::spawn_local(async move {
                    let incoming = tokio::io::copy(&mut stream_read, &mut write);
                    let outgoing = async {
                        let mut ending = ending;
                        let mut bytes = [0; 16384];
                        loop {
                            tokio::select! {
                                _ = &mut ending => {
                                    stream_write.shutdown().await?;
                                    let _ = ended.send(());
                                    return Ok::<_, std::io::Error>(());
                                }
                                count = read.read(&mut bytes) => {
                                    let count = count?;
                                    if count == 0 {
                                return Ok(());
                            }
                                    stream_write.write_all(&bytes[..count]).await?;
                                }
                            }
                        }
                    };
                    tokio::try_join!(incoming, outgoing)
                }));
                let (read, write) = tokio::io::split(control);
                let network = capnp_rpc::twoparty::VatNetwork::new(
                    read.compat(),
                    write.compat_write(),
                    capnp_rpc::rpc_twoparty_capnp::Side::Server,
                    crate::protocol::reader_options(),
                );
                let configured = Arc::new(tokio::sync::Notify::new());
                let service = oracle(configured.clone(), "127.0.0.1".parse().unwrap());
                let rpc = AbortTask(tokio::task::spawn_local(capnp_rpc::RpcSystem::new(
                    Box::new(network),
                    Some(service.client),
                )));
                connected(&mut received, EdgeProtocol::Quic).await;
                configured.notified().await;
                assert_eq!(shared.readiness.count(), 1);
                end.send(()).unwrap();
                end_received.await.unwrap();
                let mut callback = conn.open_bi().await.unwrap();
                callback.write_all(&metadata::RPC_SIGNATURE).await.unwrap();
                let (read, write) = tokio::io::split(callback);
                let network = capnp_rpc::twoparty::VatNetwork::new(
                    read.compat(),
                    write.compat_write(),
                    capnp_rpc::rpc_twoparty_capnp::Side::Client,
                    crate::protocol::reader_options(),
                );
                let mut rpc_driver = capnp_rpc::RpcSystem::new(Box::new(network), None);
                let client: wire::configuration_manager::Client =
                    rpc_driver.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                let callback_driver = AbortTask(tokio::task::spawn_local(rpc_driver));
                let mut call = client.update_configuration_request();
                call.get().set_version(9);
                call.get()
                    .set_config(br#"{"ingress":[{"service":"http_status:204"}]}"#);
                let response = call.send().promise.await.unwrap();
                assert_eq!(
                    response
                        .get()
                        .unwrap()
                        .get_result()
                        .unwrap()
                        .get_latest_applied_version(),
                    9
                );
                let mut stream = conn.open_bi().await.unwrap();
                metadata::write_connect_request(
                    &mut stream,
                    &metadata::ConnectRequest {
                        destination: "https://synthetic.invalid/after-control-fin".into(),
                        connection_type: metadata::ConnectionType::Http,
                        metadata: vec![
                            ("HttpMethod".into(), "GET".into()),
                            ("HttpHost".into(), "synthetic.invalid".into()),
                        ],
                    },
                )
                .await
                .unwrap();
                stream.shutdown().await.unwrap();
                let response = metadata::read_connect_response(&mut stream).await.unwrap();
                assert!(
                    response
                        .metadata
                        .iter()
                        .any(|(key, value)| key == "HttpStatus" && value == "204")
                );
                stream.read_to_end(&mut Vec::new()).await.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(25), received.recv())
                        .await
                        .is_err()
                );
                assert_eq!(shared.readiness.count(), 1);
                assert_eq!(shared.context.metrics.ha_connections.get(), 1);
                assert!(shared.ever_quic.load(Ordering::Acquire));
                assert!(!observer.is_closed());
                conn.close();
                observer.closed().await;
                assert!(observer.is_closed());
                drop(callback_driver);
                drop(rpc);
                drop(pump);
            });
            let mut retry = None;
            let connector = serve_quic(runtime.clone(), &tls, 0, address, 0, &mut retry);
            tokio::time::timeout(Duration::from_secs(5), async {
                let (result, peer) = tokio::join!(connector, edge);
                assert!(result.is_err());
                peer.unwrap();
            })
            .await
            .unwrap();
            assert_eq!(runtime.readiness.count(), 0);
            assert_eq!(runtime.context.metrics.ha_connections.get(), 0);
            assert!(runtime.readiness.slots.lock().unwrap().is_empty());
            assert!(runtime.ever_quic.load(Ordering::Acquire));
            assert!(!runtime.should_fallback(EdgeProtocol::Quic, true, true));
        })
        .await;
}
