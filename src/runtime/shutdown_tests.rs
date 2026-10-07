use super::*;

#[tokio::test(flavor = "current_thread")]
async fn initialized_h2_grace_admits_late_ack_unregisters_it_and_keeps_accepting() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (cert, key) = certificate();
            let mut acceptor =
                boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                    .unwrap();
            acceptor.set_certificate(&cert).unwrap();
            acceptor.set_private_key(&key).unwrap();
            let acceptor = acceptor.build();
            let tls =
                EdgeTls::new(TlsPolicy::PreferPostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut config = config();
            config.ha_connections = 1;
            config.grace_period = Duration::from_secs(1);
            let mut runtime = runtime(config);
            let (events, mut received) = mpsc::unbounded_channel();
            Arc::get_mut(&mut runtime).unwrap().events = events;
            let shared = runtime.clone();
            let edge = tokio::task::spawn_local(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let tls = tokio_boring::accept(&acceptor, socket).await.unwrap();
                let (mut client, driver) = h2::client::handshake(tls).await.unwrap();
                let _driver = AbortTask(tokio::task::spawn_local(driver));
                let first =
                    control_lifetime::peer_control(&mut client, control_lifetime::Reply::Accept)
                        .await;
                assert!(matches!(
                    received.recv().await,
                    Some(Event::Connected(0, EdgeProtocol::Http2))
                ));
                let gate = Arc::new(tokio::sync::Notify::new());
                let second = control_lifetime::peer_control(
                    &mut client,
                    control_lifetime::Reply::Gated(gate.clone()),
                )
                .await;
                second.entered.notified().await;
                shared.shutdown.cancel();
                first.unregistered.notified().await;
                gate.notify_one();
                tokio::time::timeout(Duration::from_millis(500), second.unregistered.notified())
                    .await
                    .expect("late real ACK must be admitted then unregistered during grace");
                assert_eq!(first.unregisters.load(Ordering::Acquire), 1);
                assert_eq!(second.unregisters.load(Ordering::Acquire), 1);
                let (answer, _) = client
                    .send_request(
                        http::Request::builder()
                            .uri("https://synthetic.invalid/during-grace")
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .expect("no early GOAWAY may reject source-permitted grace traffic");
                assert_eq!(answer.await.unwrap().status(), 203);
                let updated = update_request(
                    &mut client,
                    9,
                    serde_json::json!({"ingress":[{"service":"http_status:204"}]}),
                )
                .await;
                assert_eq!(updated["lastAppliedVersion"], 9);
                assert_eq!(
                    shared
                        .context
                        .metrics
                        .register_success
                        .with_label_values(&["registerConnection"])
                        .get(),
                    2
                );
            });
            let mut retry = None;
            tokio::time::timeout(Duration::from_secs(5), async {
                let (result, peer) = tokio::join!(
                    serve_h2(runtime.clone(), &tls, 0, address, 0, &mut retry),
                    edge
                );
                result.unwrap();
                peer.unwrap();
            })
            .await
            .unwrap();
            assert_eq!(runtime.readiness.count(), 0);
        })
        .await;
}

#[derive(Clone, Copy, Debug)]
enum ShutdownEnd {
    BeforeAck,
    PeerClose,
    Deadline,
    Force,
    ZeroGrace,
}

async fn diagnostic(address: SocketAddr, path: &str) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    response
}

#[tokio::test(flavor = "current_thread")]
async fn global_h2_shutdown_uses_one_deadline_and_keeps_diagnostics_until_termination() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for ending in [
                ShutdownEnd::BeforeAck,
                ShutdownEnd::PeerClose,
                ShutdownEnd::Deadline,
                ShutdownEnd::Force,
                ShutdownEnd::ZeroGrace,
            ] {
                let (cert, key) = certificate();
                let mut acceptor = boring::ssl::SslAcceptor::mozilla_intermediate_v5(
                    boring::ssl::SslMethod::tls(),
                )
                .unwrap();
                acceptor.set_certificate(&cert).unwrap();
                acceptor.set_private_key(&key).unwrap();
                let acceptor = acceptor.build();
                let tls = EdgeTls::new(TlsPolicy::PreferPostQuantum, Some(&cert.to_pem().unwrap()))
                    .unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let mut config = config();
                config.ha_connections = 1;
                config.grace_period = match ending {
                    ShutdownEnd::Deadline => Duration::from_millis(150),
                    ShutdownEnd::ZeroGrace => Duration::ZERO,
                    _ => Duration::from_secs(2),
                };
                let mut runtime = runtime(config);
                let (events, received) = mpsc::unbounded_channel();
                Arc::get_mut(&mut runtime).unwrap().events = events;
                let pool = Arc::new(Mutex::new(
                    discovery::EdgePool::new(vec![vec![address]]).unwrap(),
                ));
                let metrics = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let metrics_address = metrics.local_addr().unwrap();
                let mut health =
                    health_server_on(metrics, runtime.clone(), CancellationToken::new()).unwrap();
                let shared = runtime.clone();
                let runner = tokio::task::spawn_local(async move {
                    let result = supervise(shared, pool, tls, 1, received).await;
                    health.0.abort();
                    let _ = (&mut health.0).await;
                    result
                });
                let (socket, _) = listener.accept().await.unwrap();
                let tls = tokio_boring::accept(&acceptor, socket).await.unwrap();
                let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
                let driver = AbortTask(tokio::task::spawn_local(connection));
                let peer = control_lifetime::peer_control(
                    &mut client,
                    if matches!(ending, ShutdownEnd::BeforeAck) {
                        control_lifetime::Reply::Pending
                    } else {
                        control_lifetime::Reply::BlockUnregister
                    },
                )
                .await;
                if matches!(ending, ShutdownEnd::BeforeAck) {
                    peer.entered.notified().await;
                    assert!(!runtime.startup_announced.load(Ordering::Acquire));
                } else {
                    peer.configured.notified().await;
                    assert!(runtime.startup_announced.load(Ordering::Acquire));
                    let ready = diagnostic(metrics_address, "/ready").await;
                    assert!(ready.starts_with(b"HTTP/1.1 200"));
                    assert!(
                        String::from_utf8(ready)
                            .unwrap()
                            .contains("\"readyConnections\":1")
                    );
                }
                let started = Instant::now();
                runtime.shutdown.cancel();
                if !matches!(ending, ShutdownEnd::BeforeAck | ShutdownEnd::ZeroGrace) {
                    peer.unregistered.notified().await;
                    assert_eq!(peer.unregisters.load(Ordering::Acquire), 1);
                    let ready = diagnostic(metrics_address, "/ready").await;
                    assert!(ready.starts_with(b"HTTP/1.1 503"));
                    assert!(
                        String::from_utf8(ready)
                            .unwrap()
                            .contains("\"readyConnections\":0")
                    );
                    let metrics = diagnostic(metrics_address, "/metrics").await;
                    assert!(metrics.starts_with(b"HTTP/1.1 200"));
                    assert!(
                        String::from_utf8(metrics)
                            .unwrap()
                            .contains("cloudflared_tunnel_ha_connections")
                    );
                    let (answer, _) = client
                        .send_request(
                            http::Request::builder()
                                .uri("https://synthetic.invalid/grace")
                                .body(())
                                .unwrap(),
                            true,
                        )
                        .expect("global grace must preserve outer H2 admission");
                    assert_eq!(answer.await.unwrap().status(), 203);
                }
                let mut driver = Some(driver);
                match ending {
                    ShutdownEnd::PeerClose => drop(driver.take()),
                    ShutdownEnd::Force => runtime.force.cancel(),
                    _ => {}
                }
                tokio::time::timeout(Duration::from_secs(1), runner)
                    .await
                    .unwrap_or_else(|_| {
                        panic!("shutdown {ending:?} exceeded its one operation deadline")
                    })
                    .unwrap()
                    .unwrap();
                if matches!(ending, ShutdownEnd::Deadline) {
                    assert!(started.elapsed() >= runtime.config.grace_period);
                }
                assert_eq!(runtime.readiness.count(), 0);
                assert!(
                    tokio::net::TcpStream::connect(metrics_address)
                        .await
                        .is_err()
                );
                if matches!(ending, ShutdownEnd::BeforeAck) {
                    assert_eq!(peer.unregisters.load(Ordering::Acquire), 0);
                    assert!(runtime.force.is_cancelled());
                }
                drop(driver);
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn queued_connected_event_cannot_reclassify_decoded_ack_as_early_shutdown() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (cert, key) = certificate();
            let mut acceptor =
                boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                    .unwrap();
            acceptor.set_certificate(&cert).unwrap();
            acceptor.set_private_key(&key).unwrap();
            let acceptor = acceptor.build();
            let tls =
                EdgeTls::new(TlsPolicy::PreferPostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut config = config();
            config.ha_connections = 1;
            let mut runtime = runtime(config);
            let (events, received) = mpsc::unbounded_channel();
            Arc::get_mut(&mut runtime).unwrap().events = events;
            let shared = runtime.clone();
            let edge_tls = tls.clone();
            let connection = AbortTask(tokio::task::spawn_local(async move {
                let mut retry = None;
                serve_h2(shared, &edge_tls, 0, address, 0, &mut retry).await
            }));
            let (socket, _) = listener.accept().await.unwrap();
            let tls_socket = tokio_boring::accept(&acceptor, socket).await.unwrap();
            let (mut client, driver) = h2::client::handshake(tls_socket).await.unwrap();
            let _driver = AbortTask(tokio::task::spawn_local(driver));
            let peer = control_lifetime::peer_control(
                &mut client,
                control_lifetime::Reply::LocallyManaged,
            )
            .await;
            peer.configured.notified().await;
            assert_eq!(received.len(), 1, "actual Connected remains unconsumed");
            assert!(runtime.startup_announced.load(Ordering::Acquire));
            assert_eq!(runtime.readiness.count(), 1);
            runtime.shutdown.cancel();
            let pool = Arc::new(Mutex::new(
                discovery::EdgePool::new(vec![vec![address]]).unwrap(),
            ));
            supervise(runtime.clone(), pool, tls, 1, received)
                .await
                .unwrap();
            assert!(
                !runtime.force.is_cancelled(),
                "historical real ACK must select initialized shutdown even before observer delivery"
            );
            peer.unregistered.notified().await;
            assert_eq!(peer.unregisters.load(Ordering::Acquire), 1);
            drop(connection);
        })
        .await;
}
