use super::*;
use crate::config::{Credentials, OriginRequest};
use crate::protocol::tunnelrpc_capnp as wire;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

#[path = "control_lifetime_tests.rs"]
mod control_lifetime;

pub(crate) fn config() -> RunConfig {
    let configuration =
        LoadedConfig::from_json(r#"{"ingress":[{"service":"http_status:203"}]}"#).unwrap();
    RunConfig {
        credentials: Credentials {
            account_tag: "synthetic-account".into(),
            tunnel_secret: b"synthetic-secret".to_vec(),
            tunnel_id: Uuid::from_bytes([1; 16]),
            endpoint: None,
        },
        ingress: configuration.ingress.clone(),
        origin_request: OriginRequest::default(),
        source: None,
        protocol: Protocol::Http2,
        edge_ip_version: "auto".into(),
        metrics: String::new(),
        ha_connections: 4,
        grace_period: Duration::from_secs(2),
        region: String::new(),
        edge_bind_address: Some("127.0.0.2".parse().unwrap()),
        post_quantum: false,
        quic_disable_pmtu_discovery: false,
        connection_window: 30 * 1024 * 1024,
        stream_window: 6 * 1024 * 1024,
        edge_ca: None,
        max_active_flows: None,
        dns_resolver_addrs: Vec::new(),
        icmpv4_src: None,
        icmpv6_src: None,
        features: Vec::new(),
        logging: crate::observability::logging::Options::default(),
        known_secrets: Vec::new(),
        management_hostname: "management.argotunnel.com".into(),
        management_diagnostics: false,
        connector_label: String::new(),
        service_op_ip: String::new(),
        diagnostic_cli_flags: Default::default(),
        token_authenticated: false,
        quick_hostname: String::new(),
        quick_authorizer: None,
        rpc_timeout: Duration::from_secs(2),
        write_stream_timeout: Duration::ZERO,
        dial_edge_timeout: Duration::from_secs(3),
        retries: 5,
        max_edge_addr_retries: 8,
        edge: Vec::new(),
        no_prechecks: true,
        pidfile: None,
        disable_path_normalization: false,
        configuration,
    }
}
fn runtime(config: RunConfig) -> Arc<Runtime> {
    let (events, _) = mpsc::unbounded_channel();
    let context = crate::observability::Context::quiet().unwrap();
    let features = Arc::new(super::features::FeatureSelector::new(
        &config.credentials.account_tag,
        config.features.clone(),
        config.post_quantum,
    ));
    let network = crate::network::NetworkState::with_context(&config, context.clone()).unwrap();
    let management = Arc::new(crate::observability::management::Service::new(
        context.clone(),
        Uuid::from_bytes([2; 16]),
        "",
        None,
        false,
    ));
    Arc::new(Runtime {
        proxy: Arc::new(ProxyState::with_context(&config, context.clone()).unwrap()),
        context,
        features,
        network,
        management,
        configuration: tokio::sync::Mutex::new(ConfigurationState {
            version: -1,
            current: config.configuration.clone(),
        }),
        config,
        readiness: Arc::new(Readiness {
            slots: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            shutting_down: AtomicBool::new(false),
        }),
        client_id: Uuid::from_bytes([2; 16]),
        events,
        shutdown: CancellationToken::new(),
        force: CancellationToken::new(),
        ever_quic: AtomicBool::new(false),
        notify_socket: None,
        startup_announced: AtomicBool::new(false),
    })
}

#[test]
fn source_retry_policy_distinguishes_startup_registration_and_live_disconnect() {
    for failure in [
        RegistrationError::Rpc(capnp::Error::failed("synthetic RPC failure".into())),
        RegistrationError::Timeout,
        RegistrationError::Rejected {
            cause: "synthetic permanent rejection".into(),
        },
    ] {
        let error = anyhow::Error::new(RegistrationFailure(failure));
        assert!(
            retry_policy(&error, true, false).stop_startup,
            "permanent first registration must not reconnect"
        );
        let follower = retry_policy(&error, false, true);
        assert!(!follower.stop_startup);
        assert!(follower.supervised);
        assert!(!follower.allow_fallback);
        let initialized_first = retry_policy(&error, true, true);
        assert!(!initialized_first.stop_startup);
        assert!(
            initialized_first.supervised,
            "initialized supervisor restarts a first-worker permanent failure"
        );
    }
    let retry = anyhow::Error::new(RegistrationFailure(RegistrationError::RetryAfter {
        cause: "synthetic retry".into(),
        delay: Duration::from_secs(99),
    }));
    let policy = retry_policy(&retry, true, false);
    assert!(!policy.stop_startup);
    assert!(!policy.supervised);
    assert!(policy.allow_fallback);
    let unauthorized = anyhow::Error::new(RegistrationFailure(RegistrationError::Rejected {
        cause: "Unauthorized: synthetic propagation lag".into(),
    }));
    let policy = retry_policy(&unauthorized, true, false);
    assert!(!policy.stop_startup);
    assert!(!policy.supervised);
    assert!(!policy.allow_fallback);
    let duplicate = anyhow::Error::new(RegistrationFailure(RegistrationError::Rejected {
        cause: "EDUPCONN".into(),
    }));
    let policy = retry_policy(&duplicate, true, false);
    assert!(!policy.stop_startup);
    assert!(policy.rotate);
    assert!(!policy.allow_fallback);
    let disconnected = anyhow::Error::new(RegistrationError::Disconnected);
    let policy = retry_policy(&disconnected, true, true);
    assert!(!policy.stop_startup);
    assert!(!policy.supervised);
    assert!(
        policy.allow_fallback,
        "live control loss follows transport recovery, not admission failure"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn decoded_ack_on_canceled_attempt_counts_success_without_readiness() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (result, _) = registration::tests::acknowledged_then_eof().await;
            let mut connection = result.unwrap();
            let mut config = config();
            config.protocol = Protocol::Auto;
            let mut runtime = runtime(config);
            let (events, mut received) = mpsc::unbounded_channel();
            Arc::get_mut(&mut runtime).unwrap().events = events;
            let pending = scope::PendingSessionContext::new(
                &runtime.config,
                2,
                "http2",
                "127.0.0.1:7844".parse().unwrap(),
                features::FeatureSnapshot {
                    version: crate::network::DatagramVersion::V2,
                    features: connection.identity().features().to_vec(),
                    skip_prechecks: true,
                },
                runtime.config.management_hostname.clone(),
            );
            let control = pending.cancellation().child_token();
            control.cancel();
            let lease = runtime
                .registered(
                    2,
                    EdgeProtocol::Http2,
                    "127.0.0.1:7844".parse().unwrap(),
                    &connection,
                    &pending,
                    SessionLiveness::Http2 { control },
                )
                .await
                .unwrap();
            assert_eq!(runtime.readiness.count(), 0);
            assert_eq!(runtime.context.metrics.ha_connections.get(), 0);
            assert_eq!(
                runtime
                    .context
                    .metrics
                    .register_success
                    .with_label_values(&["registerConnection"])
                    .get(),
                1
            );
            assert_eq!(
                runtime
                    .context
                    .metrics
                    .register_fail
                    .with_label_values(&["server_error", "registerConnection"])
                    .get(),
                0
            );
            assert!(!runtime.ever_quic.load(Ordering::Acquire));
            assert!(matches!(
                received.recv().await,
                Some(Event::Connected(2, EdgeProtocol::Http2))
            ));
            assert_eq!(connection.identity().client_id(), runtime.client_id);
            assert_eq!(
                connection.identity().tunnel_id(),
                runtime.config.credentials.tunnel_id
            );
            connection.disconnected().await;
            let error = anyhow::Error::new(RegistrationError::Disconnected);
            let retry = retry_policy(
                &error,
                true,
                runtime.startup_announced.load(Ordering::Acquire),
            );
            assert!(!retry.stop_startup);
            assert!(!retry.supervised);
            assert!(retry.allow_fallback);
            assert!(
                runtime.should_fallback(EdgeProtocol::Quic, true, true),
                "H2 admission must not fabricate QUIC history"
            );
            drop(lease);
            assert!(runtime.readiness.slots.lock().unwrap().is_empty());
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn acknowledged_quic_transport_close_retries_same_connector_and_index() {
    tokio::task::LocalSet::new()
        .run_until(async {
            fn listener(address: SocketAddr) -> Arc<tokio::net::UdpSocket> {
                let socket = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )
                .unwrap();
                socket.set_reuse_address(true).unwrap();
                socket.set_reuse_port(true).unwrap();
                socket.bind(&address.into()).unwrap();
                socket.set_nonblocking(true).unwrap();
                let socket: std::net::UdpSocket = socket.into();
                Arc::new(tokio::net::UdpSocket::from_std(socket).unwrap())
            }
            fn peer_config(
                cert: &boring::x509::X509,
                key: &boring::pkey::PKey<boring::pkey::Private>,
            ) -> quiche::Config {
                let mut ssl =
                    boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
                ssl.set_certificate(cert).unwrap();
                ssl.set_private_key(key).unwrap();
                ssl.set_curves_list("X25519MLKEM768").unwrap();
                let mut config =
                    quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl)
                        .unwrap();
                config.set_application_protos(&[b"argotunnel"]).unwrap();
                config.set_max_idle_timeout(5000);
                config.set_initial_max_data(1024 * 1024);
                config.set_initial_max_stream_data_bidi_local(65536);
                config.set_initial_max_stream_data_bidi_remote(65536);
                config.set_initial_max_streams_bidi(128);
                config.enable_dgram(true, 32, 32);
                config
            }
            let (cert, key) = certificate();
            let tls =
                EdgeTls::new(TlsPolicy::RequirePostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
            let socket = listener("127.0.0.1:0".parse().unwrap());
            let address = socket.local_addr().unwrap();
            let mut config = config();
            config.protocol = Protocol::Auto;
            config.ha_connections = 1;
            let mut runtime = runtime(config);
            let (events, mut received) = mpsc::unbounded_channel();
            Arc::get_mut(&mut runtime).unwrap().events = events;
            let observed = Arc::new(Mutex::new(vec![]));
            let attempts = observed.clone();
            let close = Arc::new(tokio::sync::Notify::new());
            let trigger = close.clone();
            let shared = runtime.clone();
            let edge = async move {
                let mut socket = socket;
                for attempt in 0..2 {
                    let mut config = peer_config(&cert, &key);
                    let mut packet = vec![0; 65527];
                    let (n, remote) = socket.recv_from(&mut packet).await.unwrap();
                    if attempt==1 {
                        assert_eq!(shared.readiness.count(),0,"closed first transport must not retain readiness while retry handshakes");
                        assert_eq!(shared.context.metrics.ha_connections.get(),0);
                        assert!(shared.ever_quic.load(Ordering::Acquire));
                    }
                    let header = quiche::Header::from_slice(&mut packet[..n], 20).unwrap();
                    let conn: tokio_quiche::quic::QuicheConnection =
                        quiche::accept_with_buf_factory(
                            &header.dcid,
                            None,
                            address,
                            remote,
                            &mut config,
                        )
                        .unwrap();
                    let initial = tokio_quiche::quic::Incoming {
                        peer_addr: remote,
                        local_addr: address,
                        rx_time: None,
                        buf: packet[..n].to_vec(),
                        gro: None,
                        so_mark_data: None,
                    };
                    let mut peer = transport::quic::attach_server(conn, socket, initial)
                        .await
                        .unwrap();
                    let control = peer.accept_bi().await.unwrap();
                    assert_eq!(control.id(), 0);
                    let (read, write) = tokio::io::split(control);
                    let network = capnp_rpc::twoparty::VatNetwork::new(
                        read.compat(),
                        write.compat_write(),
                        capnp_rpc::rpc_twoparty_capnp::Side::Server,
                        crate::protocol::reader_options(),
                    );
                    let oracle: wire::registration_server::Client = capnp_rpc::new_client(Oracle {
                        registered: Arc::new(tokio::sync::Notify::new()),
                        unregistered: Arc::new(AtomicBool::new(false)),
                        observed: attempts.clone(),
                        local_configuration: Arc::new(AtomicBool::new(false)),
                        origin_ip: "127.0.0.1".parse().unwrap(),
                        reject: false,
                        acknowledgement: None,
                        timestamps: None,
                        unregister_count: None,
                    });
                    let mut rpc = AbortTask(tokio::task::spawn_local(capnp_rpc::RpcSystem::new(
                        Box::new(network),
                        Some(oracle.client),
                    )));
                    if attempt == 0 {
                        trigger.notified().await;
                        socket = listener(address);
                        peer.close();
                    } else {
                        let _ = (&mut rpc.0).await;
                        assert!(shared.shutdown.is_cancelled());
                        break;
                    }
                }
            };
            let monitor = async {
                assert!(matches!(
                    received.recv().await,
                    Some(Event::Connected(0, EdgeProtocol::Quic))
                ));
                assert_eq!(runtime.readiness.count(), 1);
                close.notify_one();
                assert!(matches!(
                    received.recv().await,
                    Some(Event::Connected(0, EdgeProtocol::Quic))
                ));
                assert_eq!(runtime.readiness.count(), 1);
                assert_eq!(
                    runtime
                        .context
                        .metrics
                        .register_success
                        .with_label_values(&["registerConnection"])
                        .get(),
                    2
                );
                assert!(runtime.ever_quic.load(Ordering::Acquire));
                assert!(!runtime.should_fallback(EdgeProtocol::Quic, true, true));
                runtime.shutdown.cancel();
            };
            let pool = Arc::new(Mutex::new(
                discovery::EdgePool::new(vec![vec![address]]).unwrap(),
            ));
            let mut worker = AbortTask(tokio::task::spawn_local(lane(
                runtime.clone(),
                pool,
                tls,
                0,
                EdgeProtocol::Quic,
            )));
            tokio::time::timeout(Duration::from_secs(10), async {
                let (result, _, _) = tokio::join!(&mut worker.0, edge, monitor);
                result.unwrap().unwrap();
            })
            .await
            .unwrap();
            assert_eq!(
                observed.lock().unwrap().as_slice(),
                &[(0, runtime.client_id), (0, runtime.client_id)]
            );
            assert_eq!(runtime.readiness.count(), 0);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn failed_first_rpc_stops_without_ready_notification_pid_or_second_dial() {
    tokio::task::LocalSet::new().run_until(async{
        let (cert,key)=certificate();let mut acceptor=boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();acceptor.set_certificate(&cert).unwrap();acceptor.set_private_key(&key).unwrap();let acceptor=acceptor.build();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();let tls=EdgeTls::new(TlsPolicy::PreferPostQuantum,Some(&cert.to_pem().unwrap())).unwrap();
        let notify_path=std::env::temp_dir().join(format!("cloudflared-notify-{}",Uuid::new_v4()));let receiver=std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();receiver.set_nonblocking(true).unwrap();let pid_path=std::env::temp_dir().join(format!("cloudflared-pid-{}",Uuid::new_v4()));
        let mut config=config();config.pidfile=Some(pid_path.clone());config.ha_connections=1;config.retries=0;let mut runtime=runtime(config);let (events,event_rx)=mpsc::unbounded_channel();let state=Arc::get_mut(&mut runtime).unwrap();state.events=events;state.notify_socket=Some(notify_path.clone().into_os_string());
        let attempts=Arc::new(std::sync::atomic::AtomicUsize::new(0));let dial_count=attempts.clone();let edge=tokio::task::spawn_local(async move{
            let (socket,_)=listener.accept().await.unwrap();dial_count.fetch_add(1,Ordering::SeqCst);let tls=tokio_boring::accept(&acceptor,socket).await.unwrap();let (mut client,connection)=h2::client::handshake(tls).await.unwrap();let mut driver=AbortTask(tokio::task::spawn_local(connection));
            let (answer,mut send)=client.send_request(http::Request::builder().method("POST").uri("https://example.invalid/control").header("cf-cloudflared-proxy-connection-upgrade","control-stream").body(()).unwrap(),false).unwrap();let _=answer.await.unwrap();send.send_reset(h2::Reason::CANCEL);
            tokio::select!{second=listener.accept()=>{second.unwrap();dial_count.fetch_add(1,Ordering::SeqCst);},_=(&mut driver.0)=>{}}
        });
        let pool=Arc::new(Mutex::new(discovery::EdgePool::new(vec![vec![address]]).unwrap()));let result=tokio::time::timeout(Duration::from_secs(5),supervise(runtime.clone(),pool,tls,1,event_rx)).await.unwrap();
        assert!(result.unwrap_err().downcast_ref::<RegistrationFailure>().is_some());edge.await.unwrap();assert_eq!(attempts.load(Ordering::SeqCst),1);assert_eq!(runtime.readiness.count(),0);assert!(!runtime.startup_announced.load(Ordering::Acquire));assert!(!pid_path.exists());let mut bytes=[0;32];assert!(receiver.recv(&mut bytes).is_err());std::fs::remove_file(notify_path).unwrap();
    }).await;
}

#[tokio::test]
async fn remote_versions_keep_prior_valid_configuration_and_redact_local_payload() {
    let mut config = config();
    config.configuration.settings.insert(
        "token".into(),
        serde_yaml_ng::Value::String("synthetic-secret".into()),
    );
    let runtime = runtime(config);
    let valid = runtime
        .update(
            7,
            br#"{"ingress":[{"service":"http_status:204"}]}"#.to_vec(),
        )
        .await;
    assert_eq!(valid.latest_applied_version, 7);
    assert!(valid.error.is_empty());
    let stale = runtime
        .update(
            6,
            br#"{"ingress":[{"service":"http_status:205"}]}"#.to_vec(),
        )
        .await;
    assert_eq!(stale.latest_applied_version, 7);
    let invalid = runtime
        .update(
            8,
            br#"{"ingress":[{"hostname":"example.invalid","service":"http_status:203"}]}"#.to_vec(),
        )
        .await;
    assert_eq!(invalid.latest_applied_version, 7);
    assert!(!invalid.error.is_empty());
    assert_eq!(
        runtime.proxy.configuration().await.ingress[0].service,
        "http_status:204"
    );
    assert!(
        !String::from_utf8(runtime.local_configuration().await.unwrap())
            .unwrap()
            .contains("synthetic-secret")
    );
    assert!(!runtime.readiness.ready());
}

type RegistrationTimes = Arc<Mutex<Vec<(u8, Instant)>>>;
struct Oracle {
    registered: Arc<tokio::sync::Notify>,
    unregistered: Arc<AtomicBool>,
    observed: Arc<Mutex<Vec<(u8, Uuid)>>>,
    local_configuration: Arc<AtomicBool>,
    origin_ip: std::net::Ipv4Addr,
    reject: bool,
    acknowledgement: Option<Arc<tokio::sync::Notify>>,
    timestamps: Option<RegistrationTimes>,
    unregister_count: Option<Arc<std::sync::atomic::AtomicUsize>>,
}
impl wire::registration_server::Server for Oracle {
    async fn register_connection(
        self: Rc<Self>,
        params: wire::registration_server::RegisterConnectionParams,
        mut results: wire::registration_server::RegisterConnectionResults,
    ) -> capnp::Result<()> {
        let p = params.get()?;
        assert_eq!(
            p.get_auth()?.get_account_tag()?.to_str().unwrap(),
            "synthetic-account"
        );
        assert_eq!(p.get_auth()?.get_tunnel_secret()?, b"synthetic-secret");
        let opts = p.get_options()?;
        let ip =
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(opts.get_origin_local_ip()?).unwrap())
                .to_ipv4_mapped()
                .unwrap();
        assert_eq!(ip, self.origin_ip);
        self.observed.lock().unwrap().push((
            p.get_conn_index(),
            Uuid::from_slice(opts.get_client()?.get_client_id()?).unwrap(),
        ));
        if let Some(times) = &self.timestamps {
            times
                .lock()
                .unwrap()
                .push((p.get_conn_index(), Instant::now()));
        }
        self.registered.notify_one();
        if let Some(acknowledgement) = &self.acknowledgement {
            acknowledgement.notified().await;
        }
        if self.reject {
            let mut error = results.get().init_result().init_result().init_error();
            error.set_cause("synthetic permanent rejection");
            error.set_should_retry(false);
            return Ok(());
        }
        let mut details = results
            .get()
            .init_result()
            .init_result()
            .init_connection_details();
        let mut connection_id = [3; 16];
        connection_id[15] = p.get_conn_index();
        details.set_uuid(&connection_id);
        details.set_location_name("TST");
        details.set_tunnel_is_remotely_managed(false);
        Ok(())
    }
    async fn unregister_connection(
        self: Rc<Self>,
        _: wire::registration_server::UnregisterConnectionParams,
        _: wire::registration_server::UnregisterConnectionResults,
    ) -> capnp::Result<()> {
        self.unregistered.store(true, Ordering::Release);
        if let Some(count) = &self.unregister_count {
            count.fetch_add(1, Ordering::AcqRel);
        }
        Ok(())
    }
    async fn update_local_configuration(
        self: Rc<Self>,
        params: wire::registration_server::UpdateLocalConfigurationParams,
        _: wire::registration_server::UpdateLocalConfigurationResults,
    ) -> capnp::Result<()> {
        self.local_configuration.store(true, Ordering::Release);
        let value: serde_json::Value = serde_json::from_slice(params.get()?.get_config()?).unwrap();
        assert_eq!(value["ingress"][0]["service"], "http_status:203");
        assert!(value.get("token").is_none());
        Ok(())
    }
}

pub(crate) fn certificate() -> (
    boring::x509::X509,
    boring::pkey::PKey<boring::pkey::Private>,
) {
    let (old, key) = crate::crypto::tests::certificate();
    let mut cert = boring::x509::X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(old.serial_number()).unwrap();
    cert.set_subject_name(old.subject_name()).unwrap();
    cert.set_issuer_name(old.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(old.not_before()).unwrap();
    cert.set_not_after(old.not_after()).unwrap();
    cert.append_extension(
        &boring::x509::extension::BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .unwrap(),
    )
    .unwrap();
    let san = boring::x509::extension::SubjectAlternativeName::new()
        .dns("h2.cftunnel.com")
        .dns("quic.cftunnel.com")
        .build(&cert.x509v3_context(None, None))
        .unwrap();
    cert.append_extension(&san).unwrap();
    cert.sign(&key, boring::hash::MessageDigest::sha256())
        .unwrap();
    (cert.build(), key)
}

#[tokio::test(flavor = "current_thread")]
async fn diagnostic_http_real_metrics_snapshot_and_cancel_owned_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut config = config();
            config.quick_hostname = "synthetic.trycloudflare.com".into();
            let runtime = runtime(config);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut server =
                health_server_on(listener, runtime.clone(), runtime.shutdown.clone()).unwrap();
            for (path, status, needle) in [
                ("/ready", 503, "\"readyConnections\":0"),
                ("/metrics", 200, "cloudflared_tunnel_ha_connections"),
                ("/config", 200, "\"version\":-1"),
                ("/quicktunnel", 200, "synthetic.trycloudflare.com"),
                ("/diag/tunnel", 200, "\"icmp_sources\""),
                ("/debug/pprof/cmdline", 403, "forbidden"),
                ("/debug/pprof/heap", 501, "unavailable"),
                ("/logs", 404, "404 page not found"),
            ] {
                let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
                socket
                    .write_all(
                        format!(
                            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                let mut bytes = Vec::new();
                tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                let response = String::from_utf8(bytes).unwrap();
                assert!(
                    response.starts_with(&format!("HTTP/1.1 {status}")),
                    "{response}"
                );
                assert!(response.contains(needle), "{response}");
            }
            let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
            tokio::task::yield_now().await;
            runtime.shutdown.cancel();
            tokio::time::timeout(Duration::from_secs(2), &mut server.0)
                .await
                .unwrap()
                .unwrap();
            let mut byte = [0; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), idle.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            assert!(tokio::net::TcpStream::connect(address).await.is_err());
        })
        .await;
}

async fn update_request(
    client: &mut h2::client::SendRequest<Bytes>,
    version: i32,
    configuration: serde_json::Value,
) -> serde_json::Value {
    let request = http::Request::builder()
        .method("POST")
        .uri("https://example.invalid/")
        .header(
            "cf-cloudflared-proxy-connection-upgrade",
            "update-configuration",
        )
        .body(())
        .unwrap();
    let (response, mut body) = client.send_request(request, false).unwrap();
    body.send_data(
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({"version":version,"config":configuration}))
                .unwrap(),
        ),
        true,
    )
    .unwrap();
    let mut response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut bytes = Vec::new();
    while let Some(data) = response.body_mut().data().await {
        let data = data.unwrap();
        bytes.extend_from_slice(&data);
        response
            .body_mut()
            .flow_control()
            .release_capacity(data.len())
            .unwrap();
    }
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn ha_four_actual_tls_registrations_share_connector_uuid_and_stagger_followers() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (cert, key) = certificate();
            let mut acceptor =
                boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                    .unwrap();
            acceptor.set_certificate(&cert).unwrap();
            acceptor.set_private_key(&key).unwrap();
            let acceptor = Arc::new(acceptor.build());
            let tls =
                EdgeTls::new(TlsPolicy::PreferPostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
            let config = config();
            let mut runtime = runtime(config);
            let (events, event_rx) = mpsc::unbounded_channel();
            Arc::get_mut(&mut runtime).unwrap().events = events;
            let observed = Arc::new(Mutex::new(Vec::new()));
            let times = Arc::new(Mutex::new(Vec::new()));
            let unregister_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut peers = Vec::new();
            let mut addresses = Vec::new();
            for _ in 0..4 {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                addresses.push(listener.local_addr().unwrap());
                let acceptor = acceptor.clone();
                let observed = observed.clone();
                let times = times.clone();
                let unregister_count = unregister_count.clone();
                peers.push(AbortTask(tokio::task::spawn_local(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let tls = tokio_boring::accept(&acceptor, socket).await.unwrap();
                    let (mut client, driver) = h2::client::handshake(tls).await.unwrap();
                    let _driver = AbortTask(tokio::task::spawn_local(driver));
                    let (answer, send) = client
                        .send_request(
                            http::Request::builder()
                                .method("POST")
                                .uri("https://example.invalid/control")
                                .header("cf-cloudflared-proxy-connection-upgrade", "control-stream")
                                .body(())
                                .unwrap(),
                            false,
                        )
                        .unwrap();
                    let response = answer.await.unwrap();
                    let (control, pump) = h2_control::bridge(response.into_body(), send);
                    let _pump = AbortTask(pump);
                    let (read, write) = tokio::io::split(control);
                    let network = capnp_rpc::twoparty::VatNetwork::new(
                        read.compat(),
                        write.compat_write(),
                        capnp_rpc::rpc_twoparty_capnp::Side::Server,
                        crate::protocol::reader_options(),
                    );
                    let oracle: wire::registration_server::Client = capnp_rpc::new_client(Oracle {
                        registered: Arc::new(tokio::sync::Notify::new()),
                        unregistered: Arc::new(AtomicBool::new(false)),
                        observed,
                        local_configuration: Arc::new(AtomicBool::new(false)),
                        origin_ip: "127.0.0.2".parse().unwrap(),
                        reject: false,
                        acknowledgement: None,
                        timestamps: Some(times),
                        unregister_count: Some(unregister_count),
                    });
                    let rpc = capnp_rpc::RpcSystem::new(Box::new(network), Some(oracle.client));
                    let _ = rpc.await;
                })));
            }
            let pool = Arc::new(Mutex::new(
                discovery::EdgePool::new(vec![addresses]).unwrap(),
            ));
            let monitor = async {
                while runtime.readiness.count() != 4 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                assert_eq!(runtime.context.metrics.ha_connections.get(), 4);
                assert_eq!(
                    runtime
                        .context
                        .metrics
                        .register_success
                        .with_label_values(&["registerConnection"])
                        .get(),
                    4
                );
                let mut observed = observed.lock().unwrap().clone();
                observed.sort_by_key(|(index, _)| *index);
                assert_eq!(
                    observed,
                    (0..4)
                        .map(|index| (index, runtime.client_id))
                        .collect::<Vec<_>>()
                );
                let mut times = times.lock().unwrap().clone();
                times.sort_by_key(|(index, _)| *index);
                assert!(times[2].1.duration_since(times[1].1) >= Duration::from_millis(900));
                assert!(times[3].1.duration_since(times[2].1) >= Duration::from_millis(900));
                runtime.shutdown.cancel();
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                let (result, _) =
                    tokio::join!(supervise(runtime.clone(), pool, tls, 4, event_rx), monitor);
                result.unwrap();
            })
            .await
            .unwrap();
            assert_eq!(runtime.readiness.count(), 0);
            assert_eq!(runtime.context.metrics.ha_connections.get(), 0);
            assert_eq!(unregister_count.load(Ordering::Acquire), 4);
            drop(peers);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn named_h2_real_tls_rpc_http_remote_updates_and_graceful_unregister() {
    tokio::task::LocalSet::new().run_until(async{
        let (cert,key)=certificate();let mut acceptor=boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();acceptor.set_certificate(&cert).unwrap();acceptor.set_private_key(&key).unwrap();let acceptor=acceptor.build();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();let temp=std::env::temp_dir().join(format!("cloudflared-ca-{}.pem",Uuid::new_v4()));std::fs::write(&temp,cert.to_pem().unwrap()).unwrap();
        let pid_path=std::env::temp_dir().join(format!("cloudflared-pid-{}",Uuid::new_v4()));let notify_path=std::env::temp_dir().join(format!("cloudflared-notify-{}",Uuid::new_v4()));let notify=std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();notify.set_nonblocking(true).unwrap();
        let mut config=config();config.management_hostname="127.0.0.1".into();config.pidfile=Some(pid_path.clone());config.edge_ca=Some(temp.clone());let edge_tls=tls(&config).unwrap();std::fs::remove_file(temp).unwrap();let mut runtime=runtime(config);Arc::get_mut(&mut runtime).unwrap().notify_socket=Some(notify_path.clone().into_os_string());
        assert!(!pid_path.exists());let mut notify_bytes=[0;32];assert!(notify.recv(&mut notify_bytes).is_err());assert_eq!(runtime.readiness.response(runtime.client_id).0,503);
        let registered=Arc::new(tokio::sync::Notify::new());let unregistered=Arc::new(AtomicBool::new(false));let observed=Arc::new(Mutex::new(Vec::new()));
        let local_configuration=Arc::new(AtomicBool::new(false));let configured=local_configuration.clone();let ready=registered.clone();let closed=unregistered.clone();let seen=observed.clone();let shared=runtime.clone();
        let edge=tokio::task::spawn_local(async move{
            let (socket,_)=listener.accept().await.unwrap();let tls=tokio_boring::accept(&acceptor,socket).await.unwrap();assert!(tls.ssl().selected_alpn_protocol().is_none());
            let (mut client,connection)=h2::client::handshake(tls).await.unwrap();let _connection=AbortTask(tokio::task::spawn_local(connection));
            let (answer,send)=client.send_request(http::Request::builder().method("POST").uri("https://example.invalid/control").header("cf-cloudflared-proxy-connection-upgrade","control-stream").body(()).unwrap(),false).unwrap();
            let response=answer.await.unwrap();let (control,pump)=h2_control::bridge(response.into_body(),send);let _pump=AbortTask(pump);let (read,write)=tokio::io::split(control);
            let network=capnp_rpc::twoparty::VatNetwork::new(read.compat(),write.compat_write(),capnp_rpc::rpc_twoparty_capnp::Side::Server,crate::protocol::reader_options());
            let server:wire::registration_server::Client=capnp_rpc::new_client(Oracle{registered:ready.clone(),unregistered:closed.clone(),observed:seen,local_configuration:configured.clone(),origin_ip:"127.0.0.2".parse().unwrap(),reject:false,acknowledgement:None,timestamps:None,unregister_count:None});let rpc=capnp_rpc::RpcSystem::new(Box::new(network),Some(server.client));let mut rpc_task=AbortTask(tokio::task::spawn_local(rpc));
            ready.notified().await;
            tokio::time::timeout(Duration::from_secs(2),async{while !shared.readiness.ready(){tokio::time::sleep(Duration::from_millis(1)).await}}).await.unwrap();
            let (response,_)=client.send_request(http::Request::builder().uri("https://example.invalid/path").body(()).unwrap(),true).unwrap();assert_eq!(response.await.unwrap().status(),203);
            let accepted=update_request(&mut client,7,serde_json::json!({"ingress":[{"service":"http_status:204"}]})).await;assert_eq!(accepted["lastAppliedVersion"],7);assert!(accepted["err"].is_null());
            let stale=update_request(&mut client,6,serde_json::json!({"ingress":[{"service":"http_status:205"}]})).await;assert_eq!(stale["lastAppliedVersion"],7);
            let invalid=update_request(&mut client,8,serde_json::json!({"ingress":[{"hostname":"example.invalid","service":"http_status:205"}]})).await;assert_eq!(invalid["lastAppliedVersion"],7);assert_eq!(invalid["err"],serde_json::json!({}));
            let (response,_)=client.send_request(http::Request::builder().uri("https://example.invalid/path").body(()).unwrap(),true).unwrap();assert_eq!(response.await.unwrap().status(),204);
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let destination=listener.local_addr().unwrap();
            let origin=tokio::task::spawn_local(async move {
                use tokio::io::{AsyncReadExt,AsyncWriteExt};
                let (mut socket,_)=listener.accept().await.unwrap();let mut bytes=Vec::new();socket.read_to_end(&mut bytes).await.unwrap();socket.write_all(&bytes).await.unwrap();socket.shutdown().await.unwrap();
            });
            let (response,mut send)=client.send_request(http::Request::builder().method("POST").uri(format!("https://{destination}/ping")).header("cf-cloudflared-proxy-src","tcp").body(()).unwrap(),false).unwrap();
            let response=response.await.unwrap();assert_eq!(response.status(),200,"private TCP URI authority matching management hostname must bypass management token admission");
            let mut body=response.into_body();send.send_data(Bytes::from_static(b"private-h2"),true).unwrap();let mut returned=Vec::new();while let Some(data)=body.data().await {let data=data.unwrap();returned.extend_from_slice(&data);body.flow_control().release_capacity(data.len()).unwrap();}assert_eq!(returned,b"private-h2");origin.await.unwrap();
            assert!(configured.load(Ordering::Acquire));shared.shutdown.cancel();let _=(&mut rpc_task.0).await;assert!(closed.load(Ordering::Acquire));
        });
        let mut reset=None;let connector=serve_h2(runtime.clone(),&edge_tls,0,address,0,&mut reset);
        tokio::time::timeout(Duration::from_secs(10),async{let (a,b)=tokio::join!(connector,edge);a.unwrap();b.unwrap();}).await.unwrap();
        assert!(!runtime.readiness.ready());assert_eq!(observed.lock().unwrap().as_slice(),&[(0,runtime.client_id)]);let n=notify.recv(&mut notify_bytes).unwrap();assert_eq!(&notify_bytes[..n],b"READY=1");assert_eq!(std::fs::read_to_string(&pid_path).unwrap(),std::process::id().to_string());std::fs::remove_file(pid_path).unwrap();std::fs::remove_file(notify_path).unwrap();
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn named_quic_real_tls_first_stream_rpc_http_config_and_unregister() {
    quic_preack_fixture(false, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_quic_registration_cleans_preack_udp_and_never_becomes_ready() {
    quic_preack_fixture(false, true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn persistent_preack_rpc_with_later_streams_keeps_runtime_progressing() {
    quic_preack_fixture(true, false).await;
}

async fn quic_preack_fixture(keep_callback_open: bool, reject: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::task::LocalSet::new()
        .run_until(async {
            let (cert, key) = certificate();
            let mut ssl =
                boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
            ssl.set_certificate(&cert).unwrap();
            ssl.set_private_key(&key).unwrap();
            ssl.set_curves_list("X25519MLKEM768").unwrap();
            let mut peer_config =
                quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
            peer_config
                .set_application_protos(&[b"argotunnel"])
                .unwrap();
            peer_config.set_max_idle_timeout(5000);
            peer_config.set_initial_max_data(1024 * 1024);
            peer_config.set_initial_max_stream_data_bidi_local(64 * 1024);
            peer_config.set_initial_max_stream_data_bidi_remote(64 * 1024);
            peer_config.set_initial_max_streams_bidi(128);
            peer_config.enable_dgram(true, 32, 32);
            let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let address = socket.local_addr().unwrap();
            let path = std::env::temp_dir().join(format!("cloudflared-ca-{}.pem", Uuid::new_v4()));
            std::fs::write(&path, cert.to_pem().unwrap()).unwrap();
            let mut config = config();
            config.protocol = Protocol::Auto;
            config.post_quantum = true;
            config.edge_ca = Some(path.clone());
            let edge_tls = tls(&config).unwrap();
            std::fs::remove_file(path).unwrap();
            let runtime = runtime(config);
            let shared = runtime.clone();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let observed = seen.clone();
            let configured = Arc::new(AtomicBool::new(false));
            let local_configuration = configured.clone();
            let unregistered = Arc::new(AtomicBool::new(false));
            let closed = unregistered.clone();
            let edge = tokio::task::spawn_local(async move {
                let mut packet = vec![0; 65527];
                let (n, peer) = socket.recv_from(&mut packet).await.unwrap();
                let header = quiche::Header::from_slice(&mut packet[..n], 20).unwrap();
                let conn: tokio_quiche::quic::QuicheConnection = quiche::accept_with_buf_factory(
                    &header.dcid,
                    None,
                    address,
                    peer,
                    &mut peer_config,
                )
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
                let control = conn.accept_bi().await.unwrap();
                assert_eq!(
                    control.id(),
                    0,
                    "registration must be first unprefixed client stream"
                );
                let (read, write) = tokio::io::split(control);
                let network = capnp_rpc::twoparty::VatNetwork::new(
                    read.compat(),
                    write.compat_write(),
                    capnp_rpc::rpc_twoparty_capnp::Side::Server,
                    crate::protocol::reader_options(),
                );
                let ready = Arc::new(tokio::sync::Notify::new());
                let acknowledgement = Arc::new(tokio::sync::Notify::new());
                let server: wire::registration_server::Client = capnp_rpc::new_client(Oracle {
                    registered: ready.clone(),
                    unregistered: closed.clone(),
                    observed,
                    local_configuration: local_configuration.clone(),
                    origin_ip: "127.0.0.1".parse().unwrap(),
                    reject,
                    acknowledgement: Some(acknowledgement.clone()),
                    timestamps: None,
                    unregister_count: None,
                });
                let mut registration_rpc = AbortTask(tokio::task::spawn_local(
                    capnp_rpc::RpcSystem::new(Box::new(network), Some(server.client)),
                ));
                ready.notified().await;
                assert_eq!(shared.readiness.count(), 0);
                let mut config_stream = conn.open_bi().await.unwrap();
                config_stream
                    .write_all(&metadata::RPC_SIGNATURE)
                    .await
                    .unwrap();
                let (read, write) = tokio::io::split(config_stream);
                let network = capnp_rpc::twoparty::VatNetwork::new(
                    read.compat(),
                    write.compat_write(),
                    capnp_rpc::rpc_twoparty_capnp::Side::Client,
                    crate::protocol::reader_options(),
                );
                let mut rpc = capnp_rpc::RpcSystem::new(Box::new(network), None);
                let client: wire::configuration_manager::Client =
                    rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                let udp: wire::session_manager::Client =
                    rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                let _preack_driver = AbortTask(tokio::task::spawn_local(rpc));
                let mut call = client.update_configuration_request();
                call.get().set_version(6);
                call.get()
                    .set_config(br#"{"ingress":[{"service":"http_status:203"}]}"#);
                let answer = call.send().promise.await.unwrap();
                assert_eq!(
                    answer
                        .get()
                        .unwrap()
                        .get_result()
                        .unwrap()
                        .get_latest_applied_version(),
                    6
                );
                let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let destination = origin.local_addr().unwrap();
                let _origin = AbortTask(tokio::task::spawn_local(async move {
                    let mut bytes = [0; 1500];
                    loop {
                        let (n, peer) = origin.recv_from(&mut bytes).await.unwrap();
                        origin.send_to(&bytes[..n], peer).await.unwrap();
                    }
                }));
                let session_id = [7; 16];
                let mut call = udp.register_udp_session_request();
                call.get().set_session_id(&session_id);
                call.get().set_dst_ip(&[127, 0, 0, 1]);
                call.get().set_dst_port(destination.port());
                call.get().set_close_after_idle_hint(5_000_000_000);
                call.get().set_trace_context("");
                let answer = call.send().promise.await.unwrap();
                assert!(
                    answer
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
                let packet = crate::protocol::datagram::DatagramV2::Udp {
                    session_id,
                    payload: b"preack-udp".to_vec(),
                };
                conn.send_datagram(Bytes::from(packet.encode().unwrap()))
                    .await
                    .unwrap();
                let reply = conn.recv_datagram().await.unwrap();
                assert_eq!(
                    crate::protocol::datagram::DatagramV2::decode(&reply).unwrap(),
                    packet
                );
                assert_eq!(shared.network.active_flows(), 1);
                let mut preack_data = conn.open_bi().await.unwrap();
                metadata::write_connect_request(
                    &mut preack_data,
                    &metadata::ConnectRequest {
                        destination: "https://example.invalid/preack".into(),
                        connection_type: metadata::ConnectionType::Http,
                        metadata: vec![
                            ("HttpMethod".into(), "GET".into()),
                            ("HttpHost".into(), "example.invalid".into()),
                        ],
                    },
                )
                .await
                .unwrap();
                preack_data.shutdown().await.unwrap();
                let response = metadata::read_connect_response(&mut preack_data)
                    .await
                    .unwrap();
                assert!(
                    response
                        .metadata
                        .iter()
                        .any(|(key, value)| key == "HttpStatus" && value == "203")
                );
                let mut body = Vec::new();
                preack_data.read_to_end(&mut body).await.unwrap();
                drop(preack_data);
                use base64::Engine;
                let token=format!("{}.{}.{}",base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#),base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"tun":{"id":shared.config.credentials.tunnel_id,"account_tag":"synthetic-account"},"actor":{"id":"synthetic-actor"}})).unwrap()),base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8;64]));
                let mut ping=conn.open_bi().await.unwrap();
                metadata::write_connect_request(&mut ping,&metadata::ConnectRequest{destination:format!("https://destination.invalid/ping?access_token={token}"),connection_type:metadata::ConnectionType::Http,metadata:vec![("HttpMethod".into(),"GET".into()),("HttpHost".into(),"management.argotunnel.com".into()),("HttpHeader:Host".into(),"caller.invalid".into())]}).await.unwrap();
                ping.shutdown().await.unwrap();
                let response=metadata::read_connect_response(&mut ping).await.unwrap();
                assert!(response.metadata.iter().any(|(key,value)|key=="HttpStatus"&&value=="200"));
                ping.read_to_end(&mut Vec::new()).await.unwrap();drop(ping);
                let mut logs=conn.open_bi().await.unwrap();
                metadata::write_connect_request(&mut logs,&metadata::ConnectRequest{destination:format!("https://destination.invalid/logs?access_token={token}"),connection_type:metadata::ConnectionType::Websocket,metadata:vec![("HttpMethod".into(),"GET".into()),("HttpHost".into(),"management.argotunnel.com".into()),("HttpHeader:Host".into(),"caller.invalid".into()),("HttpHeader:Origin".into(),"https://management.argotunnel.com".into()),("HttpHeader:Connection".into(),"Upgrade".into()),("HttpHeader:Upgrade".into(),"websocket".into()),("HttpHeader:Sec-WebSocket-Version".into(),"13".into()),("HttpHeader:Sec-WebSocket-Key".into(),base64::engine::general_purpose::STANDARD.encode([4u8;16]))]}).await.unwrap();
                let response=metadata::read_connect_response(&mut logs).await.unwrap();
                assert!(response.metadata.iter().any(|(key,value)|key=="HttpStatus"&&value=="101"),"authoritative management HttpHost must allow same-origin despite conflicting ordinary Host/destination");
                use futures::StreamExt;
                let mut websocket=tokio_tungstenite::WebSocketStream::from_raw_socket(logs,tokio_tungstenite::tungstenite::protocol::Role::Client,None).await;
                websocket.close(None).await.unwrap();let _=websocket.next().await;drop(websocket);
                let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let destination=listener.local_addr().unwrap();
                let origin=tokio::task::spawn_local(async move{let (mut socket,_)=listener.accept().await.unwrap();let mut bytes=Vec::new();socket.read_to_end(&mut bytes).await.unwrap();socket.write_all(&bytes).await.unwrap();socket.shutdown().await.unwrap();});
                let mut private=conn.open_bi().await.unwrap();
                metadata::write_connect_request(&mut private,&metadata::ConnectRequest{destination:destination.to_string(),connection_type:metadata::ConnectionType::Tcp,metadata:vec![("HttpHost".into(),"management.argotunnel.com".into()),("HttpHeader:Host".into(),"caller.invalid".into())]}).await.unwrap();
                let response=metadata::read_connect_response(&mut private).await.unwrap();assert!(response.error.is_empty());assert!(!response.metadata.iter().any(|(key,_)|key=="HttpStatus"),"private TCP must bypass HTTP management interception");private.write_all(b"private-tcp").await.unwrap();private.shutdown().await.unwrap();let mut returned=Vec::new();private.read_to_end(&mut returned).await.unwrap();assert_eq!(returned,b"private-tcp");origin.await.unwrap();drop(private);
                let _persistent_callback = if keep_callback_open {
                    Some(_preack_driver)
                } else {
                    drop(_preack_driver);
                    None
                };
                assert_eq!(
                    shared.readiness.count(),
                    0,
                    "pre-ack traffic cannot fabricate registration readiness"
                );
                acknowledgement.notify_one();
                if reject {
                    let _ = (&mut registration_rpc.0).await;
                    assert_eq!(shared.readiness.count(), 0);
                    assert!(!shared.startup_announced.load(Ordering::Acquire));
                    assert!(!closed.load(Ordering::Acquire));
                    conn.close();
                    return;
                }
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !shared.readiness.ready() || !local_configuration.load(Ordering::Acquire)
                    {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .unwrap();
                if let Some(callback) = &_persistent_callback {
                    tokio::time::timeout(Duration::from_secs(3), async {
                        while !callback.0.is_finished() {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    })
                    .await
                    .unwrap();
                    assert_eq!(
                        shared.readiness.count(),
                        1,
                        "expired callback RPC must not invalidate live control registration"
                    );
                }
                let mut stream = conn.open_bi().await.unwrap();
                assert_eq!(stream.id(), 21);
                metadata::write_connect_request(
                    &mut stream,
                    &metadata::ConnectRequest {
                        destination: "https://example.invalid/path".into(),
                        connection_type: metadata::ConnectionType::Http,
                        metadata: vec![
                            ("HttpMethod".into(), "GET".into()),
                            ("HttpHost".into(), "example.invalid".into()),
                        ],
                    },
                )
                .await
                .unwrap();
                stream.shutdown().await.unwrap();
                let response = metadata::read_connect_response(&mut stream).await.unwrap();
                assert!(response.error.is_empty());
                assert!(
                    response
                        .metadata
                        .iter()
                        .any(|(key, value)| key == "HttpStatus" && value == "203")
                );
                let mut body = Vec::new();
                stream.read_to_end(&mut body).await.unwrap();
                let mut stream = conn.open_bi().await.unwrap();
                assert_eq!(stream.id(), 25);
                stream.write_all(&metadata::RPC_SIGNATURE).await.unwrap();
                let (read, write) = tokio::io::split(stream);
                let network = capnp_rpc::twoparty::VatNetwork::new(
                    read.compat(),
                    write.compat_write(),
                    capnp_rpc::rpc_twoparty_capnp::Side::Client,
                    crate::protocol::reader_options(),
                );
                let mut rpc = capnp_rpc::RpcSystem::new(Box::new(network), None);
                let client: wire::configuration_manager::Client =
                    rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                let _callback_driver = AbortTask(tokio::task::spawn_local(rpc));
                let mut call = client.update_configuration_request();
                call.get().set_version(7);
                call.get()
                    .set_config(br#"{"ingress":[{"service":"http_status:204"}]}"#);
                let answer = call.send().promise.await.unwrap();
                let result = answer.get().unwrap().get_result().unwrap();
                assert_eq!(result.get_latest_applied_version(), 7);
                assert!(result.get_err().unwrap().to_str().unwrap().is_empty());
                drop(_callback_driver);
                shared.shutdown.cancel();
                let _ = (&mut registration_rpc.0).await;
                assert!(closed.load(Ordering::Acquire));
                conn.close();
            });
            let mut reset = None;
            let connector = serve_quic(runtime.clone(), &edge_tls, 0, address, 0, &mut reset);
            tokio::time::timeout(Duration::from_secs(10), async {
                let (a, b) = tokio::join!(connector, edge);
                if reject {
                    assert!(
                        a.unwrap_err()
                            .downcast_ref::<RegistrationFailure>()
                            .is_some()
                    );
                } else {
                    a.unwrap();
                }
                b.unwrap();
            })
            .await
            .unwrap();
            assert!(!runtime.readiness.ready());
            assert_eq!(runtime.ever_quic.load(Ordering::Acquire), !reject);
            assert_eq!(
                runtime.should_fallback(EdgeProtocol::Quic, true, true),
                reject,
                "successful historical QUIC suppresses fallback after every connection disconnects"
            );
            assert_eq!(seen.lock().unwrap().as_slice(), &[(0, runtime.client_id)]);
            assert_eq!(configured.load(Ordering::Acquire), !reject);
            tokio::time::timeout(Duration::from_secs(2), async {
                while runtime.network.active_flows() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        })
        .await;
}
