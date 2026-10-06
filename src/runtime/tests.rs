use super::*;
use crate::config::{Credentials, OriginRequest};
use crate::protocol::tunnelrpc_capnp as wire;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

fn config() -> RunConfig {
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
        token_authenticated: false,
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
    Arc::new(Runtime {
        proxy: Arc::new(ProxyState::new(&config).unwrap()),
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

struct Oracle {
    registered: Arc<tokio::sync::Notify>,
    unregistered: Arc<AtomicBool>,
    observed: Arc<Mutex<Vec<(u8, Uuid)>>>,
    local_configuration: Arc<AtomicBool>,
    origin_ip: std::net::Ipv4Addr,
    reject: bool,
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
        details.set_uuid(&[3; 16]);
        details.set_location_name("TST");
        details.set_tunnel_is_remotely_managed(false);
        self.registered.notify_one();
        Ok(())
    }
    async fn unregister_connection(
        self: Rc<Self>,
        _: wire::registration_server::UnregisterConnectionParams,
        _: wire::registration_server::UnregisterConnectionResults,
    ) -> capnp::Result<()> {
        self.unregistered.store(true, Ordering::Release);
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

fn certificate() -> (
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
async fn named_h2_real_tls_rpc_http_remote_updates_and_graceful_unregister() {
    tokio::task::LocalSet::new().run_until(async{
        let (cert,key)=certificate();let mut acceptor=boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();acceptor.set_certificate(&cert).unwrap();acceptor.set_private_key(&key).unwrap();let acceptor=acceptor.build();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();let temp=std::env::temp_dir().join(format!("cloudflared-ca-{}.pem",Uuid::new_v4()));std::fs::write(&temp,cert.to_pem().unwrap()).unwrap();
        let pid_path=std::env::temp_dir().join(format!("cloudflared-pid-{}",Uuid::new_v4()));let notify_path=std::env::temp_dir().join(format!("cloudflared-notify-{}",Uuid::new_v4()));let notify=std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();notify.set_nonblocking(true).unwrap();
        let mut config=config();config.pidfile=Some(pid_path.clone());config.edge_ca=Some(temp.clone());let edge_tls=tls(&config).unwrap();std::fs::remove_file(temp).unwrap();let mut runtime=runtime(config);Arc::get_mut(&mut runtime).unwrap().notify_socket=Some(notify_path.clone().into_os_string());
        assert!(!pid_path.exists());let mut notify_bytes=[0;32];assert!(notify.recv(&mut notify_bytes).is_err());assert_eq!(runtime.readiness.response(runtime.client_id).0,503);
        let registered=Arc::new(tokio::sync::Notify::new());let unregistered=Arc::new(AtomicBool::new(false));let observed=Arc::new(Mutex::new(Vec::new()));
        let local_configuration=Arc::new(AtomicBool::new(false));let configured=local_configuration.clone();let ready=registered.clone();let closed=unregistered.clone();let seen=observed.clone();let shared=runtime.clone();
        let edge=tokio::task::spawn_local(async move{
            let (socket,_)=listener.accept().await.unwrap();let tls=tokio_boring::accept(&acceptor,socket).await.unwrap();assert!(tls.ssl().selected_alpn_protocol().is_none());
            let (mut client,connection)=h2::client::handshake(tls).await.unwrap();let _connection=AbortTask(tokio::task::spawn_local(connection));
            let (answer,send)=client.send_request(http::Request::builder().method("POST").uri("https://example.invalid/control").header("cf-cloudflared-proxy-connection-upgrade","control-stream").body(()).unwrap(),false).unwrap();
            let response=answer.await.unwrap();let (control,pump)=h2_control::bridge(response.into_body(),send);let _pump=AbortTask(pump);let (read,write)=tokio::io::split(control);
            let network=capnp_rpc::twoparty::VatNetwork::new(read.compat(),write.compat_write(),capnp_rpc::rpc_twoparty_capnp::Side::Server,crate::protocol::reader_options());
            let server:wire::registration_server::Client=capnp_rpc::new_client(Oracle{registered:ready.clone(),unregistered:closed.clone(),observed:seen,local_configuration:configured.clone(),origin_ip:"127.0.0.2".parse().unwrap(),reject:false});let rpc=capnp_rpc::RpcSystem::new(Box::new(network),Some(server.client));let mut rpc_task=AbortTask(tokio::task::spawn_local(rpc));
            ready.notified().await;
            tokio::time::timeout(Duration::from_secs(2),async{while !shared.readiness.ready(){tokio::time::sleep(Duration::from_millis(1)).await}}).await.unwrap();
            let (response,_)=client.send_request(http::Request::builder().uri("https://example.invalid/path").body(()).unwrap(),true).unwrap();assert_eq!(response.await.unwrap().status(),203);
            let accepted=update_request(&mut client,7,serde_json::json!({"ingress":[{"service":"http_status:204"}]})).await;assert_eq!(accepted["lastAppliedVersion"],7);assert!(accepted["err"].is_null());
            let stale=update_request(&mut client,6,serde_json::json!({"ingress":[{"service":"http_status:205"}]})).await;assert_eq!(stale["lastAppliedVersion"],7);
            let invalid=update_request(&mut client,8,serde_json::json!({"ingress":[{"hostname":"example.invalid","service":"http_status:205"}]})).await;assert_eq!(invalid["lastAppliedVersion"],7);assert_eq!(invalid["err"],serde_json::json!({}));
            let (response,_)=client.send_request(http::Request::builder().uri("https://example.invalid/path").body(()).unwrap(),true).unwrap();assert_eq!(response.await.unwrap().status(),204);
            assert!(configured.load(Ordering::Acquire));shared.shutdown.cancel();let _=(&mut rpc_task.0).await;assert!(closed.load(Ordering::Acquire));
        });
        let mut reset=None;let connector=serve_h2(runtime.clone(),&edge_tls,0,address,0,&mut reset);
        tokio::time::timeout(Duration::from_secs(10),async{let (a,b)=tokio::join!(connector,edge);a.unwrap();b.unwrap();}).await.unwrap();
        assert!(!runtime.readiness.ready());assert_eq!(observed.lock().unwrap().as_slice(),&[(0,runtime.client_id)]);let n=notify.recv(&mut notify_bytes).unwrap();assert_eq!(&notify_bytes[..n],b"READY=1");assert_eq!(std::fs::read_to_string(&pid_path).unwrap(),std::process::id().to_string());std::fs::remove_file(pid_path).unwrap();std::fs::remove_file(notify_path).unwrap();
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn named_quic_real_tls_first_stream_rpc_http_config_and_unregister() {
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
            config.protocol = Protocol::Quic;
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
                let server: wire::registration_server::Client = capnp_rpc::new_client(Oracle {
                    registered: ready.clone(),
                    unregistered: closed.clone(),
                    observed,
                    local_configuration: local_configuration.clone(),
                    origin_ip: "127.0.0.1".parse().unwrap(),
                    reject: false,
                });
                let mut registration_rpc = AbortTask(tokio::task::spawn_local(
                    capnp_rpc::RpcSystem::new(Box::new(network), Some(server.client)),
                ));
                ready.notified().await;
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !shared.readiness.ready() || !local_configuration.load(Ordering::Acquire)
                    {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .unwrap();
                let mut stream = conn.open_bi().await.unwrap();
                assert_eq!(stream.id(), 1);
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
                assert_eq!(stream.id(), 5);
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
                a.unwrap();
                b.unwrap();
            })
            .await
            .unwrap();
            assert!(!runtime.readiness.ready());
            assert!(runtime.ever_quic.load(Ordering::Acquire));
            assert_eq!(seen.lock().unwrap().as_slice(), &[(0, runtime.client_id)]);
            assert!(configured.load(Ordering::Acquire));
        })
        .await;
}
