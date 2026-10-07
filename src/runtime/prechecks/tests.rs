use super::*;
use std::cell::{Cell, RefCell};

struct Mock {
    groups: Vec<Vec<SocketAddr>>,
    dns_failures: Cell<u8>,
    dns_calls: Cell<u8>,
    dns_times: RefCell<Vec<Instant>>,
    lookups: RefCell<Vec<String>>,
    calls: RefCell<Vec<(Kind, SocketAddr, Instant)>>,
    failed: Vec<(Kind, SocketAddr)>,
    hang: bool,
}
impl Mock {
    fn new(groups: Vec<Vec<SocketAddr>>) -> Self {
        Self {
            groups,
            dns_failures: Cell::new(0),
            dns_calls: Cell::new(0),
            dns_times: RefCell::new(vec![]),
            lookups: RefCell::new(vec![]),
            calls: RefCell::new(vec![]),
            failed: vec![],
            hang: false,
        }
    }
}
impl Dialers for Mock {
    async fn resolve(&self, _: &str) -> Result<Vec<Vec<SocketAddr>>> {
        self.dns_calls.set(self.dns_calls.get() + 1);
        self.dns_times.borrow_mut().push(Instant::now());
        if self.hang {
            futures::future::pending::<()>().await;
        }
        if self.dns_failures.get() > 0 {
            self.dns_failures.set(self.dns_failures.get() - 1);
            bail!("synthetic DNS failure");
        }
        Ok(self.groups.clone())
    }
    async fn lookup_host(&self, address: &str) -> Result<Vec<ProbeAddress>> {
        self.lookups.borrow_mut().push(address.into());
        Ok(self
            .groups
            .iter()
            .flatten()
            .copied()
            .map(ProbeAddress::from)
            .collect())
    }
    async fn connect(&self, kind: Kind, address: SocketAddr, _: &EdgeTls) -> Result<()> {
        self.calls
            .borrow_mut()
            .push((kind, address, Instant::now()));
        if self.hang {
            futures::future::pending::<()>().await;
        }
        if self.failed.contains(&(kind, address)) {
            bail!("synthetic dial failure");
        }
        Ok(())
    }
    async fn management(&self) -> Result<()> {
        if self.hang {
            futures::future::pending::<()>().await;
        }
        Ok(())
    }
}
fn config() -> Config {
    Config::diagnostic("")
}
fn grouped() -> Vec<Vec<SocketAddr>> {
    vec![
        vec![
            "192.0.2.10:7844".parse().unwrap(),
            "[2001:db8::10]:7844".parse().unwrap(),
        ],
        vec![
            "192.0.2.20:7844".parse().unwrap(),
            "[2001:db8::20]:7844".parse().unwrap(),
        ],
    ]
}

pub(crate) async fn fixture_report() -> Report {
    let mock = Mock::new(grouped());
    run(&config(), &mock, CancellationToken::new()).await
}

#[tokio::test(start_paused = true)]
async fn dns_retry_delays_family_probes_source_order_and_numeric_report_schema() {
    let mock = Mock::new(grouped());
    mock.dns_failures.set(2);
    let started = Instant::now();
    let report = run(&config(), &mock, CancellationToken::new()).await;
    assert_eq!(mock.dns_calls.get(), 3);
    assert_eq!(
        *mock.dns_times.borrow(),
        [
            started,
            started + Duration::from_secs(1),
            started + Duration::from_secs(3)
        ]
    );
    assert_eq!(
        mock.calls.borrow().len(),
        8,
        "both address families must be probed even when IPv4 passes"
    );
    assert_eq!(report.suggested_protocol, Some(1));
    assert!(!report.hard_fail());
    assert!(!report.warning());
    assert_eq!(
        report.results.iter().map(|r| r.kind).collect::<Vec<_>>(),
        [
            Kind::Dns,
            Kind::Dns,
            Kind::Quic,
            Kind::Quic,
            Kind::Http2,
            Kind::Http2,
            Kind::Management
        ]
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["SuggestedProtocol"], 1);
    assert_eq!(json["Results"][0]["Type"], 0);
    assert_eq!(json["Results"][0]["ProbeStatus"], 0);
    assert!(uuid::Uuid::parse_str(json["RunID"].as_str().unwrap()).is_ok());
    assert_eq!(json["Results"][0]["Target"], "region1.v2.argotunnel.com");
}

#[tokio::test(start_paused = true)]
async fn partial_dns_retains_valid_region_and_reports_missing_family_as_skip() {
    let mut config = config();
    config.region = "fed".into();
    config.ip_version = "6".into();
    let mock = Mock::new(vec![vec!["192.0.2.10:7844".parse().unwrap()], vec![]]);
    let report = run(&config, &mock, CancellationToken::new()).await;
    assert_eq!(mock.dns_calls.get(), 3);
    assert_eq!(report.results[0].probe_status, Status::Pass);
    assert_eq!(report.results[1].probe_status, Status::Fail);
    assert_eq!(report.results[0].target, "fed-region1.v2.argotunnel.com");
    assert!(
        report
            .results
            .iter()
            .filter(|r| matches!(r.kind, Kind::Quic | Kind::Http2))
            .all(|r| r.probe_status == Status::Skip)
    );
    assert!(mock.calls.borrow().is_empty());
    assert!(report.hard_fail());
    assert_eq!(report.suggested_protocol, None);
}

#[tokio::test(start_paused = true)]
async fn any_address_success_wins_but_worst_region_controls_suggestion_and_override() {
    let mut mock = Mock::new(grouped());
    mock.failed = mock
        .groups
        .iter()
        .flatten()
        .copied()
        .filter(|a| a.is_ipv6())
        .map(|address| (Kind::Quic, address))
        .collect();
    let report = run(&config(), &mock, CancellationToken::new()).await;
    assert_eq!(report.suggested_protocol, Some(1));
    assert!(!report.failed(Kind::Quic));
    let mut mock = Mock::new(grouped());
    mock.failed = mock.groups[1]
        .iter()
        .copied()
        .map(|address| (Kind::Quic, address))
        .collect();
    let report = run(&config(), &mock, CancellationToken::new()).await;
    assert_eq!(report.suggested_protocol, Some(0));
    assert!(report.warning());
    assert!(!report.hard_fail());
    let mut override_config = config();
    override_config.protocol = Protocol::Http2;
    let mock = Mock::new(grouped());
    let report = run(&override_config, &mock, CancellationToken::new()).await;
    assert_eq!(report.suggested_protocol, Some(0));
    assert_eq!(
        override_config.protocol,
        Protocol::Http2,
        "report must never change configured transport"
    );
}

#[tokio::test(start_paused = true)]
async fn suite_deadlines_and_cancellation_do_not_poll_new_operations_after_expiry() {
    for seconds in [10, 15] {
        let mut config = config();
        config.timeout = Duration::from_secs(seconds);
        let mut mock = Mock::new(grouped());
        mock.hang = true;
        let start = Instant::now();
        let report = run(&config, &mock, CancellationToken::new()).await;
        assert_eq!(Instant::now() - start, Duration::from_secs(seconds));
        assert_eq!(mock.dns_calls.get(), 1);
        assert!(mock.calls.borrow().is_empty());
        assert!(report.hard_fail());
    }
    let mut mock = Mock::new(grouped());
    mock.hang = true;
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let start = Instant::now();
    let configuration = config();
    let (report, _) = tokio::join!(run(&configuration, &mock, cancel), async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        stop.cancel();
    });
    assert_eq!(Instant::now() - start, Duration::from_secs(2));
    assert!(report.hard_fail());
    assert_eq!(mock.dns_calls.get(), 1);
    assert!(mock.calls.borrow().is_empty());
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mock = Mock::new(grouped());
    let _ = run(&config(), &mock, cancel).await;
    assert_eq!(mock.dns_calls.get(), 0);
}

#[tokio::test(start_paused = true)]
async fn static_edges_skip_srv_lookup_and_source_missing_family_and_tls_errors_are_reported() {
    let mut config = config();
    config.edges = vec!["synthetic.invalid:7844".into()];
    config.ip_version = "6".into();
    let mock = Mock::new(vec![vec!["192.0.2.10:7844".parse().unwrap()]]);
    let report = run(&config, &mock, CancellationToken::new()).await;
    assert_eq!(mock.dns_calls.get(), 0);
    assert_eq!(*mock.lookups.borrow(), config.edges);
    assert_eq!(report.results[0].target, "synthetic.invalid:7844");
    assert!(
        report
            .results
            .iter()
            .filter(|r| matches!(r.kind, Kind::Quic | Kind::Http2))
            .all(|r| r.probe_status == Status::Skip)
    );
}

#[tokio::test]
async fn tls_root_file_failure_is_reported_for_every_transport_target() {
    let mut config = config();
    let mock = Mock::new(grouped());
    config.ca =
        Some(std::env::temp_dir().join(format!("missing-synthetic-ca-{}", uuid::Uuid::new_v4())));
    let report = run(&config, &mock, CancellationToken::new()).await;
    assert!(
        report
            .results
            .iter()
            .filter(|r| matches!(r.kind, Kind::Quic | Kind::Http2))
            .all(|r| r.probe_status == Status::Fail
                && r.details.starts_with("TLS configuration failed:"))
    );
}

#[tokio::test(start_paused = true)]
async fn per_dial_five_second_limits_retry_twice_and_clamp_to_whole_suite() {
    for (seconds, expected) in [(10, vec![0, 6]), (15, vec![0, 6, 13])] {
        let start = Instant::now();
        let calls = RefCell::new(vec![]);
        let budget = Budget {
            deadline: start + Duration::from_secs(seconds),
            cancel: CancellationToken::new(),
        };
        let result = budget
            .retry(Duration::from_secs(5), || {
                calls.borrow_mut().push(Instant::now() - start);
                futures::future::pending::<Result<()>>()
            })
            .await;
        assert!(result.is_err());
        assert_eq!(Instant::now() - start, Duration::from_secs(seconds));
        assert_eq!(
            *calls.borrow(),
            expected
                .into_iter()
                .map(Duration::from_secs)
                .collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn report_logs_source_box_and_structured_rows_with_one_run_id() {
    let path =
        std::env::temp_dir().join(format!("synthetic-precheck-log-{}", uuid::Uuid::new_v4()));
    let context = Context::new(
        crate::observability::logging::Options {
            json: true,
            file: Some(path.clone()),
            disable_terminal: true,
            ..Default::default()
        },
        vec![],
    )
    .unwrap();
    let report = fixture_report().await;
    report.log(&context);
    drop(context);
    let rows = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    std::fs::remove_file(path).unwrap();
    let structured = rows
        .iter()
        .filter(|row| row["message"] == "precheck")
        .collect::<Vec<_>>();
    assert_eq!(structured.len(), 7);
    assert!(
        structured
            .iter()
            .all(|row| row["run_id"] == report.run_id.to_string())
    );
    assert!(rows.iter().any(|row| {
        row["message"]
            .as_str()
            .is_some_and(|line| line.contains("CONNECTIVITY PRE-CHECKS"))
    }));
    assert!(rows.iter().any(|row| {
        row["message"]
            .as_str()
            .is_some_and(|line| line.starts_with("+") && line.ends_with("+"))
    }));
    let summary = rows
        .iter()
        .find(|row| row["message"] == "precheck complete")
        .unwrap();
    assert_eq!(summary["hard_fail"], false);
    assert_eq!(summary["suggested_protocol"], "quic");
}

#[tokio::test(flavor = "current_thread")]
async fn startup_task_obeys_both_skip_controls_and_drop_cancels_pending_work() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut config = super::super::tests::config();
            let mut snapshot =
                super::super::features::FeatureSelector::new("synthetic-account", vec![], false)
                    .snapshot(false);
            let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            for (cli, dns) in [(true, false), (false, true), (true, true)] {
                config.no_prechecks = cli;
                snapshot.skip_prechecks = dns;
                let marker = polled.clone();
                assert!(
                    spawn_if_enabled(&config, &snapshot, async move {
                        marker.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    })
                    .is_none()
                );
            }
            tokio::task::yield_now().await;
            assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
            config.no_prechecks = false;
            snapshot.skip_prechecks = false;
            struct Dropped(Arc<std::sync::atomic::AtomicUsize>);
            impl Drop for Dropped {
                fn drop(&mut self) {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let guard = Dropped(dropped.clone());
            let started = Arc::new(tokio::sync::Notify::new());
            let notify = started.clone();
            let task = spawn_if_enabled(&config, &snapshot, async move {
                let _guard = guard;
                notify.notify_one();
                futures::future::pending::<()>().await;
            })
            .unwrap();
            started.notified().await;
            assert!(!task.0.is_finished());
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), async { 42 })
                    .await
                    .unwrap(),
                42,
                "pending diagnostic task must not gate unrelated startup work"
            );
            drop(task);
            tokio::task::yield_now().await;
            assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
        })
        .await;
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
        .dns("probe.cftunnel.com")
        .build(&cert.x509v3_context(None, None))
        .unwrap();
    cert.append_extension(&san).unwrap();
    cert.sign(&key, boring::hash::MessageDigest::sha256())
        .unwrap();
    (cert.build(), key)
}

#[tokio::test]
async fn native_loopback_tls_probe_has_probe_sni_no_alpn_and_no_h2_bytes() {
    use tokio::io::AsyncReadExt;
    let (cert, key) = certificate();
    let mut acceptor =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.set_private_key(&key).unwrap();
    let acceptor = acceptor.build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tls = EdgeTls::new(TlsPolicy::RequirePostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
    let peer = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = tokio_boring::accept(&acceptor, socket).await.unwrap();
        assert_eq!(
            stream.ssl().servername(boring::ssl::NameType::HOST_NAME),
            Some("probe.cftunnel.com")
        );
        assert!(stream.ssl().selected_alpn_protocol().is_none());
        let mut byte = [0; 1];
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "TLS-only probe must not send any H2 bytes"
        );
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        let native = Native::default();
        let (result, _) = tokio::join!(native.connect(Kind::Http2, address, &tls), peer);
        result.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_loopback_management_probe_is_tcp_only_and_source_action_excludes_self_update() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let native = Native {
        management_target: listener.local_addr().unwrap().to_string(),
    };
    let peer = async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut byte = [0; 1];
        assert_eq!(
            socket.read(&mut byte).await.unwrap(),
            0,
            "management probe sends neither TLS nor HTTP"
        );
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        let (result, _) = tokio::join!(native.management(), peer);
        result.unwrap();
    })
    .await
    .unwrap();
    assert!(!Kind::Management.action().contains("update"));
}

#[tokio::test]
async fn native_loopback_quic_probe_has_no_streams_registration_or_datagrams() {
    let (cert, key) = certificate();
    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
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
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let tls = EdgeTls::new(TlsPolicy::RequirePostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
    let peer = async move {
        let mut bytes = vec![0; 65527];
        let (n, remote) = socket.recv_from(&mut bytes).await.unwrap();
        let header = quiche::Header::from_slice(&mut bytes[..n], 20).unwrap();
        let connection: tokio_quiche::quic::QuicheConnection =
            quiche::accept_with_buf_factory(&header.dcid, None, address, remote, &mut config)
                .unwrap();
        let initial = tokio_quiche::quic::Incoming {
            peer_addr: remote,
            local_addr: address,
            rx_time: None,
            buf: bytes[..n].to_vec(),
            gro: None,
            so_mark_data: None,
        };
        let mut peer = transport::quic::attach_server(connection, socket, initial)
            .await
            .unwrap();
        let mut incoming = peer.take_incoming().unwrap();
        let streams = incoming.streams.recv().await;
        assert!(
            streams.is_none(),
            "probe must never open a registration/data/RPC stream"
        );
        assert!(incoming.datagrams.recv().await.is_none());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        let native = Native::default();
        let (result, _) = tokio::join!(native.connect(Kind::Quic, address, &tls), peer);
        result.unwrap();
    })
    .await
    .unwrap();
}
