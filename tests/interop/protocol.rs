use cloudflare_tunnel_rust::protocol::{
    callbacks::*, datagram::*, headers, metadata::*, registration::*,
};
use futures::FutureExt;
use std::{
    io::{BufRead, BufReader},
    net::IpAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    rc::Rc,
    time::Duration,
};
use uuid::Uuid;

const TUNNEL: &str = "11111111-1111-4111-8111-111111111111";
const CLIENT: &str = "22222222-2222-4222-8222-222222222222";
const CONNECTION: &str = "33333333-3333-4333-8333-333333333333";
fn oracle() -> PathBuf {
    std::env::var_os("CLOUDFLARED_GO_ORACLE")
        .expect("run scripts/test-interop.sh")
        .into()
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn server(mode: &str) -> (Process, String) {
    let child = Command::new(oracle())
        .args(["server", mode])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut child = Process(child);
    let mut address = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    assert!(address.starts_with("127.0.0.1:"));
    (child, address.trim().into())
}
fn request() -> RegistrationRequest {
    RegistrationRequest {
        auth: TunnelAuth {
            account_tag: "synthetic-account".into(),
            tunnel_secret: b"synthetic-secret".to_vec(),
        },
        tunnel_id: TUNNEL.parse().unwrap(),
        connection_index: 2,
        client_id: CLIENT.parse().unwrap(),
        features: vec!["serialized_headers".into(), "support_quic_eof".into()],
        version: "synthetic-version".into(),
        arch: "linux_amd64".into(),
        origin_ip: Some("192.0.2.1".parse().unwrap()),
        previous_attempts: 3,
    }
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("cloudflared-interop-{}", Uuid::new_v4()));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
#[ignore = "requires pinned Go oracle; scripts/test-interop.sh"]
async fn go_rust_metadata_headers_and_datagrams() {
    let dir = Scratch::new();
    assert!(
        Command::new(oracle())
            .arg("fixtures")
            .arg(&dir.0)
            .status()
            .unwrap()
            .success()
    );
    let bytes = std::fs::read(dir.0.join("go-request.bin")).unwrap();
    let mut input = bytes.as_slice();
    assert_eq!(
        read_stream_kind(&mut input).await.unwrap(),
        StreamKind::Data
    );
    let decoded = read_connect_request(&mut input).await.unwrap();
    assert_eq!(decoded.destination, "https://example.invalid/path");
    assert_eq!(decoded.connection_type, ConnectionType::Http);
    assert_eq!(decoded.metadata.len(), 3);
    assert_eq!(input, b"synthetic body");
    let mut output = Vec::new();
    write_connect_request(&mut output, &decoded).await.unwrap();
    output.extend_from_slice(b"synthetic body");
    std::fs::write(dir.0.join("rust-request.bin"), output).unwrap();
    let h = std::fs::read_to_string(dir.0.join("go-headers.txt")).unwrap();
    let pairs = headers::deserialize(&h).unwrap();
    assert_eq!(pairs.len(), 3);
    assert!(
        pairs
            .iter()
            .any(|(k, v)| k == b"X-Binary" && v == &vec![255, b':', b';'])
    );
    std::fs::write(dir.0.join("rust-headers.txt"), headers::serialize(&pairs)).unwrap();
    let v2 = std::fs::read(dir.0.join("go-v2.bin")).unwrap();
    let decoded = DatagramV2::decode(&v2).unwrap();
    assert_eq!(decoded.encode().unwrap(), v2);
    let v3 = std::fs::read(dir.0.join("go-v3.bin")).unwrap();
    let decoded = DatagramV3::decode(&v3).unwrap();
    assert_eq!(decoded.encode().unwrap(), v3);
    std::fs::write(dir.0.join("rust-v3.bin"), decoded.encode().unwrap()).unwrap();
    let resp = std::fs::read(dir.0.join("go-v3-response.bin")).unwrap();
    assert_eq!(DatagramV3::decode(&resp).unwrap().encode().unwrap(), resp);
    let mut bytes = Vec::new();
    write_connect_response(
        &mut bytes,
        &ConnectResponse {
            error: "synthetic error".into(),
            metadata: vec![("HttpStatus".into(), "502".into())],
        },
    )
    .await
    .unwrap();
    std::fs::write(dir.0.join("rust-response.bin"), bytes).unwrap();
    assert!(
        Command::new(oracle())
            .arg("decode")
            .arg(&dir.0)
            .status()
            .unwrap()
            .success()
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires pinned Go oracle; scripts/test-interop.sh"]
async fn real_registration_success_rejection_retry_timeout_disconnect() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let metrics = cloudflare_tunnel_rust::observability::metrics::Metrics::new().unwrap();
            let (_child, address) = server("success");
            let stream = tokio::net::TcpStream::connect(&address).await.unwrap();
            let connected =
                register_connection(stream, request(), Duration::from_secs(3), metrics.clone())
                    .await
                    .unwrap();
            assert!(connected.is_ready());
            assert_eq!(connected.identity().connection_index(), 2);
            assert_eq!(
                connected.identity().tunnel_id(),
                TUNNEL.parse::<Uuid>().unwrap()
            );
            assert_eq!(
                connected.identity().client_id(),
                CLIENT.parse::<Uuid>().unwrap()
            );
            assert_eq!(
                connected.details().uuid,
                CONNECTION.parse::<Uuid>().unwrap()
            );
            assert!(!connected.details().remotely_managed);
            connected
                .send_local_configuration(b"{\"synthetic\":true}")
                .await
                .unwrap();
            connected.unregister(Duration::from_secs(3)).await.unwrap();
            for mode in ["reject", "retry", "timeout"] {
                let (_child, address) = server(mode);
                let stream = tokio::net::TcpStream::connect(&address).await.unwrap();
                let outcome = register_connection(
                    stream,
                    request(),
                    Duration::from_millis(250),
                    metrics.clone(),
                )
                .await;
                match (mode, outcome) {
                    ("reject", Err(RegistrationError::Rejected { cause })) => {
                        assert_eq!(cause, "synthetic permanent rejection")
                    }
                    ("retry", Err(RegistrationError::RetryAfter { cause, delay })) => {
                        assert_eq!(cause, "synthetic transient rejection");
                        assert_eq!(delay, Duration::from_secs(2));
                    }
                    ("timeout", Err(RegistrationError::Timeout)) => {}
                    (_, Err(error)) => panic!("unexpected {mode} outcome: {error}"),
                    (_, Ok(_)) => panic!("rejected registration produced carrier"),
                }
            }
            let (_child, address) = server("disconnect");
            let stream = tokio::net::TcpStream::connect(&address).await.unwrap();
            let mut connected =
                register_connection(stream, request(), Duration::from_secs(3), metrics.clone())
                    .await
                    .unwrap();
            tokio::time::timeout(Duration::from_secs(3), connected.disconnected())
                .await
                .unwrap();
            assert!(!connected.is_ready());
            assert!(matches!(
                connected.send_local_configuration(b"{}").await,
                Err(RegistrationError::Disconnected)
            ));
            assert!(!format!("{:?}", request()).contains("synthetic-secret"));
            assert!(!format!("{:?}", request()).contains("synthetic-account"));
            assert_eq!(
                metrics
                    .rpc_client_operations
                    .with_label_values(&["registration", "register_connection"])
                    .get(),
                5
            );
            assert_eq!(
                metrics
                    .rpc_client_failures
                    .with_label_values(&["registration", "register_connection"])
                    .get(),
                3
            );
            assert_eq!(
                metrics
                    .rpc_client_operations
                    .with_label_values(&["registration", "update_local_configuration"])
                    .get(),
                2
            );
            assert_eq!(
                metrics
                    .rpc_client_failures
                    .with_label_values(&["registration", "update_local_configuration"])
                    .get(),
                1
            );
            assert_eq!(
                metrics
                    .rpc_client_operations
                    .with_label_values(&["registration", "unregister_connection"])
                    .get(),
                1
            );
        })
        .await;
}

struct Callbacks;
impl EdgeCallbacks for Callbacks {
    fn update_configuration(
        &self,
        version: i32,
        config: Vec<u8>,
    ) -> futures::future::LocalBoxFuture<'static, ConfigurationResult> {
        async move {
            assert_eq!(version, 7);
            assert_eq!(config, b"{\"synthetic\":true}");
            ConfigurationResult {
                latest_applied_version: version,
                error: String::new(),
            }
        }
        .boxed_local()
    }
    fn register_udp_session(
        &self,
        req: UdpRegistration,
    ) -> futures::future::LocalBoxFuture<'static, Result<UdpRegistrationResult, capnp::Error>> {
        async move {
            assert_eq!(req.session_id, TUNNEL.parse::<Uuid>().unwrap());
            assert_eq!(req.destination, "192.0.2.53".parse::<IpAddr>().unwrap());
            assert_eq!(req.port, 53);
            assert_eq!(req.idle_hint, Duration::from_secs(210));
            assert_eq!(req.trace_context, "synthetic-trace");
            Ok(UdpRegistrationResult {
                error: String::new(),
                spans: vec![1, 2, 3],
            })
        }
        .boxed_local()
    }
    fn unregister_udp_session(
        &self,
        id: Uuid,
        message: String,
    ) -> futures::future::LocalBoxFuture<'static, Result<(), capnp::Error>> {
        async move {
            assert_eq!(id, TUNNEL.parse::<Uuid>().unwrap());
            assert_eq!(message, "synthetic close");
            Ok(())
        }
        .boxed_local()
    }
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires pinned Go oracle; scripts/test-interop.sh"]
async fn go_calls_rust_configuration_and_session_capabilities() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let metrics = cloudflare_tunnel_rust::observability::metrics::Metrics::new().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let child = Process(
                Command::new(oracle())
                    .args(["callbacks", &address])
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(
                read_stream_kind(&mut stream).await.unwrap(),
                StreamKind::Rpc
            );
            let task = tokio::task::spawn_local(serve_callbacks(
                stream,
                Rc::new(Callbacks),
                Duration::from_secs(10),
                metrics.clone(),
            ));
            let status = tokio::task::spawn_blocking(move || {
                let mut child = child;
                child.0.wait().unwrap()
            })
            .await
            .unwrap();
            assert!(status.success());
            assert_eq!(
                metrics
                    .rpc_server_operations
                    .with_label_values(&["config", "update_configuration"])
                    .get(),
                1
            );
            assert_eq!(
                metrics
                    .rpc_server_operations
                    .with_label_values(&["session", "register_udp_session"])
                    .get(),
                1
            );
            assert_eq!(
                metrics
                    .rpc_server_operations
                    .with_label_values(&["session", "unregister_udp_session"])
                    .get(),
                1
            );
            let _ = tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap();
        })
        .await;
}

#[test]
#[ignore = "requires pinned Go oracle; scripts/test-interop.sh"]
fn go_rust_regex_ascii_unicode_fold_and_syntax_corpus() {
    let vectors = [
        (r"^\d+$", vec!["123", "١٢٣", "１２"]),
        (r"^\D+$", vec!["x", "١", "1"]),
        (r"^\w+$", vec!["word_1", "é", "α"]),
        (r"(?i)^\w+$", vec!["ſ", "K", "é"]),
        (r"^\W+$", vec!["é", "!", "a"]),
        (
            r"^\s+$",
            vec![" \t\n\r\u{c}", "\u{b}", "\u{a0}", "\u{2003}"],
        ),
        (r"^\S+$", vec!["\u{a0}", "\u{b}", " "]),
        (r"\bword\b", vec!["word", "sword", "éwordé"]),
        (r"\bé\b", vec!["é", " é ", "xéx"]),
        (r"\Bé\B", vec!["é", " é ", "xéx"]),
        (r"^[\d_]+$", vec!["1_", "١", "_"]),
        (r"^[^\d]+$", vec!["١", "x", "1"]),
        (r"^[a&&b]+$", vec!["a", "b", "&", "c"]),
        (r"^[a[b]]$", vec!["a]", "b]", "[]", "a"]),
        (r"^[[:space:]]+$", vec!["\u{b}", "\u{a0}", " "]),
        (r"(?P<x>a)(?P<x>b)", vec!["ab", "aa"]),
        (r"(?P<1>a)", vec!["a", "1"]),
        (r"\123", vec!["S", "123"]),
        (r"\12", vec!["\n", "12"]),
        (r"\0", vec!["\0", "0"]),
        (r"\777", vec!["ǿ", "777"]),
        (r"\1", vec!["1"]),
        (r"\Q[a&&b]\E", vec!["[a&&b]", "a"]),
        (r"\Q[unclosed", vec!["[unclosed", "unclosed"]),
        (r"^\p{Greek}+$", vec!["αβ", "ab"]),
        (r"^\p{Han}+$", vec!["汉", "\u{2ebf0}"]),
        (r"^\pL+$", vec!["é", "\u{1c89}", "1"]),
        (r"(?i)^\p{Lu}+$", vec!["é", "k", "K", "\u{1c8a}"]),
        (r"^\p{Letter}$", vec!["a"]),
        (r"(?i)^k$", vec!["k", "K", "K"]),
        (r"(?i:k)(?-i:s)", vec!["ks", "Ks", "KS"]),
        (r"(?i)^\x{1c89}$", vec!["\u{1c89}", "\u{1c8a}"]),
        (r"^.$", vec!["é", "\n"]),
        (r"(?s)^.$", vec!["é", "\n"]),
        (r"a$", vec!["a", "a\n"]),
        (r"a{1000}", vec!["a"]),
        (r"a{1001}", vec!["a"]),
        (r"(?x)a", vec!["a"]),
        (r"\\d", vec![r"\d", "1"]),
    ];
    let input = serde_json::Value::Array(
        vectors
            .iter()
            .map(|(pattern, inputs)| serde_json::json!({"pattern":pattern,"inputs":inputs}))
            .collect(),
    );
    let output = Command::new(oracle())
        .args(["regex", &input.to_string()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let reference: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for ((pattern, inputs), expected) in vectors.iter().zip(reference) {
        let expression = cloudflare_tunnel_rust::config::compile_ingress_path(pattern);
        assert_eq!(
            expression.is_ok(),
            expected["valid"].as_bool().unwrap(),
            "syntax {pattern}"
        );
        if let Ok(expression) = expression {
            let actual = inputs
                .iter()
                .map(|input| expression.is_match(input))
                .collect::<Vec<_>>();
            assert_eq!(
                serde_json::json!(actual),
                expected["matches"],
                "matches {pattern}"
            );
        }
    }
}

#[test]
#[ignore = "requires pinned Go oracle; scripts/test-interop.sh"]
fn go_rust_ingress_access_normalization_and_invalid_utf8_paths() {
    use cloudflare_tunnel_rust::config::{
        LoadedConfig, canonical_path, ingress_requires_normalization, matcher_path,
    };
    let mut vectors = Vec::new();
    for mode in ["none", "global", "rule"] {
        for disable in [false, true] {
            for path in [
                "/public/../admin",
                "/public/%2e%2e/admin",
                "/public/%5c../admin",
                "/bad/%ff",
                "/bad/%e2%82",
                "/bad/%e2%82%ac",
            ] {
                let mut configuration = serde_json::json!({"ingress":[{"path":"^/admin$","service":"http_status:204"},{"path":"^/bad/�{2}$","service":"http_status:205"},{"path":"^/bad/�$","service":"http_status:206"},{"service":"http_status:404"}]});
                let access = serde_json::json!({"required":true,"teamName":"synthetic","audTag":["synthetic-aud"]});
                if mode == "global" {
                    configuration["originRequest"] = serde_json::json!({"access":access});
                }
                if mode == "rule" {
                    configuration["ingress"][0]["originRequest"] =
                        serde_json::json!({"access":access});
                }
                vectors.push(serde_json::json!({"configuration":configuration,"disable":disable,"url":format!("https://example.invalid{path}")}));
            }
        }
    }
    let output = Command::new(oracle())
        .args(["ingress", &serde_json::to_string(&vectors).unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let reference: Vec<usize> = serde_json::from_slice(&output.stdout).unwrap();
    for (vector, index) in vectors.iter().zip(reference) {
        let configuration: LoadedConfig =
            serde_json::from_value(vector["configuration"].clone()).unwrap();
        let uri: http::Uri = vector["url"].as_str().unwrap().parse().unwrap();
        let mut path = matcher_path(uri.path()).unwrap();
        if !vector["disable"].as_bool().unwrap() && ingress_requires_normalization(&configuration) {
            path = canonical_path(&path);
        }
        let actual = configuration
            .ingress
            .iter()
            .position(|rule| rule.matches("example.invalid", &path, false).unwrap())
            .unwrap();
        assert_eq!(actual, index, "vector {vector}");
    }
}

#[test]
#[ignore = "requires pinned Go oracle; scripts/test-interop.sh"]
fn go_rust_access_url_source_contract() {
    use cloudflare_tunnel_rust::access::ApplicationUrl;
    let inputs = [
        "",
        "app.example.invalid",
        "app.example.invalid/path",
        "http://app.example.invalid",
        "http://app.example.invalid:80",
        "http://app.example.invalid:443/path",
        "https://app.example.invalid:443",
        "https://app.example.invalid:80/",
        "https://app.example.invalid:65536/",
        "https://UPPER.example.invalid/a/../b",
        "https://app.example.invalid/a/%2e/%2E%2E/b",
        "https://app.example.invalid/a/../b#fragment",
        "https://app.example.invalid/a/%2e%2e/b#fragment",
        "https://app.example.invalid#fragment",
        "https://app.example.invalid/path?q=#fragment",
        "https://app.example.invalid/path?",
        "https://app.example.invalid/café",
        "https://app.example.invalid/%2e/café!",
        "https://bücher.example.invalid/path",
        "https://BÜCHER.Example.invalid/path",
        "https://synthetic-user:synthetic-pass@app.example.invalid/a/../b",
        "https://synthetic%2duser:synthetic%3apass@app.example.invalid/path",
        "::1",
        "http://::1/path",
        "https://[::1]/path",
        "[::1]:8443/path",
        "https://[::1]:80/a/%2e%2e/b",
        "https://app.example.invalid:",
        "https://app.example.invalid:bad/",
        "https://app.example.invalid:%38%30/",
        "https:///path",
        "https://app.example.invalid/%xy",
        "https://app.example.invalid/space in path",
        "https://app.example.invalid/?space=in query",
        "https://app.example.invalid/line\nbreak",
        "ftp://service.example.invalid/path",
        "HTTPS://app.example.invalid/path",
    ];
    let vectors = inputs
        .iter()
        .flat_map(|input| [false, true].map(|curl| serde_json::json!({"input":input,"curl":curl})))
        .collect::<Vec<_>>();
    let output = Command::new(oracle())
        .args(["access-url", &serde_json::to_string(&vectors).unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let reference: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for (vector, expected) in vectors.iter().zip(reference) {
        let input = vector["input"].as_str().unwrap();
        let parsed = if vector["curl"].as_bool().unwrap() {
            ApplicationUrl::curl(input)
        } else {
            ApplicationUrl::access(input)
        };
        assert_eq!(
            parsed.is_ok(),
            expected["valid"].as_bool().unwrap(),
            "input {vector}"
        );
        if let Ok(application) = parsed {
            assert_eq!(
                application.as_str(),
                expected["url"].as_str().unwrap(),
                "URL {vector}"
            );
            assert_eq!(
                application.host(),
                expected["host"].as_str().unwrap(),
                "host {vector}"
            );
            assert_eq!(
                application.path(),
                expected["path"].as_str().unwrap(),
                "path {vector}"
            );
            assert_eq!(
                application.query().unwrap_or(""),
                expected["query"].as_str().unwrap(),
                "query {vector}"
            );
            let request = application.request_uri();
            if application.query().is_some_and(|query| query.contains(' ')) {
                // Go accepts this raw query; http::Uri cannot represent it without changing the target.
                assert!(expected["request_valid"].as_bool().unwrap());
                assert!(request.is_err());
                continue;
            }
            assert_eq!(
                request.is_ok(),
                expected["request_valid"].as_bool().unwrap(),
                "request validity {vector}"
            );
            if let Ok(request) = request {
                assert_eq!(
                    request.path_and_query().unwrap().as_str(),
                    expected["request_uri"].as_str().unwrap(),
                    "request target {vector}"
                );
                assert_eq!(
                    request.authority().unwrap().as_str(),
                    expected["request_host"].as_str().unwrap(),
                    "request Host {vector}"
                );
            }
        }
    }
}
