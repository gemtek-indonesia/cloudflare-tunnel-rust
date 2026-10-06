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
            let (_child, address) = server("success");
            let stream = tokio::net::TcpStream::connect(&address).await.unwrap();
            let connected = register_connection(stream, request(), Duration::from_secs(3))
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
                let outcome =
                    register_connection(stream, request(), Duration::from_millis(250)).await;
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
            let mut connected = register_connection(stream, request(), Duration::from_secs(3))
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
            ));
            let status = tokio::task::spawn_blocking(move || {
                let mut child = child;
                child.0.wait().unwrap()
            })
            .await
            .unwrap();
            assert!(status.success());
            let _ = tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap();
        })
        .await;
}
