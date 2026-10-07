use super::*;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() < 16 * 1024);
    }
    bytes
}

#[tokio::test]
async fn connect_preserves_authority_auth_scope_and_buffered_upgrade_bytes() {
    for authority in [
        "synthetic.invalid:080",
        "[2001:db8::1]:00443",
        "synthetic.invalid:99999",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expected = authority.to_owned();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = String::from_utf8(head(&mut socket).await).unwrap();
            assert!(request.starts_with(&format!("CONNECT {expected} HTTP/1.1\r\n")));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains(&format!("host: {expected}\r\n"))
            );
            let expected_auth = format!(
                "proxy-authorization: Basic {}\r\n",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"synthetic")
            );
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains(&expected_auth.to_ascii_lowercase())
            );
            socket
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\nprebuffer")
                .await
                .unwrap();
            let mut body = Vec::new();
            socket.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"application");
            assert!(
                !body
                    .windows(19)
                    .any(|value| value.eq_ignore_ascii_case(b"proxy-authorization"))
            );
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            let stream = TcpStream::connect(address).await.unwrap();
            let auth = HeaderValue::from_str(&format!(
                "Basic {}",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"synthetic")
            ))
            .unwrap();
            let mut tunnel = http_connect(stream, authority, Some(&auth)).await.unwrap();
            let mut bytes = [0; 9];
            tunnel.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"prebuffer");
            tunnel.write_all(b"application").await.unwrap();
            tunnel.shutdown().await.unwrap();
            drop(tunnel);
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn connect_rejection_and_cancel_close_owned_proxy_socket() {
    for status in [Some(407), Some(2000), None] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (received, ready) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            head(&mut socket).await;
            received.send(()).unwrap();
            if let Some(status) = status {
                socket
                    .write_all(
                        format!("HTTP/1.1 {status} synthetic\r\nContent-Length: 0\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
            let mut body = Vec::new();
            socket.read_to_end(&mut body).await.unwrap();
            assert!(body.is_empty());
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            let stream = TcpStream::connect(address).await.unwrap();
            let task =
                tokio::spawn(
                    async move { http_connect(stream, "synthetic.invalid:443", None).await },
                );
            ready.await.unwrap();
            if status.is_none() {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                assert!(task.await.unwrap().is_err());
            }
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
}

#[derive(Debug)]
struct SocksWire {
    methods: Vec<u8>,
    auth: Option<(Vec<u8>, Vec<u8>)>,
    address_type: Option<u8>,
    destination: Vec<u8>,
}
async fn socks_peer(listener: TcpListener, method: u8) -> SocksWire {
    let (mut socket, _) = listener.accept().await.unwrap();
    assert_eq!(socket.read_u8().await.unwrap(), 5);
    let length = socket.read_u8().await.unwrap();
    let mut methods = vec![0; usize::from(length)];
    socket.read_exact(&mut methods).await.unwrap();
    socket.write_all(&[5, method]).await.unwrap();
    let mut wire = SocksWire {
        methods,
        auth: None,
        address_type: None,
        destination: Vec::new(),
    };
    let version = match socket.read_u8().await {
        Ok(version) => version,
        Err(_) => return wire,
    };
    let version = if method == 2 {
        assert_eq!(version, 1);
        let length = socket.read_u8().await.unwrap();
        let mut username = vec![0; usize::from(length)];
        socket.read_exact(&mut username).await.unwrap();
        let length = socket.read_u8().await.unwrap();
        let mut password = vec![0; usize::from(length)];
        socket.read_exact(&mut password).await.unwrap();
        wire.auth = Some((username, password));
        socket.write_all(&[1, 0]).await.unwrap();
        socket.read_u8().await.unwrap()
    } else {
        version
    };
    assert_eq!(version, 5);
    assert_eq!(socket.read_u8().await.unwrap(), 1);
    assert_eq!(socket.read_u8().await.unwrap(), 0);
    let kind = socket.read_u8().await.unwrap();
    wire.address_type = Some(kind);
    let length = match kind {
        1 => 4,
        4 => 16,
        3 => usize::from(socket.read_u8().await.unwrap()),
        _ => panic!("unexpected fixture address type"),
    };
    wire.destination = vec![0; length];
    socket.read_exact(&mut wire.destination).await.unwrap();
    assert_eq!(socket.read_u16().await.unwrap(), 8080);
    socket
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await
        .unwrap();
    let mut next = [0; 1];
    if socket.read(&mut next).await.unwrap() == 1 {
        assert_eq!(next[0], b'G');
        head(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    }
    wire
}
type Socks = hyper_util::client::legacy::connect::proxy::SocksV5<
    hyper_util::client::legacy::connect::HttpConnector,
>;
async fn socks_wire(method: u8, configure: impl FnOnce(Socks) -> Socks) -> (bool, SocksWire) {
    use hyper_util::client::legacy::connect::{HttpConnector, proxy::SocksV5};
    use tower_service::Service;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(socks_peer(listener, method));
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let mut socks = configure(SocksV5::new(
        format!("socks5://{address}").parse().unwrap(),
        http,
    ));
    let result = socks
        .call("http://[2001:db8::1]:8080/".parse().unwrap())
        .await;
    let success = result.is_ok();
    drop(result);
    (success, peer.await.unwrap())
}
async fn installed_socks_wire(method: u8, authenticate: bool) -> (bool, SocksWire) {
    socks_wire(method, |socks| {
        if authenticate {
            socks.with_auth("synthetic-user".into(), "synthetic-password".into())
        } else {
            socks
        }
    })
    .await
}
#[tokio::test]
async fn installed_socks_ipv6_is_binary_and_password_policy_is_strict() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (success, wire) = installed_socks_wire(0, false).await;
        assert!(success);
        assert_eq!(wire.methods, [0]);
        assert_eq!(wire.address_type, Some(4));
        assert_eq!(
            wire.destination,
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        let (success, wire) = installed_socks_wire(2, true).await;
        assert!(success);
        assert_eq!(wire.methods, [2]);
        assert_eq!(wire.address_type, Some(4));
        assert_eq!(
            wire.auth,
            Some((b"synthetic-user".to_vec(), b"synthetic-password".to_vec()))
        );
        let (success, wire) = installed_socks_wire(0, true).await;
        assert!(!success);
        assert_eq!(wire.methods, [2]);
        assert_eq!(wire.address_type, None);
    })
    .await
    .unwrap();
}
#[tokio::test]
#[ignore = "requires the pinned Go proxy environment oracle"]
async fn go_socks_opt_in_auth_offer_choices_and_raw_byte_contract() {
    let oracle = std::env::var_os("CLOUDFLARED_GO_PROXY_ORACLE").expect("pinned Go proxy oracle");
    tokio::time::timeout(Duration::from_secs(6), async {
        for (method, raw) in [(0, false), (2, false), (2, true)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let peer = tokio::spawn(socks_peer(listener, method));
            let (user, password) = if raw {
                (b"u\xff".to_vec(), b"p\xfe".to_vec())
            } else {
                (b"synthetic-user".to_vec(), b"synthetic-password".to_vec())
            };
            let proxy = if raw {
                format!("socks5://u%FF:p%FE@{address}")
            } else {
                format!("socks5://synthetic-user:synthetic-password@{address}")
            };
            let mut child = tokio::process::Command::new(&oracle)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let input = serde_json::json!({"environment":{"HTTP_PROXY":proxy},"probe":"http://[2001:db8::1]:8080/"});
            child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).await.unwrap();
            let output = child.wait_with_output().await.unwrap();
            assert!(output.status.success());
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["success"], true);
            let source = peer.await.unwrap();
            assert_eq!(source.methods, [0, 2]);
            assert_eq!(source.address_type, Some(4));
            let (success, current) = socks_wire(method, |socks| {
                socks.with_auth_bytes(user, password).allow_no_auth().send_optimistically(true)
            }).await;
            assert!(success);
            assert_eq!(current.methods, source.methods);
            assert_eq!(current.auth, source.auth);
            assert_eq!(current.address_type, source.address_type);
            assert_eq!(current.destination, source.destination);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn socks_opt_in_byte_lengths_choice_and_redacted_debug() {
    use hyper_util::client::legacy::connect::{HttpConnector, proxy::SocksV5};
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let socks = SocksV5::new(
        "socks5://uri-user:uri-password@127.0.0.1:9"
            .parse()
            .unwrap(),
        http,
    )
    .with_auth_bytes(b"auth-user".to_vec(), b"auth-password".to_vec())
    .allow_no_auth();
    let debug = format!("{socks:?}");
    for secret in [
        "uri-user",
        "uri-password",
        "auth-user",
        "auth-password",
        "127.0.0.1",
    ] {
        assert!(!debug.contains(secret));
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        for (username, password, method, expected) in [
            (vec![], vec![], 0, true),
            (vec![], vec![], 2, false),
            (vec![], vec![b'p'; 256], 0, true),
            (vec![b'u'], vec![], 2, true),
            (vec![b'u'; 255], vec![b'p'; 255], 2, true),
            (vec![b'u'; 256], vec![b'p'], 2, false),
            (vec![b'u'], vec![b'p'; 256], 2, false),
            (vec![b'u'], vec![b'p'], 255, false),
        ] {
            let (success, wire) = socks_wire(method, |socks| {
                socks
                    .with_auth_bytes(username.clone(), password.clone())
                    .allow_no_auth()
                    .send_optimistically(true)
            })
            .await;
            assert_eq!(success, expected);
            assert_eq!(wire.methods, [0, 2]);
            if method == 2 && expected {
                assert_eq!(wire.auth, Some((username, password)));
            } else {
                assert!(wire.auth.is_none());
            }
        }
    })
    .await
    .unwrap();
}

async fn banner_peer(listener: TcpListener) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut negotiation = [0; 3];
    socket.read_exact(&mut negotiation).await.unwrap();
    assert_eq!(negotiation, [5, 1, 0]);
    socket.write_all(&[5, 0]).await.unwrap();
    let mut request = [0; 22];
    socket.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[..4], &[5, 1, 0, 4]);
    let reply = [
        &[5, 0, 0, 1, 127, 0, 0, 1, 0, 0][..],
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nbanner",
    ]
    .concat();
    socket.write_all(&reply).await.unwrap();
    let mut request = Vec::new();
    socket.read_to_end(&mut request).await.unwrap();
    socket.shutdown().await.unwrap();
}
#[tokio::test]
#[ignore = "requires the pinned Go proxy environment oracle"]
async fn go_coalesced_socks_reply_and_application_banner_boundary() {
    use hyper_util::client::legacy::connect::{HttpConnector, proxy::SocksV5};
    use tower_service::Service;
    let oracle = std::env::var_os("CLOUDFLARED_GO_PROXY_ORACLE").expect("pinned Go proxy oracle");
    tokio::time::timeout(Duration::from_secs(4), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(banner_peer(listener));
        let mut child = tokio::process::Command::new(&oracle)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn().unwrap();
        let input = serde_json::json!({"environment":{"HTTP_PROXY":format!("socks5://{address}")},"probe":"http://[2001:db8::1]:8080/"});
        child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).await.unwrap();
        let output = child.wait_with_output().await.unwrap();
        let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(source["success"], true);
        assert_eq!(source["body"], base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"banner"));
        peer.await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(banner_peer(listener));
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let mut socks = SocksV5::new(format!("socks5://{address}").parse().unwrap(), http);
        let mut stream = socks.call("http://[2001:db8::1]:8080/".parse().unwrap()).await.unwrap();
        let mut stream = hyper_util::rt::TokioIo::new(&mut stream);
        stream.write_all(b"GET / HTTP/1.1\r\nHost: synthetic.invalid\r\n\r\n").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert!(body.ends_with(b"banner"), "coalesced application bytes must survive SOCKS success");
        peer.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn socks_fragmented_variable_replies_and_cancel_preserve_owned_streams() {
    use hyper_util::client::legacy::connect::{HttpConnector, proxy::SocksV5};
    use tower_service::Service;
    for address in [
        vec![1, 127, 0, 0, 1, 0, 0],
        [
            vec![4],
            "2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            vec![0, 0],
        ]
        .concat(),
        [vec![3, 7], b"example".to_vec(), vec![0, 0]].concat(),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut offer = [0; 4];
            socket.read_exact(&mut offer).await.unwrap();
            assert_eq!(offer, [5, 2, 0, 2]);
            socket.write_all(&[5]).await.unwrap();
            tokio::task::yield_now().await;
            socket.write_all(&[2]).await.unwrap();
            let mut auth = [0; 5];
            socket.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth, [1, 1, b'u', 1, b'p']);
            socket.write_all(&[1]).await.unwrap();
            tokio::task::yield_now().await;
            socket.write_all(&[0]).await.unwrap();
            let mut request = [0; 22];
            socket.read_exact(&mut request).await.unwrap();
            let reply = [vec![5, 0, 0], address].concat();
            socket.write_all(&reply[..4]).await.unwrap();
            tokio::task::yield_now().await;
            socket.write_all(&[reply[4]]).await.unwrap();
            tokio::task::yield_now().await;
            socket
                .write_all(&[&reply[5..], b"banner"].concat())
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut http = HttpConnector::new();
            http.enforce_http(false);
            let mut socks = SocksV5::new(format!("socks5://{endpoint}").parse().unwrap(), http)
                .with_auth_bytes(vec![b'u'], vec![b'p'])
                .allow_no_auth()
                .send_optimistically(true);
            let stream = socks
                .call("http://[2001:db8::1]:8080/".parse().unwrap())
                .await
                .unwrap();
            let mut stream = hyper_util::rt::TokioIo::new(stream);
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"banner");
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (received, ready) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut offer = [0; 4];
        socket.read_exact(&mut offer).await.unwrap();
        received.send(()).unwrap();
        assert!(socket.read_u8().await.is_err());
    });
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let mut socks = SocksV5::new(format!("socks5://{endpoint}").parse().unwrap(), http)
        .with_auth_bytes(vec![b'u'], vec![b'p'])
        .allow_no_auth();
    let task = tokio::spawn(async move {
        socks
            .call("http://[2001:db8::1]:8080/".parse().unwrap())
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[test]
fn explicit_socks_ports_cannot_fall_back_to_443() {
    let invalid: http::Uri = "http://synthetic.invalid:99999/".parse().unwrap();
    assert!(invalid.port().is_none());
    assert!(socks_destination(&invalid).is_err());
    for target in [
        "https://synthetic.invalid:0/",
        "http://[2001:db8::1]:65536/",
    ] {
        assert!(socks_destination(&target.parse().unwrap()).is_err());
    }
    for (target, port) in [
        ("http://synthetic.invalid/", 80),
        ("https://synthetic.invalid/", 443),
        ("http://synthetic.invalid:080/", 80),
        ("https://[2001:db8::1]:65535/", 65535),
    ] {
        assert_eq!(
            socks_destination(&target.parse().unwrap())
                .unwrap()
                .port_u16(),
            Some(port)
        );
    }
}

fn custom_host_flags(ssl: &mut boring::ssl::SslRef) -> Result<(), boring::error::ErrorStack> {
    crate::crypto::enforce_hostname_policy(ssl);
    Ok(())
}
#[tokio::test]
async fn tls_proxy_connect_target_tls_verify_each_peer_and_isolate_auth() {
    use boring::ssl::{SslAcceptor, SslConnector, SslMethod};
    use boring::x509::store::X509StoreBuilder;
    for mode in ["good", "bad-proxy", "bad-target"] {
        let proxy_name = if mode == "bad-proxy" {
            "other.test"
        } else {
            "proxy.test"
        };
        let target_name = if mode == "bad-target" {
            "other.test"
        } else {
            "target.test"
        };
        let (proxy_cert, proxy_key) =
            crate::crypto::tests::certificate_for_names(proxy_name, &[proxy_name]);
        let (target_cert, target_key) =
            crate::crypto::tests::certificate_for_names(target_name, &[target_name]);
        let mut roots = X509StoreBuilder::new().unwrap();
        roots.add_cert(proxy_cert.clone()).unwrap();
        roots.add_cert(target_cert.clone()).unwrap();
        let mut client = SslConnector::builder(SslMethod::tls()).unwrap();
        client.set_cert_store_builder(roots);
        client.set_alpn_protos(b"\x08http/1.1").unwrap();
        let client = client.build();
        let mut proxy = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        proxy.set_certificate(&proxy_cert).unwrap();
        proxy.set_private_key(&proxy_key).unwrap();
        let proxy = proxy.build();
        let mut target = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        target.set_certificate(&target_cert).unwrap();
        target.set_private_key(&target_key).unwrap();
        let target = target.build();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let unused_origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let outer = tokio_boring::accept(&proxy, socket).await;
            if mode == "bad-proxy" {
                assert!(outer.is_err());
                return;
            }
            let mut outer = outer.unwrap();
            let connect = String::from_utf8(head(&mut outer).await).unwrap();
            assert!(connect.starts_with("CONNECT target.test:00443 HTTP/1.1\r\n"));
            assert!(
                connect
                    .to_ascii_lowercase()
                    .contains("proxy-authorization:")
            );
            outer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            let inner = tokio_boring::accept(&target, outer).await;
            if mode == "bad-target" {
                assert!(inner.is_err());
                return;
            }
            let mut inner = inner.unwrap();
            let request = String::from_utf8(head(&mut inner).await).unwrap();
            assert!(request.starts_with("GET / HTTP/1.1\r\n"));
            assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
            assert!(!request.contains("synthetic-user"));
            inner
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            inner.shutdown().await.unwrap();
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            let socket = TcpStream::connect(address).await.unwrap();
            let outer = tls_connect(socket, "proxy.test", &client, custom_host_flags, None).await;
            if mode == "bad-proxy" {
                assert!(outer.is_err());
            } else {
                let authorization = HeaderValue::from_str(&format!(
                    "Basic {}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        b"synthetic-user:synthetic-password"
                    )
                ))
                .unwrap();
                let tunnel =
                    http_connect(outer.unwrap(), "target.test:00443", Some(&authorization))
                        .await
                        .unwrap();
                let inner =
                    tls_connect(tunnel, "target.test", &client, custom_host_flags, None).await;
                if mode == "bad-target" {
                    assert!(inner.is_err());
                } else {
                    let mut inner = inner.unwrap();
                    inner
                        .write_all(b"GET / HTTP/1.1\r\nHost: target.test\r\n\r\n")
                        .await
                        .unwrap();
                    let mut bytes = Vec::new();
                    inner.read_to_end(&mut bytes).await.unwrap();
                    assert!(bytes.ends_with(b"OK"));
                }
            }
            peer.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(30), unused_origin.accept())
                    .await
                    .is_err()
            );
        })
        .await
        .unwrap();
    }
}

async fn failure_prefix_peer(listener: TcpListener) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut offer = [0; 3];
    socket.read_exact(&mut offer).await.unwrap();
    assert_eq!(offer, [5, 1, 0]);
    socket.write_all(&[5, 0]).await.unwrap();
    let mut request = [0; 22];
    socket.read_exact(&mut request).await.unwrap();
    socket.write_all(&[5, 5, 0, 1]).await.unwrap();
    assert!(socket.read_u8().await.is_err());
}
#[tokio::test]
#[ignore = "requires the pinned Go proxy environment oracle"]
async fn go_socks_failure_prefix_is_rejected_before_bound_address() {
    use hyper_util::client::legacy::connect::{HttpConnector, proxy::SocksV5};
    use tower_service::Service;
    let oracle = std::env::var_os("CLOUDFLARED_GO_PROXY_ORACLE").expect("pinned Go proxy oracle");
    tokio::time::timeout(Duration::from_secs(2), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(failure_prefix_peer(listener));
        let mut child = tokio::process::Command::new(&oracle)
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
        let input = serde_json::json!({"environment":{"HTTP_PROXY":format!("socks5://{address}")},"probe":"http://[2001:db8::1]:8080/"});
        child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).await.unwrap();
        let output = child.wait_with_output().await.unwrap();
        let source:serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(source["success"],false);
        peer.await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(failure_prefix_peer(listener));
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let mut socks = SocksV5::new(format!("socks5://{address}").parse().unwrap(),http);
        let pending = socks.call("http://[2001:db8::1]:8080/".parse().unwrap());
        assert!(tokio::time::timeout(Duration::from_millis(150), pending).await.unwrap().is_err());
        peer.await.unwrap();
    }).await.unwrap();
}
