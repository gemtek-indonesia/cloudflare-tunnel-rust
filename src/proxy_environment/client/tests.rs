use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::collections::BTreeMap;

#[tokio::test]
async fn plain_http_routes_absolute_form_and_proxy_auth_without_direct_leak() {
    let mut proxy = crate::proxy_environment::fixtures::HttpPeer::start(
        http::StatusCode::OK,
        Bytes::from_static(b"proxy"),
    )
    .await;
    let settings = Arc::new(EnvironmentProxy::from_environment(&BTreeMap::from([(
        "HTTP_PROXY".into(),
        format!("http://synthetic-user:synthetic-password@{}", proxy.address),
    )])));
    let connector = Connector::platform().unwrap().with_settings(settings);
    let client = HttpClient::<Full<Bytes>>::new(connector);
    let response = client
        .request(
            http::Request::builder()
                .uri("http://synthetic.invalid:080/raw?x=%ff")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        b"proxy".as_slice()
    );
    let received = proxy.requests.recv().await.unwrap();
    assert_eq!(received.method, http::Method::GET);
    assert_eq!(
        received.uri.to_string(),
        "http://synthetic.invalid:080/raw?x=%ff"
    );
    assert!(
        received
            .headers
            .contains_key(http::header::PROXY_AUTHORIZATION)
    );
    let mut direct = crate::proxy_environment::fixtures::HttpPeer::start(
        http::StatusCode::OK,
        Bytes::from_static(b"direct"),
    )
    .await;
    let response = client
        .request(
            http::Request::builder()
                .uri(format!("http://{}/", direct.address))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        b"direct".as_slice()
    );
    let received = direct.requests.recv().await.unwrap();
    assert_eq!(received.uri.to_string(), "/");
    assert!(
        !received
            .headers
            .contains_key(http::header::PROXY_AUTHORIZATION)
    );
}

#[tokio::test]
async fn native_factory_modes_keep_admin_quick_and_diagnostics_direct() {
    const CHILD: &str = "CLOUDFLARED_PROXY_FACTORY_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let api = std::env::var("CLOUDFLARED_PROXY_TEST_API").unwrap();
        let quick = std::env::var("CLOUDFLARED_PROXY_TEST_QUICK").unwrap();
        let diagnostic = std::env::var("CLOUDFLARED_PROXY_TEST_DIAG").unwrap();
        let access = crate::access::http_client().unwrap();
        let error = access.get(api.parse().unwrap()).await.err().unwrap();
        assert!(format!("{error:#}").contains("CGI"));
        let account = crate::administration::AccountClient::new(
            crate::administration::credentials::AccountCredentials {
                zone_id: "synthetic-zone".into(),
                account_id: "synthetic-account".into(),
                api_token: "synthetic-account-token".into(),
                endpoint: String::new(),
            },
            &api,
        )
        .unwrap();
        assert!(account.tunnels(Vec::new()).await.unwrap().is_empty());
        let invocation = crate::cli::Invocation::parse(
            [
                "--config",
                "/dev/null",
                "tunnel",
                "--quick-service",
                &quick,
                "--url",
                "http://127.0.0.1:8080",
            ]
            .map(str::to_owned),
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        let config = crate::quick_tunnel::prepare(&invocation).await.unwrap();
        assert_eq!(config.quick_hostname, "synthetic.invalid");
        let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .build::<_, Full<Bytes>>(crate::administration::verified_connector().unwrap());
        assert!(
            client
                .get(diagnostic.parse().unwrap())
                .await
                .unwrap()
                .status()
                .is_success()
        );
        return;
    }
    let mut proxy = crate::proxy_environment::fixtures::HttpPeer::start(
        http::StatusCode::BAD_GATEWAY,
        Bytes::new(),
    )
    .await;
    let api_body = serde_json::to_vec(&serde_json::json!({"success":true,"result":[],"result_info":{"count":0,"per_page":10,"total_count":0}})).unwrap();
    let mut api =
        crate::proxy_environment::fixtures::HttpPeer::start_gzip(Bytes::from(api_body)).await;
    let quick_body = serde_json::to_vec(&serde_json::json!({"success":true,"result":{"id":"00000000-0000-4000-8000-000000000001","hostname":"synthetic.invalid","account_tag":"synthetic-account","secret":STANDARD.encode(b"synthetic-secret")}})).unwrap();
    let mut quick =
        crate::proxy_environment::fixtures::HttpPeer::start_gzip(Bytes::from(quick_body)).await;
    let mut diagnostic =
        crate::proxy_environment::fixtures::HttpPeer::start(http::StatusCode::OK, Bytes::new())
            .await;
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .env_clear().env(CHILD,"1").env("HTTP_PROXY",format!("http://{}",proxy.address)).env("REQUEST_METHOD","GET")
        .env("CLOUDFLARED_PROXY_TEST_API",format!("http://{}/client/v4",api.address))
        .env("CLOUDFLARED_PROXY_TEST_QUICK",format!("http://{}",quick.address))
        .env("CLOUDFLARED_PROXY_TEST_DIAG",format!("http://{}/diag/tunnel",diagnostic.address))
        .args(["--exact","proxy_environment::client::tests::native_factory_modes_keep_admin_quick_and_diagnostics_direct","--nocapture"])
        .output().await.unwrap();
    assert!(output.status.success(), "owned factory-mode child failed");
    let api_request = api.requests.recv().await.unwrap();
    assert!(api_request.uri.path().contains("/cfd_tunnel"));
    assert_eq!(api_request.headers[http::header::ACCEPT_ENCODING], "gzip");
    let quick_request = quick.requests.recv().await.unwrap();
    assert_eq!(quick_request.uri.path(), "/tunnel");
    assert_eq!(quick_request.headers[http::header::ACCEPT_ENCODING], "gzip");
    assert_eq!(
        diagnostic.requests.recv().await.unwrap().uri.path(),
        "/diag/tunnel"
    );
    assert!(proxy.requests.try_recv().is_err());
}

#[tokio::test]
async fn native_access_factory_decodes_gzip_through_environment_proxy() {
    const CHILD: &str = "CLOUDFLARED_GZIP_ENVIRONMENT_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let response = crate::access::http_client()
            .unwrap()
            .get("http://synthetic.invalid/owned-gzip".parse().unwrap())
            .await
            .unwrap();
        assert!(
            !response
                .headers()
                .contains_key(http::header::CONTENT_ENCODING)
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            b"owned-environment".as_slice()
        );
        return;
    }
    let mut proxy = crate::proxy_environment::fixtures::HttpPeer::start_gzip(Bytes::from_static(
        b"owned-environment",
    ))
    .await;
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .env_clear().env(CHILD, "1").env("HTTP_PROXY", format!("http://{}", proxy.address))
        .args(["--exact", "proxy_environment::client::tests::native_access_factory_decodes_gzip_through_environment_proxy", "--nocapture"])
        .output().await.unwrap();
    assert!(
        output.status.success(),
        "owned environment gzip child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = proxy.requests.recv().await.unwrap();
    assert_eq!(
        request.uri.to_string(),
        "http://synthetic.invalid/owned-gzip"
    );
    assert_eq!(request.headers[http::header::ACCEPT_ENCODING], "gzip");
}

#[tokio::test]
async fn carrier_http_proxy_connects_plain_websocket_and_scopes_password_auth() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for password_present in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let credentials = if password_present {
            "synthetic-user:synthetic-password"
        } else {
            "synthetic-user"
        };
        let settings = Arc::new(EnvironmentProxy::from_environment(&BTreeMap::from([(
            "HTTP_PROXY".into(),
            format!("http://{credentials}@{address}"),
        )])));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
                assert!(request.len() < 16 * 1024);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT synthetic.invalid:080 HTTP/1.1\r\n"));
            assert_eq!(
                request
                    .to_ascii_lowercase()
                    .contains("proxy-authorization:"),
                password_present
            );
            socket
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nowned-banner")
                .await
                .unwrap();
            let mut application = Vec::new();
            socket.read_to_end(&mut application).await.unwrap();
            assert_eq!(application, b"owned-websocket-request");
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let connector = Connector::platform().unwrap().with_settings(settings);
            let mut connection = connector
                .dial_with_reference(
                    "http://synthetic.invalid:080/path".parse().unwrap(),
                    Profile::Carrier,
                    None,
                )
                .await
                .unwrap();
            let mut banner = [0; 12];
            connection.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"owned-banner");
            connection
                .write_all(b"owned-websocket-request")
                .await
                .unwrap();
            connection.shutdown().await.unwrap();
            drop(connection);
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn carrier_rejects_https_and_socks5h_proxy_without_dial_or_direct_fallback() {
    for scheme in ["https", "socks5h"] {
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let settings = Arc::new(EnvironmentProxy::from_environment(&BTreeMap::from([(
            "HTTP_PROXY".into(),
            format!("{scheme}://{}", proxy.local_addr().unwrap()),
        )])));
        let connector = Connector::platform().unwrap().with_settings(settings);
        assert!(
            connector
                .dial_with_reference(
                    "http://synthetic.invalid:80/path".parse().unwrap(),
                    Profile::Carrier,
                    None,
                )
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), proxy.accept())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), target.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn access_http_and_jwks_factories_verify_https_proxy_and_target_separately() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const CHILD: &str = "CLOUDFLARED_ACCESS_TLS_PROXY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let response = crate::access::http_client()
            .unwrap()
            .get("https://synthetic.invalid/application".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            b"owned-application".as_slice()
        );
        let access = crate::access::jwt::JwtVerifier::access(&crate::config::AccessConfig {
            required: true,
            team_name: "synthetic".into(),
            aud_tag: vec!["synthetic-audience".into()],
            ..Default::default()
        })
        .unwrap();
        let broker = crate::access::jwt::JwtVerifier::quick_tunnel().unwrap();
        for (algorithm, verifier) in [("RS256", access), ("ES256", broker.clone())] {
            let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(
                    &serde_json::json!({"alg":algorithm,"kid":"synthetic-missing-key","typ":"JWT"}),
                )
                .unwrap(),
            );
            let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
            let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]);
            let token = format!("{header}.{payload}.{signature}");
            let result = if algorithm == "ES256" {
                verifier.verify_broker(&token).await
            } else {
                verifier.verify(&token).await
            };
            assert!(result.is_err());
        }
        return;
    }
    let (certificate, key) = crate::crypto::tests::certificate_for_sans(
        "synthetic-root",
        &[
            "synthetic.invalid",
            "synthetic.cloudflareaccess.com",
            "login.trycloudflare.com",
        ],
        &["127.0.0.1"],
    );
    let directory = std::env::temp_dir().join(format!("access-proxy-tls-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let ca = directory.join("root.pem");
    std::fs::write(&ca, certificate.to_pem().unwrap()).unwrap();
    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    builder.set_certificate(&certificate).unwrap();
    builder.set_private_key(&key).unwrap();
    let acceptor = builder.build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
    let mut server = crate::runtime::AbortTask(tokio::spawn(async move {
        let mut workers = tokio::task::JoinSet::new();
        for _ in 0..3 {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let requests = requests.clone();
            workers.spawn(async move {
                let mut outer = tokio_boring::accept(&acceptor, socket).await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(outer.read_u8().await.unwrap());
                    assert!(head.len() < 16 * 1024);
                }
                let head = String::from_utf8(head).unwrap();
                assert!(head.starts_with("CONNECT "));
                assert!(head.to_ascii_lowercase().contains("proxy-authorization:"));
                outer
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let target = tokio_boring::accept(&acceptor, outer).await.unwrap();
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| {
                        let requests = requests.clone();
                        async move {
                            assert!(
                                !request
                                    .headers()
                                    .contains_key(http::header::PROXY_AUTHORIZATION)
                            );
                            let path = request.uri().path().to_owned();
                            requests.send(path.clone()).unwrap();
                            let body = if path == "/application" {
                                Bytes::from_static(b"owned-application")
                            } else {
                                Bytes::from_static(b"{\"keys\":[]}")
                            };
                            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(body)))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(target), service)
                    .await;
            });
        }
        while let Some(worker) = workers.join_next().await {
            worker.unwrap();
        }
    }));
    let output = tokio::time::timeout(std::time::Duration::from_secs(8), tokio::process::Command::new(std::env::current_exe().unwrap())
        .env_clear().env(CHILD,"1").env("HTTPS_PROXY",format!("https://synthetic-user:synthetic-password@{address}"))
        .env("SSL_CERT_FILE",&ca).env("SSL_CERT_DIR",&directory)
        .args(["--exact","proxy_environment::client::tests::access_http_and_jwks_factories_verify_https_proxy_and_target_separately","--nocapture"])
        .output()).await.unwrap().unwrap();
    assert!(
        output.status.success(),
        "owned Access proxy TLS child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut paths = Vec::new();
    for _ in 0..3 {
        paths.push(
            tokio::time::timeout(std::time::Duration::from_secs(3), received.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    paths.sort();
    assert_eq!(
        paths,
        [
            "/.well-known/jwks.json",
            "/application",
            "/cdn-cgi/access/certs"
        ]
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), &mut server.0)
        .await
        .unwrap()
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn proxy_absolute_target_uses_host_after_physical_pool_checkout() {
    let mut proxy = crate::proxy_environment::fixtures::HttpPeer::start(
        http::StatusCode::OK,
        Bytes::from_static(b"owned"),
    )
    .await;
    let connector =
        Connector::platform()
            .unwrap()
            .with_settings(Arc::new(EnvironmentProxy::from_environment(
                &BTreeMap::from([("HTTP_PROXY".into(), format!("http://{}", proxy.address))]),
            )));
    let client = HttpClient::<Full<Bytes>>::new(connector.clone());
    for host in ["first.invalid:080", "second.invalid:81"] {
        let response = client
            .request(
                http::Request::builder()
                    .uri("http://physical.invalid:080/raw?x=%ff")
                    .header(http::header::HOST, host)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        response.into_body().collect().await.unwrap();
        let received = proxy.requests.recv().await.unwrap();
        assert_eq!(received.uri.to_string(), format!("http://{host}/raw?x=%ff"));
        assert_eq!(received.headers[http::header::HOST], host);
    }
    assert_eq!(
        proxy.connections.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let error = client
        .request(
            http::Request::builder()
                .uri("http://physical.invalid:080/")
                .header(http::header::HOST, "synthetic-user@invalid")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .err()
        .unwrap();
    assert!(!format!("{error:?}").contains("synthetic-user"));
    assert!(proxy.requests.try_recv().is_err());
    let default_client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(connector);
    default_client
        .request(
            http::Request::builder()
                .uri("http://physical.invalid:080/default")
                .header(http::header::HOST, "override.invalid")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let received = proxy.requests.recv().await.unwrap();
    assert_eq!(
        received.uri.to_string(),
        "http://physical.invalid:080/default"
    );
    assert_eq!(received.headers[http::header::HOST], "override.invalid");
}

async fn h2_peer(
    certificate: &boring::x509::X509,
    key: &boring::pkey::PKey<boring::pkey::Private>,
) -> (
    std::net::SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<http::Version>,
    crate::runtime::AbortTask<()>,
) {
    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    builder.set_certificate(certificate).unwrap();
    builder.set_private_key(key).unwrap();
    builder.set_alpn_select_callback(|_, offered| {
        boring::ssl::select_next_proto(b"\x02h2", offered).ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (versions, received) = tokio::sync::mpsc::unbounded_channel();
    let task = crate::runtime::AbortTask(tokio::spawn(async move {
        let mut workers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=listener.accept()=>{
                    let (socket,_)=accepted.unwrap();
                    let acceptor=acceptor.clone();
                    let versions=versions.clone();
                    workers.spawn(async move {
                        let stream=tokio_boring::accept(&acceptor,socket).await.unwrap();
                        assert_eq!(stream.ssl().selected_alpn_protocol(),Some(b"h2".as_slice()));
                        let service=hyper::service::service_fn(move |request:http::Request<hyper::body::Incoming>| {
                            versions.send(request.version()).unwrap();
                            async { Ok::<_,std::convert::Infallible>(http::Response::new(Full::new(Bytes::from_static(b"owned-h2")))) }
                        });
                        let _=hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream),service).await;
                    });
                }
                completed=workers.join_next(),if !workers.is_empty()=>{completed.unwrap().unwrap();}
            }
        }
    }));
    (address, received, task)
}

#[tokio::test]
async fn default_http_tls_uses_actual_h2_negotiation_for_dispatch() {
    let (certificate, key) =
        crate::crypto::tests::certificate_for_sans("synthetic-root", &[], &["127.0.0.1"]);
    let (address, mut versions, _task) = h2_peer(&certificate, &key).await;
    let mut tls = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
    tls.cert_store_mut().add_cert(certificate).unwrap();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let connector = Connector::platform()
        .unwrap()
        .with_settings(Arc::new(EnvironmentProxy::from_environment(
            &BTreeMap::new(),
        )))
        .with_transport(http, tls.build(), |ssl| {
            crate::crypto::enforce_hostname_policy(ssl);
            Ok(())
        });
    let client = HttpClient::<Full<Bytes>>::new(connector);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client.get(format!("https://{address}/").parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        b"owned-h2".as_slice()
    );
    assert_eq!(versions.recv().await.unwrap(), http::Version::HTTP_2);
}

#[tokio::test]
#[ignore = "requires the pinned Go proxy environment oracle"]
async fn go_default_http_tls_negotiates_h2() {
    use tokio::io::AsyncWriteExt;
    let oracle = std::env::var_os("CLOUDFLARED_GO_PROXY_ORACLE").expect("pinned Go proxy oracle");
    let (certificate, key) =
        crate::crypto::tests::certificate_for_sans("synthetic-root", &[], &["127.0.0.1"]);
    let (address, mut versions, _task) = h2_peer(&certificate, &key).await;
    let directory = std::env::temp_dir().join(format!("go-proxy-h2-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let ca = directory.join("root.pem");
    std::fs::write(&ca, certificate.to_pem().unwrap()).unwrap();
    let mut child = tokio::process::Command::new(oracle)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let input = serde_json::json!({"environment":{"SSL_CERT_FILE":ca,"SSL_CERT_DIR":directory},"probe":format!("https://{address}/")});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .await
        .unwrap();
    let output = tokio::time::timeout(std::time::Duration::from_secs(4), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["success"], true);
    assert_eq!(versions.recv().await.unwrap(), http::Version::HTTP_2);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn access_websocket_factory_keeps_http1_through_authenticated_proxy() {
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const CHILD: &str = "CLOUDFLARED_ACCESS_WS_PROXY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let endpoint =
            crate::access::ApplicationUrl::remote("https://synthetic.invalid/socket").unwrap();
        let stream = crate::access::forward::dial_socket(&endpoint, None)
            .await
            .unwrap();
        let (mut websocket, _) =
            tokio_tungstenite::client_async("wss://synthetic.invalid/socket", stream)
                .await
                .unwrap();
        websocket
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                Bytes::from_static(b"owned-duplex"),
            ))
            .await
            .unwrap();
        assert_eq!(
            websocket.next().await.unwrap().unwrap().into_data(),
            b"owned-duplex".as_slice()
        );
        websocket.close(None).await.unwrap();
        return;
    }
    let (certificate, key) =
        crate::crypto::tests::certificate_for_names("synthetic-root", &["synthetic.invalid"]);
    let directory =
        std::env::temp_dir().join(format!("access-websocket-proxy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let ca = directory.join("root.pem");
    std::fs::write(&ca, certificate.to_pem().unwrap()).unwrap();
    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    builder.set_certificate(&certificate).unwrap();
    builder.set_private_key(&key).unwrap();
    builder.set_alpn_select_callback(|_, offered| {
        assert!(!offered.windows(3).any(|value| value == b"\x02h2"));
        boring::ssl::select_next_proto(b"\x08http/1.1", offered)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
            assert!(head.len() < 16 * 1024);
        }
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("CONNECT synthetic.invalid:443 HTTP/1.1\r\n"));
        assert!(head.to_ascii_lowercase().contains("proxy-authorization:"));
        socket
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let stream = tokio_boring::accept(&acceptor, socket).await.unwrap();
        assert_eq!(stream.ssl().selected_alpn_protocol(), None);
        struct Admission;
        impl tokio_tungstenite::tungstenite::handshake::server::Callback for Admission {
            fn on_request(
                self,
                request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                response: tokio_tungstenite::tungstenite::handshake::server::Response,
            ) -> Result<
                tokio_tungstenite::tungstenite::handshake::server::Response,
                tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
            > {
                assert!(
                    !request
                        .headers()
                        .contains_key(http::header::PROXY_AUTHORIZATION)
                );
                assert_eq!(request.uri().path(), "/socket");
                Ok(response)
            }
        }
        let mut websocket = tokio_tungstenite::accept_hdr_async(stream, Admission)
            .await
            .unwrap();
        let message = websocket.next().await.unwrap().unwrap();
        websocket.send(message).await.unwrap();
        let close = websocket.next().await.unwrap().unwrap();
        assert!(close.is_close());
        let _ = websocket.flush().await;
    });
    let output=tokio::time::timeout(std::time::Duration::from_secs(5),tokio::process::Command::new(std::env::current_exe().unwrap())
        .env_clear().env(CHILD,"1").env("HTTPS_PROXY",format!("http://synthetic-user:synthetic-password@{address}"))
        .env("SSL_CERT_FILE",&ca).env("SSL_CERT_DIR",&directory)
        .args(["--exact","proxy_environment::client::tests::access_websocket_factory_keeps_http1_through_authenticated_proxy","--nocapture"]).output()).await.unwrap().unwrap();
    assert!(
        output.status.success(),
        "owned Access WebSocket proxy child failed"
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
#[ignore = "requires the pinned Go proxy environment oracle"]
async fn go_unicode_proxy_dial_address_uses_idna_before_authority_validation() {
    use tokio::io::AsyncWriteExt;
    let oracle = std::env::var_os("CLOUDFLARED_GO_PROXY_ORACLE").expect("pinned Go proxy oracle");
    for authority in [
        "bücher.invalid:080",
        "BÜCHER.invalid:8080",
        "İ.invalid:8080",
        "ΣΟΣ.invalid:8080",
    ] {
        let mut peer = crate::proxy_environment::fixtures::HttpPeer::start(
            http::StatusCode::OK,
            Bytes::from_static(b"owned"),
        )
        .await;
        let raw = format!("http://{authority}");
        let settings = EnvironmentProxy::from_environment(&BTreeMap::from([(
            "HTTP_PROXY".into(),
            raw.clone(),
        )]));
        let selected = settings
            .select("http", "synthetic.invalid", Some("80"))
            .unwrap()
            .unwrap();
        let rust = proxy_uri(selected)
            .unwrap()
            .authority()
            .unwrap()
            .as_str()
            .to_owned();
        let mut child = tokio::process::Command::new(&oracle)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = serde_json::json!({"environment":{"HTTP_PROXY":raw},"probe":"http://synthetic.invalid/","dial_override":peer.address.to_string()});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .await
            .unwrap();
        let output =
            tokio::time::timeout(std::time::Duration::from_secs(4), child.wait_with_output())
                .await
                .unwrap()
                .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["success"], true);
        assert_eq!(
            rust,
            response["dial_address"].as_str().unwrap(),
            "proxy authority {authority}"
        );
        assert_eq!(
            peer.requests.recv().await.unwrap().uri.to_string(),
            "http://synthetic.invalid/"
        );
    }
}

#[tokio::test]
async fn tls_deadline_cancels_owned_socket_without_direct_retry() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut hello = Vec::new();
        socket.take(65536).read_to_end(&mut hello).await.unwrap();
        assert!(!hello.is_empty());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    });
    let connector = Connector::platform()
        .unwrap()
        .with_settings(Arc::new(EnvironmentProxy::from_environment(
            &BTreeMap::new(),
        )))
        .with_tls_timeout(Some(std::time::Duration::from_millis(30)));
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connector.dial(format!("https://{address}/").parse().unwrap()),
    )
    .await
    .unwrap()
    .err()
    .unwrap();
    assert!(error.to_string().contains("TLS handshake timed out"));
    tokio::time::timeout(std::time::Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

async fn http1_socks_auth_case(
    oracle: Option<&std::ffi::OsStr>,
    user: &str,
    password: &str,
    method: u8,
) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let valid = !user.is_empty() && user.len() < 256 && password.len() < 256;
    let succeeds = method == 0 || valid;
    let expected_user = user.as_bytes().to_vec();
    let expected_password = password.as_bytes().to_vec();
    let go = oracle.is_some();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        assert_eq!(socket.read_u8().await.unwrap(), 5);
        let count = socket.read_u8().await.unwrap();
        let mut offered = vec![0; usize::from(count)];
        socket.read_exact(&mut offered).await.unwrap();
        assert_eq!(offered, [0, 2]);
        socket.write_all(&[5, method]).await.unwrap();
        if method == 2 {
            if !valid {
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).await.unwrap();
                assert!(bytes.is_empty());
                return;
            }
            assert_eq!(socket.read_u8().await.unwrap(), 1);
            let count = socket.read_u8().await.unwrap();
            let mut field = vec![0; usize::from(count)];
            socket.read_exact(&mut field).await.unwrap();
            assert_eq!(field, expected_user);
            let count = socket.read_u8().await.unwrap();
            let mut field = vec![0; usize::from(count)];
            socket.read_exact(&mut field).await.unwrap();
            assert_eq!(field, expected_password);
            socket.write_all(&[1, 0]).await.unwrap();
        }
        let mut prefix = [0; 4];
        socket.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix, [5, 1, 0, 3]);
        let count = socket.read_u8().await.unwrap();
        let mut hostname = vec![0; usize::from(count)];
        socket.read_exact(&mut hostname).await.unwrap();
        assert_eq!(hostname, b"synthetic.invalid");
        assert_eq!(socket.read_u16().await.unwrap(), 80);
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        if go {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(socket.read_u8().await.unwrap());
                assert!(head.len() < 16 * 1024);
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nowned",
                )
                .await
                .unwrap();
        }
    });
    let raw = format!("socks5://{user}:{password}@{address}");
    let result = if let Some(oracle) = oracle {
        let mut child = tokio::process::Command::new(oracle)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = serde_json::json!({"environment":{"HTTP_PROXY":raw},"probe":"http://synthetic.invalid/"});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .await
            .unwrap();
        let output =
            tokio::time::timeout(std::time::Duration::from_secs(4), child.wait_with_output())
                .await
                .unwrap()
                .unwrap();
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["success"]
            .as_bool()
            .unwrap()
    } else {
        let connector = Connector::platform().unwrap().with_settings(Arc::new(
            EnvironmentProxy::from_environment(&BTreeMap::from([("HTTP_PROXY".into(), raw)])),
        ));
        let connected = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            connector.dial_transport("http://synthetic.invalid/".parse().unwrap(), Profile::Http1),
        )
        .await
        .unwrap();
        let succeeded = connected.is_ok();
        drop(connected);
        succeeded
    };
    assert_eq!(result, succeeds);
    tokio::time::timeout(std::time::Duration::from_secs(3), peer)
        .await
        .unwrap()
        .unwrap();
    result
}

#[tokio::test]
async fn http1_socks_uses_net_http_auth_even_with_empty_or_oversized_credentials() {
    for (user, password) in [
        (String::new(), "synthetic".into()),
        ("u".repeat(256), String::new()),
        ("u".into(), "p".repeat(256)),
        ("u".into(), "p".repeat(255)),
    ] {
        for method in [0, 2] {
            http1_socks_auth_case(None, &user, &password, method).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires the pinned Go proxy environment oracle"]
async fn go_http1_socks_auth_omission_is_exclusive_to_carrier() {
    let oracle = std::env::var_os("CLOUDFLARED_GO_PROXY_ORACLE").expect("pinned Go proxy oracle");
    for (user, password) in [
        (String::new(), "synthetic".into()),
        ("u".repeat(256), String::new()),
        ("u".into(), "p".repeat(256)),
        ("u".into(), "p".repeat(255)),
    ] {
        for method in [0, 2] {
            http1_socks_auth_case(Some(&oracle), &user, &password, method).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn net_http_connect_deadline_releases_only_owned_pending_tunnel() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, ready) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
            assert!(request.len() < 16 * 1024);
        }
        sent.send(()).unwrap();
        let mut remaining = Vec::new();
        socket.read_to_end(&mut remaining).await.unwrap();
        assert!(remaining.is_empty());
        socket.shutdown().await.unwrap();
    });
    let connector =
        Connector::platform()
            .unwrap()
            .with_settings(Arc::new(EnvironmentProxy::from_environment(
                &BTreeMap::from([("HTTPS_PROXY".into(), format!("http://{address}"))]),
            )));
    let task = tokio::spawn(async move {
        connector
            .dial_transport(
                "https://synthetic.invalid/".parse().unwrap(),
                Profile::Http1,
            )
            .await
    });
    ready.await.unwrap();
    tokio::time::advance(std::time::Duration::from_secs(59)).await;
    assert!(!task.is_finished());
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    let error = task.await.unwrap().err().unwrap();
    assert!(error.to_string().contains("CONNECT timed out"));
    peer.await.unwrap();
}
