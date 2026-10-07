use super::*;
use std::{fs, os::unix::fs::symlink};

#[test]
fn native_pool_keeps_partial_success_and_ignores_absent_or_malformed_inputs() {
    let dir = std::env::temp_dir().join(format!("native-ca-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let cert = tests::certificate().0;
    let good = dir.join("root.pem");
    fs::write(&good, cert.to_pem().unwrap()).unwrap();
    let missing = dir.join("absent");
    assert!(
        !linux_roots(std::slice::from_ref(&dir), std::slice::from_ref(&dir))
            .unwrap()
            .is_empty()
    );
    assert!(linux_roots(std::slice::from_ref(&dir), std::slice::from_ref(&missing)).is_err());
    assert!(
        linux_roots(
            std::slice::from_ref(&missing),
            std::slice::from_ref(&missing)
        )
        .unwrap()
        .is_empty()
    );
    let bad = dir.join("bad.pem");
    fs::write(&bad, b"invalid certificate input").unwrap();
    assert!(
        linux_roots(std::slice::from_ref(&bad), std::slice::from_ref(&missing))
            .unwrap()
            .is_empty()
    );
    assert!(
        linux_roots(&[bad, good], std::slice::from_ref(&missing))
            .unwrap()
            .is_empty()
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn native_pool_skips_same_directory_symlinks_and_entry_read_errors() {
    let dir = std::env::temp_dir().join(format!("native-links-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let cert = tests::certificate().0;
    let good = dir.join("root.pem");
    fs::write(&good, cert.to_pem().unwrap()).unwrap();
    symlink("root.pem", dir.join("same-dir.pem")).unwrap();
    fs::create_dir(dir.join("unreadable-as-file")).unwrap();
    let certs = linux_roots(&[], std::slice::from_ref(&dir)).unwrap();
    assert_eq!(certs.len(), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn certificate_framing_recovers_valid_blocks_and_excludes_headers() {
    let cert = tests::certificate().0;
    let good = cert.to_pem().unwrap();
    let invalid = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    assert_eq!(
        pem_certificates(&[good.as_slice(), invalid].concat()).len(),
        1
    );
    assert_eq!(
        pem_certificates(&[invalid, good.as_slice()].concat()).len(),
        1
    );
    let text = String::from_utf8(good.clone()).unwrap();
    for input in [
        text.replace("-----END CERTIFICATE-----", "-----END CERTIFICATE-----junk"),
        text.replace(
            "-----BEGIN CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n",
        ),
        text.replace("CERTIFICATE", "PUBLIC KEY"),
        text.replace("-----END CERTIFICATE-----\n", ""),
    ] {
        assert!(pem_certificates(input.as_bytes()).is_empty());
    }
    let nested = [
        b"-----BEGIN CERTIFICATE-----\ninvalid\n".as_slice(),
        good.as_slice(),
    ]
    .concat();
    assert_eq!(pem_certificates(&nested).len(), 1);
    assert_eq!(
        pem_certificates(text.replace('\n', "\r\n").as_bytes()).len(),
        1
    );
    assert!(EdgeTls::new(TlsPolicy::default(), Some(invalid)).is_err());
    assert!(
        EdgeTls::new(
            TlsPolicy::default(),
            Some(&[invalid, good.as_slice()].concat())
        )
        .is_ok()
    );
}

#[tokio::test]
async fn edge_tls_rejects_common_name_only_and_keeps_valid_sans() {
    for (names, host, succeeds) in [
        (vec![], "edge.test", false),
        (vec!["edge.test"], "edge.test", true),
        (vec!["other.test"], "edge.test", false),
        (vec!["*.edge.test"], "foo.edge.test", true),
        (vec!["f*.edge.test"], "foo.edge.test", false),
    ] {
        let (cert, key) = tests::certificate_for_names("edge.test", &names);
        let mut acceptor =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                .unwrap();
        acceptor.set_certificate(&cert).unwrap();
        acceptor.set_private_key(&key).unwrap();
        let acceptor = acceptor.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_boring::accept(&acceptor, socket).await.is_ok()
        });
        let tls = EdgeTls::new(TlsPolicy::default(), Some(&cert.to_pem().unwrap())).unwrap();
        let client = crate::transport::h2::dial_tls_with_options(
            addr,
            host,
            &tls,
            &crate::transport::EdgeDialOptions::default(),
        )
        .await;
        assert_eq!(client.is_ok(), succeeds, "{names:?} {host}");
        assert_eq!(server.await.unwrap(), succeeds);
    }
}

#[tokio::test]
async fn platform_connector_env_child() {
    let Ok(url) = std::env::var("CLOUDFLARED_PLATFORM_TEST_URL") else {
        return;
    };
    let succeeds = std::env::var("CLOUDFLARED_PLATFORM_TEST_SUCCESS").unwrap() == "true";
    let connector = crate::administration::verified_connector().unwrap();
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build::<_, http_body_util::Full<bytes::Bytes>>(connector);
    let request = http::Request::get(url)
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(3), client.request(request))
        .await
        .unwrap();
    assert_eq!(response.is_ok(), succeeds);
    if let Ok(response) = response {
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap();
        assert_eq!(body.to_bytes(), bytes::Bytes::from_static(b"ok"));
    }
}

#[tokio::test]
async fn platform_http_is_lazy_and_verified_https_requires_san_and_roots() {
    for (secure, native_error, names, succeeds) in [
        (false, true, vec![], true),
        (true, true, vec!["localhost"], false),
        (true, false, vec![], false),
        (true, false, vec!["localhost"], true),
    ] {
        let dir = std::env::temp_dir().join(format!("platform-ca-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("root.pem");
        let (cert, key) = tests::certificate_for_names("localhost", &names);
        fs::write(&path, cert.to_pem().unwrap()).unwrap();
        let mut acceptor =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                .unwrap();
        acceptor.set_certificate(&cert).unwrap();
        acceptor.set_private_key(&key).unwrap();
        let acceptor = acceptor.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let service =
                hyper::service::service_fn(|_: http::Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(http::Response::new(
                        http_body_util::Full::new(bytes::Bytes::from_static(b"ok")),
                    ))
                });
            if secure {
                if let Ok(stream) = tokio_boring::accept(&acceptor, socket).await {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await
                        .unwrap();
                }
            } else {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .await
                    .unwrap();
            }
        });
        let result = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crypto::trust_tests::platform_connector_env_child",
                "--nocapture",
            ])
            .env("SSL_CERT_FILE", if native_error { &dir } else { &path })
            .env("SSL_CERT_DIR", dir.join("absent"))
            .env(
                "CLOUDFLARED_PLATFORM_TEST_URL",
                format!(
                    "{}://localhost:{}/",
                    if secure { "https" } else { "http" },
                    addr.port()
                ),
            )
            .env("CLOUDFLARED_PLATFORM_TEST_SUCCESS", succeeds.to_string())
            .output()
            .await
            .unwrap();
        assert!(
            result.status.success(),
            "platform child failed: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn native_cache_env_child() {
    let Ok(mode) = std::env::var("CLOUDFLARED_CA_CACHE_MODE") else {
        return;
    };
    let file = PathBuf::from(std::env::var_os("SSL_CERT_FILE").unwrap());
    let (cert, key) = tests::certificate();
    let pem = cert.to_pem().unwrap();
    match mode.as_str() {
        "failure" => fs::create_dir(&file).unwrap(),
        "empty" => fs::write(&file, b"invalid certificate input").unwrap(),
        "success" => fs::write(&file, &pem).unwrap(),
        _ => panic!("unknown synthetic cache mode"),
    }
    let initial = native_roots();
    assert_eq!(initial.is_ok(), mode != "failure");
    if mode == "failure" {
        fs::remove_dir(&file).unwrap();
    }
    fs::write(
        &file,
        if mode == "success" {
            b"changed certificate input".as_slice()
        } else {
            pem.as_slice()
        },
    )
    .unwrap();
    let explicit = native_roots().unwrap();
    assert_eq!(explicit.len(), usize::from(mode != "empty"));
    let mut acceptor =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.set_private_key(&key).unwrap();
    let acceptor = acceptor.build();
    let connector = crate::administration::verified_tls_connector()
        .unwrap()
        .build();
    let mut ssl = connector
        .configure()
        .unwrap()
        .into_ssl("edge.test")
        .unwrap();
    configure_platform_trust(&mut ssl).unwrap();
    let (client_io, server_io) = tokio::io::duplex(8192);
    let (client, server) = tokio::join!(
        tokio_boring::SslStreamBuilder::new(ssl, client_io).connect(),
        tokio_boring::accept(&acceptor, server_io)
    );
    assert_eq!(client.is_ok(), mode == "success");
    assert_eq!(server.is_ok(), mode == "success");
}

#[tokio::test]
async fn native_cache_success_empty_and_failure_match_process_source_policy() {
    for mode in ["success", "empty", "failure"] {
        let dir = std::env::temp_dir().join(format!("ca-cache-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let result = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crypto::trust_tests::native_cache_env_child",
                "--nocapture",
            ])
            .env("SSL_CERT_FILE", dir.join("roots.pem"))
            .env("SSL_CERT_DIR", dir.join("missing"))
            .env("CLOUDFLARED_CA_CACHE_MODE", mode)
            .output()
            .await
            .unwrap();
        assert!(
            result.status.success(),
            "cache child failed: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
