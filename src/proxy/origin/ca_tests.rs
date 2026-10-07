use super::*;
use std::fs;

#[tokio::test]
async fn origin_reference_names_sni_and_explicit_insecure_policy() {
    let (cert, key) = crate::crypto::tests::certificate_for_sans(
        "localhost",
        &["localhost"],
        &["127.0.0.1", "::1"],
    );
    let dir = std::env::temp_dir().join(format!("origin-name-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let ca = dir.join("root.pem");
    fs::write(&ca, cert.to_pem().unwrap()).unwrap();
    let context = crate::observability::Context::quiet().unwrap();
    for (name, insecure, succeeds, expected_sni, ipv6) in [
        ("localhost.", false, true, "localhost", false),
        ("[localhost]", false, false, "[localhost]", false),
        ("[127.0.0.1]", false, true, "", false),
        ("[[127.0.0.1]]", false, false, "[[127.0.0.1]]", false),
        ("[::1]", false, true, "", true),
        ("127.0.0.1.", false, false, "127.0.0.1", false),
        ("wrong.test", true, true, "wrong.test", false),
        ("localhost\0evil", true, false, "", false),
    ] {
        let sni = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let captured = sni.clone();
        let mut acceptor =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_servername_callback(move |ssl, _| {
            *captured.lock().unwrap() = ssl
                .servername(boring::ssl::NameType::HOST_NAME)
                .unwrap_or("")
                .into();
            Ok(())
        });
        let acceptor = acceptor.build();
        let listener = tokio::net::TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_boring::accept(&acceptor, socket).await.is_ok()
        });
        let url = url::Url::parse(&format!("https://{address}/")).unwrap();
        let settings = OriginRequest {
            ca_pool: Some(ca.to_str().unwrap().into()),
            origin_server_name: Some(name.into()),
            no_tls_verify: Some(insecure),
            ..Default::default()
        };
        let mut connector =
            OriginConnector::new(Service::Http(url.clone()), settings, &context).unwrap();
        let client = connector.call(url.as_str().parse().unwrap()).await;
        assert_eq!(
            client.is_ok(),
            succeeds,
            "name={name:?} insecure={insecure}"
        );
        assert_eq!(server.await.unwrap(), succeeds);
        assert_eq!(sni.lock().unwrap().as_str(), expected_sni);
    }
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn origin_ca_env_child() {
    let Ok(mode) = std::env::var("CLOUDFLARED_ORIGIN_CA_MODE") else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os("CLOUDFLARED_ORIGIN_CA_DIR").unwrap());
    let native = dir.join("native.pem");
    let custom = dir.join("custom.pem");
    let (native_cert, native_key) =
        crate::crypto::tests::certificate_for_names("native-root.test", &["localhost"]);
    let (custom_cert, custom_key) =
        crate::crypto::tests::certificate_for_names("custom-root.test", &["localhost"]);
    if mode == "failure" {
        fs::create_dir(&native).unwrap()
    } else {
        fs::write(&native, native_cert.to_pem().unwrap()).unwrap()
    }
    let invalid = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    fs::write(
        &custom,
        [invalid, custom_cert.to_pem().unwrap().as_slice()].concat(),
    )
    .unwrap();
    let context = crate::observability::Context::quiet().unwrap();
    let mut logs = context
        .logger
        .subscribe(
            "synthetic-origin-ca",
            crate::observability::logging::Filters::default(),
        )
        .unwrap();
    let roots = origin_roots(Some(&custom), &context).unwrap();
    if mode == "failure" {
        let log = logs.receiver.try_recv().unwrap();
        assert_eq!(log.level, crate::observability::logging::Level::Error);
        assert_eq!(log.message, "error obtaining the system certificates");
    } else {
        assert!(logs.receiver.try_recv().is_err());
    }
    let der: Vec<_> = roots.iter().map(|cert| cert.to_der().unwrap()).collect();
    assert!(der.contains(&custom_cert.to_der().unwrap()));
    assert_eq!(
        der.contains(&native_cert.to_der().unwrap()),
        mode != "failure"
    );
    for cert in X509::stack_from_pem(include_bytes!("../../crypto/cloudflare-roots.pem")).unwrap() {
        assert!(der.contains(&cert.to_der().unwrap()))
    }
    for cert in X509::stack_from_pem(include_bytes!("../../crypto/hello-root.pem")).unwrap() {
        assert!(der.contains(&cert.to_der().unwrap()))
    }
    for (cert, key, succeeds) in [
        (native_cert, native_key, mode != "failure"),
        (custom_cert, custom_key, true),
    ] {
        let mut acceptor =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        acceptor.set_private_key(&key).unwrap();
        let acceptor = acceptor.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_boring::accept(&acceptor, socket).await.is_ok()
        });
        let url = url::Url::parse(&format!("https://localhost:{}/", address.port())).unwrap();
        let settings = OriginRequest {
            ca_pool: Some(custom.to_str().unwrap().to_owned()),
            ..Default::default()
        };
        let mut connector =
            OriginConnector::new(Service::Http(url.clone()), settings, &context).unwrap();
        let client = connector.call(url.as_str().parse().unwrap()).await;
        assert_eq!(client.is_ok(), succeeds);
        assert_eq!(server.await.unwrap(), succeeds);
    }
    let missing = dir.join("absent.pem");
    assert!(
        Origin::new(
            "http://localhost:9",
            OriginRequest {
                ca_pool: Some(missing.to_str().unwrap().into()),
                ..Default::default()
            },
            &context
        )
        .is_err()
    );
    fs::write(&custom, b"malformed custom CA input").unwrap();
    assert!(
        Origin::new(
            "http://localhost:9",
            OriginRequest {
                ca_pool: Some(custom.to_str().unwrap().into()),
                ..Default::default()
            },
            &context
        )
        .is_ok()
    );
    assert!(
        Origin::new(
            "http://localhost:9",
            OriginRequest {
                ca_pool: Some(String::new()),
                ..Default::default()
            },
            &context
        )
        .is_ok()
    );
    let mut saw_custom_warning = false;
    while let Ok(log) = logs.receiver.try_recv() {
        saw_custom_warning |= log.level == crate::observability::logging::Level::Info
            && log.message
                == "could not append the provided origin CA to the cloudflared certificate pool";
    }
    assert!(saw_custom_warning);
}

#[tokio::test]
async fn origin_ca_union_and_native_failure_fallback_are_verified() {
    for mode in ["success", "failure"] {
        let dir = std::env::temp_dir().join(format!("origin-ca-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let result = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "proxy::origin::ca_tests::origin_ca_env_child",
                "--nocapture",
            ])
            .env("CLOUDFLARED_ORIGIN_CA_MODE", mode)
            .env("CLOUDFLARED_ORIGIN_CA_DIR", &dir)
            .env("SSL_CERT_FILE", dir.join("native.pem"))
            .env("SSL_CERT_DIR", dir.join("absent"))
            .output()
            .await
            .unwrap();
        assert!(
            result.status.success(),
            "origin child failed: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
