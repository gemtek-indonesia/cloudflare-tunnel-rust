use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::sync::{Arc, Mutex};
use std::{io::Write, os::unix::fs::OpenOptionsExt};

#[test]
fn native_add_host_rejects_empty_and_nul_inputs_safely() {
    let empty = String::with_capacity(8);
    for host in ["", empty.as_str(), "local\0host"] {
        let mut params = boring::x509::verify::X509VerifyParam::new().unwrap();
        assert!(params.add_host(host).is_err());
    }
    let mut params = boring::x509::verify::X509VerifyParam::new().unwrap();
    params.set_host("edge.test").unwrap();
    params.add_host("alternate.test").unwrap();
}

fn go_handshake(
    reference: &str,
    cert: &X509,
    key: &boring::pkey::PKey<boring::pkey::Private>,
) -> serde_json::Value {
    let file = std::env::temp_dir().join(format!("tls-name-{}.json", uuid::Uuid::new_v4()));
    let mut input = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)
        .unwrap();
    input.write_all(&serde_json::to_vec(&serde_json::json!({"kind":"tls-name", "pem":STANDARD.encode(cert.to_pem().unwrap()), "key":STANDARD.encode(key.private_key_to_pem_pkcs8().unwrap()), "name":reference})).unwrap()).unwrap();
    drop(input);
    let output = std::process::Command::new(
        std::env::var_os("CLOUDFLARED_GO_TRUST_ORACLE").expect("run scripts/test-interop.sh"),
    )
    .arg(&file)
    .output()
    .unwrap();
    std::fs::remove_file(file).unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

async fn handshake(
    reference: &str,
    cert: &X509,
    key: &boring::pkey::PKey<boring::pkey::Private>,
    raw: bool,
    ipv6: bool,
) -> (bool, String) {
    let sni = Arc::new(Mutex::new(String::new()));
    let captured = sni.clone();
    let mut acceptor = boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate(cert).unwrap();
    acceptor.set_private_key(key).unwrap();
    acceptor.set_servername_callback(move |ssl, _| {
        *captured.lock().unwrap() = ssl
            .servername(boring::ssl::NameType::HOST_NAME)
            .unwrap_or("")
            .to_owned();
        Ok(())
    });
    let acceptor = acceptor.build();
    let listener = tokio::net::TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = tokio_boring::accept(&acceptor, socket).await;
    });
    let mut connector = boring::ssl::SslConnector::builder(SslMethod::tls()).unwrap();
    connector.cert_store_mut().add_cert(cert).unwrap();
    let connector = connector.build();
    let result = if raw {
        let tls = EdgeTls::new(TlsPolicy::default(), Some(&cert.to_pem().unwrap())).unwrap();
        crate::transport::h2::dial_tls_with_options(
            address,
            reference,
            &tls,
            &crate::transport::EdgeDialOptions::default(),
        )
        .await
        .is_ok()
    } else {
        let ssl = ssl_for_name(&connector, reference)
            .unwrap_or_else(|error| panic!("reference={reference:?}: {error:#}"));
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio_boring::SslStreamBuilder::new(ssl, socket)
            .connect()
            .await
            .is_ok()
    };
    server.await.unwrap();
    let captured = sni.lock().unwrap().clone();
    (result, captured)
}

#[tokio::test]
#[ignore = "requires pinned Go trust oracle; run scripts/test-interop.sh"]
async fn go_tls_reference_and_sni_contract() {
    for (names, ips) in [
        (vec!["localhost"], vec!["127.0.0.1", "::1"]),
        (vec!["127.0.0.1"], vec![]),
        (vec!["127.0.0.1."], vec![]),
        (vec!["*.example.test"], vec![]),
        (vec!["*.example.test."], vec![]),
        (vec!["child.example.test"], vec![]),
    ] {
        let (cert, key) = tests::certificate_for_sans("localhost", &names, &ips);
        for reference in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "localhost..",
            "[localhost]",
            "[[localhost]]",
            "localhost]",
            "[localhost",
            "127.0.0.1",
            "[127.0.0.1]",
            "[[127.0.0.1]]",
            "::ffff:127.0.0.1",
            "[::ffff:127.0.0.1]",
            "127.0.0.1.",
            "127.0.0.1..",
            "::1",
            "[::1]",
            "[[::1]]",
            "fe80::1%lo",
            "foo.example.test",
            "foo.example.test.",
            "foo.example.test..",
            "example.test",
            ".example.test",
            "*.example.test",
        ] {
            let expected = go_handshake(reference, &cert, &key);
            let (success, sni) = handshake(reference, &cert, &key, false, false).await;
            assert_eq!(
                success,
                expected["ok"].as_bool().unwrap(),
                "reference={reference:?} names={names:?}"
            );
            assert_eq!(
                sni,
                expected["sni"].as_str().unwrap(),
                "reference={reference:?}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires pinned Go trust oracle; run scripts/test-interop.sh"]
async fn go_ipv4_mapped_certificate_san_native_gap() {
    let (cert, key) = tests::certificate_for_sans("localhost", &[], &["::ffff:127.0.0.1"]);
    for reference in ["127.0.0.1", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]"] {
        assert_eq!(go_handshake(reference, &cert, &key)["ok"], true);
        assert_eq!(
            handshake(reference, &cert, &key, false, false).await,
            (false, String::new())
        );
    }
}

#[tokio::test]
async fn tls_name_shapes_keep_reference_kind_and_reject_nul() {
    let (cert, key) =
        tests::certificate_for_sans("localhost", &["localhost"], &["127.0.0.1", "::1"]);
    for (reference, success, sni) in [
        ("localhost.", true, "localhost"),
        ("[localhost]", false, "[localhost]"),
        ("[[127.0.0.1]]", false, "[[127.0.0.1]]"),
        ("[127.0.0.1]", true, ""),
        ("[::1]", true, ""),
        ("127.0.0.1.", false, "127.0.0.1"),
    ] {
        assert_eq!(
            handshake(reference, &cert, &key, false, false).await,
            (success, sni.to_owned())
        );
    }
    let connector = boring::ssl::SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build();
    assert!(ssl_for_name(&connector, "local\0host").is_err());
    let mut ssl = boring::ssl::Ssl::new(connector.context()).unwrap();
    assert!(set_tls_name(&mut ssl, "local\0host").is_err());
}

#[tokio::test]
async fn edge_h2_reference_names_and_sni_over_ipv4_and_ipv6() {
    let (cert, key) =
        tests::certificate_for_sans("localhost", &["localhost"], &["127.0.0.1", "::1"]);
    for (name, success, sni, ipv6) in [
        ("localhost.", true, "localhost", false),
        ("[localhost]", false, "[localhost]", false),
        ("[127.0.0.1]", true, "", false),
        ("[[127.0.0.1]]", false, "[[127.0.0.1]]", false),
        ("[::1]", true, "", true),
        ("[[::1]]", false, "[[::1]]", true),
        ("127.0.0.1.", false, "127.0.0.1", false),
        ("localhost\0evil", false, "", false),
    ] {
        assert_eq!(
            handshake(name, &cert, &key, true, ipv6).await,
            (success, sni.into()),
            "{name:?}"
        );
    }
}
