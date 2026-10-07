use super::*;
use std::{collections::BTreeMap, sync::Arc};

#[tokio::test]
async fn raw_dotted_numeric_origin_requires_dns_san_not_ip_san() {
    let directory =
        std::env::temp_dir().join(format!("origin-dotted-name-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let context = crate::observability::Context::quiet().unwrap();
    for dns_identity in [false, true] {
        let (certificate, key) = if dns_identity {
            crate::crypto::tests::certificate_for_sans("synthetic-root", &["127.0.0.1."], &[])
        } else {
            crate::crypto::tests::certificate_for_sans("synthetic-root", &[], &["127.0.0.1"])
        };
        let ca = directory.join("root.pem");
        std::fs::write(&ca, certificate.to_pem().unwrap()).unwrap();
        let mut builder =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder.set_certificate(&certificate).unwrap();
        builder.set_private_key(&key).unwrap();
        let socket_path = directory.join(if dns_identity { "dns.sock" } else { "ip.sock" });
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let raw_service = "https://127.0.0.1.:443/";
        let acceptor = builder.build();
        let server = tokio::spawn(async move {
            let (socket, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
            tokio_boring::accept(&acceptor, socket).await.is_ok()
        });
        let mut connector = OriginConnector::new(
            Service::Http(url::Url::parse(raw_service).unwrap()),
            OriginRequest {
                ca_pool: Some(ca.to_str().unwrap().into()),
                ..Default::default()
            },
            Some(raw_service.parse().unwrap()),
            &context,
        )
        .unwrap();
        connector.routed = connector
            .routed
            .with_unix(socket_path, Some(Duration::from_secs(3)))
            .with_settings(Arc::new(
                crate::proxy_environment::EnvironmentProxy::from_environment(&BTreeMap::new()),
            ));
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            connector.call(raw_service.parse().unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(
            result.is_ok(),
            dns_identity,
            "dotted numeric origin DNS identity"
        );
        assert_eq!(server.await.unwrap(), dns_identity);
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn origin_https_proxy_matches_first_hop_host_and_preserves_target_policy() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (certificate, key) = crate::crypto::tests::certificate_for_sans(
        "synthetic-root",
        &["request.invalid", "physical.invalid", "configured.invalid"],
        &["127.0.0.1"],
    );
    let directory =
        std::env::temp_dir().join(format!("origin-proxy-name-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let ca = directory.join("root.pem");
    std::fs::write(&ca, certificate.to_pem().unwrap()).unwrap();
    let context = crate::observability::Context::quiet().unwrap();
    for (match_sni, configured, first_name, target_name) in [
        (false, false, "", "physical.invalid"),
        (false, true, "configured.invalid", "configured.invalid"),
        (true, false, "request.invalid", "physical.invalid"),
        (true, true, "request.invalid", "configured.invalid"),
    ] {
        let mut builder =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder.set_certificate(&certificate).unwrap();
        builder.set_private_key(&key).unwrap();
        let offered = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = offered.clone();
        builder.set_select_certificate_callback(move |hello| {
            capture.lock().unwrap().push(
                hello
                    .get_extension(
                        boring::ssl::ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                    )
                    .map(<[u8]>::to_vec),
            );
            Ok(())
        });
        builder.set_alpn_select_callback(|_, protocols| {
            boring::ssl::select_next_proto(b"\x08http/1.1", protocols)
                .ok_or(boring::ssl::AlpnError::NOACK)
        });
        let acceptor = builder.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut outer = tokio_boring::accept(&acceptor, socket).await.unwrap();
            assert_eq!(
                outer
                    .ssl()
                    .servername(boring::ssl::NameType::HOST_NAME)
                    .unwrap_or(""),
                first_name
            );
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(outer.read_u8().await.unwrap());
                assert!(request.len() < 16 * 1024);
            }
            assert!(request.starts_with(b"CONNECT physical.invalid:443 HTTP/1.1\r\n"));
            outer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            let target = tokio_boring::accept(&acceptor, outer).await.unwrap();
            assert_eq!(
                target
                    .ssl()
                    .servername(boring::ssl::NameType::HOST_NAME)
                    .unwrap_or(""),
                target_name
            );
        });
        let physical = "https://physical.invalid:443/";
        let mut connector = OriginConnector::new(
            Service::Http(url::Url::parse(physical).unwrap()),
            OriginRequest {
                ca_pool: Some(ca.to_str().unwrap().into()),
                match_sni_to_host: Some(match_sni),
                http2_origin: Some(true),
                origin_server_name: configured.then(|| "configured.invalid".into()),
                ..Default::default()
            },
            Some(physical.parse().unwrap()),
            &context,
        )
        .unwrap();
        connector.routed = connector.routed.with_settings(Arc::new(
            crate::proxy_environment::EnvironmentProxy::from_environment(&BTreeMap::from([(
                "HTTPS_PROXY".into(),
                format!("https://{address}"),
            )])),
        ));
        tokio::time::timeout(Duration::from_secs(3), async {
            let connection = connector
                .call("https://request.invalid/".parse().unwrap())
                .await
                .unwrap();
            drop(connection);
            server.await.unwrap();
            let offered = offered.lock().unwrap();
            assert_eq!(offered.len(), 2);
            assert_eq!(offered[0].is_none(), match_sni);
            assert!(offered[1].is_some());
        })
        .await
        .unwrap();
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn direct_match_sni_keeps_source_http1_even_with_http2_origin() {
    let (certificate, key) = crate::crypto::tests::certificate_for_sans(
        "synthetic-root",
        &["request.invalid"],
        &["127.0.0.1"],
    );
    let directory =
        std::env::temp_dir().join(format!("origin-match-alpn-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let ca = directory.join("root.pem");
    std::fs::write(&ca, certificate.to_pem().unwrap()).unwrap();
    let context = crate::observability::Context::quiet().unwrap();
    for match_sni in [false, true] {
        let mut builder =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder.set_certificate(&certificate).unwrap();
        builder.set_private_key(&key).unwrap();
        builder.set_select_certificate_callback(move |hello| {
            let offered = hello
                .get_extension(boring::ssl::ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
            assert_eq!(offered.is_some(), !match_sni);
            Ok(())
        });
        builder.set_alpn_select_callback(|_, offered| {
            boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", offered)
                .ok_or(boring::ssl::AlpnError::NOACK)
        });
        let acceptor = builder.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let physical = format!("https://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let stream = tokio_boring::accept(&acceptor, socket).await.unwrap();
            let expected = if match_sni {
                None
            } else {
                Some(b"h2".as_slice())
            };
            assert_eq!(stream.ssl().selected_alpn_protocol(), expected);
        });
        let mut connector = OriginConnector::new(
            Service::Http(url::Url::parse(&physical).unwrap()),
            OriginRequest {
                ca_pool: Some(ca.to_str().unwrap().into()),
                http2_origin: Some(true),
                match_sni_to_host: Some(match_sni),
                ..Default::default()
            },
            Some(physical.parse().unwrap()),
            &context,
        )
        .unwrap();
        connector.routed = connector.routed.with_settings(Arc::new(
            crate::proxy_environment::EnvironmentProxy::from_environment(&BTreeMap::new()),
        ));
        tokio::time::timeout(Duration::from_secs(3), async {
            let connection = connector
                .call("https://request.invalid/".parse().unwrap())
                .await
                .unwrap();
            assert_eq!(connection.inner().h2, !match_sni);
            drop(connection);
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn custom_first_hop_skips_tls_deadline_and_retains_owned_cancellation() {
    use tokio::io::AsyncReadExt;
    let context = crate::observability::Context::quiet().unwrap();
    for (match_sni, proxy) in [(false, false), (true, false), (false, true), (true, true)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let physical = if proxy {
            "https://physical.invalid/".to_owned()
        } else {
            format!("https://{endpoint}/")
        };
        let (sent, ready) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.read_u8().await.unwrap();
            sent.send(()).unwrap();
            let mut bytes = Vec::new();
            socket.take(65536).read_to_end(&mut bytes).await.unwrap();
        });
        let mut connector = OriginConnector::new(
            Service::Http(url::Url::parse(&physical).unwrap()),
            OriginRequest {
                match_sni_to_host: Some(match_sni),
                tls_timeout: Some(crate::config::DurationValue(Duration::from_millis(20))),
                ..Default::default()
            },
            Some(physical.parse().unwrap()),
            &context,
        )
        .unwrap();
        connector.routed = connector.routed.with_settings(Arc::new(
            crate::proxy_environment::EnvironmentProxy::from_environment(&if proxy {
                BTreeMap::from([("HTTPS_PROXY".into(), format!("https://{endpoint}"))])
            } else {
                BTreeMap::new()
            }),
        ));
        let mut task = tokio::spawn(async move {
            connector
                .call("https://request.invalid/".parse().unwrap())
                .await
        });
        ready.await.unwrap();
        if match_sni {
            assert!(
                tokio::time::timeout(Duration::from_millis(60), &mut task)
                    .await
                    .is_err()
            );
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(60), &mut task)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
        }
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }
}
