use super::*;
use crate::{
    cli::Invocation,
    config::{self, Protocol},
};
use base64::Engine;
use http_body_util::Full;
use std::{collections::BTreeMap, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn state(service: &str) -> Arc<ProxyState> {
    state_with_settings(service, config::OriginRequest::default())
}

fn state_with_settings(service: &str, settings: config::OriginRequest) -> Arc<ProxyState> {
    let token = base64::engine::general_purpose::STANDARD.encode(
        br#"{"a":"synthetic","s":"c3ludGhldGlj","t":"00000000-0000-4000-8000-000000000001"}"#,
    );
    let env = BTreeMap::from([("TUNNEL_TOKEN".into(), token)]);
    let mut config = Invocation::parse(
        ["--config", "/dev/null", "tunnel", "run", "--url", service].map(str::to_owned),
        &env,
        None,
    )
    .unwrap()
    .run_config(None)
    .unwrap();
    config.origin_request = settings;
    assert_eq!(config.protocol, Protocol::Auto);
    Arc::new(ProxyState::new(&config).unwrap())
}

fn request(method: &str, websocket: bool) -> ConnectRequest {
    ConnectRequest {
        destination: "https://app.example.invalid/public/%2e%2e/admin?tag=value".into(),
        connection_type: if websocket {
            ConnectionType::Websocket
        } else {
            ConnectionType::Http
        },
        metadata: vec![
            ("HttpMethod".into(), method.into()),
            ("HttpHost".into(), "app.example.invalid".into()),
        ],
    }
}

#[tokio::test]
async fn streamed_upload_duplicate_headers_and_bodyless_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                hyper_util::rt::TokioIo::new(socket),
                hyper::service::service_fn(
                    |request: http::Request<hyper::body::Incoming>| async move {
                        assert_eq!(
                            request.uri().path_and_query().unwrap().as_str(),
                            "/public/%2e%2e/admin?tag=value"
                        );
                        assert_eq!(request.headers()[http::header::HOST], "app.example.invalid");
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        assert_eq!(body.len(), 256 * 1024);
                        let mut response = http::Response::new(Full::new(body));
                        response
                            .headers_mut()
                            .append("set-cookie", HeaderValue::from_static("a=1"));
                        response
                            .headers_mut()
                            .append("set-cookie", HeaderValue::from_static("b=2"));
                        Ok::<_, io::Error>(response)
                    },
                ),
            )
            .await
            .unwrap();
    });
    let state = state(&format!("http://{address}"));
    let (mut client, server) = tokio::io::duplex(256);
    let mut head = request("POST", false);
    head.metadata
        .push(("HttpHeader:Content-Length".into(), (256 * 1024).to_string()));
    let proxy = tokio::spawn(serve_data(server, head, state));
    tokio::time::timeout(Duration::from_secs(5), async {
        client.write_all(&vec![b'x'; 256 * 1024]).await.unwrap();
        client.shutdown().await.unwrap();
        let response = crate::protocol::metadata::read_connect_response(&mut client)
            .await
            .unwrap();
        assert_eq!(
            response
                .metadata
                .iter()
                .filter(|(name, _)| name == "HttpHeader:Set-Cookie")
                .count(),
            2
        );
        let mut body = Vec::new();
        client.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, vec![b'x'; 256 * 1024]);
        proxy.await.unwrap().unwrap();
        origin.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bodyless_request_does_not_wait_for_edge_fin_and_bad_update_is_atomic() {
    let state = state("http_status:404");
    let before = state.configuration().await;
    let bad = config::LoadedConfig::from_json(
        r#"{"ingress":[{"hostname":"bad.example.invalid","service":"http_status:200"}]}"#,
    )
    .unwrap();
    assert!(state.replace(bad).await.is_err());
    assert_eq!(
        state.configuration().await.ingress[0].service,
        before.ingress[0].service
    );
    let (mut client, server) = tokio::io::duplex(16);
    let task = tokio::spawn(serve_data(server, request("GET", false), state));
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        crate::protocol::metadata::read_connect_response(&mut client),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        response
            .metadata
            .contains(&("HttpStatus".into(), "404".into()))
    );
    client.read_to_end(&mut Vec::new()).await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn websocket_upgrade_keeps_raw_stream_and_half_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(socket.read_u8().await.unwrap());
            assert!(headers.len() < 16 * 1024);
        }
        assert!(
            String::from_utf8(headers)
                .unwrap()
                .to_ascii_lowercase()
                .contains("upgrade: websocket")
        );
        socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: synthetic\r\n\r\n").await.unwrap();
        let mut body = Vec::new();
        socket.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"raw-websocket-frame");
        socket.write_all(b"reply-after-half-close").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let state = state(&format!("http://{address}"));
    let (mut client, server) = tokio::io::duplex(32);
    let proxy = tokio::spawn(serve_data(server, request("GET", true), state));
    tokio::time::timeout(Duration::from_secs(5), async {
        let response = crate::protocol::metadata::read_connect_response(&mut client)
            .await
            .unwrap();
        assert!(
            response
                .metadata
                .contains(&("HttpStatus".into(), "101".into()))
        );
        client.write_all(b"raw-websocket-frame").await.unwrap();
        client.shutdown().await.unwrap();
        let mut body = Vec::new();
        client.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"reply-after-half-close");
        proxy.await.unwrap().unwrap();
        origin.await.unwrap();
    })
    .await
    .unwrap();
}

async fn one_request(state: Arc<ProxyState>) -> (ConnectResponse, Vec<u8>) {
    let (mut client, server) = tokio::io::duplex(128);
    let task = tokio::spawn(serve_data(server, request("GET", false), state));
    let response = crate::protocol::metadata::read_connect_response(&mut client)
        .await
        .unwrap();
    let mut body = Vec::new();
    client.read_to_end(&mut body).await.unwrap();
    let result = task.await.unwrap();
    assert_eq!(result.is_ok(), response.error.is_empty());
    (response, body)
}

#[tokio::test]
async fn keepalive_pool_reuses_connection_and_obeys_idle_timeout() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    let server = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(socket),
                        hyper::service::service_fn(|_| async {
                            Ok::<_, io::Error>(http::Response::new(Full::new(Bytes::from_static(
                                b"pooled",
                            ))))
                        }),
                    )
                    .await;
            });
        }
    });
    let state = state_with_settings(
        &format!("http://{address}"),
        config::OriginRequest {
            keep_alive_connections: Some(1),
            keep_alive_timeout: Some(config::DurationValue(Duration::from_millis(50))),
            ..Default::default()
        },
    );
    assert_eq!(one_request(state.clone()).await.1, b"pooled");
    assert_eq!(one_request(state.clone()).await.1, b"pooled");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(one_request(state).await.1, b"pooled");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn verified_tls_custom_ca_sni_host_override_and_http2_origin() {
    let (cert, key) = crate::crypto::tests::certificate();
    let path = std::env::temp_dir().join(format!("origin-ca-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, cert.to_pem().unwrap()).unwrap();
    let mut tls =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls()).unwrap();
    tls.set_certificate(&cert).unwrap();
    tls.set_private_key(&key).unwrap();
    tls.set_alpn_select_callback(|_, protocols| {
        boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", protocols)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let tls = tls.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let socket = tokio_boring::accept(&tls, socket).await.unwrap();
        assert_eq!(
            socket.ssl().servername(boring::ssl::NameType::HOST_NAME),
            Some("edge.test")
        );
        assert_eq!(
            socket.ssl().selected_alpn_protocol(),
            Some(b"h2".as_slice())
        );
        let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(
                hyper_util::rt::TokioIo::new(socket),
                hyper::service::service_fn(
                    |request: http::Request<hyper::body::Incoming>| async move {
                        assert_eq!(
                            request.headers()[http::header::HOST],
                            "internal.example.invalid"
                        );
                        assert_eq!(request.headers()["x-forwarded-host"], "app.example.invalid");
                        Ok::<_, io::Error>(http::Response::new(Full::new(Bytes::from_static(
                            b"verified-h2-origin",
                        ))))
                    },
                ),
            )
            .await;
    });
    let state = state_with_settings(
        &format!("https://{address}"),
        config::OriginRequest {
            ca_pool: Some(path.to_string_lossy().into()),
            origin_server_name: Some("edge.test".into()),
            http_host_header: Some("internal.example.invalid".into()),
            http2_origin: Some(true),
            ..Default::default()
        },
    );
    let (response, body) = tokio::time::timeout(Duration::from_secs(5), one_request(state))
        .await
        .unwrap();
    assert!(response.error.is_empty());
    assert_eq!(body, b"verified-h2-origin");
    std::fs::remove_file(path).unwrap();
    server.abort();
}

#[tokio::test]
async fn h2_edge_preserves_serialized_response_headers() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (socket, _) = origin.accept().await.unwrap();
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(
                hyper_util::rt::TokioIo::new(socket),
                hyper::service::service_fn(
                    |request: http::Request<hyper::body::Incoming>| async move {
                        assert_eq!(request.headers()["x-synthetic"], "restored");
                        let mut response =
                            http::Response::new(Full::new(Bytes::from_static(b"h2-edge")));
                        response
                            .headers_mut()
                            .append("set-cookie", HeaderValue::from_static("a=1"));
                        response
                            .headers_mut()
                            .append("set-cookie", HeaderValue::from_static("b=2"));
                        Ok::<_, io::Error>(response)
                    },
                ),
            )
            .await;
    });
    let state = state(&format!("http://{origin_address}"));
    let edge = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = edge.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = edge.accept().await.unwrap();
        let mut connection = h2::server::handshake(socket).await.unwrap();
        while let Some(Ok((request, response))) = connection.accept().await {
            tokio::spawn(serve_h2(request, response, state.clone()));
        }
    });
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut client, connection) = h2::client::handshake(socket).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .uri("https://app.example.invalid/")
        .header(
            headers::REQUEST_HEADERS,
            headers::serialize(&[(b"X-Synthetic".to_vec(), b"restored".to_vec())]),
        )
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let mut response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()[headers::RESPONSE_META],
        "{\"src\":\"origin\"}"
    );
    let decoded = headers::deserialize(
        response.headers()[headers::RESPONSE_HEADERS]
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        decoded
            .iter()
            .filter(|(name, _)| name == b"Set-Cookie")
            .count(),
        2
    );
    assert_eq!(
        response.body_mut().data().await.unwrap().unwrap(),
        "h2-edge"
    );
    driver.abort();
    server.abort();
    origin_task.abort();
}
