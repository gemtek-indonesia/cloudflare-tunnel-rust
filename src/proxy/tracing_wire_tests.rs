use super::*;
use http_body_util::Full;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SAMPLED: &str = "11111111111111111111111111111111:2222222222222222:0:1";
const UNSAMPLED: &str = "11111111111111111111111111111111:2222222222222222:0:0";

fn controlled_child(name: &str) -> bool {
    if std::env::var("CLOUDFLARED_HTTP_TRACE_TEST_CHILD").is_ok() {
        return false;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        &format!("network::tests::http_tracing::{name}"),
        "--nocapture",
    ]);
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(|key| key.starts_with("OTEL_")) {
            command.env_remove(key);
        }
    }
    let output = command
        .env("CLOUDFLARED_HTTP_TRACE_TEST_CHILD", "1")
        .env("OTEL_TRACES_SAMPLER", "parentbased_always_on")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "wire trace probe failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    true
}
fn check(value: &str, traced: bool, remote: bool) {
    use base64::Engine;
    if !traced {
        assert_eq!(value, "origin-trace");
        return;
    }
    let decoded = ExportTraceServiceRequest::decode(
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    assert_eq!(decoded.resource_spans.len(), 2);
    let spans: Vec<_> = decoded
        .resource_spans
        .iter()
        .flat_map(|r| r.scope_spans.iter().flat_map(|s| s.spans.iter()))
        .collect();
    assert_eq!(spans[0].name, "ingress_match");
    assert_eq!(spans[1].name, "ttfb_origin");
    assert_eq!(spans[1].status.as_ref().unwrap().code, 1);
    if remote {
        assert_eq!(spans[0].parent_span_id, [0x22; 8]);
        assert_eq!(spans[0].trace_id, spans[1].trace_id);
    } else {
        assert!(spans[0].parent_span_id.is_empty());
        assert_ne!(spans[0].trace_id, spans[1].trace_id);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn http_trace_real_quic_and_h2_headers_preserve_boundary_and_collision() {
    if controlled_child("http_trace_real_quic_and_h2_headers_preserve_boundary_and_collision") {
        return;
    }
    tokio::task::LocalSet::new()
        .run_until(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let _origin = crate::runtime::AbortTask(tokio::task::spawn_local(async move {
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    tokio::task::spawn_local(async move {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(
                                hyper_util::rt::TokioIo::new(socket),
                                hyper::service::service_fn(
                                    |request: http::Request<hyper::body::Incoming>| async move {
                                        assert!(!request.headers().contains_key("cf-trace-id"));
                                        assert_eq!(
                                            request.headers()["uber-trace-id"],
                                            "unchanged-uber"
                                        );
                                        assert_eq!(
                                            request.headers()["traceparent"],
                                            "unchanged-w3c"
                                        );
                                        Ok::<_, std::io::Error>(
                                            http::Response::builder()
                                                .status(503)
                                                .header(
                                                    "cf-int-cloudflared-tracing",
                                                    "origin-trace",
                                                )
                                                .body(Full::new(Bytes::from_static(b"body")))
                                                .unwrap(),
                                        )
                                    },
                                ),
                            )
                            .await;
                    });
                }
            }));
            let mut config = crate::runtime::tests::config();
            config.ingress = vec![crate::config::IngressRule {
                service: format!("http://{address}"),
                ..Default::default()
            }];
            let proxy = Arc::new(
                crate::proxy::ProxyState::new(&config, uuid::Uuid::from_bytes([7; 16])).unwrap(),
            );
            let network = NetworkState::new(&config).unwrap();
            let mut pair = pair(network, &config, 0, DatagramVersion::V3).await;
            for (context, traced, remote) in [
                (Some(SAMPLED), true, true),
                (Some(UNSAMPLED), false, false),
                (Some("malformed"), true, false),
                (None, false, false),
            ] {
                let mut stream = pair.peer.open_bi().await.unwrap();
                let mut fields = vec![
                    ("HttpMethod".into(), "GET".into()),
                    ("HttpHost".into(), "app.example.invalid".into()),
                    ("HttpHeader:Uber-Trace-Id".into(), "unchanged-uber".into()),
                    ("HttpHeader:Traceparent".into(), "unchanged-w3c".into()),
                ];
                if let Some(context) = context {
                    fields.push(("HttpHeader:Cf-Trace-Id".into(), context.into()));
                }
                crate::protocol::metadata::write_connect_request(
                    &mut stream,
                    &crate::protocol::metadata::ConnectRequest {
                        destination: "https://app.example.invalid/path".into(),
                        connection_type: crate::protocol::metadata::ConnectionType::Http,
                        metadata: fields,
                    },
                )
                .await
                .unwrap();
                let mut incoming = pair.received.streams.recv().await.unwrap();
                assert_eq!(
                    crate::protocol::metadata::read_stream_kind(&mut incoming)
                        .await
                        .unwrap(),
                    crate::protocol::metadata::StreamKind::Data
                );
                let request = crate::protocol::metadata::read_connect_request(&mut incoming)
                    .await
                    .unwrap();
                let proxy = proxy.clone();
                let worker = tokio::task::spawn_local(async move {
                    crate::proxy::serve_quic(incoming, request, proxy)
                        .await
                        .unwrap();
                });
                let response = crate::protocol::metadata::read_connect_response(&mut stream)
                    .await
                    .unwrap();
                assert!(response.error.is_empty());
                let value = &response
                    .metadata
                    .iter()
                    .find(|(name, _)| name == "HttpHeader:Cf-Int-Cloudflared-Tracing")
                    .unwrap()
                    .1;
                check(value, traced, remote);
                let mut body = Vec::new();
                stream.read_to_end(&mut body).await.unwrap();
                assert_eq!(body, b"body");
                worker.await.unwrap();
            }
            pair.scope.cancellation().cancel();
            pair.client.close();
            pair.peer.close();
            let edge = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = edge.local_addr().unwrap();
            let _server = crate::runtime::AbortTask(tokio::task::spawn_local(async move {
                let (socket, _) = edge.accept().await.unwrap();
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(Ok((request, response))) = connection.accept().await {
                    tokio::task::spawn_local(crate::proxy::serve_h2(
                        request,
                        response,
                        proxy.clone(),
                    ));
                }
            }));
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let (mut client, connection) = h2::client::handshake(socket).await.unwrap();
            let _driver = crate::runtime::AbortTask(tokio::task::spawn_local(async move {
                let _ = connection.await;
            }));
            for (context, traced, remote) in [
                (Some(SAMPLED), true, true),
                (Some(UNSAMPLED), false, false),
                (Some("malformed"), true, false),
                (None, false, false),
            ] {
                let mut request = http::Request::builder()
                    .uri("https://app.example.invalid/path")
                    .header("uber-trace-id", "unchanged-uber")
                    .header("traceparent", "unchanged-w3c");
                if let Some(context) = context {
                    request = request.header("cf-trace-id", context);
                }
                let (response, _) = client
                    .send_request(request.body(()).unwrap(), true)
                    .unwrap();
                let mut response = response.await.unwrap();
                assert_eq!(response.status(), 503);
                check(
                    response.headers()["cf-int-cloudflared-tracing"]
                        .to_str()
                        .unwrap(),
                    traced,
                    remote,
                );
                let serialized = crate::protocol::headers::deserialize(
                    response.headers()[crate::protocol::headers::RESPONSE_HEADERS]
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                assert!(
                    !serialized
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case(b"cf-int-cloudflared-tracing"))
                );
                let mut body = Vec::new();
                while let Some(chunk) = response.body_mut().data().await {
                    let chunk = chunk.unwrap();
                    response
                        .body_mut()
                        .flow_control()
                        .release_capacity(chunk.len())
                        .unwrap();
                    body.extend_from_slice(&chunk);
                }
                assert_eq!(body, b"body");
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn http_trace_real_quic_websocket_exports_before_duplex() {
    if controlled_child("http_trace_real_quic_websocket_exports_before_duplex") {
        return;
    }
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{Message, protocol::Role},
    };
    tokio::task::LocalSet::new()
        .run_until(async {
            let (address, _origin) = crate::proxy::tag_test_origin::start().await;
            let mut config = crate::runtime::tests::config();
            config.ingress = vec![crate::config::IngressRule {
                service: format!("http://{address}"),
                ..Default::default()
            }];
            let proxy = Arc::new(
                crate::proxy::ProxyState::new(&config, uuid::Uuid::from_bytes([7; 16])).unwrap(),
            );
            let network = NetworkState::new(&config).unwrap();
            let mut pair = pair(network, &config, 0, DatagramVersion::V3).await;
            let mut stream = pair.peer.open_bi().await.unwrap();
            crate::protocol::metadata::write_connect_request(
                &mut stream,
                &crate::protocol::metadata::ConnectRequest {
                    destination: "https://app.example.invalid/path".into(),
                    connection_type: crate::protocol::metadata::ConnectionType::Websocket,
                    metadata: vec![
                        ("HttpMethod".into(), "GET".into()),
                        ("HttpHost".into(), "app.example.invalid".into()),
                        ("HttpHeader:Cf-Trace-Id".into(), SAMPLED.into()),
                        (
                            "HttpHeader:Sec-WebSocket-Key".into(),
                            base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                b"synthetic-key-12",
                            ),
                        ),
                        ("HttpHeader:Sec-WebSocket-Version".into(), "13".into()),
                    ],
                },
            )
            .await
            .unwrap();
            let mut incoming = pair.received.streams.recv().await.unwrap();
            crate::protocol::metadata::read_stream_kind(&mut incoming)
                .await
                .unwrap();
            let request = crate::protocol::metadata::read_connect_request(&mut incoming)
                .await
                .unwrap();
            let worker =
                tokio::task::spawn_local(crate::proxy::serve_quic(incoming, request, proxy));
            let response = crate::protocol::metadata::read_connect_response(&mut stream)
                .await
                .unwrap();
            assert!(
                response
                    .metadata
                    .contains(&("HttpStatus".into(), "101".into()))
            );
            check(
                &response
                    .metadata
                    .iter()
                    .find(|(key, _)| key == "HttpHeader:Cf-Int-Cloudflared-Tracing")
                    .unwrap()
                    .1,
                true,
                true,
            );
            let mut websocket = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
            websocket.next().await.unwrap().unwrap();
            websocket
                .send(Message::Binary(Bytes::from_static(b"trace-duplex")))
                .await
                .unwrap();
            assert_eq!(
                websocket.next().await.unwrap().unwrap().into_data(),
                b"trace-duplex".as_slice()
            );
            websocket.close(None).await.unwrap();
            drop(websocket);
            let _ = timeout(Duration::from_secs(1), worker).await.unwrap();
            pair.scope.cancellation().cancel();
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

fn check_stream_trace(value: &str) {
    use base64::Engine;
    let decoded = ExportTraceServiceRequest::decode(
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    assert_eq!(decoded.resource_spans.len(), 2);
    let spans: Vec<_> = decoded
        .resource_spans
        .iter()
        .flat_map(|r| r.scope_spans.iter().flat_map(|s| s.spans.iter()))
        .collect();
    assert_eq!(spans[0].name, "ingress_match");
    assert_eq!(spans[1].name, "stream-connect");
    assert_eq!(spans[1].status.as_ref().unwrap().code, 0);
    assert!(spans[1].attributes.is_empty());
    assert_eq!(spans[0].parent_span_id, [0x22; 8]);
    assert_eq!(spans[1].parent_span_id, spans[0].parent_span_id);
    assert_eq!(spans[1].trace_id, spans[0].trace_id);
    assert!(spans[0].end_time_unix_nano <= spans[1].start_time_unix_nano);
}

#[tokio::test(flavor = "current_thread")]
async fn http_trace_real_quic_public_streams_export_at_ack_and_socks_dials_later() {
    if controlled_child("http_trace_real_quic_public_streams_export_at_ack_and_socks_dials_later") {
        return;
    }
    use futures::{FutureExt, SinkExt, StreamExt};
    use tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{Message, protocol::Role},
    };
    tokio::task::LocalSet::new()
        .run_until(async {
            let base = crate::runtime::tests::config();
            let mut pair = pair(
                NetworkState::new(&base).unwrap(),
                &base,
                0,
                DatagramVersion::V3,
            )
            .await;
            for kind in ["tcp", "bastion", "socks", "dial_error", "destination_error"] {
                for sampled in [true, false] {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let mut config = base.clone();
                    let service = match kind {
                        "bastion" | "destination_error" => "bastion".into(),
                        "socks" => "socks-proxy".into(),
                        _ => format!("tcp://{address}"),
                    };
                    config.ingress = vec![crate::config::IngressRule {
                        service,
                        origin_request: crate::config::OriginRequest {
                            ip_rules: vec![
                                serde_json::json!({"prefix":"127.0.0.0/8","allow":true}),
                            ],
                            ..Default::default()
                        },
                        ..Default::default()
                    }];
                    let proxy = Arc::new(
                        crate::proxy::ProxyState::new(&config, uuid::Uuid::from_bytes([7; 16]))
                            .unwrap(),
                    );
                    let mut fields = vec![
                        ("HttpHost".into(), "app.example.invalid".into()),
                        (
                            "HttpHeader:Cf-Trace-Id".into(),
                            if sampled { SAMPLED } else { UNSAMPLED }.into(),
                        ),
                        (
                            "HttpHeader:Sec-WebSocket-Key".into(),
                            "c3ludGhldGljLWtleS0xMg==".into(),
                        ),
                    ];
                    if kind == "bastion" {
                        fields.push((
                            "HttpHeader:Cf-Access-Jump-Destination".into(),
                            address.to_string(),
                        ));
                    }
                    let mut stream = pair.peer.open_bi().await.unwrap();
                    crate::protocol::metadata::write_connect_request(
                        &mut stream,
                        &crate::protocol::metadata::ConnectRequest {
                            destination: "https://app.example.invalid/path".into(),
                            connection_type: crate::protocol::metadata::ConnectionType::Websocket,
                            metadata: fields,
                        },
                    )
                    .await
                    .unwrap();
                    let mut incoming = pair.received.streams.recv().await.unwrap();
                    crate::protocol::metadata::read_stream_kind(&mut incoming)
                        .await
                        .unwrap();
                    let request = crate::protocol::metadata::read_connect_request(&mut incoming)
                        .await
                        .unwrap();
                    let listener = if kind == "dial_error" {
                        drop(listener);
                        None
                    } else {
                        Some(listener)
                    };
                    let worker = tokio::task::spawn_local(crate::proxy::serve_quic(
                        incoming, request, proxy,
                    ));
                    let response = crate::protocol::metadata::read_connect_response(&mut stream)
                        .await
                        .unwrap();
                    let carrier = response
                        .metadata
                        .iter()
                        .find(|(key, _)| key == "HttpHeader:Cf-Int-Cloudflared-Tracing");
                    if matches!(kind, "dial_error" | "destination_error") {
                        assert!(!response.error.is_empty());
                        assert!(carrier.is_none());
                        assert!(worker.await.unwrap().is_err());
                        continue;
                    }
                    assert!(response.error.is_empty());
                    assert!(
                        response
                            .metadata
                            .contains(&("HttpStatus".into(), "101".into()))
                    );
                    if sampled {
                        check_stream_trace(&carrier.unwrap().1);
                    } else {
                        assert!(carrier.is_none());
                    }
                    let listener = listener.unwrap();
                    let mut websocket =
                        WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
                    if kind == "socks" {
                        assert!(
                            listener.accept().now_or_never().is_none(),
                            "SOCKS ACK must precede destination dialing"
                        );
                        websocket
                            .send(Message::Binary(Bytes::from_static(&[5, 1, 0])))
                            .await
                            .unwrap();
                        assert_eq!(
                            websocket.next().await.unwrap().unwrap().into_data(),
                            [5, 0].as_slice()
                        );
                        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
                        connect.extend(address.port().to_be_bytes());
                        websocket
                            .send(Message::Binary(connect.into()))
                            .await
                            .unwrap();
                        assert_eq!(websocket.next().await.unwrap().unwrap().into_data()[1], 0);
                    }
                    let (mut socket, _) = listener.accept().await.unwrap();
                    websocket
                        .send(Message::Binary(Bytes::from_static(b"ping")))
                        .await
                        .unwrap();
                    let mut bytes = [0; 4];
                    socket.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"ping");
                    socket.write_all(b"pong").await.unwrap();
                    assert_eq!(
                        websocket.next().await.unwrap().unwrap().into_data(),
                        b"pong".as_slice()
                    );
                    websocket.close(None).await.unwrap();
                    websocket.get_mut().shutdown().await.unwrap();
                    timeout(Duration::from_secs(2), worker)
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap();
                    drop(websocket);
                    drop(socket);
                }
            }
            pair.scope.cancellation().cancel();
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn http_trace_real_h2_public_tcp_ack_has_direct_carrier() {
    if controlled_child("http_trace_real_h2_public_tcp_ack_has_direct_carrier") {
        return;
    }
    tokio::task::LocalSet::new()
        .run_until(async {
            let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = crate::runtime::tests::config();
            config.ingress = vec![crate::config::IngressRule {
                service: format!("tcp://{}", origin.local_addr().unwrap()),
                ..Default::default()
            }];
            let proxy = Arc::new(
                crate::proxy::ProxyState::new(&config, uuid::Uuid::from_bytes([7; 16])).unwrap(),
            );
            let edge = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = edge.local_addr().unwrap();
            let _server = crate::runtime::AbortTask(tokio::task::spawn_local(async move {
                let (socket, _) = edge.accept().await.unwrap();
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(Ok((request, response))) = connection.accept().await {
                    tokio::task::spawn_local(crate::proxy::serve_h2(
                        request,
                        response,
                        proxy.clone(),
                    ));
                }
            }));
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let (mut client, connection) = h2::client::handshake(socket).await.unwrap();
            let _driver = crate::runtime::AbortTask(tokio::task::spawn_local(async move {
                let _ = connection.await;
            }));
            for context in [SAMPLED, UNSAMPLED] {
                let request = http::Request::builder()
                    .uri("https://app.example.invalid/path")
                    .header("cf-cloudflared-proxy-connection-upgrade", "websocket")
                    .header("cf-trace-id", context)
                    .body(())
                    .unwrap();
                let (response, mut send) = client.send_request(request, false).unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), 200);
                if context == SAMPLED {
                    check_stream_trace(
                        response.headers()["cf-int-cloudflared-tracing"]
                            .to_str()
                            .unwrap(),
                    );
                } else {
                    assert!(
                        !response
                            .headers()
                            .contains_key("cf-int-cloudflared-tracing")
                    );
                }
                let headers = crate::protocol::headers::deserialize(
                    response.headers()[crate::protocol::headers::RESPONSE_HEADERS]
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                assert!(
                    !headers
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case(b"cf-int-cloudflared-tracing"))
                );
                let (mut socket, _) = origin.accept().await.unwrap();
                send.send_reset(h2::Reason::CANCEL);
                drop(response);
                let mut bytes = [0; 1];
                assert_eq!(
                    timeout(Duration::from_secs(2), socket.read(&mut bytes))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
            }
        })
        .await;
}
