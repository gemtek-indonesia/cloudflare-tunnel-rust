use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::Role},
};

struct TagOracle(mpsc::UnboundedSender<Uuid>);
impl wire::registration_server::Server for TagOracle {
    async fn register_connection(
        self: Rc<Self>,
        params: wire::registration_server::RegisterConnectionParams,
        mut results: wire::registration_server::RegisterConnectionResults,
    ) -> capnp::Result<()> {
        let params = params.get()?;
        assert_eq!(params.get_conn_index(), 0);
        let id = Uuid::from_slice(params.get_options()?.get_client()?.get_client_id()?).unwrap();
        self.0.send(id).unwrap();
        let mut details = results
            .get()
            .init_result()
            .init_result()
            .init_connection_details();
        details.set_uuid(&[3; 16]);
        details.set_location_name("TST");
        details.set_tunnel_is_remotely_managed(true);
        Ok(())
    }
    async fn unregister_connection(
        self: Rc<Self>,
        _: wire::registration_server::UnregisterConnectionParams,
        _: wire::registration_server::UnregisterConnectionResults,
    ) -> capnp::Result<()> {
        Ok(())
    }
    async fn update_local_configuration(
        self: Rc<Self>,
        _: wire::registration_server::UpdateLocalConfigurationParams,
        _: wire::registration_server::UpdateLocalConfigurationResults,
    ) -> capnp::Result<()> {
        Ok(())
    }
}

fn registration_peer<S: AsyncRead + AsyncWrite + Unpin + 'static>(
    stream: S,
    observed: mpsc::UnboundedSender<Uuid>,
) -> AbortTask<capnp::Result<()>> {
    let (read, write) = tokio::io::split(stream);
    let network = capnp_rpc::twoparty::VatNetwork::new(
        read.compat(),
        write.compat_write(),
        capnp_rpc::rpc_twoparty_capnp::Side::Server,
        crate::protocol::reader_options(),
    );
    let oracle: wire::registration_server::Client = capnp_rpc::new_client(TagOracle(observed));
    AbortTask(tokio::task::spawn_local(capnp_rpc::RpcSystem::new(
        Box::new(network),
        Some(oracle.client),
    )))
}

fn expected(id: Uuid) -> serde_json::Value {
    serde_json::json!({"id":["incoming-id","user-id",id.to_string()],"x":["incoming","one","two"]})
}
async fn websocket_tags<S: AsyncRead + AsyncWrite + Unpin>(stream: S, id: Uuid) {
    let mut websocket = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
    let first = websocket.next().await.unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&first.into_data()).unwrap(),
        expected(id)
    );
    websocket
        .send(Message::Binary(Bytes::from_static(b"tag-binding-echo")))
        .await
        .unwrap();
    assert_eq!(
        websocket.next().await.unwrap().unwrap().into_data(),
        b"tag-binding-echo"[..]
    );
    websocket.close(None).await.unwrap();
}

fn headers(websocket: bool) -> Vec<(String, String)> {
    let mut headers = vec![
        ("HttpMethod".into(), "GET".into()),
        ("HttpHost".into(), "synthetic.invalid".into()),
        ("HttpHeader:cf-warp-tag-id".into(), "incoming-id".into()),
        ("HttpHeader:cf-warp-tag-x".into(), "incoming".into()),
    ];
    if websocket {
        headers.extend([
            ("HttpHeader:Connection".into(), "Upgrade".into()),
            ("HttpHeader:Upgrade".into(), "websocket".into()),
            ("HttpHeader:Sec-WebSocket-Version".into(), "13".into()),
            (
                "HttpHeader:Sec-WebSocket-Key".into(),
                STANDARD.encode(b"synthetic-key-12"),
            ),
        ]);
    }
    headers
}

async fn quic_tags(conn: &transport::quic::QuicConnection, id: Uuid) {
    for websocket in [false, true] {
        let mut stream = conn.open_bi().await.unwrap();
        metadata::write_connect_request(
            &mut stream,
            &metadata::ConnectRequest {
                destination: format!(
                    "https://synthetic.invalid/{}",
                    if websocket { "ws" } else { "http" }
                ),
                connection_type: if websocket {
                    metadata::ConnectionType::Websocket
                } else {
                    metadata::ConnectionType::Http
                },
                metadata: headers(websocket),
            },
        )
        .await
        .unwrap();
        if !websocket {
            stream.shutdown().await.unwrap();
        }
        let response = metadata::read_connect_response(&mut stream).await.unwrap();
        assert!(response.error.is_empty());
        assert!(
            response
                .metadata
                .iter()
                .any(|(key, value)| key == "HttpStatus"
                    && value == if websocket { "101" } else { "200" })
        );
        if websocket {
            websocket_tags(stream, id).await;
        } else {
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                expected(id)
            );
        }
    }
}
async fn h2_tags(client: &mut h2::client::SendRequest<Bytes>, id: Uuid) {
    for websocket in [false, true] {
        let mut request = http::Request::builder()
            .uri(format!(
                "https://synthetic.invalid/{}",
                if websocket { "ws" } else { "http" }
            ))
            .header("cf-warp-tag-id", "incoming-id")
            .header("cf-warp-tag-x", "incoming");
        if websocket {
            request = request
                .header("cf-cloudflared-proxy-connection-upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", STANDARD.encode(b"synthetic-key-12"));
        }
        let (answer, send) = client
            .send_request(request.body(()).unwrap(), !websocket)
            .unwrap();
        let response = answer.await.unwrap();
        assert_eq!(response.status(), 200);
        if websocket {
            let (stream, pump) = h2_control::bridge(response.into_body(), send);
            let _pump = AbortTask(pump);
            websocket_tags(stream, id).await;
        } else {
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(part) = body.data().await {
                let part = part.unwrap();
                bytes.extend_from_slice(&part);
                body.flow_control().release_capacity(part.len()).unwrap();
            }
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                expected(id)
            );
        }
    }
}

async fn quic_replace(
    conn: &transport::quic::QuicConnection,
    version: i32,
    configuration: &serde_json::Value,
) {
    let mut stream = conn.open_bi().await.unwrap();
    stream.write_all(&metadata::RPC_SIGNATURE).await.unwrap();
    let (read, write) = tokio::io::split(stream);
    let network = capnp_rpc::twoparty::VatNetwork::new(
        read.compat(),
        write.compat_write(),
        capnp_rpc::rpc_twoparty_capnp::Side::Client,
        crate::protocol::reader_options(),
    );
    let mut rpc = capnp_rpc::RpcSystem::new(Box::new(network), None);
    let client: wire::configuration_manager::Client =
        rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
    let _driver = AbortTask(tokio::task::spawn_local(rpc));
    let mut request = client.update_configuration_request();
    request.get().set_version(version);
    request
        .get()
        .set_config(&serde_json::to_vec(configuration).unwrap());
    let response = request.send().promise.await.unwrap();
    assert_eq!(
        response
            .get()
            .unwrap()
            .get_result()
            .unwrap()
            .get_latest_applied_version(),
        version
    );
}

#[tokio::test(flavor = "current_thread")]
async fn http_and_websocket_tags_bind_real_registration_uuid_across_replace_and_reconnect() {
    for protocol in [EdgeProtocol::Quic, EdgeProtocol::Http2] {
        tokio::task::LocalSet::new()
            .run_until(tag_transport(protocol))
            .await;
    }
}

async fn tag_transport(protocol: EdgeProtocol) {
    let (origin, _origin) = crate::proxy::tag_test_origin::start().await;
    let configuration = serde_json::json!({"ingress":[{"service":format!("http://{origin}")} ]});
    let mut config = config();
    config.configuration = LoadedConfig::from_json(&configuration.to_string()).unwrap();
    config.ingress = config.configuration.ingress.clone();
    config.tags = vec![
        (
            http::HeaderName::from_static("cf-warp-tag-x"),
            http::HeaderValue::from_static("one"),
        ),
        (
            http::HeaderName::from_static("cf-warp-tag-x"),
            http::HeaderValue::from_static("two"),
        ),
        (
            http::HeaderName::from_static("cf-warp-tag-id"),
            http::HeaderValue::from_static("user-id"),
        ),
    ];
    let mut runtime = runtime(config);
    let (events, mut received) = mpsc::unbounded_channel();
    Arc::get_mut(&mut runtime).unwrap().events = events;
    let (observed, mut ids) = mpsc::unbounded_channel();
    let (cert, key) = certificate();
    let tls = EdgeTls::new(TlsPolicy::PreferPostQuantum, Some(&cert.to_pem().unwrap())).unwrap();
    for epoch in 0..2 {
        let replacement = serde_json::json!({"ingress":[{"service":format!("http://{origin}")}],"originRequest":{"httpHostHeader":"replacement.invalid"}});
        let version = epoch * 2 + 1;
        if protocol == EdgeProtocol::Http2 {
            let mut acceptor =
                boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                    .unwrap();
            acceptor.set_certificate(&cert).unwrap();
            acceptor.set_private_key(&key).unwrap();
            let acceptor = acceptor.build();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let observed = observed.clone();
            let edge = async {
                let (socket, _) = listener.accept().await.unwrap();
                let tls = tokio_boring::accept(&acceptor, socket).await.unwrap();
                let (mut client, driver) = h2::client::handshake(tls).await.unwrap();
                let _driver = AbortTask(tokio::task::spawn_local(driver));
                let (answer, send) = client
                    .send_request(
                        http::Request::builder()
                            .method("POST")
                            .uri("https://synthetic.invalid/control")
                            .header("cf-cloudflared-proxy-connection-upgrade", "control-stream")
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                let (control, pump) = h2_control::bridge(answer.await.unwrap().into_body(), send);
                let _pump = AbortTask(pump);
                let _rpc = registration_peer(control, observed);
                let id = ids.recv().await.unwrap();
                assert_eq!(id, runtime.client_id);
                assert!(matches!(
                    received.recv().await,
                    Some(Event::Connected(0, EdgeProtocol::Http2))
                ));
                h2_tags(&mut client, id).await;
                let answer = update_request(&mut client, version, replacement).await;
                assert_eq!(answer["lastAppliedVersion"], version);
                h2_tags(&mut client, id).await;
            };
            let shared = runtime.clone();
            let edge_tls = tls.clone();
            let mut connector = AbortTask(tokio::task::spawn_local(async move {
                let mut retry = None;
                serve_h2(shared, &edge_tls, 0, address, 0, &mut retry).await
            }));
            tokio::time::timeout(Duration::from_secs(8), async {
                let (result, _) = tokio::join!(&mut connector.0, edge);
                assert!(result.unwrap().is_err());
            })
            .await
            .unwrap();
        } else {
            let mut ssl =
                boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
            ssl.set_certificate(&cert).unwrap();
            ssl.set_private_key(&key).unwrap();
            ssl.set_curves_list("X25519MLKEM768").unwrap();
            let mut config =
                quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
            config.set_application_protos(&[b"argotunnel"]).unwrap();
            config.set_max_idle_timeout(5000);
            config.set_initial_max_data(1024 * 1024);
            config.set_initial_max_stream_data_bidi_local(65536);
            config.set_initial_max_stream_data_bidi_remote(65536);
            config.set_initial_max_streams_bidi(128);
            config.enable_dgram(true, 32, 32);
            let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let address = socket.local_addr().unwrap();
            let observed = observed.clone();
            let edge = async {
                let mut packet = vec![0; 65527];
                let (n, peer) = socket.recv_from(&mut packet).await.unwrap();
                let header = quiche::Header::from_slice(&mut packet[..n], 20).unwrap();
                let conn: tokio_quiche::quic::QuicheConnection =
                    quiche::accept_with_buf_factory(&header.dcid, None, address, peer, &mut config)
                        .unwrap();
                let initial = tokio_quiche::quic::Incoming {
                    peer_addr: peer,
                    local_addr: address,
                    rx_time: None,
                    buf: packet[..n].to_vec(),
                    gro: None,
                    so_mark_data: None,
                };
                let mut conn = transport::quic::attach_server(conn, socket, initial)
                    .await
                    .unwrap();
                let control = conn.accept_bi().await.unwrap();
                assert_eq!(control.id(), 0);
                let _rpc = registration_peer(control, observed);
                let id = ids.recv().await.unwrap();
                assert_eq!(id, runtime.client_id);
                assert!(matches!(
                    received.recv().await,
                    Some(Event::Connected(0, EdgeProtocol::Quic))
                ));
                quic_tags(&conn, id).await;
                quic_replace(&conn, version, &replacement).await;
                quic_tags(&conn, id).await;
                conn.close();
            };
            let shared = runtime.clone();
            let edge_tls = tls.clone();
            let mut connector = AbortTask(tokio::task::spawn_local(async move {
                let mut retry = None;
                serve_quic(shared, &edge_tls, 0, address, 0, &mut retry).await
            }));
            tokio::time::timeout(Duration::from_secs(8), async {
                let (result, _) = tokio::join!(&mut connector.0, edge);
                assert!(result.unwrap().is_err());
            })
            .await
            .unwrap();
        }
        assert_eq!(runtime.readiness.count(), 0);
    }
    assert_eq!(
        runtime
            .context
            .metrics
            .register_success
            .with_label_values(&["registerConnection"])
            .get(),
        2
    );
}
