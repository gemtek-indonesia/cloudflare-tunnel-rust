use super::*;
use crate::observability::metrics::Metrics;

fn registration(id: [u8; 16], destination: SocketAddr) -> Vec<u8> {
    DatagramV3::Registration {
        id,
        destination,
        idle_seconds: 1,
        traced: false,
        payload: vec![],
    }
    .encode()
    .unwrap()
}
fn payload(id: [u8; 16], bytes: &[u8]) -> Vec<u8> {
    DatagramV3::Payload {
        id,
        payload: bytes.to_vec(),
    }
    .encode()
    .unwrap()
}
async fn response_attempt(
    pair: &mut Pair,
    bytes: Vec<u8>,
) -> crate::runtime::AbortTask<anyhow::Result<()>> {
    pair.peer.send_datagram(Bytes::from(bytes)).await.unwrap();
    let bytes = timeout(Duration::from_secs(1), pair.received.datagrams.recv())
        .await
        .unwrap()
        .unwrap();
    let connection = pair.connection.clone();
    crate::runtime::AbortTask(tokio::task::spawn_local(async move {
        connection.handle(bytes).await
    }))
}
fn active(metrics: &Metrics, index: u8) -> i64 {
    metrics
        .udp_active_flows
        .with_label_values(&[&index.to_string()])
        .get()
}
fn count(counter: &prometheus::IntCounterVec, index: u8) -> u64 {
    counter.with_label_values(&[&index.to_string()]).get()
}

#[tokio::test(flavor = "current_thread")]
async fn metric_lifetimes_distinguish_creator_index_current_route_and_response_outcomes() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let metrics = state.context.metrics.clone();
            let mut creator = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let mut migrated = pair(state.clone(), &config, 1, DatagramVersion::V3).await;
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let mut sender = creator.connection.sender.clone();
            let (entered, release) = sender.gate_next_registration_datagram();
            let mut failed =
                response_attempt(&mut creator, registration([30; 16], destination)).await;
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(active(&metrics, 0), 1);
            assert_eq!(count(&metrics.udp_total_flows, 0), 1);
            release
                .send(Err(std::io::Error::other(
                    "synthetic first response failure",
                )))
                .unwrap();
            assert!(
                timeout(Duration::from_secs(1), &mut failed.0)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            drained(&state).await;
            assert_eq!(active(&metrics, 0), 0);
            assert_eq!(count(&metrics.udp_failed_flows, 0), 0);
            let id = [31; 16];
            creator.send(registration(id, destination)).await;
            creator.receive().await;
            assert_eq!(count(&metrics.udp_total_flows, 0), 2);
            let (entered, release) = sender.gate_next_registration_datagram();
            let mut retry = response_attempt(&mut creator, registration(id, destination)).await;
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(count(&metrics.udp_retry_flow_responses, 0), 0);
            release
                .send(Err(std::io::Error::other(
                    "synthetic retry response failure",
                )))
                .unwrap();
            assert!(
                timeout(Duration::from_secs(1), &mut retry.0)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert_eq!(count(&metrics.udp_retry_flow_responses, 0), 0);
            creator.send(registration(id, destination)).await;
            creator.receive().await;
            assert_eq!(count(&metrics.udp_retry_flow_responses, 0), 1);
            assert_eq!(count(&metrics.udp_total_flows, 0), 2);
            let mut sender = migrated.connection.sender.clone();
            let (entered, release) = sender.gate_next_registration_datagram();
            let mut migration = response_attempt(
                &mut migrated,
                registration(id, "127.0.0.1:1".parse().unwrap()),
            )
            .await;
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(count(&metrics.udp_migrated_flows, 1), 1);
            assert_eq!(active(&metrics, 0), 1);
            release
                .send(Err(std::io::Error::other(
                    "synthetic migration response failure",
                )))
                .unwrap();
            assert!(
                timeout(Duration::from_secs(1), &mut migration.0)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert_eq!(count(&metrics.udp_migrated_flows, 1), 1);
            migrated.send(payload(id, b"original destination")).await;
            let mut buffer = [0; 128];
            let (n, address) = timeout(Duration::from_secs(1), origin.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..n], b"original destination");
            origin.send_to(&[0; 1281], address).await.unwrap();
            origin.send_to(&[0; 1501], address).await.unwrap();
            origin
                .send_to(b"ordered read barrier", address)
                .await
                .unwrap();
            let DatagramV3::Payload { payload: reply, .. } =
                DatagramV3::decode(&migrated.receive().await).unwrap()
            else {
                panic!("expected origin barrier")
            };
            assert_eq!(reply, b"ordered read barrier");
            assert_eq!(
                metrics
                    .udp_dropped_datagrams
                    .with_label_values(&["1", "read_too_large"])
                    .get(),
                2
            );
            creator.send(payload([99; 16], b"unknown flow")).await;
            assert_eq!(
                metrics
                    .udp_dropped_datagrams
                    .with_label_values(&["0", "write_flow_unknown"])
                    .get(),
                1
            );
            let (entered, release) = sender.gate_next_payload_datagram();
            origin.send_to(b"failed reply", address).await.unwrap();
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            release
                .send(Err(std::io::Error::other(
                    "synthetic payload transport failure",
                )))
                .unwrap();
            drained(&state).await;
            assert_eq!(count(&metrics.udp_failed_flows, 1), 1);
            assert_eq!(count(&metrics.udp_failed_flows, 0), 0);
            assert_eq!(active(&metrics, 0), 0);
            creator.send(registration([32; 16], destination)).await;
            creator.receive().await;
            timeout(Duration::from_millis(1500), drained(&state))
                .await
                .unwrap();
            assert_eq!(active(&metrics, 0), 0);
            assert_eq!(count(&metrics.udp_failed_flows, 0), 0);
            creator.send(registration([33; 16], destination)).await;
            creator.receive().await;
            creator.scope.cancellation().cancel();
            timeout(Duration::from_millis(300), drained(&state))
                .await
                .unwrap();
            assert_eq!(active(&metrics, 0), 0);
            assert_eq!(count(&metrics.udp_total_flows, 0), 4);
            let exported = String::from_utf8(metrics.encode().unwrap()).unwrap();
            for line in [
                "cloudflared_udp_active_flows{conn_index=\"0\"} 0",
                "cloudflared_udp_total_flows{conn_index=\"0\"} 4",
                "cloudflared_udp_failed_flows{conn_index=\"1\"} 1",
                "cloudflared_udp_retry_flow_responses{conn_index=\"0\"} 1",
                "cloudflared_udp_migrated_flows{conn_index=\"1\"} 1",
                "cloudflared_udp_dropped_datagrams{conn_index=\"1\",reason=\"read_too_large\"} 2",
            ] {
                assert!(
                    exported.contains(line),
                    "missing actual event metric {line}"
                );
            }
            assert!(!exported.contains("reason=\"read_failed\""));
            creator.client.close();
            creator.peer.close();
            migrated.scope.cancellation().cancel();
            migrated.client.close();
            migrated.peer.close();
        })
        .await;
}

struct UdpCallbacks(Arc<Connection>);
impl crate::protocol::callbacks::EdgeCallbacks for UdpCallbacks {
    fn update_configuration(
        &self,
        version: i32,
        _: Vec<u8>,
    ) -> futures::future::LocalBoxFuture<'static, crate::protocol::callbacks::ConfigurationResult>
    {
        Box::pin(async move {
            crate::protocol::callbacks::ConfigurationResult {
                latest_applied_version: version,
                error: "configuration unavailable in UDP fixture".into(),
            }
        })
    }
    fn register_udp_session(
        &self,
        request: crate::protocol::callbacks::UdpRegistration,
    ) -> futures::future::LocalBoxFuture<
        'static,
        Result<crate::protocol::callbacks::UdpRegistrationResult, capnp::Error>,
    > {
        let connection = self.0.clone();
        Box::pin(async move { Ok(connection.register_udp(request).await) })
    }
    fn unregister_udp_session(
        &self,
        id: uuid::Uuid,
        _: String,
    ) -> futures::future::LocalBoxFuture<'static, Result<(), capnp::Error>> {
        let connection = self.0.clone();
        Box::pin(async move {
            connection
                .unregister_udp(id)
                .await
                .map_err(|error| capnp::Error::failed(error.to_string()))
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn real_v3_unsupported_rpc_metrics_preserve_body_errors_exceptions_and_decoder_boundary() {
    tokio::task::LocalSet::new().run_until(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let config = crate::runtime::tests::config();
        let state = NetworkState::new(&config).unwrap();
        let metrics = state.context.metrics.clone();
        let mut pair = pair(state.clone(), &config, 2, DatagramVersion::V3).await;
        let mut stream = pair.peer.open_bi().await.unwrap();
        stream.write_all(&crate::protocol::metadata::RPC_SIGNATURE).await.unwrap();
        let mut control = timeout(Duration::from_secs(1), pair.received.streams.recv()).await.unwrap().unwrap();
        let mut signature = [0;6];
        control.read_exact(&mut signature).await.unwrap();
        assert_eq!(signature, crate::protocol::metadata::RPC_SIGNATURE);
        let _server = crate::runtime::AbortTask(tokio::task::spawn_local(crate::protocol::callbacks::serve_callbacks(
            control, std::rc::Rc::new(UdpCallbacks(pair.connection.clone())), Duration::from_secs(5), metrics.clone(),
        )));
        let (read, write) = tokio::io::split(stream);
        let network = capnp_rpc::twoparty::VatNetwork::new(read.compat(), write.compat_write(), capnp_rpc::rpc_twoparty_capnp::Side::Client, crate::protocol::reader_options());
        let mut rpc = capnp_rpc::RpcSystem::new(Box::new(network), None);
        let client: crate::protocol::tunnelrpc_capnp::session_manager::Client = rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
        let _driver = crate::runtime::AbortTask(tokio::task::spawn_local(rpc));
        let mut call = client.register_udp_session_request();
        call.get().set_session_id(&[31;16]);
        call.get().set_dst_ip(&[127,0,0,1]);
        call.get().set_dst_port(53);
        let response = timeout(Duration::from_secs(1), call.send().promise).await.unwrap().unwrap();
        assert_eq!(response.get().unwrap().get_result().unwrap().get_err().unwrap().to_str().unwrap(), "datagram v3 does not support RegisterUdpSession RPC");
        assert_eq!(metrics.udp_unsupported_remote_commands.with_label_values(&["2","register_udp_session"]).get(), 1);
        assert_eq!(metrics.rpc_server_failures.with_label_values(&["session","register_udp_session"]).get(), 0);
        let mut malformed = client.register_udp_session_request();
        malformed.get().set_session_id(&[31;15]);
        malformed.get().set_dst_ip(&[127,0,0,1]);
        assert!(timeout(Duration::from_secs(1), malformed.send().promise).await.unwrap().is_err());
        assert_eq!(metrics.udp_unsupported_remote_commands.with_label_values(&["2","register_udp_session"]).get(), 1);
        assert_eq!(metrics.rpc_server_failures.with_label_values(&["session","register_udp_session"]).get(), 1);
        let mut unregister = client.unregister_udp_session_request();
        unregister.get().set_session_id(&[31;16]);
        assert!(timeout(Duration::from_secs(1), unregister.send().promise).await.unwrap().is_err());
        assert_eq!(metrics.udp_unsupported_remote_commands.with_label_values(&["2","unregister_udp_session"]).get(), 1);
        assert_eq!(metrics.rpc_server_failures.with_label_values(&["session","unregister_udp_session"]).get(), 1);
        let exported = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(exported.contains("cloudflared_udp_unsupported_remote_command_total{command=\"register_udp_session\",conn_index=\"2\"} 1"));
        assert!(exported.contains("cloudflared_udp_unsupported_remote_command_total{command=\"unregister_udp_session\",conn_index=\"2\"} 1"));
        assert_eq!(state.active_flows(), 0);
        pair.scope.cancellation().cancel(); pair.client.close(); pair.peer.close();
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn migrated_flow_failure_log_retains_context_after_creator_teardown() {
    tokio::task::LocalSet::new()
        .run_until(async {
            use crate::observability::logging::{Event, Filters, Level};
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut logs = state
                .context
                .logger
                .subscribe(
                    "synthetic",
                    Filters {
                        events: vec![Event::Udp],
                        level: Some(Level::Error),
                        sampling: 0.0,
                    },
                )
                .unwrap();
            let mut creator = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let mut migrated = pair(state.clone(), &config, 1, DatagramVersion::V3).await;
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let id = [34; 16];
            creator
                .send(registration(id, origin.local_addr().unwrap()))
                .await;
            creator.receive().await;
            migrated
                .send(registration(id, origin.local_addr().unwrap()))
                .await;
            migrated.receive().await;
            let weak_creator = Arc::downgrade(&creator.connection);
            drop(creator);
            assert!(
                weak_creator.upgrade().is_none(),
                "the failure log must not retain a creator connection owner"
            );
            migrated.send(payload(id, b"announce")).await;
            let mut buffer = [0; 64];
            let (_, address) = timeout(Duration::from_secs(1), origin.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            let mut sender = migrated.connection.sender.clone();
            let (entered, release) = sender.gate_next_payload_datagram();
            origin.send_to(b"reply failure", address).await.unwrap();
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            release
                .send(Err(std::io::Error::other("synthetic migrated failure")))
                .unwrap();
            let log = timeout(Duration::from_secs(1), logs.receiver.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(log.message, "UDP flow closed with an error");
            assert_eq!(log.fields.get("connIndex"), Some(&serde_json::json!(1)));
            assert_eq!(
                log.fields.get("flowID"),
                Some(&serde_json::json!(
                    uuid::Uuid::from_bytes(id).simple().to_string()
                ))
            );
            assert_eq!(
                log.fields.get("error"),
                Some(&serde_json::json!("synthetic migrated failure"))
            );
            drained(&state).await;
            assert_eq!(
                state
                    .context
                    .metrics
                    .udp_failed_flows
                    .with_label_values(&["1"])
                    .get(),
                1
            );
            migrated.scope.cancellation().cancel();
            migrated.client.close();
            migrated.peer.close();
        })
        .await;
}
