use super::*;

fn fixture(config: &RunConfig, available: [bool; 2]) -> Arc<NetworkState> {
    let mut state = NetworkState::new(config).unwrap();
    Arc::get_mut(&mut state).unwrap().icmp = icmp::IcmpRouter::fixture(config, available);
    state
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_before_origin_write_exports_no_request_span() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = fixture(&config, [true; 2]);
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
            let packet = packet::IcmpPacket {
                source: "127.0.0.1".parse().unwrap(),
                destination: "127.0.0.1".parse().unwrap(),
                ttl: 64,
                message: vec![8, 0, 0, 0, 0, 7, 0, 3],
            };
            let (entered, release) = state
                .icmp
                .gate_existing_origin_write(&pair.connection, &packet)
                .await;
            let mut identity = [0x11; 25];
            identity[16..24].fill(0x22);
            identity[24] = 1;
            let bytes = Bytes::from(
                DatagramV2::TracedIp {
                    identity,
                    payload: packet.encode().unwrap(),
                }
                .encode()
                .unwrap(),
            );
            let connection = pair.connection.clone();
            let mut request = crate::runtime::AbortTask(tokio::task::spawn_local(async move {
                connection.handle(bytes).await
            }));
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            pair.scope.cancellation().cancel();
            timeout(Duration::from_secs(1), &mut request.0)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(
                release.send(()).is_err(),
                "origin write future must be canceled before sending"
            );
            assert!(
                timeout(Duration::from_millis(50), pair.incoming.datagrams.recv())
                    .await
                    .is_err(),
                "unsent canceled request must export neither reply nor request span"
            );
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn v3_icmp_queue_has_128_pending_and_owned_cancel_while_udp_and_other_attempt_progress() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = fixture(&config, [true; 2]);
            let mut first = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let mut sibling = pair(state.clone(), &config, 1, DatagramVersion::V3).await;
            let incoming = std::mem::replace(
                &mut first.received.datagrams,
                tokio::sync::mpsc::channel(1).1,
            );
            let (entered, release) = state.icmp.gate_next_request();
            let mut worker = crate::runtime::AbortTask(tokio::task::spawn_local(serve_datagrams(
                first.connection.clone(),
                incoming,
            )));
            first
                .peer
                .send_datagram(Bytes::from(DatagramV3::Icmp(vec![0xff]).encode().unwrap()))
                .await
                .unwrap();
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            for _ in 0..129 {
                first
                    .peer
                    .send_datagram(Bytes::from(DatagramV3::Icmp(vec![0xff]).encode().unwrap()))
                    .await
                    .unwrap();
                tokio::task::yield_now().await;
            }
            timeout(Duration::from_secs(1), async {
                while state
                    .context
                    .metrics
                    .icmp_dropped_packets
                    .with_label_values(&["0", "write_full"])
                    .get()
                    == 0
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(
                state
                    .context
                    .metrics
                    .icmp_dropped_packets
                    .with_label_values(&["0", "write_full"])
                    .get(),
                1
            );
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for (pair, id, dispatched) in [
                (&mut first, [70; 16], true),
                (&mut sibling, [71; 16], false),
            ] {
                let packet = DatagramV3::Registration {
                    id,
                    destination: origin.local_addr().unwrap(),
                    idle_seconds: 1,
                    traced: false,
                    payload: vec![],
                }
                .encode()
                .unwrap();
                if dispatched {
                    pair.peer.send_datagram(Bytes::from(packet)).await.unwrap();
                } else {
                    pair.send(packet).await;
                }
                assert!(matches!(
                    DatagramV3::decode(&pair.receive().await).unwrap(),
                    DatagramV3::Response {
                        response_type: 0,
                        ..
                    }
                ));
            }
            first.scope.cancellation().cancel();
            timeout(Duration::from_secs(1), &mut worker.0)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(
                release.send(()).is_err(),
                "attempt must join held ICMP worker before returning"
            );
            assert_eq!(
                state
                    .context
                    .metrics
                    .icmp_dropped_packets
                    .with_label_values(&["0", "write_failed"])
                    .get(),
                0
            );
            assert!(
                sibling
                    .try_send(DatagramV3::Icmp(vec![0xff]).encode().unwrap())
                    .await
                    .is_err()
            );
            assert_eq!(
                state
                    .context
                    .metrics
                    .icmp_dropped_packets
                    .with_label_values(&["1", "write_failed"])
                    .get(),
                1
            );
            assert_eq!(state.v3.len(), 1);
            sibling
                .send(
                    DatagramV3::Payload {
                        id: [71; 16],
                        payload: b"sibling alive".to_vec(),
                    }
                    .encode()
                    .unwrap(),
                )
                .await;
            let mut buffer = [0; 64];
            let (n, _) = timeout(Duration::from_secs(1), origin.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..n], b"sibling alive");
            sibling.scope.cancellation().cancel();
            drained(&state).await;
            first.client.close();
            first.peer.close();
            sibling.client.close();
            sibling.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn disabled_icmp_drops_before_decode_without_metrics_or_reply() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = fixture(&config, [false; 2]);
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            pair.send(DatagramV3::Icmp(vec![0xff]).encode().unwrap())
                .await;
            assert_eq!(state.icmp.len(), 0);
            assert_eq!(
                state
                    .context
                    .metrics
                    .icmp_dropped_packets
                    .with_label_values(&["0", "write_failed"])
                    .get(),
                0
            );
            assert!(
                timeout(Duration::from_millis(50), pair.incoming.datagrams.recv())
                    .await
                    .is_err()
            );
            pair.scope.cancellation().cancel();
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn v3_worker_decode_error_and_ttl_send_failure_count_only_actual_failed_packets() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = fixture(&config, [true; 2]);
            let mut pair = pair(state.clone(), &config, 2, DatagramVersion::V3).await;
            let incoming = std::mem::replace(
                &mut pair.received.datagrams,
                tokio::sync::mpsc::channel(1).1,
            );
            let mut worker = crate::runtime::AbortTask(tokio::task::spawn_local(serve_datagrams(
                pair.connection.clone(),
                incoming,
            )));
            pair.peer
                .send_datagram(Bytes::from(DatagramV3::Icmp(vec![0xff]).encode().unwrap()))
                .await
                .unwrap();
            timeout(Duration::from_secs(1), async {
                while state
                    .context
                    .metrics
                    .icmp_dropped_packets
                    .with_label_values(&["2", "write_failed"])
                    .get()
                    == 0
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            pair.scope.cancellation().cancel();
            timeout(Duration::from_secs(1), &mut worker.0)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            pair.client.close();
            let packet = packet::IcmpPacket {
                source: "127.0.0.1".parse().unwrap(),
                destination: "127.0.0.1".parse().unwrap(),
                ttl: 1,
                message: vec![8, 0, 0, 0, 0, 7, 0, 3],
            }
            .encode()
            .unwrap();
            assert!(
                pair.connection
                    .handle(Bytes::from(DatagramV3::Icmp(packet).encode().unwrap()))
                    .await
                    .is_err()
            );
            assert_eq!(
                state
                    .context
                    .metrics
                    .icmp_dropped_packets
                    .with_label_values(&["2", "write_failed"])
                    .get(),
                2
            );
            let exported = String::from_utf8(state.context.metrics.encode().unwrap()).unwrap();
            assert!(exported.contains(
                "cloudflared_icmp_dropped_packets{conn_index=\"2\",reason=\"write_failed\"} 2"
            ));
            pair.peer.close();
        })
        .await;
}

#[test]
fn startup_checks_families_independently_and_all_failure_preserves_daemon() {
    let context = crate::observability::Context::quiet().unwrap();
    let mut config = crate::runtime::tests::config();
    config.icmpv4_src = Some("192.0.2.254".parse().unwrap());
    config.icmpv6_src = Some("2001:db8::ffff".into());
    let router = icmp::IcmpRouter::new(&config, &context.logger);
    assert!(!router.enabled());
    assert_eq!(router.len(), 0);
    assert!(NetworkState::new(&config).is_ok());
    config.icmpv4_src = Some("127.0.0.1".parse().unwrap());
    let router = icmp::IcmpRouter::new(&config, &context.logger);
    assert!(!router.supports(false));
    config.icmpv4_src = Some("192.0.2.254".parse().unwrap());
    config.icmpv6_src = Some("::1".into());
    let router = icmp::IcmpRouter::new(&config, &context.logger);
    assert!(!router.supports(true));
    config.quick_hostname = "synthetic.example.invalid".into();
    let router = icmp::IcmpRouter::new(&config, &context.logger);
    assert!(!router.enabled());
    config.quick_hostname.clear();
    config.icmpv6_src = Some("::1%../synthetic".into());
    assert!(
        NetworkState::new(&config)
            .unwrap()
            .icmp_sources()
            .is_empty()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn early_echo_and_bind_failure_export_error_span_but_missing_family_exports_none() {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use prost::Message;
    tokio::task::LocalSet::new()
        .run_until(async {
            for echo in [false, true] {
                let mut config = crate::runtime::tests::config();
                config.icmpv4_src = Some("192.0.2.254".parse().unwrap());
                let state = fixture(&config, [true, false]);
                let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V2).await;
                let mut identity = [0x11; 25];
                identity[16..24].fill(0x22);
                identity[24] = 1;
                let request = packet::IcmpPacket {
                    source: "127.0.0.1".parse().unwrap(),
                    destination: "127.0.0.1".parse().unwrap(),
                    ttl: 64,
                    message: vec![if echo { 8 } else { 11 }, 0, 0, 0, 0, 7, 0, 3],
                }
                .encode()
                .unwrap();
                assert!(
                    pair.try_send(
                        DatagramV2::TracedIp {
                            identity,
                            payload: request
                        }
                        .encode()
                        .unwrap()
                    )
                    .await
                    .is_err()
                );
                let DatagramV2::TraceSpans {
                    identity: actual,
                    payload,
                } = DatagramV2::decode(&pair.receive().await).unwrap()
                else {
                    panic!("expected early error trace");
                };
                assert_eq!(actual, identity);
                let export = ExportTraceServiceRequest::decode(payload.as_slice()).unwrap();
                let span = &export.resource_spans[0].scope_spans[0].spans[0];
                assert_eq!(span.name, "icmp-echo-request");
                assert_eq!(span.status.as_ref().unwrap().code, 2);
                assert_eq!(span.parent_span_id, [0x22; 8]);
                assert_eq!(state.icmp.len(), 0);
                assert!(
                    timeout(Duration::from_millis(30), pair.incoming.datagrams.recv())
                        .await
                        .is_err()
                );
                pair.scope.cancellation().cancel();
                pair.client.close();
                pair.peer.close();
            }
            let config = crate::runtime::tests::config();
            let state = fixture(&config, [false, true]);
            let mut pair = pair(state, &config, 0, DatagramVersion::V2).await;
            let request = packet::IcmpPacket {
                source: "127.0.0.1".parse().unwrap(),
                destination: "127.0.0.1".parse().unwrap(),
                ttl: 64,
                message: vec![8, 0, 0, 0, 0, 7, 0, 3],
            }
            .encode()
            .unwrap();
            assert!(
                pair.try_send(
                    DatagramV2::TracedIp {
                        identity: [1; 25],
                        payload: request
                    }
                    .encode()
                    .unwrap()
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("ICMPv4 proxy was not instantiated")
            );
            assert!(
                timeout(Duration::from_millis(30), pair.incoming.datagrams.recv())
                    .await
                    .is_err()
            );
            pair.scope.cancellation().cancel();
            pair.client.close();
            pair.peer.close();
        })
        .await;
}
