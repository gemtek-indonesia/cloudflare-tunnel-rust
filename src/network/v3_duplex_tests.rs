use super::v3_ack::pending_migration;
use super::*;
use crate::network::session::OriginWriteOutcome;

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
fn payload(id: [u8; 16], value: &[u8]) -> Vec<u8> {
    DatagramV3::Payload {
        id,
        payload: value.to_vec(),
    }
    .encode()
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_payload_send_preserves_writer_and_owned_idle_or_cancel_cleanup() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for cancel in [false, true] {
                let config = crate::runtime::tests::config();
                let state = NetworkState::new(&config).unwrap();
                let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
                let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let id = [20; 16];
                pair.send(registration(id, origin.local_addr().unwrap()))
                    .await;
                assert!(matches!(
                    DatagramV3::decode(&pair.receive().await).unwrap(),
                    DatagramV3::Response {
                        response_type: 0,
                        ..
                    }
                ));
                pair.send(payload(id, b"announce origin address")).await;
                let mut buffer = [0; 128];
                let (n, address) = timeout(Duration::from_secs(1), origin.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&buffer[..n], b"announce origin address");
                let mut sender = pair.connection.sender.clone();
                let (entered, release) = sender.gate_next_payload_datagram();
                origin.send_to(b"held response", address).await.unwrap();
                timeout(Duration::from_secs(1), entered)
                    .await
                    .unwrap()
                    .unwrap();
                pair.send(payload(id, b"writer remains independent")).await;
                let (n, _) = timeout(Duration::from_millis(100), origin.recv_from(&mut buffer))
                    .await
                    .expect("a blocked origin-reply send must not block the origin writer")
                    .unwrap();
                assert_eq!(&buffer[..n], b"writer remains independent");
                if cancel {
                    pair.scope.cancellation().cancel();
                }
                timeout(
                    Duration::from_millis(if cancel { 300 } else { 1500 }),
                    drained(&state),
                )
                .await
                .expect("the lifecycle owner must close independently of the held send");
                assert!(
                    release.send(Ok(())).is_err(),
                    "owned reader must be joined before releasing its flow slot"
                );
                assert_eq!(state.v3.len(), 0);
                assert_eq!(state.active_flows(), 0);
                pair.client.close();
                pair.peer.close();
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn origin_write_boundary_preserves_reader_and_drop_or_fatal_outcomes() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for outcome in ["send", "short", "deadline", "fatal"] {
                let config = crate::runtime::tests::config();
                let state = NetworkState::new(&config).unwrap();
                let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
                let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let id = [21; 16];
                pair.send(registration(id, origin.local_addr().unwrap()))
                    .await;
                pair.receive().await;
                pair.send(payload(id, b"announce")).await;
                let mut buffer = [0; 128];
                let (_, address) = timeout(Duration::from_secs(1), origin.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                let (entered, release) = state.v3.gate_next_origin_write(id);
                pair.send(payload(id, b"held origin write")).await;
                timeout(Duration::from_secs(1), entered)
                    .await
                    .unwrap()
                    .unwrap();
                origin.send_to(b"reader progresses", address).await.unwrap();
                let DatagramV3::Payload { payload: reply, .. } =
                    DatagramV3::decode(&pair.receive().await).unwrap()
                else {
                    panic!("expected actual origin reply")
                };
                assert_eq!(reply, b"reader progresses");
                pair.send(payload(id, b"next packet")).await;
                match outcome {
                    "send" => {
                        release.send(OriginWriteOutcome::Send).ok().unwrap();
                        let (n, _) = timeout(Duration::from_secs(1), origin.recv_from(&mut buffer))
                            .await
                            .unwrap()
                            .unwrap();
                        assert_eq!(&buffer[..n], b"held origin write");
                    }
                    "short" => {
                        release.send(OriginWriteOutcome::Short(1)).ok().unwrap();
                    }
                    "fatal" => {
                        release
                            .send(OriginWriteOutcome::Error(std::io::Error::other(
                                "synthetic write failure",
                            )))
                            .ok()
                            .unwrap();
                        timeout(Duration::from_millis(300), drained(&state))
                            .await
                            .unwrap();
                        assert_eq!(state.v3.len(), 0);
                        assert_eq!(
                            state
                                .context
                                .metrics
                                .udp_failed_flows
                                .with_label_values(&["0"])
                                .get(),
                            1
                        );
                        pair.client.close();
                        pair.peer.close();
                        continue;
                    }
                    "deadline" => {}
                    _ => unreachable!(),
                }
                let (n, _) = timeout(Duration::from_millis(400), origin.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&buffer[..n], b"next packet");
                assert_eq!(state.v3.len(), 1);
                let reason = if outcome == "deadline" {
                    "write_deadline_exceeded"
                } else {
                    "write_failed"
                };
                assert_eq!(
                    state
                        .context
                        .metrics
                        .udp_dropped_datagrams
                        .with_label_values(&["0", reason])
                        .get(),
                    u64::from(outcome != "send")
                );
                assert_eq!(
                    state
                        .context
                        .metrics
                        .udp_failed_flows
                        .with_label_values(&["0"])
                        .get(),
                    0
                );
                pair.scope.cancellation().cancel();
                timeout(Duration::from_millis(300), drained(&state))
                    .await
                    .unwrap();
                pair.client.close();
                pair.peer.close();
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn migration_requests_have_individual_acceptance_and_skip_canceled_queue_head() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for cancel_first in [false, true] {
                let config = crate::runtime::tests::config();
                let state = NetworkState::new(&config).unwrap();
                let mut creator = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
                let mut first = pair(state.clone(), &config, 1, DatagramVersion::V3).await;
                let mut last = pair(state.clone(), &config, 2, DatagramVersion::V3).await;
                let (_, empty) = tokio::sync::mpsc::channel(1);
                let incoming = std::mem::replace(&mut creator.received.datagrams, empty);
                let mut dispatcher = crate::runtime::AbortTask(tokio::task::spawn_local(
                    serve_datagrams(creator.connection.clone(), incoming),
                ));
                let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let destination = origin.local_addr().unwrap();
                let id = [22; 16];
                let mut creator_sender = creator.connection.sender.clone();
                let (creator_entered, creator_release) =
                    creator_sender.gate_next_registration_datagram();
                creator
                    .peer
                    .send_datagram(Bytes::from(registration(id, destination)))
                    .await
                    .unwrap();
                timeout(Duration::from_secs(1), creator_entered)
                    .await
                    .unwrap()
                    .unwrap();
                let mut first_request = pending_migration(&mut first, id, destination).await;
                if cancel_first {
                    first.scope.cancellation().cancel();
                    assert!(
                        timeout(Duration::from_secs(1), &mut first_request)
                            .await
                            .unwrap()
                            .is_err()
                    );
                }
            let last_request = pending_migration(&mut last, id, destination).await;
            let unrelated = [25; 16];
            last.send(registration(unrelated, destination)).await;
            assert!(matches!(DatagramV3::decode(&last.receive().await).unwrap(),
                DatagramV3::Response { id: response_id, response_type: 0, .. } if response_id == unrelated));
                assert!(
                    timeout(Duration::from_millis(30), last.incoming.datagrams.recv())
                        .await
                        .is_err()
                );
                let mut last_sender = last.connection.sender.clone();
                let (last_entered, last_release) = last_sender.gate_next_registration_datagram();
                let mut first_sender = first.connection.sender.clone();
                let (first_entered, first_release) = first_sender.gate_next_registration_datagram();
                let mut last_task =
                    crate::runtime::AbortTask(tokio::task::spawn_local(last_request));
                let mut first_task = if cancel_first {
                    None
                } else {
                    Some(crate::runtime::AbortTask(tokio::task::spawn_local(
                        first_request,
                    )))
                };
                creator_release.send(Ok(())).unwrap();
                assert!(matches!(
                    DatagramV3::decode(&creator.receive().await).unwrap(),
                    DatagramV3::Response {
                        response_type: 0,
                        ..
                    }
                ));
                timeout(Duration::from_secs(1), last_entered)
                    .await
                    .unwrap()
                    .unwrap();
                if !cancel_first {
                    timeout(Duration::from_secs(1), first_entered)
                        .await
                        .unwrap()
                        .unwrap();
                    first_release.send(Ok(())).unwrap();
                    assert!(matches!(
                        DatagramV3::decode(&first.receive().await).unwrap(),
                        DatagramV3::Response {
                            response_type: 0,
                            ..
                        }
                    ));
                    timeout(Duration::from_secs(1), &mut first_task.as_mut().unwrap().0)
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap();
                } else {
                    assert!(
                        timeout(Duration::from_millis(30), first.incoming.datagrams.recv())
                            .await
                            .is_err()
                    );
                    drop(first_release);
                }
                last_release.send(Ok(())).unwrap();
                assert!(matches!(
                    DatagramV3::decode(&last.receive().await).unwrap(),
                    DatagramV3::Response {
                        response_type: 0,
                        ..
                    }
                ));
                timeout(Duration::from_secs(1), &mut last_task.0)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                creator.scope.cancellation().cancel();
                timeout(Duration::from_secs(1), &mut dispatcher.0)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                last.send(payload(
                    id,
                    b"latest accepted connection survives creator cancellation",
                ))
                .await;
                let mut buffer = [0; 128];
                let (n, address) = timeout(Duration::from_secs(1), origin.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    &buffer[..n],
                    b"latest accepted connection survives creator cancellation"
                );
                origin
                    .send_to(b"latest route owns replies", address)
                    .await
                    .unwrap();
                let DatagramV3::Payload { payload: reply, .. } =
                    DatagramV3::decode(&last.receive().await).unwrap()
                else {
                    panic!("expected migrated origin reply")
                };
                assert_eq!(reply, b"latest route owns replies");
            assert_eq!(state.active_flows(), 2);
                last.scope.cancellation().cancel();
                timeout(Duration::from_millis(300), drained(&state))
                    .await
                    .unwrap();
                creator.client.close();
                creator.peer.close();
                first.client.close();
                first.peer.close();
                last.client.close();
                last.peer.close();
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn held_reply_keeps_captured_sender_and_next_reply_uses_accepted_migration() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut old = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let mut next = pair(state.clone(), &config, 1, DatagramVersion::V3).await;
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let id = [23; 16];
            old.send(registration(id, origin.local_addr().unwrap()))
                .await;
            old.receive().await;
            old.send(payload(id, b"announce")).await;
            let mut buffer = [0; 128];
            let (_, address) = timeout(Duration::from_secs(1), origin.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            let mut sender = old.connection.sender.clone();
            let (entered, release) = sender.gate_next_payload_datagram();
            origin.send_to(b"held old route", address).await.unwrap();
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            next.send(registration(id, "127.0.0.1:1".parse().unwrap()))
                .await;
            assert!(matches!(
                DatagramV3::decode(&next.receive().await).unwrap(),
                DatagramV3::Response {
                    response_type: 0,
                    ..
                }
            ));
            old.scope.cancellation().cancel();
            next.send(payload(id, b"original destination remains"))
                .await;
            let (n, _) = timeout(Duration::from_millis(100), origin.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..n], b"original destination remains");
            release.send(Ok(())).unwrap();
            let DatagramV3::Payload { payload: reply, .. } =
                DatagramV3::decode(&old.receive().await).unwrap()
            else {
                panic!("expected held old-route reply")
            };
            assert_eq!(reply, b"held old route");
            origin.send_to(b"new route", address).await.unwrap();
            let DatagramV3::Payload { payload: reply, .. } =
                DatagramV3::decode(&next.receive().await).unwrap()
            else {
                panic!("expected migrated reply")
            };
            assert_eq!(reply, b"new route");
            next.scope.cancellation().cancel();
            timeout(Duration::from_millis(300), drained(&state))
                .await
                .unwrap();
            assert_eq!(state.v3.len(), 0);
            let rebound = std::net::UdpSocket::bind(address).expect(
                "both I/O workers must release their origin socket before releasing the flow slot",
            );
            drop(rebound);
            old.client.close();
            old.peer.close();
            next.client.close();
            next.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn writer_queue_keeps_512_pending_packets_and_drops_overflow() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let origin = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let id = [24; 16];
            pair.send(registration(id, origin.local_addr().unwrap()))
                .await;
            pair.receive().await;
            let (entered, release) = state.v3.gate_next_origin_write(id);
            pair.send(payload(id, &0u16.to_be_bytes())).await;
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            for i in 1..=513u16 {
                pair.connection
                    .handle(Bytes::from(payload(id, &i.to_be_bytes())))
                    .await
                    .unwrap();
            }
            assert_eq!(
                state
                    .context
                    .metrics
                    .udp_dropped_datagrams
                    .with_label_values(&["0", "write_full"])
                    .get(),
                1
            );
            let receiver = origin.clone();
            let mut reads = crate::runtime::AbortTask(tokio::task::spawn_local(async move {
                let mut buffer = [0; 8];
                for i in 0..=512u16 {
                    let (n, _) = receiver.recv_from(&mut buffer).await.unwrap();
                    assert_eq!(n, 2);
                    assert_eq!(u16::from_be_bytes(buffer[..2].try_into().unwrap()), i);
                }
            }));
            release.send(OriginWriteOutcome::Send).ok().unwrap();
            timeout(Duration::from_secs(1), &mut reads.0)
                .await
                .unwrap()
                .unwrap();
            assert!(
                timeout(Duration::from_millis(30), origin.recv_from(&mut [0; 8]))
                    .await
                    .is_err(),
                "overflow packet must not reach the origin"
            );
            pair.scope.cancellation().cancel();
            timeout(Duration::from_millis(300), drained(&state))
                .await
                .unwrap();
            assert_eq!(state.active_flows(), 0);
            pair.client.close();
            pair.peer.close();
        })
        .await;
}
