use super::*;
use futures::FutureExt;

pub(super) async fn pending_migration(
    pair: &mut Pair,
    id: [u8; 16],
    destination: SocketAddr,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>>>> {
    pair.peer
        .send_datagram(Bytes::from(registration(id, destination)))
        .await
        .unwrap();
    let bytes = timeout(Duration::from_secs(1), pair.received.datagrams.recv())
        .await
        .unwrap()
        .unwrap();
    let connection = pair.connection.clone();
    let mut request = Box::pin(async move { connection.handle(bytes).await });
    assert!(request.as_mut().now_or_never().is_none());
    request
}

fn registration(id: [u8; 16], destination: SocketAddr) -> Vec<u8> {
    DatagramV3::Registration {
        id,
        destination,
        idle_seconds: 5,
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
async fn send(pair: &Pair, bytes: Vec<u8>) {
    pair.peer.send_datagram(Bytes::from(bytes)).await.unwrap();
}
async fn origin_packet(origin: &tokio::net::UdpSocket, expected: &[u8]) {
    let mut buffer = [0; 1500];
    let (n, _) = timeout(Duration::from_millis(300), origin.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..n], expected);
}

#[tokio::test(flavor = "current_thread")]
async fn response_gate_preserves_new_start_and_existing_payload_progress() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let (_, empty) = tokio::sync::mpsc::channel(1);
            let incoming = std::mem::replace(&mut pair.received.datagrams, empty);
            let mut worker = crate::runtime::AbortTask(tokio::task::spawn_local(serve_datagrams(
                pair.connection.clone(),
                incoming,
            )));
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let live = [1; 16];
            let pending = [2; 16];
            send(&pair, registration(live, destination)).await;
            assert!(matches!(
                DatagramV3::decode(&pair.receive().await).unwrap(),
                DatagramV3::Response {
                    response_type: 0,
                    ..
                }
            ));
            let mut sender = pair.connection.sender.clone();
            let (entered, release) = sender.gate_next_registration_datagram();
            send(&pair, registration(pending, destination)).await;
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            send(&pair, payload(pending, b"must queue before response")).await;
            let mut buffer = [0; 64];
            assert!(
                timeout(Duration::from_millis(30), origin.recv_from(&mut buffer))
                    .await
                    .is_err()
            );
            send(&pair, payload(live, b"existing flow progresses")).await;
            origin_packet(&origin, b"existing flow progresses").await;
            release.send(Ok(())).unwrap();
            assert!(matches!(DatagramV3::decode(&pair.receive().await).unwrap(),
            DatagramV3::Response { id, response_type: 0, .. } if id == pending));
            origin_packet(&origin, b"must queue before response").await;
            pair.scope.cancellation().cancel();
            timeout(Duration::from_secs(1), &mut worker.0)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            drained(&state).await;
            assert_eq!(state.v3.len(), 0);
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn retry_refresh_waits_for_successful_response_send() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for fail in [true, false] {
                let config = crate::runtime::tests::config();
                let state = NetworkState::new(&config).unwrap();
                let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
                let (_, empty) = tokio::sync::mpsc::channel(1);
                let incoming = std::mem::replace(&mut pair.received.datagrams, empty);
                let mut worker = crate::runtime::AbortTask(tokio::task::spawn_local(
                    serve_datagrams(pair.connection.clone(), incoming),
                ));
                let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let destination = origin.local_addr().unwrap();
                let id = [3; 16];
                let registration = |destination, idle_seconds| {
                    DatagramV3::Registration {
                        id,
                        destination,
                        idle_seconds,
                        traced: false,
                        payload: vec![],
                    }
                    .encode()
                    .unwrap()
                };
                send(&pair, registration(destination, 1)).await;
                assert!(matches!(
                    DatagramV3::decode(&pair.receive().await).unwrap(),
                    DatagramV3::Response {
                        response_type: 0,
                        ..
                    }
                ));
                tokio::time::sleep(Duration::from_millis(700)).await;
                assert_eq!(state.v3.len(), 1);
                let mut sender = pair.connection.sender.clone();
                let (entered, release) = sender.gate_next_registration_datagram();
                send(&pair, registration("127.0.0.1:1".parse().unwrap(), 20)).await;
                timeout(Duration::from_secs(1), entered)
                    .await
                    .unwrap()
                    .unwrap();
                if fail {
                    timeout(Duration::from_millis(600), drained(&state)).await.expect(
                    "retry response that cannot be sent must not refresh prior idle lifetime"
                );
                    release
                        .send(Err(std::io::Error::other(
                            "synthetic response transport failure",
                        )))
                        .unwrap();
                } else {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    release.send(Ok(())).unwrap();
                    assert!(matches!(
                        DatagramV3::decode(&pair.receive().await).unwrap(),
                        DatagramV3::Response {
                            response_type: 0,
                            ..
                        }
                    ));
                    assert!(
                        timeout(Duration::from_millis(850), drained(&state))
                            .await
                            .is_err(),
                        "successful retry refresh must begin after the real response send"
                    );
                    timeout(Duration::from_millis(500), drained(&state))
                        .await
                        .unwrap();
                }
                assert_eq!(state.v3.len(), 0);
                assert_eq!(state.active_flows(), 0);
                pair.scope.cancellation().cancel();
                timeout(Duration::from_secs(1), &mut worker.0)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                pair.client.close();
                pair.peer.close();
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn saturated_registration_tasks_drop_only_new_requests_and_cancel_owned_attempts() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut config = crate::runtime::tests::config();
            config.icmpv4_src = Some("127.0.0.1".parse().unwrap());
            config.icmpv6_src = Some("::1".into());
            let mut state = NetworkState::new(&config).unwrap();
            // TTL conversion uses no ping socket and must not depend on host permissions.
            Arc::get_mut(&mut state).unwrap().icmp = icmp::IcmpRouter::fixture(&config, [true; 2]);
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let (_, empty) = tokio::sync::mpsc::channel(1);
            let incoming = std::mem::replace(&mut pair.received.datagrams, empty);
            let mut worker = crate::runtime::AbortTask(tokio::task::spawn_local(serve_datagrams(
                pair.connection.clone(),
                incoming,
            )));
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let live = [1; 16];
            send(&pair, registration(live, destination)).await;
            assert!(matches!(
                DatagramV3::decode(&pair.receive().await).unwrap(),
                DatagramV3::Response {
                    response_type: 0,
                    ..
                }
            ));
            let mut sender = pair.connection.sender.clone();
            let mut releases = Vec::new();
            for byte in 2..18 {
                let (entered, release) = sender.gate_next_registration_datagram();
                send(&pair, registration([byte; 16], destination)).await;
                timeout(Duration::from_secs(1), entered)
                    .await
                    .unwrap()
                    .unwrap();
                releases.push(release);
            }
            send(&pair, registration([99; 16], destination)).await;
            send(
                &pair,
                payload(live, b"payload bypasses registration saturation"),
            )
            .await;
            origin_packet(&origin, b"payload bypasses registration saturation").await;
            let ip = "127.0.0.1".parse().unwrap();
            let request = packet::IcmpPacket {
                source: ip,
                destination: ip,
                ttl: 1,
                message: vec![8, 0, 0, 0, 0, 1, 0, 1],
            }
            .encode()
            .unwrap();
            send(&pair, DatagramV3::Icmp(request).encode().unwrap()).await;
            let DatagramV3::Icmp(reply) = DatagramV3::decode(&pair.receive().await).unwrap() else {
                panic!("ICMP must progress while responses are pending")
            };
            assert_eq!(packet::IcmpPacket::decode(&reply).unwrap().message[0], 11);
            assert!(
                timeout(Duration::from_millis(100), pair.incoming.datagrams.recv())
                    .await
                    .is_err(),
                "saturation must fabricate no registration response"
            );
            assert_eq!(
                state.v3.len(),
                17,
                "active sessions have no invented maximum; only pending tasks are bounded"
            );
            assert_eq!(state.active_flows(), 17);
            pair.scope.cancellation().cancel();
            timeout(Duration::from_secs(1), &mut worker.0)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            drained(&state).await;
            assert_eq!(state.v3.len(), 0);
            for release in releases {
                assert!(
                    release.send(Ok(())).is_err(),
                    "each admitted send future must be dropped on attempt cancellation"
                );
            }
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn successful_duplicate_response_cannot_start_flow_before_creator_response() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut pair = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let (_, empty) = tokio::sync::mpsc::channel(1);
            let incoming = std::mem::replace(&mut pair.received.datagrams, empty);
            let mut worker = crate::runtime::AbortTask(tokio::task::spawn_local(serve_datagrams(
                pair.connection.clone(),
                incoming,
            )));
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let id = [4; 16];
            let mut sender = pair.connection.sender.clone();
            let (entered, creator) = sender.gate_next_registration_datagram();
            send(&pair, registration(id, destination)).await;
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            let (entered, retry) = sender.gate_next_registration_datagram();
            send(&pair, registration(id, destination)).await;
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            retry.send(Ok(())).unwrap();
            assert!(matches!(
                DatagramV3::decode(&pair.receive().await).unwrap(),
                DatagramV3::Response {
                    response_type: 0,
                    ..
                }
            ));
            send(&pair, payload(id, b"no writer before creator response")).await;
            let mut buffer = [0; 128];
            assert!(
                timeout(Duration::from_millis(100), origin.recv_from(&mut buffer))
                    .await
                    .is_err()
            );
            creator
                .send(Err(std::io::Error::other(
                    "synthetic initial response failure",
                )))
                .unwrap();
            drained(&state).await;
            assert_eq!(state.v3.len(), 0);
            assert!(
                timeout(Duration::from_millis(100), pair.incoming.datagrams.recv())
                    .await
                    .is_err()
            );
            pair.scope.cancellation().cancel();
            timeout(Duration::from_secs(1), &mut worker.0)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            pair.client.close();
            pair.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn canceled_creator_retires_pending_session_without_migration_response() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut creator = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let mut migrated = pair(state.clone(), &config, 1, DatagramVersion::V3).await;
            let (_, empty) = tokio::sync::mpsc::channel(1);
            let incoming = std::mem::replace(&mut creator.received.datagrams, empty);
            let mut worker = crate::runtime::AbortTask(tokio::task::spawn_local(serve_datagrams(
                creator.connection.clone(),
                incoming,
            )));
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let id = [5; 16];
            let mut sender = creator.connection.sender.clone();
            let (entered, release) = sender.gate_next_registration_datagram();
            send(&creator, registration(id, destination)).await;
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            let mut migration = pending_migration(&mut migrated, id, destination).await;
            assert!(
                timeout(
                    Duration::from_millis(30),
                    migrated.incoming.datagrams.recv()
                )
                .await
                .is_err()
            );
            assert_eq!(state.v3.len(), 1);
            creator.scope.cancellation().cancel();
            timeout(Duration::from_secs(1), &mut worker.0)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(release.send(Ok(())).is_err());
            assert!(
                timeout(Duration::from_secs(1), &mut migration)
                    .await
                    .unwrap()
                    .is_err()
            );
            assert!(
                timeout(
                    Duration::from_millis(30),
                    migrated.incoming.datagrams.recv()
                )
                .await
                .is_err()
            );
            timeout(Duration::from_millis(300), drained(&state))
                .await
                .expect(
                    "a canceled creator must retire its pending generation even after migration",
                );
            assert_eq!(state.v3.len(), 0);
            assert_eq!(state.active_flows(), 0);
            assert!(!migrated.scope.cancellation().is_cancelled());
            creator.client.close();
            creator.peer.close();
            migrated.client.close();
            migrated.peer.close();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn retired_creator_cleanup_preserves_replacement_generation() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let config = crate::runtime::tests::config();
            let state = NetworkState::new(&config).unwrap();
            let mut creator = pair(state.clone(), &config, 0, DatagramVersion::V3).await;
            let mut migrated = pair(state.clone(), &config, 1, DatagramVersion::V3).await;
            let mut replacement = pair(state.clone(), &config, 1, DatagramVersion::V3).await;
            let (_, empty) = tokio::sync::mpsc::channel(1);
            let incoming = std::mem::replace(&mut creator.received.datagrams, empty);
            let mut worker = crate::runtime::AbortTask(tokio::task::spawn_local(serve_datagrams(
                creator.connection.clone(),
                incoming,
            )));
            let origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = origin.local_addr().unwrap();
            let id = [6; 16];
            let mut sender = creator.connection.sender.clone();
            let (entered, release) = sender.gate_next_registration_datagram();
            send(&creator, registration(id, destination)).await;
            timeout(Duration::from_secs(1), entered)
                .await
                .unwrap()
                .unwrap();
            let mut migration = pending_migration(&mut migrated, id, destination).await;
            state.v3.remove(id, None).await;
            assert!(
                timeout(Duration::from_secs(1), &mut migration)
                    .await
                    .unwrap()
                    .is_err()
            );
            drained(&state).await;
            replacement.send(registration(id, destination)).await;
            assert!(matches!(
                DatagramV3::decode(&replacement.receive().await).unwrap(),
                DatagramV3::Response {
                    response_type: 0,
                    ..
                }
            ));
            creator.scope.cancellation().cancel();
            timeout(Duration::from_secs(1), &mut worker.0)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(release.send(Ok(())).is_err());
            assert_eq!(state.v3.len(), 1);
            assert_eq!(state.active_flows(), 1);
            replacement
                .send(payload(id, b"replacement remains live"))
                .await;
            origin_packet(&origin, b"replacement remains live").await;
            replacement.scope.cancellation().cancel();
            drained(&state).await;
            creator.client.close();
            creator.peer.close();
            migrated.client.close();
            migrated.peer.close();
            replacement.client.close();
            replacement.peer.close();
        })
        .await;
}
