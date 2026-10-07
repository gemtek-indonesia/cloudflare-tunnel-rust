use super::*;
use futures::FutureExt;

struct Callbacks;
impl EdgeCallbacks for Callbacks {
    fn update_configuration(
        &self,
        version: i32,
        _: Vec<u8>,
    ) -> LocalBoxFuture<'static, ConfigurationResult> {
        async move {
            ConfigurationResult {
                latest_applied_version: version,
                error: "synthetic configuration rejection".into(),
            }
        }
        .boxed_local()
    }
    fn register_udp_session(
        &self,
        _: UdpRegistration,
    ) -> LocalBoxFuture<'static, Result<UdpRegistrationResult, capnp::Error>> {
        async {
            Ok(UdpRegistrationResult {
                error: "synthetic origin unavailable".into(),
                spans: vec![],
            })
        }
        .boxed_local()
    }
    fn unregister_udp_session(
        &self,
        _: Uuid,
        _: String,
    ) -> LocalBoxFuture<'static, Result<(), capnp::Error>> {
        async { Err(capnp::Error::failed("synthetic method failure".into())) }.boxed_local()
    }
}
#[tokio::test(flavor = "current_thread")]
async fn actual_rpc_methods_count_success_decode_failure_and_normal_lifetime_expiry() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let metrics = Metrics::new().unwrap();
            let (client_io, server_io) = tokio::io::duplex(4096);
            let server = tokio::task::spawn_local(serve_callbacks(
                server_io,
                Rc::new(Callbacks),
                Duration::from_millis(100),
                metrics.clone(),
            ));
            let (read, write) = tokio::io::split(client_io);
            let network = twoparty::VatNetwork::new(
                read.compat(),
                write.compat_write(),
                Side::Client,
                crate::protocol::reader_options(),
            );
            let mut rpc = RpcSystem::new(Box::new(network), None);
            let config: wire::configuration_manager::Client = rpc.bootstrap(Side::Server);
            let sessions: wire::session_manager::Client = rpc.bootstrap(Side::Server);
            let driver = tokio::task::spawn_local(rpc);
            let mut update = config.update_configuration_request();
            update.get().set_version(7);
            update.get().set_config(b"{}");
            let result = update.send().promise.await.unwrap();
            assert_eq!(
                result
                    .get()
                    .unwrap()
                    .get_result()
                    .unwrap()
                    .get_err()
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "synthetic configuration rejection"
            );
            let mut register = sessions.register_udp_session_request();
            register.get().set_session_id(Uuid::nil().as_bytes());
            register.get().set_dst_ip(&[127, 0, 0, 1]);
            let result = register.send().promise.await.unwrap();
            assert_eq!(
                result
                    .get()
                    .unwrap()
                    .get_result()
                    .unwrap()
                    .get_err()
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "synthetic origin unavailable"
            );
            let mut malformed = sessions.register_udp_session_request();
            malformed.get().set_session_id(&[1, 2]);
            assert!(malformed.send().promise.await.is_err());
            let mut unregister = sessions.unregister_udp_session_request();
            unregister.get().set_session_id(Uuid::nil().as_bytes());
            assert!(unregister.send().promise.await.is_err());
            assert_eq!(
                metrics
                    .rpc_server_operations
                    .with_label_values(&["config", "update_configuration"])
                    .get(),
                1
            );
            assert_eq!(
                metrics
                    .rpc_server_failures
                    .with_label_values(&["config", "update_configuration"])
                    .get(),
                0,
                "application rejection is a successful RPC response"
            );
            assert_eq!(
                metrics
                    .rpc_server_operations
                    .with_label_values(&["session", "register_udp_session"])
                    .get(),
                2
            );
            assert_eq!(
                metrics
                    .rpc_server_failures
                    .with_label_values(&["session", "register_udp_session"])
                    .get(),
                1
            );
            assert_eq!(
                metrics
                    .rpc_server_failures
                    .with_label_values(&["session", "unregister_udp_session"])
                    .get(),
                1
            );
            assert!(
                server.await.unwrap().is_ok(),
                "whole callback expiry is normal source completion"
            );
            assert_eq!(
                metrics
                    .rpc_server_failures
                    .with_label_values(&["config", "update_configuration"])
                    .get(),
                0
            );
            driver.abort();
            let _ = driver.await;
        })
        .await;
}
