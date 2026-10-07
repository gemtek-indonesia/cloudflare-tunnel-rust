use super::*;
use crate::cli::Invocation;
use http_body_util::BodyExt;
use std::collections::BTreeMap;
#[tokio::test]
async fn public_and_protected_provisioning_bind_real_runtime_inputs() {
    for protected in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream),hyper::service::service_fn(move|request:http::Request<hyper::body::Incoming>|async move {
                assert_eq!(request.method(),"POST");
                let path=request.uri().path().to_owned();
                let bytes=request.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(bytes.as_ref(),if protected {br#"{"auth_mode":"otp"}"#.as_slice()}else{b"".as_slice()});
                if path=="/tunnel" {
                    return Ok::<_,std::io::Error>(http::Response::builder().status(308).header(http::header::LOCATION,"/redirected-tunnel").body(Full::new(Bytes::new())).unwrap());
                }
                assert_eq!(path,"/redirected-tunnel");
                let json=serde_json::json!({"success":true,"result":{"id":"00000000-0000-4000-8000-000000000042","hostname":"synthetic.trycloudflare.com","account_tag":"synthetic-account","secret":STANDARD.encode(b"synthetic-secret")}});
                Ok::<_,std::io::Error>(http::Response::new(Full::new(Bytes::from(serde_json::to_vec(&json).unwrap()))))
            })).await.unwrap();
        });
        let mut args = vec![
            "--config".into(),
            "/dev/null".into(),
            "tunnel".into(),
            "--hello-world".into(),
            "--quick-service".into(),
            format!("http://{address}"),
        ];
        if protected {
            args.extend(["--allowed-mail".into(), "visitor@example.invalid".into()]);
        }
        let invocation = Invocation::parse(args, &BTreeMap::new(), None).unwrap();
        let config = prepare(&invocation).await.unwrap();
        assert_eq!(
            config.credentials.tunnel_id.to_string(),
            "00000000-0000-4000-8000-000000000042"
        );
        assert_eq!(config.credentials.tunnel_secret, b"synthetic-secret");
        assert_eq!(config.quick_hostname, "synthetic.trycloudflare.com");
        assert_eq!(config.ha_connections, 1);
        assert_eq!(config.protocol, Protocol::Quic);
        assert_eq!(config.quick_authorizer.is_some(), protected);
        server.abort();
        let _ = server.await;
    }
}
