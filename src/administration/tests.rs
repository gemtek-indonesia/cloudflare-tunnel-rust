use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[tokio::test]
async fn adhoc_creates_once_reuses_credentials_routes_and_rolls_back_failed_write() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let active = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captures = requests.clone();
    let state = active.clone();
    let id = Uuid::from_bytes([3; 16]);
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let captures = captures.clone();
            let state = state.clone();
            tasks.spawn(async move{
            let service=hyper::service::service_fn(move|request:http::Request<hyper::body::Incoming>|{
                let captures=captures.clone();let state=state.clone();async move{
                    let method=request.method().clone();let uri=request.uri().to_string();let body=request.into_body().collect().await.unwrap().to_bytes();
                    captures.lock().unwrap().push((method.clone(),uri.clone(),body.to_vec()));
                    let (status,result)=if method==http::Method::GET {(200,json!({"success":true,"result":if state.load(Ordering::Acquire){vec![json!({"id":id,"name":"fixture"})]}else{vec![]},"result_info":{"count":u64::from(state.load(Ordering::Acquire)),"per_page":100,"total_count":u64::from(state.load(Ordering::Acquire))}}))}
                    else if method==http::Method::POST {state.store(true,Ordering::Release);(200,json!({"success":true,"result":{"id":id,"name":"fixture"}}))}
                    else if method==http::Method::PUT {(500,json!({"success":false,"errors":[{"code":1000,"message":"synthetic route failure"}]}))}
                    else {state.store(false,Ordering::Release);(200,json!({"success":true}))};
                    Ok::<_,std::convert::Infallible>(http::Response::builder().status(status).body(Full::new(Bytes::from(serde_json::to_vec(&result).unwrap()))).unwrap())
                }
            });let _=hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(socket),service).await;
        });
        }
    });
    let dir = std::env::temp_dir().join(format!("cloudflared-adhoc-test-{}", Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let cert = dir.join("cert.pem");
    let credential = dir.join("credentials.json");
    let config = dir.join("config.yml");
    std::fs::write(&config, b"{}").unwrap();
    let account = credentials::AccountCredentials {
        zone_id: "synthetic-zone".into(),
        account_id: "synthetic-account".into(),
        api_token: "synthetic-token".into(),
        endpoint: String::new(),
    };
    let client = AccountClient::new(account, &format!("http://{address}/client/v4")).unwrap();
    let invocation = Invocation::parse(
        vec![
            "tunnel".into(),
            "--name".into(),
            "fixture".into(),
            "--hostname".into(),
            "fixture.example".into(),
            "--loglevel".into(),
            "fatal".into(),
            "--credentials-file".into(),
            credential.to_str().unwrap().into(),
            "--config".into(),
            config.to_str().unwrap().into(),
        ],
        &Default::default(),
        None,
    )
    .unwrap();
    let first = prepare_adhoc_with_client(&invocation, &client, &cert)
        .await
        .unwrap();
    assert_eq!(first.tunnel_id, id);
    assert_eq!(first.tunnel_secret.len(), 32);
    let saved = std::fs::read(&credential).unwrap();
    let second = prepare_adhoc_with_client(&invocation, &client, &cert)
        .await
        .unwrap();
    assert_eq!(second.tunnel_secret, first.tunnel_secret);
    assert_eq!(std::fs::read(&credential).unwrap(), saved);
    assert!(
        create_with_credentials(
            &client,
            "another",
            vec![7; 32],
            credential.to_str().unwrap(),
            &cert
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(&credential).unwrap(), saved);
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|(method, _, _)| method == http::Method::POST)
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|(method, _, _)| method == http::Method::PUT)
            .count(),
        2
    );
    assert!(
        requests.iter().any(
            |(method, uri, _)| method == http::Method::DELETE && uri.ends_with("?cascade=true")
        )
    );
    let route: Value = serde_json::from_slice(
        &requests
            .iter()
            .find(|(method, _, _)| method == http::Method::PUT)
            .unwrap()
            .2,
    )
    .unwrap();
    assert_eq!(
        route,
        json!({"type":"dns","user_hostname":"fixture.example","overwrite_existing":false})
    );
    drop(requests);
    server.abort();
    std::fs::remove_dir_all(dir).unwrap();
}
