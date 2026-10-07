use super::*;
use std::sync::{Arc, Mutex};

async fn pages(pages: Vec<Value>) -> (Result<Vec<Value>>, Vec<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let queries = Arc::new(Mutex::new(Vec::new()));
    let captured = queries.clone();
    let pages = Arc::new(pages);
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let captured = captured.clone();
            let pages = pages.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| {
                        let captured = captured.clone();
                        let pages = pages.clone();
                        async move {
                            let mut queries = captured.lock().unwrap();
                            let index = queries.len();
                            queries.push(request.uri().query().unwrap_or("").to_owned());
                            let (status, body) = pages.get(index).map_or(
                                (http::StatusCode::BAD_REQUEST, json!({"success":false})),
                                |value| (http::StatusCode::OK, value.clone()),
                            );
                            Ok::<_, std::convert::Infallible>(
                                http::Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from(
                                        serde_json::to_vec(&body).unwrap(),
                                    )))
                                    .unwrap(),
                            )
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let client = AccountClient::new(
        AccountCredentials {
            account_id: "synthetic-account".into(),
            zone_id: "synthetic-zone".into(),
            api_token: "synthetic-token".into(),
            endpoint: String::new(),
        },
        &format!("http://{address}/client/v4"),
    )
    .unwrap();
    let result = client.tunnels(vec![("is_deleted", "false".into())]).await;
    server.abort();
    let _ = server.await;
    let queries = queries.lock().unwrap().clone();
    (result, queries)
}

fn corpus() -> Vec<Vec<Value>> {
    vec![
        vec![
            json!({"success":true,"result":null,"result_info":{"count":0,"per_page":10,"total_count":0}}),
        ],
        vec![json!({"success":true,"result":[],"result_info":null})],
        vec![
            json!({"success":true,"result":[],"result_info":{"count":null,"page":null,"per_page":10,"total_count":0}}),
        ],
        vec![
            json!({"success":true,"result":[],"result_info":{"count":"0","per_page":10,"total_count":0}}),
        ],
        vec![
            json!({"success":true,"result":[],"result_info":{"count":0.0,"per_page":10,"total_count":0}}),
        ],
        vec![json!({"success":true,"result":[],"result_info":[]})],
        vec![json!({"success":true,"result_info":{"count":0,"per_page":10,"total_count":0}})],
        vec![json!({"success":true,"result":[],"result_info":{"page":"invalid"}})],
        vec![
            json!({"success":true,"result":[],"result_info":{"count":-1,"per_page":0,"total_count":2}}),
        ],
        vec![
            json!({"success":true,"result":[{"name":"one"}],"result_info":{"count":1,"per_page":1,"total_count":2}}),
            json!({"success":true,"result":[{"name":"two"}],"result_info":{"count":1,"per_page":1,"total_count":2}}),
        ],
        vec![
            json!({"success":true,"result":[{"name":"one"}],"result_info":{"count":1,"per_page":2,"total_count":8}}),
        ],
        vec![
            json!({"success":true,"result":[{"name":"one"}],"result_info":{"count":1,"per_page":1,"total_count":3}}),
            json!({"success":false,"errors":[{"code":123,"message":"synthetic failure"}]}),
        ],
        vec![
            json!({"success":true,"result":{},"result_info":{"count":0,"per_page":10,"total_count":0}}),
        ],
    ]
}

#[tokio::test]
async fn pagination_accepts_null_and_rejects_malformed_metadata() {
    for (index, pages_input) in corpus().into_iter().enumerate() {
        let succeeds = [0, 1, 2, 8, 9, 10].contains(&index);
        let (result, queries) = pages(pages_input).await;
        assert_eq!(result.is_ok(), succeeds, "case{index}");
        assert_eq!(
            queries.len(),
            if [9, 11].contains(&index) { 2 } else { 1 },
            "case{index}"
        );
        if index == 9 {
            assert_eq!(result.unwrap().len(), 2);
        }
    }
}

#[tokio::test]
#[ignore = "requires pinned Go administration oracle; run scripts/test-interop.sh"]
async fn go_administration_pagination_contract() {
    let directory = std::env::temp_dir().join(format!("admin-page-oracle-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let empty = directory.join("empty.pem");
    std::fs::write(&empty, b"").unwrap();
    for (index, inputs) in corpus().into_iter().enumerate() {
        let file = directory.join("input.json");
        std::fs::write(
            &file,
            serde_json::to_vec(
                &json!({"command":"list","args":["--output","json"],"pages":inputs}),
            )
            .unwrap(),
        )
        .unwrap();
        let output = std::process::Command::new(
            std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE").expect("run scripts/test-interop.sh"),
        )
        .arg(&file)
        .env_clear()
        .env("HOME", &directory)
        .env("SSL_CERT_FILE", &empty)
        .env("SSL_CERT_DIR", directory.join("missing"))
        .env("TZ", "UTC")
        .output()
        .unwrap();
        assert!(output.status.success(), "source case{index}");
        let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
        let (actual, queries) = pages(inputs).await;
        assert_eq!(
            actual.is_err(),
            expected["failure"].as_bool().unwrap(),
            "case{index}"
        );
        assert_eq!(json!(queries), expected["queries"], "case{index}");
    }
    std::fs::remove_dir_all(directory).unwrap();
}
