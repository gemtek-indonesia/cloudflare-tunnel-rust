use super::*;
use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
};

async fn origin_request(service: &str) -> Vec<u8> {
    let context = crate::observability::Context::quiet().unwrap();
    let settings = crate::config::OriginRequest {
        http_host_header: Some("origin-host.invalid".into()),
        ..Default::default()
    };
    let origin = origin::Origin::new(service, settings, &context).unwrap();
    let head = RequestHead::new(
        http::Method::GET,
        "https://incoming.invalid/raw?x=%ff".parse().unwrap(),
        http::HeaderMap::new(),
        "incoming.invalid".into(),
        false,
        false,
    )
    .unwrap();
    origin
        .request(&head, body::ChannelBody::empty())
        .await
        .unwrap()
        .response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}
#[tokio::test]
async fn origin_physical_case_port_and_unix_dial_override_use_environment_proxy() {
    const CHILD: &str = "CLOUDFLARED_ORIGIN_PROXY_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert_eq!(
            origin_request("http://synthetic.invalid:080").await,
            b"proxy"
        );
        let localhost = std::env::var("CLOUDFLARED_ORIGIN_PROXY_TEST_LOCALHOST").unwrap();
        assert_eq!(origin_request(&localhost).await, b"proxy");
        let unix = std::env::var("CLOUDFLARED_ORIGIN_PROXY_TEST_UNIX").unwrap();
        assert_eq!(origin_request(&unix).await, b"unix");
        return;
    }
    let mut proxy = crate::proxy_environment::fixtures::HttpPeer::start(
        http::StatusCode::OK,
        Bytes::from_static(b"proxy"),
    )
    .await;
    let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let direct_address = direct.local_addr().unwrap();
    let directory = std::env::temp_dir().join(format!("origin-proxy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let socket_path = directory.join("origin.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let unix = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
            assert!(head.len() < 16 * 1024);
        }
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("GET http://incoming.invalid/raw?x=%ff HTTP/1.1\r\n"));
        assert!(head.to_ascii_lowercase().contains("proxy-authorization:"));
        assert!(
            head.to_ascii_lowercase()
                .contains("host: incoming.invalid\r\n")
        );
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nunix")
            .await
            .unwrap();
    });
    let output=tokio::process::Command::new(std::env::current_exe().unwrap())
        .env_clear().env(CHILD,"1")
        .env("HTTP_PROXY",format!("http://synthetic-user:synthetic-password@{}",proxy.address))
        .env("NO_PROXY","synthetic.invalid:80")
        .env("CLOUDFLARED_ORIGIN_PROXY_TEST_LOCALHOST",format!("http://LOCALHOST:{}",direct_address.port()))
        .env("CLOUDFLARED_ORIGIN_PROXY_TEST_UNIX",format!("unix:{}",socket_path.display()))
        .args(["--exact","proxy::proxy_environment_tests::origin_physical_case_port_and_unix_dial_override_use_environment_proxy","--nocapture"])
        .output().await.unwrap();
    assert!(output.status.success(), "owned origin proxy child failed");
    let first = proxy.requests.recv().await.unwrap();
    assert_eq!(
        first.uri.to_string(),
        "http://origin-host.invalid/raw?x=%ff"
    );
    assert_eq!(first.headers[http::header::HOST], "origin-host.invalid");
    assert!(
        first
            .headers
            .contains_key(http::header::PROXY_AUTHORIZATION)
    );
    let second = proxy.requests.recv().await.unwrap();
    assert_eq!(second.uri.host(), Some("origin-host.invalid"));
    assert!(
        second
            .headers
            .contains_key(http::header::PROXY_AUTHORIZATION)
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), direct.accept())
            .await
            .is_err()
    );
    unix.await.unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
#[ignore = "requires the pinned Go proxy environment oracle"]
async fn go_unix_origin_keeps_proxy_selection_and_unix_dial_override() {
    let oracle = std::env::var_os("CLOUDFLARED_GO_PROXY_ORACLE").expect("pinned Go proxy oracle");
    let directory = std::env::temp_dir().join(format!("go-unix-proxy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("origin.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = proxy.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
            assert!(head.len() < 16 * 1024);
        }
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("GET http://incoming.invalid/raw?x=%ff HTTP/1.1\r\n"));
        assert!(head.to_ascii_lowercase().contains("proxy-authorization:"));
        assert!(
            head.to_ascii_lowercase()
                .contains("host: incoming.invalid\r\n")
        );
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nunix")
            .await
            .unwrap();
    });
    let mut child = tokio::process::Command::new(oracle)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let input = serde_json::json!({"environment":{"HTTP_PROXY":format!("http://synthetic-user:synthetic-password@{endpoint}")},"probe":"http://incoming.invalid/raw?x=%ff","unix":path,"host":"incoming.invalid"});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .await
        .unwrap();
    let output = child.wait_with_output().await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["success"], true);
    assert_eq!(
        response["body"],
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"unix")
    );
    peer.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), proxy.accept())
            .await
            .is_err()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
#[ignore = "requires the pinned Go proxy environment oracle"]
async fn go_http_origin_uses_physical_route_and_host_absolute_target() {
    let oracle = std::env::var_os("CLOUDFLARED_GO_PROXY_ORACLE").expect("pinned Go proxy oracle");
    let mut proxy = crate::proxy_environment::fixtures::HttpPeer::start(
        http::StatusCode::OK,
        Bytes::from_static(b"owned"),
    )
    .await;
    let mut child = tokio::process::Command::new(oracle)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let input = serde_json::json!({"environment":{"HTTP_PROXY":format!("http://synthetic-user:synthetic-password@{}",proxy.address),"NO_PROXY":"physical.invalid:80"},"probe":"http://physical.invalid:080/raw?x=%ff","host":"origin-host.invalid"});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .await
        .unwrap();
    let output = tokio::time::timeout(std::time::Duration::from_secs(4), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["success"], true);
    let received = proxy.requests.recv().await.unwrap();
    assert_eq!(
        received.uri.to_string(),
        "http://origin-host.invalid/raw?x=%ff"
    );
    assert_eq!(received.headers[http::header::HOST], "origin-host.invalid");
    assert!(
        received
            .headers
            .contains_key(http::header::PROXY_AUTHORIZATION)
    );
}
