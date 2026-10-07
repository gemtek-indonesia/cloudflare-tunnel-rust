use super::*;
use http_body_util::{Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::BTreeMap;
use tokio::io::AsyncWriteExt;

#[derive(Clone, serde::Serialize)]
struct Case {
    method: String,
    headers: BTreeMap<String, Vec<String>>,
    coding: String,
    corrupt: bool,
    truncate: bool,
    concatenated: bool,
    garbage: String,
}

async fn observed(case: &Case, payload: Bytes) -> serde_json::Value {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let coding = case.coding.clone();
    let (headers, seen) = tokio::sync::oneshot::channel();
    let headers = Arc::new(Mutex::new(Some(headers)));
    let server = crate::runtime::AbortTask(tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let service = hyper::service::service_fn(move |request: http::Request<Incoming>| {
            let coding = coding.clone();
            let payload = payload.clone();
            let values = request
                .headers()
                .get_all(header::ACCEPT_ENCODING)
                .iter()
                .map(|value| value.to_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            headers
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(values)
                .unwrap();
            async move {
                Ok::<_, io::Error>(
                    Response::builder()
                        .header(header::CONTENT_ENCODING, coding)
                        .header(header::CONTENT_LENGTH, payload.len())
                        .body(Full::new(payload))
                        .unwrap(),
                )
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(socket), service)
            .await;
    }));
    let mut request = http::Request::builder()
        .method(case.method.as_str())
        .uri(format!("http://{address}/"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    for (key, values) in &case.headers {
        let key: http::header::HeaderName = key.parse().unwrap();
        for value in values {
            request
                .headers_mut()
                .append(&key, http::HeaderValue::from_str(value).unwrap());
        }
    }
    let method = request.method().clone();
    let added = prepare_gzip(&method, request.headers_mut());
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build_http::<Empty<Bytes>>();
    let mut result = response(client.request(request).await.unwrap(), added);
    let encoding = result
        .headers()
        .get(header::CONTENT_ENCODING)
        .map_or("", |value| value.to_str().unwrap())
        .to_owned();
    let length = result
        .headers()
        .get(header::CONTENT_LENGTH)
        .map_or(-1, |value| value.to_str().unwrap().parse::<i64>().unwrap());
    let mut bytes = Vec::new();
    let mut read_error = false;
    while let Some(frame) = result.body_mut().frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(value) = frame.into_data() {
                    bytes.extend_from_slice(&value)
                }
            }
            Err(_) => {
                read_error = true;
                break;
            }
        }
    }
    let wire = seen.await.unwrap();
    drop(server);
    serde_json::json!({"wire_encoding":if wire.is_empty(){serde_json::Value::Null}else{serde_json::json!(wire)},"content_encoding":encoding,"length":length,"body":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,bytes),"read_error":read_error,"uncompressed":added&&encoding.is_empty()})
}

#[tokio::test]
#[ignore = "requires the pinned Go HTTP policy oracle"]
async fn go_gzip_insertion_decoding_and_lazy_error_contract() {
    let oracle = std::env::var_os("CLOUDFLARED_GO_HTTP_POLICY_ORACLE")
        .expect("pinned Go HTTP policy oracle");
    let mut cases = Vec::new();
    for (method, headers) in [
        ("GET", BTreeMap::new()),
        ("HEAD", BTreeMap::new()),
        (
            "GET",
            BTreeMap::from([("Accept-Encoding".into(), vec!["".into()])]),
        ),
        (
            "GET",
            BTreeMap::from([("Accept-Encoding".into(), vec!["".into(), "br".into()])]),
        ),
        (
            "GET",
            BTreeMap::from([("Accept-Encoding".into(), vec!["gzip".into()])]),
        ),
        (
            "GET",
            BTreeMap::from([("Accept-Encoding".into(), vec!["br".into()])]),
        ),
        ("GET", BTreeMap::from([("Range".into(), vec!["".into()])])),
        (
            "GET",
            BTreeMap::from([("Range".into(), vec!["bytes=0-10".into()])]),
        ),
        (
            "GET",
            BTreeMap::from([("Range".into(), vec!["".into(), "bytes=0-10".into()])]),
        ),
    ] {
        for coding in ["gzip", "GZIP", "gzip, br", "gzip "] {
            cases.push(Case {
                method: method.into(),
                headers: headers.clone(),
                coding: coding.into(),
                corrupt: false,
                truncate: false,
                concatenated: false,
                garbage: String::new(),
            });
        }
    }
    for (corrupt, truncate, concatenated) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        cases.push(Case {
            method: "GET".into(),
            headers: BTreeMap::new(),
            coding: "gzip".into(),
            corrupt,
            truncate,
            concatenated,
            garbage: String::new(),
        });
    }
    for garbage in ["x", "trailing-garbage", "\0\0\0"] {
        cases.push(Case {
            method: "GET".into(),
            headers: BTreeMap::new(),
            coding: "gzip".into(),
            corrupt: false,
            truncate: false,
            concatenated: false,
            garbage: garbage.into(),
        });
    }
    let mut child = tokio::process::Command::new(oracle)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&cases).unwrap())
        .await
        .unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(output.status.success());
    let expected: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for (case, mut expected) in cases.iter().zip(expected) {
        let payload = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            expected["wire_body"].as_str().unwrap(),
        )
        .unwrap();
        expected.as_object_mut().unwrap().remove("wire_body");
        assert_eq!(
            observed(case, Bytes::from(payload)).await,
            expected,
            "method={} headers={:?} coding={} corrupt={} truncate={}",
            case.method,
            case.headers,
            case.coding,
            case.corrupt,
            case.truncate
        );
    }
}

async fn compressed(value: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut encoder = async_compression::tokio::write::GzipEncoder::new(Vec::new());
    encoder.write_all(value).await.unwrap();
    encoder.flush().await.unwrap();
    let prefix = encoder.get_ref().clone();
    encoder.shutdown().await.unwrap();
    let full = encoder.into_inner();
    (prefix, full)
}

async fn chunk<W: tokio::io::AsyncWrite + Unpin>(socket: &mut W, bytes: &[u8]) {
    socket
        .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
        .await
        .unwrap();
    socket.write_all(bytes).await.unwrap();
    socket.write_all(b"\r\n").await.unwrap();
}

#[tokio::test]
async fn decoded_first_chunk_precedes_origin_eof_and_trailers_follow_success() {
    use tokio::io::AsyncReadExt;
    let expected = vec![b'x'; 32768];
    let (prefix, full) = compressed(&expected).await;
    let remaining = full[prefix.len()..].to_vec();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (release, wait) = tokio::sync::oneshot::channel();
    let mut server = crate::runtime::AbortTask(tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\nConnection: close\r\n\r\n").await.unwrap();
        chunk(&mut socket, &prefix).await;
        wait.await.unwrap();
        chunk(&mut socket, &remaining).await;
        socket
            .write_all(b"0\r\nX-End: owned-trailer\r\n\r\n")
            .await
            .unwrap();
    }));
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build_http::<Empty<Bytes>>();
    let incoming = client
        .get(format!("http://{address}/").parse().unwrap())
        .await
        .unwrap();
    let mut body = response(incoming, true).into_body();
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(!first.is_empty());
    assert!(!server.0.is_finished());
    release.send(()).unwrap();
    let mut decoded = first.to_vec();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.unwrap();
        match frame.into_data() {
            Ok(data) => decoded.extend_from_slice(&data),
            Err(frame) => {
                assert_eq!(decoded, expected);
                trailers = Some(frame.into_trailers().unwrap());
            }
        }
    }
    assert_eq!(decoded, expected);
    assert_eq!(trailers.unwrap()["x-end"], "owned-trailer");
    (&mut server.0).await.unwrap();
}

#[tokio::test]
async fn dropping_streaming_decoder_cancels_owned_pending_origin_body() {
    use tokio::io::AsyncReadExt;
    let (prefix, _) = compressed(&vec![b'x'; 32768]).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        chunk(&mut socket, &prefix).await;
        let mut remainder = Vec::new();
        socket.read_to_end(&mut remainder).await.unwrap();
        assert!(remainder.is_empty());
    });
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build_http::<Empty<Bytes>>();
    let incoming = client
        .get(format!("http://{address}/").parse().unwrap())
        .await
        .unwrap();
    let mut body = response(incoming, true).into_body();
    assert!(
        !tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap()
            .is_empty()
    );
    drop(body);
    tokio::time::timeout(std::time::Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn invalid_gzip_footer_never_forwards_origin_trailers() {
    use tokio::io::AsyncReadExt;
    let (_, mut payload) = compressed(b"owned-body").await;
    let footer = payload.len() - 8;
    payload[footer] ^= 1;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\nConnection: close\r\n\r\n").await.unwrap();
        chunk(&mut socket, &payload).await;
        socket
            .write_all(b"0\r\nX-End: invalid-footer\r\n\r\n")
            .await
            .unwrap();
    });
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build_http::<Empty<Bytes>>();
    let incoming = client
        .get(format!("http://{address}/").parse().unwrap())
        .await
        .unwrap();
    let mut body = response(incoming, true).into_body();
    let mut failed = false;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => assert!(!frame.is_trailers()),
            Err(_) => failed = true,
        }
    }
    assert!(failed);
    server.await.unwrap();
}

#[tokio::test]
async fn bounded_consumers_limit_decoded_bytes() {
    let expected = vec![b'x'; 65536];
    let (_, payload) = compressed(&expected).await;
    assert!(payload.len() < 1024);
    let mut peer = crate::proxy_environment::fixtures::HttpPeer::start_with_headers(
        http::StatusCode::OK,
        Bytes::from(payload),
        HeaderMap::from_iter([(
            header::CONTENT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        )]),
    )
    .await;
    let client = crate::proxy_environment::client::HttpClient::<Empty<Bytes>>::new(
        crate::proxy_environment::client::Connector::platform()
            .unwrap()
            .with_settings(Arc::new(
                crate::proxy_environment::EnvironmentProxy::from_environment(&BTreeMap::new()),
            )),
    );
    for limit in [1024, expected.len()] {
        let mut response = client
            .get(format!("http://{}/", peer.address).parse().unwrap())
            .await
            .unwrap();
        let body = crate::access::bounded_body(&mut response, limit).await;
        if limit == 1024 {
            assert_eq!(
                body.unwrap_err().to_string(),
                "HTTP response exceeds maximum size"
            );
        } else {
            assert_eq!(body.unwrap(), expected);
        }
        assert_eq!(
            peer.requests.recv().await.unwrap().headers[header::ACCEPT_ENCODING],
            "gzip"
        );
    }
}
