use super::*;
use http_body_util::{Full, StreamBody};
use hyper::body::Frame;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

fn response(status: u16, location: Option<&str>) -> Response<ResponseBody> {
    let mut response = Response::builder().status(status);
    if let Some(location) = location {
        response = response.header(header::LOCATION, location);
    }
    response
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap()
}

#[tokio::test]
async fn methods_replay_and_sticky_body_drop() {
    for status in [301, 302, 303, 307, 308] {
        for method in ["GET", "HEAD", "POST", "PUT", "DELETE"] {
            let mut calls = 0;
            let request = Request::builder()
                .method(method)
                .uri("https://synthetic.invalid/start")
                .body(Full::new(Bytes::from_static(b"owned-body")))
                .unwrap();
            follow(request, |request| {
                calls += 1;
                let call = calls;
                async move {
                    let (parts, body) = request.into_parts();
                    let body = body.collect().await.unwrap().to_bytes();
                    if call == 1 {
                        assert_eq!(body, "owned-body");
                        Ok(response(status, Some("/final")))
                    } else {
                        let expected = if status < 307 && !["GET", "HEAD"].contains(&method) {
                            "GET"
                        } else {
                            method
                        };
                        assert_eq!(parts.method, expected);
                        assert_eq!(body, if status < 307 { "" } else { "owned-body" });
                        Ok(response(200, None))
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(calls, 2);
        }
    }
    for statuses in [vec![302, 307], vec![307, 302, 308], vec![301, 303, 308]] {
        let mut calls = 0;
        let request = Request::builder()
            .method("PUT")
            .uri("https://synthetic.invalid/start")
            .body(Full::new(Bytes::from_static(b"owned-body")))
            .unwrap();
        follow(request, |request| {
            let call = calls;
            calls += 1;
            let dropped = call > 0 && (statuses[0] < 307 || call > 1);
            let status = statuses.get(call).copied().unwrap_or(200);
            async move {
                let body = request.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(body.is_empty(), dropped);
                Ok(response(status, Some("/next")))
            }
        })
        .await
        .unwrap();
        assert_eq!(calls, statuses.len() + 1);
    }
}

#[tokio::test]
async fn original_headers_and_sticky_sensitive_filter() {
    let targets = [
        "https://sub.synthetic.invalid:081/one",
        "https://outside.invalid/two",
        "https://synthetic.invalid/three",
    ];
    let sensitive = [
        "authorization",
        "www-authenticate",
        "cookie",
        "cookie2",
        "proxy-authorization",
        "proxy-authenticate",
    ];
    let body_headers = [
        "content-encoding",
        "content-language",
        "content-location",
        "content-type",
    ];
    let mut request = Request::builder()
        .method("PUT")
        .uri("https://synthetic.invalid:080/start")
        .header("x-original", "owned")
        .body(Full::new(Bytes::from_static(b"owned-body")))
        .unwrap();
    for name in sensitive.into_iter().chain(body_headers) {
        request
            .headers_mut()
            .insert(name, http::HeaderValue::from_static("owned"));
    }
    let mut calls = 0;
    follow(request, |request| {
        for name in sensitive {
            assert_eq!(request.headers().contains_key(name), calls < 2);
        }
        if calls > 0 {
            for name in body_headers {
                assert!(!request.headers().contains_key(name));
            }
        }
        assert_eq!(request.headers()["x-original"], "owned");
        let result = targets
            .get(calls)
            .map_or_else(|| response(200, None), |target| response(302, Some(target)));
        calls += 1;
        std::future::ready(Ok(result))
    })
    .await
    .unwrap();
    assert_eq!(calls, 4);
}

#[tokio::test]
async fn host_userinfo_referer_and_header_first_value() {
    for (base, location, host, explicit, expected_host, expected_ref, expected_auth) in [
        (
            "https://synthetic.invalid/a",
            "/b",
            Some("bound.invalid:123"),
            None,
            Some("bound.invalid:123"),
            Some("https://synthetic.invalid/a"),
            None,
        ),
        (
            "https://synthetic.invalid/a",
            "//other.invalid/b",
            Some("bound.invalid:123"),
            None,
            Some("bound.invalid:123"),
            Some("https://synthetic.invalid/a"),
            None,
        ),
        (
            "https://synthetic.invalid/a",
            "https://other.invalid/b",
            Some("bound.invalid:123"),
            None,
            None,
            Some("https://synthetic.invalid/a"),
            None,
        ),
        (
            "https://synthetic.invalid/a",
            "http://synthetic.invalid/b",
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "https://synthetic.invalid/a",
            "http://synthetic.invalid/b",
            None,
            Some("synthetic-explicit"),
            None,
            Some("synthetic-explicit"),
            None,
        ),
        (
            "https://user:password@synthetic.invalid/a",
            "/b",
            None,
            None,
            None,
            Some("https://synthetic.invalid/a"),
            Some("Basic dXNlcjpwYXNzd29yZA=="),
        ),
        (
            "https://synthetic.invalid/a",
            "https://user:password@other.invalid/b",
            None,
            None,
            None,
            Some("https://synthetic.invalid/a"),
            Some("Basic dXNlcjpwYXNzd29yZA=="),
        ),
    ] {
        let mut request = Request::builder()
            .uri(base)
            .body(Full::<Bytes>::default())
            .unwrap();
        if let Some(host) = host {
            request
                .headers_mut()
                .insert(header::HOST, host.parse().unwrap());
        }
        if let Some(explicit) = explicit {
            request
                .headers_mut()
                .insert(header::REFERER, explicit.parse().unwrap());
        }
        let mut calls = 0;
        follow(request, |request| {
            calls += 1;
            let result = if calls == 1 {
                response(302, Some(location))
            } else {
                for (name, expected) in [
                    (header::HOST, expected_host),
                    (header::REFERER, expected_ref),
                    (header::AUTHORIZATION, expected_auth),
                ] {
                    assert_eq!(
                        request
                            .headers()
                            .get(name)
                            .map(|value| value.to_str().unwrap()),
                        expected
                    );
                }
                response(200, None)
            };
            std::future::ready(Ok(result))
        })
        .await
        .unwrap();
    }
    for values in [
        vec![""],
        vec!["", "Bearer synthetic-later"],
        vec!["Bearer synthetic-first", ""],
    ] {
        let mut request = Request::builder()
            .uri("https://synthetic.invalid/start")
            .body(Full::<Bytes>::default())
            .unwrap();
        for value in &values {
            request
                .headers_mut()
                .append(header::AUTHORIZATION, value.parse().unwrap());
        }
        let mut calls = 0;
        follow(request, |request| {
            calls += 1;
            let result = if calls == 1 {
                response(302, Some("https://user:password@synthetic.invalid/final"))
            } else {
                assert_eq!(
                    request.headers()[header::AUTHORIZATION],
                    if values[0].is_empty() {
                        "Basic dXNlcjpwYXNzd29yZA=="
                    } else {
                        values[0]
                    }
                );
                response(200, None)
            };
            std::future::ready(Ok(result))
        })
        .await
        .unwrap();
    }
}

#[test]
fn hostname_sensitive_boundaries_match_source() {
    for (base, target, expected) in [
        (
            "https://synthetic.invalid:080/start",
            "https://synthetic.invalid:081/final",
            true,
        ),
        (
            "https://synthetic.invalid/start",
            "https://sub.synthetic.invalid/final",
            true,
        ),
        (
            "https://sub.synthetic.invalid/start",
            "https://synthetic.invalid/final",
            false,
        ),
        (
            "https://synthetic.invalid/start",
            "https://notsynthetic.invalid/final",
            false,
        ),
        (
            "https://Synthetic.invalid/start",
            "https://synthetic.invalid/final",
            false,
        ),
        ("http://127.0.0.1/start", "http://sub.127.0.0.1/final", true),
        ("http://[::1]:080/start", "http://[::1]:081/final", true),
        ("http://[::1]/start", "http://[::2]/final", false),
        (
            "http://[fe80::1%25owned]:080/start",
            "http://[fe80::1%25owned]:081/final",
            true,
        ),
        (
            "http://[fe80::1%25owned]/start",
            "http://[fe80::1%25other]/final",
            false,
        ),
        (
            "https://täst.invalid/start",
            "https://xn--tst-qla.invalid/final",
            true,
        ),
        (
            "https://täst.invalid/start",
            "https://sub.xn--tst-qla.invalid/final",
            true,
        ),
    ] {
        assert_eq!(
            copy_sensitive(
                &ApplicationUrl::remote(base).unwrap(),
                &ApplicationUrl::remote(target).unwrap()
            ),
            expected
        );
    }
}

#[tokio::test]
async fn missing_empty_invalid_location_and_ten_request_ceiling() {
    for location in [None, Some(""), Some("%zz")] {
        let mut calls = 0;
        let request = Request::builder()
            .uri("https://synthetic.invalid/start")
            .body(Full::<Bytes>::default())
            .unwrap();
        let result = follow(request, |_| {
            calls += 1;
            std::future::ready(Ok(response(302, location)))
        })
        .await;
        assert_eq!(calls, 1);
        assert_eq!(result.is_err(), location == Some("%zz"));
    }
    let mut calls = 0;
    let request = Request::builder()
        .uri("https://synthetic.invalid/start")
        .body(Full::<Bytes>::default())
        .unwrap();
    let error = follow(request, |_| {
        calls += 1;
        std::future::ready(Ok(response(302, Some("/again"))))
    })
    .await
    .unwrap_err();
    assert_eq!(calls, 10);
    assert_eq!(error.to_string(), "stopped after 10 redirects");
    let request = Request::builder()
        .uri("https://synthetic.invalid/start")
        .body(Full::<Bytes>::default())
        .unwrap();
    let result = follow(request, |_| {
        let mut result = response(302, Some(""));
        result
            .headers_mut()
            .append(header::LOCATION, http::HeaderValue::from_static("/final"));
        std::future::ready(Ok(result))
    })
    .await
    .unwrap();
    assert_eq!(result.status(), 302);
}

struct TrackedStream {
    remaining: usize,
    read: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
    fail: bool,
}
impl futures::Stream for TrackedStream {
    type Item = Result<Frame<Bytes>, io::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.fail {
            self.fail = false;
            return std::task::Poll::Ready(Some(Err(io::Error::other("synthetic read failure"))));
        }
        if self.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        self.remaining -= 1;
        self.read.fetch_add(1, Ordering::Relaxed);
        std::task::Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"x")))))
    }
}
impl Drop for TrackedStream {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn intermediate_drain_is_bounded_and_errors_ignored() {
    for (length, size, fail, expected) in [
        (None, 5000, false, 2048),
        (Some(5), 5, false, 5),
        (Some(2049), 5000, false, 0),
        (None, 5, true, 0),
    ] {
        let read = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let stream = TrackedStream {
            remaining: size,
            read: read.clone(),
            dropped: dropped.clone(),
            fail,
        };
        let mut intermediate = response(302, Some("/final"));
        *intermediate.body_mut() = StreamBody::new(stream).boxed_unsync();
        if let Some(length) = length {
            intermediate
                .headers_mut()
                .insert(header::CONTENT_LENGTH, length.to_string().parse().unwrap());
        }
        let mut intermediate = Some(intermediate);
        let request = Request::builder()
            .uri("https://synthetic.invalid/start")
            .body(Full::<Bytes>::default())
            .unwrap();
        let result = follow(request, |_| {
            std::future::ready(Ok(intermediate
                .take()
                .unwrap_or_else(|| response(200, None))))
        })
        .await
        .unwrap();
        assert_eq!(result.status(), 200);
        assert_eq!(read.load(Ordering::Relaxed), expected);
        assert!(dropped.load(Ordering::Relaxed));
    }
}

#[tokio::test]
async fn transport_and_location_errors_are_redacted() {
    let request = Request::builder()
        .uri("https://synthetic.invalid/start")
        .body(Full::<Bytes>::default())
        .unwrap();
    let error = follow(request, |_| {
        std::future::ready(Err(anyhow::anyhow!("synthetic-password=private")))
    })
    .await
    .unwrap_err();
    assert_eq!(format!("{error:#}"), "HTTP request failed");
    let request = Request::builder()
        .uri("https://synthetic.invalid/start")
        .body(Full::<Bytes>::default())
        .unwrap();
    let error = follow(request, |_| {
        std::future::ready(Ok(response(
            302,
            Some("https://user:synthetic-password@synthetic.invalid/%zz"),
        )))
    })
    .await
    .unwrap_err();
    assert_eq!(format!("{error:#}"), "invalid HTTP redirect Location");
}

#[tokio::test]
#[ignore = "requires pinned Go HTTP policy oracle"]
async fn go_default_http_redirect_request_contract() {
    use serde_json::{Value, json};
    let mut cases = Vec::new();
    for status in [301, 302, 303, 307, 308] {
        for method in ["GET", "HEAD", "POST", "PUT", "DELETE"] {
            cases.push(json!({"base":"https://synthetic.invalid:080/start", "method":method, "body":"owned-body", "headers":{"content-type":["owned"],"content-language":["owned"]}, "statuses":[status], "locations":[["/final"]]}));
        }
    }
    for statuses in [vec![302, 307], vec![307, 302, 308], vec![301, 303, 308]] {
        let locations: Vec<_> = statuses.iter().map(|_| vec!["/next"]).collect();
        cases.push(json!({"base":"https://synthetic.invalid/start", "method":"PUT", "body":"owned-body", "statuses":statuses, "locations":locations}));
    }
    let sensitive = json!({"authorization":["owned"],"www-authenticate":["owned"],"cookie":["owned"],"cookie2":["owned"],"proxy-authorization":["owned"],"proxy-authenticate":["owned"],"x-original":["owned"]});
    cases.push(json!({"base":"https://synthetic.invalid:080/start", "method":"GET", "headers":sensitive, "statuses":[302,302,302], "locations":[["https://sub.synthetic.invalid:081/one"],["https://outside.invalid/two"],["https://synthetic.invalid/three"]]}));
    for (base, location) in [
        (
            "https://synthetic.invalid:080/start",
            "https://synthetic.invalid:081/final",
        ),
        (
            "https://synthetic.invalid/start",
            "https://sub.synthetic.invalid/final",
        ),
        (
            "https://sub.synthetic.invalid/start",
            "https://synthetic.invalid/final",
        ),
        (
            "https://synthetic.invalid/start",
            "https://notsynthetic.invalid/final",
        ),
        (
            "https://Synthetic.invalid/start",
            "https://synthetic.invalid/final",
        ),
        ("http://127.0.0.1/start", "http://sub.127.0.0.1/final"),
        ("http://[::1]:080/start", "http://[::1]:081/final"),
        ("http://[::1]/start", "http://[::2]/final"),
        (
            "http://[fe80::1%25owned]:080/start",
            "http://[fe80::1%25owned]:081/final",
        ),
        (
            "http://[fe80::1%25owned]/start",
            "http://[fe80::1%25other]/final",
        ),
    ] {
        cases.push(json!({"base":base, "method":"GET", "headers":{"authorization":["owned"]}, "statuses":[302], "locations":[[location]]}));
    }
    for (base, location, host, referer) in [
        ("https://synthetic.invalid/a", "/b", "bound.invalid:123", ""),
        (
            "https://synthetic.invalid/a",
            "//other.invalid/b",
            "bound.invalid:123",
            "",
        ),
        (
            "https://synthetic.invalid/a",
            "https://other.invalid/b",
            "bound.invalid:123",
            "",
        ),
        (
            "https://synthetic.invalid/a",
            "http://synthetic.invalid/b",
            "",
            "",
        ),
        (
            "https://synthetic.invalid/a",
            "http://synthetic.invalid/b",
            "",
            "synthetic-explicit",
        ),
        (
            "https://user:password@synthetic.invalid/a",
            "/b#fragment",
            "",
            "",
        ),
        (
            "https://synthetic.invalid/a",
            "https://user:password@other.invalid/b",
            "",
            "",
        ),
    ] {
        let headers = if referer.is_empty() {
            json!({})
        } else {
            json!({"referer":[referer]})
        };
        cases.push(json!({"base":base,"method":"GET","host":host,"headers":headers,"statuses":[302],"locations":[[location]]}));
    }
    for values in [
        vec![""],
        vec!["", "Bearer synthetic-later"],
        vec!["Bearer synthetic-first", ""],
    ] {
        cases.push(json!({"base":"https://synthetic.invalid/start","method":"GET","headers":{"authorization":values},"statuses":[302],"locations":[["https://user:password@synthetic.invalid/final"]]}));
    }
    for locations in [
        json!([]),
        json!([[""]]),
        json!([["", "/final"]]),
        json!([["%zz"]]),
    ] {
        cases.push(json!({"base":"https://synthetic.invalid/start","method":"GET","statuses":[302],"locations":locations}));
    }
    cases.push(json!({"base":"https://synthetic.invalid/start","method":"GET","statuses":vec![302;11],"locations":vec![vec!["/again"];11]}));
    let oracle =
        std::env::var_os("CLOUDFLARED_GO_HTTP_POLICY_ORACLE").expect("pinned Go HTTP oracle");
    let mut child = std::process::Command::new(oracle)
        .arg("redirect")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&cases).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(expected.len(), cases.len());
    for (case, expected) in cases.iter().zip(expected) {
        let mut request = Request::builder()
            .method(case["method"].as_str().unwrap())
            .uri(case["base"].as_str().unwrap())
            .body(Full::new(Bytes::from(
                case["body"].as_str().unwrap_or("").to_owned(),
            )))
            .unwrap();
        if let Some(host) = case["host"].as_str().filter(|host| !host.is_empty()) {
            request
                .headers_mut()
                .insert(header::HOST, host.parse().unwrap());
        }
        if let Some(headers) = case["headers"].as_object() {
            for (name, values) in headers {
                for value in values.as_array().unwrap() {
                    request.headers_mut().append(
                        http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                        value.as_str().unwrap().parse().unwrap(),
                    );
                }
            }
        }
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = observed.clone();
        let result = follow(request, |request| {
            let seen = seen.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = body.collect().await.unwrap().to_bytes();
                let mut headers = serde_json::Map::new();
                for name in parts.headers.keys().filter(|name| **name != header::HOST) {
                    let values: Vec<_> = parts.headers.get_all(name).iter().map(|value| value.to_str().unwrap()).collect();
                    headers.insert(name.as_str().to_owned(), json!(values));
                }
                let host = parts.headers.get(header::HOST).map_or_else(|| parts.uri.authority().unwrap().as_str(), |value| value.to_str().unwrap());
                let raw_host = parts.headers.get(header::HOST).map_or_else(
                    || ApplicationUrl::remote(&parts.uri.to_string()).unwrap().host().to_owned(),
                    |value| value.to_str().unwrap().to_owned(),
                );
                let mut seen = seen.lock().unwrap();
                let hop = seen.len();
                seen.push(json!({"method":parts.method.as_str(),"target":parts.uri.to_string(),"raw_host":raw_host,"serialized_host":host,"body":std::str::from_utf8(&body).unwrap(),"headers":headers}));
                let status = case["statuses"][hop].as_u64().unwrap_or(200) as u16;
                let mut result = response(status, None);
                if let Some(values) = case["locations"][hop].as_array() {
                    for value in values { result.headers_mut().append(header::LOCATION, value.as_str().unwrap().parse().unwrap()); }
                }
                Ok(result)
            }
        }).await;
        assert_eq!(
            result.is_err(),
            expected["error"].as_bool().unwrap(),
            "{case}"
        );
        assert_eq!(
            json!(*observed.lock().unwrap()),
            expected["requests"],
            "{case}"
        );
        if let Ok(response) = result {
            assert_eq!(
                response.status().as_u16() as u64,
                expected["status"].as_u64().unwrap(),
                "{case}"
            );
        }
    }
    eprintln!("paired default redirect request cases: {}", cases.len());
}

async fn request_head(socket: &mut tokio::net::TcpStream) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(socket.read_u8().await.ok()?);
        assert!(bytes.len() < 16384);
    }
    Some(String::from_utf8(bytes).unwrap())
}

#[tokio::test]
async fn intermediate_gzip_failures_follow_and_preserve_completed_wire_reuse() {
    use tokio::io::AsyncWriteExt;
    for kind in [
        "valid",
        "checksum",
        "truncated",
        "garbage",
        "raw_truncated",
        "decoded_large",
    ] {
        let value = if kind == "decoded_large" {
            "owned".repeat(2000)
        } else {
            "short-body".into()
        };
        let mut encoder = async_compression::tokio::write::GzipEncoder::new(Vec::new());
        encoder.write_all(value.as_bytes()).await.unwrap();
        encoder.shutdown().await.unwrap();
        let mut payload = encoder.into_inner();
        match kind {
            "checksum" => {
                let offset = payload.len() - 8;
                payload[offset] ^= 1;
            }
            "truncated" => {
                payload.truncate(payload.len() - 4);
            }
            "garbage" => payload.extend_from_slice(b"invalid trailing gzip"),
            _ => {}
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let server = crate::runtime::AbortTask(tokio::spawn(async move {
            let mut sockets = tokio::task::JoinSet::new();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::Relaxed);
                let payload = payload.clone();
                sockets.spawn(async move {
                    while let Some(head) = request_head(&mut socket).await {
                        assert!(head.to_ascii_lowercase().contains("accept-encoding: gzip\r\n"));
                        if head.starts_with("GET /final ") {
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal").await.unwrap();
                        } else if kind == "raw_truncated" {
                            socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 10\r\n\r\nx").await.unwrap();
                            break;
                        } else {
                            socket.write_all(format!("HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", payload.len()).as_bytes()).await.unwrap();
                            socket.write_all(&payload).await.unwrap();
                        }
                    }
                });
            }
        }));
        let client = crate::access::direct_http_client().unwrap();
        let request = Request::builder()
            .uri(format!("http://{address}/start"))
            .body(Full::<Bytes>::default())
            .unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            direct(&client, request)
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
        })
        .await
        .unwrap();
        assert_eq!(result, "final", "{kind}");
        assert_eq!(
            connections.load(Ordering::Relaxed),
            if kind == "raw_truncated" { 2 } else { 1 },
            "{kind}"
        );
        drop(client);
        drop(server);
    }
}

#[tokio::test]
async fn caller_cancel_and_deadline_close_redirected_request() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for deadline in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (started, start) = tokio::sync::oneshot::channel();
        let (closed, close) = tokio::sync::oneshot::channel();
        let server = crate::runtime::AbortTask(tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            assert!(
                request_head(&mut socket)
                    .await
                    .unwrap()
                    .starts_with("GET /start ")
            );
            socket
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            assert!(
                request_head(&mut socket)
                    .await
                    .unwrap()
                    .starts_with("GET /final ")
            );
            started.send(()).unwrap();
            assert!(socket.read_u8().await.is_err());
            closed.send(()).unwrap();
        }));
        let mut task = tokio::spawn(async move {
            let client = crate::access::direct_http_client().unwrap();
            let request = Request::builder()
                .uri(format!("http://{address}/start"))
                .body(Full::<Bytes>::default())
                .unwrap();
            if deadline {
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        direct(&client, request)
                    )
                    .await
                    .is_err()
                );
            } else {
                direct(&client, request).await.unwrap();
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), start)
            .await
            .unwrap()
            .unwrap();
        if !deadline {
            task.abort();
        }
        let _ = (&mut task).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), close)
            .await
            .unwrap()
            .unwrap();
        drop(server);
    }
}
