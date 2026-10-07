use super::*;
use opentelemetry::{KeyValue, trace::Span as _};
use opentelemetry_proto::tonic::{
    collector::trace::v1::ExportTraceServiceRequest, common::v1::any_value::Value, trace::v1::Span,
};
use prost::Message;

const SAMPLED: &str = "11111111111111111111111111111111:2222222222222222:0:1";

fn controlled_child(name: &str) -> bool {
    if std::env::var("CLOUDFLARED_HTTP_TRACE_TEST_CHILD").is_ok() {
        return false;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        &format!("proxy::tests::http_tracing::{name}"),
        "--nocapture",
    ]);
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(|key| key.starts_with("OTEL_")) {
            command.env_remove(key);
        }
    }
    let output = command
        .env("CLOUDFLARED_HTTP_TRACE_TEST_CHILD", "1")
        .env("OTEL_TRACES_SAMPLER", "parentbased_always_on")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "controlled trace probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    true
}

fn export(headers: &HeaderMap) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest::decode(
        base64::engine::general_purpose::STANDARD
            .decode(headers[tracing::RESPONSE_HEADER].as_bytes())
            .unwrap()
            .as_slice(),
    )
    .unwrap()
}
fn spans(export: &ExportTraceServiceRequest) -> Vec<&Span> {
    export
        .resource_spans
        .iter()
        .flat_map(|resource| {
            resource
                .scope_spans
                .iter()
                .flat_map(|scope| scope.spans.iter())
        })
        .collect()
}

#[test]
fn http_trace_strict_context_roots_strip_and_response_drain_match_source() {
    if controlled_child("http_trace_strict_context_roots_strip_and_response_drain_match_source") {
        return;
    }
    let context = crate::observability::Context::quiet().unwrap();
    for (values, exported, remote) in [
        (vec![], false, false),
        (vec![""], false, false),
        (vec![SAMPLED], true, true),
        (
            vec!["11111111111111111111111111111111:2222222222222222:0:0"],
            false,
            false,
        ),
        (vec![SAMPLED, ""], false, false),
        (vec!["bad", SAMPLED], true, true),
        (vec![SAMPLED, "bad"], true, false),
        (vec!["1111111111111111:2222222222222222:0:1"], true, true),
        (vec!["1:2222222222222222:0:1"], true, false),
        (vec!["11111111111111111111111111111111:2:0:1"], true, false),
        (
            vec!["11111111111111111111111111111111:0000000000000000:0:1"],
            true,
            false,
        ),
        (
            vec!["ABCDEF11111111111111111111111111:2222222222222222:0:1"],
            true,
            false,
        ),
        (
            vec!["11111111111111111111111111111111:2222222222222222:0:-1"],
            true,
            true,
        ),
        (
            vec!["11111111111111111111111111111111:2222222222222222:0:"],
            false,
            false,
        ),
    ] {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("cf-trace-id", HeaderValue::from_str(value).unwrap());
        }
        let trace = tracing::HttpTrace::extract(&mut headers, &context.logger);
        assert!(!headers.contains_key("cf-trace-id"));
        let mut matching = trace.start("ingress_match");
        if let Some(span) = &mut matching {
            span.set_attribute(KeyValue::new("req-host", "app.example.invalid"));
            span.set_attribute(KeyValue::new("rule-num", 0));
            span.end();
        }
        tracing::end_response(trace.start("ttfb_origin"), 503);
        headers.insert(
            tracing::RESPONSE_HEADER,
            HeaderValue::from_static("origin-trace"),
        );
        trace.response(&mut headers);
        if !exported {
            assert_eq!(headers[tracing::RESPONSE_HEADER], "origin-trace");
            continue;
        }
        let decoded = export(&headers);
        assert_eq!(decoded.resource_spans.len(), 2);
        let data = spans(&decoded);
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].name, "ingress_match");
        assert_eq!(data[0].status.as_ref().unwrap().code, 0);
        assert_eq!(data[1].name, "ttfb_origin");
        assert_eq!(data[1].status.as_ref().unwrap().code, 1);
        assert!(
            data[1]
                .attributes
                .iter()
                .any(|attribute| attribute.key == "upstreamStatusCode"
                    && attribute.value.as_ref().unwrap().value == Some(Value::IntValue(503)))
        );
        if remote {
            assert_eq!(data[0].trace_id, data[1].trace_id);
            assert_eq!(data[0].parent_span_id, [0x22; 8]);
            assert_eq!(data[0].flags, 0x301);
        } else {
            assert_ne!(data[0].trace_id, data[1].trace_id);
            assert!(data[0].parent_span_id.is_empty());
            assert!(data[1].parent_span_id.is_empty());
            assert_eq!(data[0].flags, 0x101);
        }
        for resource in &decoded.resource_spans {
            assert_eq!(
                resource.schema_url,
                "https://opentelemetry.io/schemas/1.7.0"
            );
            assert_eq!(
                resource.scope_spans[0].scope.as_ref().unwrap().name,
                "origin"
            );
            let attrs = &resource.resource.as_ref().unwrap().attributes;
            for (key, value) in [
                ("service.name", "cloudflared".to_owned()),
                ("jaeger.version", "rust-otel-0.33.0".to_owned()),
                (
                    "hostname",
                    crate::observability::management::system_hostname(),
                ),
                (
                    "process.runtime.version",
                    crate::config::UPSTREAM_VERSION.to_owned(),
                ),
                ("host.type", "linux".to_owned()),
                ("host.arch", "amd64".to_owned()),
            ] {
                assert!(
                    attrs.iter().any(|attr| attr.key == key
                        && attr.value.as_ref().unwrap().value
                            == Some(Value::StringValue(value.clone()))),
                    "missing typed resource {key}"
                );
            }
        }
        let mut after = HeaderMap::new();
        trace.response(&mut after);
        assert!(after.is_empty());
    }
}

#[test]
fn http_trace_bounded_exporter_and_utf8_byte_error_cap() {
    if controlled_child("http_trace_bounded_exporter_and_utf8_byte_error_cap") {
        return;
    }
    let context = crate::observability::Context::quiet().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("cf-trace-id", HeaderValue::from_static(SAMPLED));
    let trace = tracing::HttpTrace::extract(&mut headers, &context.logger);
    tracing::end_error(trace.start("failed"), &"界".repeat(100));
    for _ in 0..24 {
        tracing::end_response(trace.start("ttfb_origin"), 200);
    }
    trace.response(&mut headers);
    let decoded = export(&headers);
    assert_eq!(decoded.resource_spans.len(), 20);
    let data = spans(&decoded);
    let error = &data[0].status.as_ref().unwrap().message;
    assert_eq!(error.len(), 99);
    assert_eq!(data[0].status.as_ref().unwrap().code, 2);
}

#[test]
fn http_trace_sampler_env_framing_uses_sdk_in_owned_children() {
    let cases = [
        (" PARENTBASED_ALWAYS_ON ", "", "1", true),
        ("always_off", "", "1", false),
        ("always_on", "", "0", true),
        ("traceidratio", "0", "1", false),
        ("traceidratio", "-1", "0", true),
        ("parentbased_traceidratio", "0", "1", true),
        ("unsupported", "", "1", true),
    ];
    if let Ok(index) = std::env::var("CLOUDFLARED_HTTP_TRACE_SAMPLE_CASE") {
        let (_, _, flags, expected) = cases[index.parse::<usize>().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "cf-trace-id",
            HeaderValue::from_str(&format!(
                "11111111111111111111111111111111:2222222222222222:0:{flags}"
            ))
            .unwrap(),
        );
        let context = crate::observability::Context::quiet().unwrap();
        let trace = tracing::HttpTrace::extract(&mut headers, &context.logger);
        let mut matching = trace.start("ingress_match");
        if let Some(span) = &mut matching {
            span.end();
        }
        tracing::end_response(trace.start("ttfb_origin"), 200);
        trace.response(&mut headers);
        assert_eq!(headers.contains_key(tracing::RESPONSE_HEADER), expected);
        return;
    }
    for (index, (sampler, arg, _, _)) in cases.iter().enumerate() {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "proxy::tests::http_tracing::http_trace_sampler_env_framing_uses_sdk_in_owned_children",
            "--nocapture",
        ]);
        for (key, _) in std::env::vars_os() {
            if key.to_str().is_some_and(|key| key.starts_with("OTEL_")) {
                command.env_remove(key);
            }
        }
        let output = command
            .env("CLOUDFLARED_HTTP_TRACE_SAMPLE_CASE", index.to_string())
            .env("OTEL_TRACES_SAMPLER", sampler)
            .env("OTEL_TRACES_SAMPLER_ARG", arg)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "sampler probe {index} failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn http_trace_status_and_failed_roundtrip_do_not_export_headers() {
    if controlled_child("http_trace_status_and_failed_roundtrip_do_not_export_headers") {
        return;
    }
    for service in ["http_status:503", "hello_world"] {
        let mut head = request("GET", false);
        head.metadata
            .push(("HttpHeader:Cf-Trace-Id".into(), SAMPLED.into()));
        let (mut client, server) = tokio::io::duplex(1024);
        let worker = tokio::spawn(serve_data(server, head, state(service)));
        let response = crate::protocol::metadata::read_connect_response(&mut client)
            .await
            .unwrap();
        let value = response
            .metadata
            .iter()
            .find(|(name, _)| name == "HttpHeader:Cf-Int-Cloudflared-Tracing");
        assert_eq!(value.is_some(), service == "hello_world");
        client.read_to_end(&mut Vec::new()).await.unwrap();
        worker.await.unwrap().unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut data = [0; 8192];
        assert!(socket.read(&mut data).await.unwrap() > 0);
        socket.write_all(b"invalid response\r\n\r\n").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut head = request("GET", false);
    head.metadata
        .push(("HttpHeader:Cf-Trace-Id".into(), SAMPLED.into()));
    let (mut client, server) = tokio::io::duplex(1024);
    let worker = tokio::spawn(serve_data(
        server,
        head,
        state(&format!("http://{address}")),
    ));
    let response = crate::protocol::metadata::read_connect_response(&mut client)
        .await
        .unwrap();
    assert!(!response.error.is_empty());
    assert!(
        !response
            .metadata
            .iter()
            .any(|(name, _)| name == "HttpHeader:Cf-Int-Cloudflared-Tracing")
    );
    client.read_to_end(&mut Vec::new()).await.unwrap();
    assert!(worker.await.unwrap().is_err());
    origin.await.unwrap();
}

#[tokio::test]
async fn http_trace_access_and_quick_denials_do_not_export_headers() {
    if controlled_child("http_trace_access_and_quick_denials_do_not_export_headers") {
        return;
    }
    for quick in [false, true] {
        let mut config = run_config("http_status:503", Default::default());
        if quick {
            config.quick_authorizer = Some(Arc::new(
                crate::quick_tunnel::auth::Authorizer::new(
                    "synthetic.trycloudflare.com",
                    vec!["reader@example.invalid".into()],
                )
                .unwrap(),
            ));
        } else {
            config.origin_request.access = Some(crate::config::AccessConfig {
                required: true,
                team_name: "synthetic".into(),
                aud_tag: vec!["aud".into()],
                environment: String::new(),
            });
        }
        let state = Arc::new(ProxyState::new(&config, uuid::Uuid::from_bytes([7; 16])).unwrap());
        let mut head = request("GET", false);
        if quick {
            head.destination = "https://synthetic.trycloudflare.com/".into();
            for (name, value) in &mut head.metadata {
                if name == "HttpHost" {
                    *value = "synthetic.trycloudflare.com".into();
                }
            }
        }
        head.metadata
            .push(("HttpHeader:Cf-Trace-Id".into(), SAMPLED.into()));
        let (mut client, server) = tokio::io::duplex(1024);
        let worker = tokio::spawn(serve_data(server, head, state));
        let response = crate::protocol::metadata::read_connect_response(&mut client)
            .await
            .unwrap();
        assert!(
            !response
                .metadata
                .iter()
                .any(|(name, _)| name == "HttpHeader:Cf-Int-Cloudflared-Tracing")
        );
        client.read_to_end(&mut Vec::new()).await.unwrap();
        worker.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn http_trace_ttfb_ends_at_headers_before_streamed_body_eof() {
    if controlled_child("http_trace_ttfb_ends_at_headers_before_streamed_body_eof") {
        return;
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (entered, wait_entered) = tokio::sync::oneshot::channel();
        let (release_headers, wait_headers) = tokio::sync::oneshot::channel();
        let (release_body, wait_body) = tokio::sync::oneshot::channel();
        let origin = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let gates = Arc::new(std::sync::Mutex::new(Some((
                entered,
                wait_headers,
                wait_body,
            ))));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(socket),
                    hyper::service::service_fn(
                        move |_request: http::Request<hyper::body::Incoming>| {
                            let (entered, wait_headers, wait_body) =
                                gates.lock().unwrap().take().unwrap();
                            async move {
                                entered.send(()).unwrap();
                                wait_headers.await.unwrap();
                                let body = http_body_util::StreamBody::new(futures::stream::once(
                                    async move {
                                        wait_body.await.unwrap();
                                        Ok::<_, io::Error>(hyper::body::Frame::data(
                                            Bytes::from_static(b"after-headers"),
                                        ))
                                    },
                                ));
                                Ok::<_, io::Error>(http::Response::new(body))
                            }
                        },
                    ),
                )
                .await;
        });
        let mut head = request("GET", false);
        head.metadata
            .push(("HttpHeader:Cf-Trace-Id".into(), SAMPLED.into()));
        let (mut client, server) = tokio::io::duplex(1024);
        let worker = tokio::spawn(serve_data(
            server,
            head,
            state(&format!("http://{address}")),
        ));
        wait_entered.await.unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
                .await
                .is_err()
        );
        let released = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        release_headers.send(()).unwrap();
        let response = crate::protocol::metadata::read_connect_response(&mut client)
            .await
            .unwrap();
        let (_, encoded) = response
            .metadata
            .iter()
            .find(|(name, _)| name == "HttpHeader:Cf-Int-Cloudflared-Tracing")
            .unwrap();
        let decoded = ExportTraceServiceRequest::decode(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let data = spans(&decoded);
        assert!(data[1].end_time_unix_nano >= released);
        assert!(data[0].end_time_unix_nano <= data[1].start_time_unix_nano);
        assert!(!worker.is_finished());
        release_body.send(()).unwrap();
        let mut body = Vec::new();
        client.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"after-headers");
        worker.await.unwrap().unwrap();
        origin.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn public_stream_failed_ack_closes_opened_origin() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = state(&format!("tcp://{}", listener.local_addr().unwrap()));
    let mut request = request("GET", true);
    request
        .metadata
        .push(("HttpHeader:Cf-Trace-Id".into(), SAMPLED.into()));
    let mut head = RequestHead::from_quic(&request).unwrap();
    head.trace = tracing::HttpTrace::extract(&mut head.headers, &state.observability.logger);
    let (origin, _) = state.select(&head).await.unwrap();
    let (client, stream) = tokio::io::duplex(1024);
    drop(client);
    let mut sink = EdgeSink::Quic {
        writer: Box::new(stream),
        started: false,
        protected: false,
    };
    assert!(
        tcp::proxy(
            origin,
            head,
            Box::new(tokio::io::empty()),
            &mut sink,
            &state
        )
        .await
        .is_err()
    );
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut bytes = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut bytes))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
