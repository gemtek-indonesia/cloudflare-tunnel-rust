use super::{
    Context,
    logging::{Filters, Subscription},
};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http::{Request, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{CloseFrame, Role, frame::coding::CloseCode},
    },
};

#[derive(Deserialize)]
pub(crate) struct Claims {
    pub tun: Tunnel,
    pub actor: Actor,
    #[serde(default)]
    pub iss: String,
}
#[derive(Deserialize)]
pub(crate) struct Tunnel {
    pub id: String,
    pub account_tag: String,
}
#[derive(Deserialize)]
pub(crate) struct Actor {
    pub id: String,
}

/// The provider edge verifies ES256 signatures before dispatch. This decoder only
/// checks the frozen format; authority comes exclusively from the runtime receipt.
pub(crate) fn decode_token(token: &str) -> Result<Claims> {
    let segments: Vec<_> = token.split('.').collect();
    if segments.len() != 3 {
        bail!("malformed management jwt");
    }
    let header: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0])?)?;
    if header["alg"] != "ES256"
        || header
            .get("crit")
            .is_some_and(|value| value.as_array().is_none_or(|array| !array.is_empty()))
    {
        bail!("malformed management jwt");
    }
    if URL_SAFE_NO_PAD.decode(segments[2])?.len() != 64 {
        bail!("malformed management jwt signature format");
    }
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1])?)?;
    if claims.tun.id.is_empty() || claims.tun.account_tag.is_empty() || claims.actor.id.is_empty() {
        bail!("invalid management token format provided");
    }
    Ok(claims)
}

pub(crate) struct Service {
    context: Arc<Context>,
    connector_id: uuid::Uuid,
    hostname: String,
    service_address: Option<String>,
    diagnostics: bool,
}
impl Service {
    pub(crate) fn new(
        context: Arc<Context>,
        connector_id: uuid::Uuid,
        label: &str,
        service_address: Option<String>,
        diagnostics: bool,
    ) -> Self {
        let hostname = if label.is_empty() {
            system_hostname()
        } else {
            format!("custom:{label}")
        };
        Self {
            context,
            connector_id,
            hostname,
            service_address,
            diagnostics,
        }
    }
    fn authorize(
        &self,
        receipt: &crate::runtime::scope::EdgeManagementRequest,
        query: Option<&str>,
    ) -> Result<Claims> {
        if !receipt.is_live() {
            bail!("edge attempt closed");
        }
        let token = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .find(|(key, _)| key == "access_token")
            .map(|(_, value)| value.into_owned())
            .ok_or_else(|| anyhow::anyhow!("missing access_token"))?;
        let claims = decode_token(&token)?;
        if claims.tun.id.parse::<uuid::Uuid>()? != receipt.tunnel_id()
            || claims.tun.account_tag != receipt.account_tag()
        {
            bail!("management token does not match the selected tunnel");
        }
        Ok(claims)
    }
    pub(crate) async fn handle_http(
        &self,
        receipt: &crate::runtime::scope::EdgeManagementRequest,
        request: &Request<()>,
    ) -> Result<Response<Bytes>> {
        if self.authorize(receipt, request.uri().query()).is_err() {
            return response(
                400,
                "application/json",
                serde_json::to_vec(
                    &json!({"errors":[{"code":1001,"message":"missing access_token query parameter"}]}),
                )?,
            );
        }
        let methods = match request.uri().path() {
            "/ping" => Some("GET, HEAD"),
            "/host_details" | "/logs" => Some("GET"),
            "/metrics" | "/debug/pprof/heap" | "/debug/pprof/goroutine" if self.diagnostics => {
                Some("GET")
            }
            _ => None,
        };
        if let Some(methods) = methods
            && (!matches!(*request.method(), http::Method::GET | http::Method::HEAD)
                || request.method() == http::Method::HEAD && request.uri().path() != "/ping")
        {
            let mut result = response(405, "text/plain", vec![])?;
            result
                .headers_mut()
                .insert(http::header::ALLOW, http::HeaderValue::from_static(methods));
            return Ok(result);
        }
        let mut result = match (request.method(), request.uri().path()) {
            (&http::Method::GET | &http::Method::HEAD, "/ping") => {
                response(200, "text/plain", vec![])?
            }
            (&http::Method::GET, "/host_details") => {
                let mut value = json!({"connector_id":self.connector_id,"hostname":self.hostname});
                if let Some(ip) = self.private_ip().await {
                    value["ip"] = json!(ip.to_string());
                }
                response(200, "application/json", serde_json::to_vec(&value)?)?
            }
            (&http::Method::GET, "/metrics") if self.diagnostics => response(
                200,
                "text/plain; version=0.0.4",
                self.context.metrics.encode()?,
            )?,
            (&http::Method::GET, "/debug/pprof/heap" | "/debug/pprof/goroutine")
                if self.diagnostics =>
            {
                response(
                    501,
                    "text/plain",
                    b"Go runtime profiles are unavailable in the Rust implementation\n".to_vec(),
                )?
            }
            (&http::Method::GET, "/logs") => {
                if !websocket_origin_allowed(request) {
                    return response(
                        403,
                        "text/plain",
                        b"request Origin is not authorized\n".to_vec(),
                    );
                }
                let key = request
                    .headers()
                    .get("sec-websocket-key")
                    .and_then(|value| value.to_str().ok());
                if !header_token(request, http::header::CONNECTION, "Upgrade")
                    || !header_token(request, http::header::UPGRADE, "websocket")
                {
                    let mut result =
                        response(426, "text/plain", b"invalid WebSocket upgrade\n".to_vec())?;
                    result.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("Upgrade"),
                    );
                    result.headers_mut().insert(
                        http::header::UPGRADE,
                        http::HeaderValue::from_static("websocket"),
                    );
                    return Ok(result);
                }
                if !request
                    .headers()
                    .get("sec-websocket-version")
                    .is_some_and(|value| value == "13")
                    || !key.is_some_and(|key| !key.is_empty())
                {
                    return response(400, "text/plain", b"invalid WebSocket handshake\n".to_vec());
                }
                let mut response = response(101, "text/plain", vec![])?;
                response.headers_mut().insert(
                    http::header::UPGRADE,
                    http::HeaderValue::from_static("websocket"),
                );
                response.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("Upgrade"),
                );
                response.headers_mut().insert(
                    "sec-websocket-accept",
                    http::HeaderValue::from_str(
                        &tokio_tungstenite::tungstenite::handshake::derive_accept_key(
                            key.unwrap().as_bytes(),
                        ),
                    )?,
                );
                response
            }
            _ => response(404, "text/plain", b"404 page not found\n".to_vec())?,
        };
        let cors_route = matches!(request.uri().path(), "/ping" | "/host_details")
            || self.diagnostics
                && matches!(
                    request.uri().path(),
                    "/metrics" | "/debug/pprof/heap" | "/debug/pprof/goroutine"
                );
        if cors_route && matches!(*request.method(), http::Method::GET | http::Method::HEAD) {
            result
                .headers_mut()
                .insert(http::header::VARY, http::HeaderValue::from_static("Origin"));
        }
        if cors_route && let Some(origin) = cors_origin(request) {
            result
                .headers_mut()
                .insert("access-control-allow-origin", origin.clone());
            result.headers_mut().insert(
                "access-control-allow-credentials",
                http::HeaderValue::from_static("true"),
            );
            result
                .headers_mut()
                .insert(http::header::VARY, http::HeaderValue::from_static("Origin"));
        }
        Ok(result)
    }
    async fn private_ip(&self) -> Option<std::net::IpAddr> {
        let address = self.service_address.as_deref()?;
        let socket = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect(address),
        )
        .await
        .ok()?
        .ok()?;
        socket.local_addr().ok().map(|address| address.ip())
    }
    pub(crate) async fn stream_logs<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        receipt: crate::runtime::scope::EdgeManagementRequest,
        query: Option<&str>,
        stream: S,
    ) -> Result<()> {
        let claims = self.authorize(&receipt, query)?;
        let cancel = receipt.cancellation();
        let settings = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(32768));
        let mut websocket =
            WebSocketStream::from_raw_socket(stream, Role::Server, Some(settings)).await;
        let mut subscription: Option<Subscription> = None;
        let idle = tokio::time::sleep(Duration::from_secs(300));
        tokio::pin!(idle);
        let mut ping = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(15),
            Duration::from_secs(15),
        );
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    close(&mut websocket, 1000, "context closed").await;
                    break;
                }
                _ = idle.as_mut(), if subscription.is_none() => {
                    close(&mut websocket, 4003, "session was idle for too long").await;
                    break;
                }
                _ = ping.tick() => {
                    send(&mut websocket, Message::Ping(Bytes::new()), &cancel).await?;
                }
                log = async {
                    let subscription = subscription.as_mut().unwrap();
                    tokio::select! {
                        _ = subscription.cancel.cancelled() => None,
                        log = subscription.receiver.recv() => log,
                    }
                }, if subscription.is_some() => {
                    match log {
                        Some(log) => {
                            let event = serde_json::to_string(&json!({"type":"logs","logs":[log]}))?;
                            send(&mut websocket, Message::Text(event.into()), &cancel).await?;
                        }
                        None => {
                            close(&mut websocket, 1000, "context closed").await;
                            break;
                        }
                    }
                }
                message = websocket.next() => {
                    match message {
                        Some(Ok(Message::Text(text))) => {
                            let command = match serde_json::from_str::<serde_json::Value>(&text) {
                                Ok(command) => command,
                                Err(_) => {
                                    close(&mut websocket, 1003, "invalid message type was provided").await;
                                    break;
                                }
                            };
                            match command["type"].as_str().unwrap_or_default() {
                                "start_streaming" => {
                                    let filters = if command["filters"].is_null() {
                                        Ok(Filters::default())
                                    } else {
                                        serde_json::from_value::<Filters>(command["filters"].clone())
                                    };
                                    let filters = match filters {
                                        Ok(filters) if filters.level != Some(super::logging::Level::Fatal)
                                            && filters.sampling.is_finite() => filters,
                                        _ => {
                                            close(&mut websocket, 4001, "expected start streaming as first event").await;
                                            break;
                                        }
                                    };
                                    match self.context.logger.subscribe(&claims.actor.id, filters) {
                                        Ok(next) => {
                                            if let Some(old) = subscription.replace(next) {
                                                self.context.logger.remove(old.id);
                                            }
                                        }
                                        Err(_) => {
                                            close(&mut websocket, 4002, "limit exceeded for streaming sessions").await;
                                            break;
                                        }
                                    }
                                }
                                "stop_streaming" => {
                                    if let Some(old) = subscription.take() {
                                        self.context.logger.remove(old.id);
                                    }
                                    idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(300));
                                }
                                _ => {
                                    close(&mut websocket, 1003, "invalid message type was provided").await;
                                    break;
                                }
                            }
                        }
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Ok(_)) => {
                            close(&mut websocket, 1003, "invalid message type was provided").await;
                            break;
                        }
                        Some(Err(error)) => return Err(error.into()),
                    }
                }
            }
        }
        if let Some(subscription) = subscription {
            self.context.logger.remove(subscription.id);
        }
        Ok(())
    }
}
async fn close<S: AsyncRead + AsyncWrite + Unpin>(
    websocket: &mut WebSocketStream<S>,
    code: u16,
    reason: &'static str,
) {
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        websocket.send(Message::Close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: reason.into(),
        }))),
    )
    .await;
}
async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    websocket: &mut WebSocketStream<S>,
    message: Message,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<()> {
    tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        result = tokio::time::timeout(Duration::from_secs(15),websocket.send(message)) => {
            result.map_err(|_|anyhow::anyhow!("management WebSocket write timed out"))??;
            Ok(())
        }
    }
}
fn response(status: u16, content_type: &str, body: Vec<u8>) -> Result<Response<Bytes>> {
    Ok(Response::builder()
        .status(StatusCode::from_u16(status)?)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(body.into())?)
}
fn header_token(request: &Request<()>, name: http::header::HeaderName, expected: &str) -> bool {
    request
        .headers()
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(expected))
}
fn cors_origin(request: &Request<()>) -> Option<&http::HeaderValue> {
    let origin = request.headers().get(http::header::ORIGIN)?;
    let raw = origin.to_str().ok()?.to_ascii_lowercase();
    if raw.len() >= "https://.cloudflare.com".len()
        && raw.starts_with("https://")
        && raw.ends_with(".cloudflare.com")
    {
        Some(origin)
    } else {
        None
    }
}
fn websocket_origin_allowed(request: &Request<()>) -> bool {
    let Some(origin) = request.headers().get(http::header::ORIGIN) else {
        return true;
    };
    let Ok(raw) = origin.to_str() else {
        return false;
    };
    if raw.is_empty() {
        return true;
    }
    if raw.contains('\\') {
        return false;
    }
    let parse = if raw.starts_with("//") {
        format!("http:{raw}")
    } else {
        raw.to_owned()
    };
    if url::Url::parse(&parse).is_err() {
        return false;
    }
    let Some(authority) = raw
        .strip_prefix("//")
        .or_else(|| raw.split_once("://").map(|(_, authority)| authority))
    else {
        return false;
    };
    let host = authority
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let request_host = request
        .uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|host| host.to_str().ok())
        })
        .unwrap_or_default();
    !host.is_empty()
        && (host.eq_ignore_ascii_case(request_host)
            || host.to_ascii_lowercase().ends_with(".cloudflare.com"))
}
fn system_hostname() -> String {
    let mut buffer = [0u8; 256]; /* SAFETY: buffer is valid for its supplied length. */
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return "unknown".into();
    }
    String::from_utf8_lossy(
        &buffer[..buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len())],
    )
    .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires pinned Go oracle; scripts/test-interop.sh"]
    async fn go_origin_policy_differential() {
        let oracle = std::env::var("CLOUDFLARED_GO_ORACLE").expect("set pinned Go oracle path");
        let origins = [
            "",
            "https://dash.cloudflare.com",
            "HTTPS://DASH.CLOUDFLARE.COM",
            "http://dash.cloudflare.com",
            "ftp://dash.cloudflare.com",
            "//dash.cloudflare.com",
            "https://dash.cloudflare.com:443",
            "https://dash.cloudflare.com:8443",
            "https://dash.cloudflare.com/",
            "https://user@dash.cloudflare.com",
            "https://evil.test/path.cloudflare.com",
            "https://cloudflare.com",
            "https://cloudflare.com.attacker.test",
            "https://management.argotunnel.com:8443",
            "http://management.argotunnel.com:8443",
            "null",
            "https://evil\\dash.cloudflare.com",
        ];
        let cases = origins
            .iter()
            .flat_map(|origin| {
                [
                    "management.argotunnel.com",
                    "management.argotunnel.com:8443",
                ]
                .map(|host| json!({"Host":host,"Origin":origin}))
            })
            .collect::<Vec<_>>();
        let dir = std::env::temp_dir().join(format!(
            "cloudflared-origin-oracle-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("cases.json");
        std::fs::write(&path, serde_json::to_vec(&cases).unwrap()).unwrap();
        let output = std::process::Command::new(oracle)
            .arg("origins")
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "origin oracle failed");
        let results: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(results.len(), cases.len());
        let service = Service::new(
            Context::quiet().unwrap(),
            uuid::Uuid::nil(),
            "synthetic",
            None,
            false,
        );
        let receipt =
            crate::runtime::scope::fixture_receipt(uuid::Uuid::nil(), "synthetic-account");
        let token = token(uuid::Uuid::nil(), "synthetic-account", "synthetic-actor");
        for (case, expected) in cases.iter().zip(results) {
            let host = case["Host"].as_str().unwrap();
            let origin = case["Origin"].as_str().unwrap();
            let request = Request::builder()
                .uri(format!("http://{host}/ping?access_token={token}"))
                .header("origin", origin)
                .body(())
                .unwrap();
            let response = service.handle_http(&receipt, &request).await.unwrap();
            assert_eq!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or(""),
                expected["cors"].as_str().unwrap(),
                "CORS {host} {origin}"
            );
            assert_eq!(
                response
                    .headers()
                    .get("vary")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or(""),
                expected["vary"].as_str().unwrap(),
                "Vary {host} {origin}"
            );
            let request = Request::builder()
                .uri(format!("http://{host}/logs?access_token={token}"))
                .header("origin", origin)
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header(
                    "sec-websocket-key",
                    base64::engine::general_purpose::STANDARD.encode(b"the sample nonce"),
                )
                .body(())
                .unwrap();
            let response = service.handle_http(&receipt, &request).await.unwrap();
            assert_eq!(
                response.status() == 101,
                expected["ws"].as_bool().unwrap(),
                "WebSocket {host} {origin}"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    fn token(id: uuid::Uuid, account: &str, actor: &str) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#),
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(
                    &json!({"tun":{"id":id,"account_tag":account},"actor":{"id":actor}})
                )
                .unwrap()
            ),
            URL_SAFE_NO_PAD.encode([0u8; 64])
        )
    }
    #[tokio::test]
    async fn host_details_uses_actual_local_tcp_address_and_bound_live_receipt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let id = uuid::Uuid::new_v4();
        let receipt = crate::runtime::scope::fixture_receipt(id, "synthetic-account");
        let service = Service::new(
            Context::quiet().unwrap(),
            uuid::Uuid::nil(),
            "synthetic",
            Some(address.to_string()),
            false,
        );
        let request = Request::builder()
            .uri(format!(
                "/host_details?access_token={}",
                token(id, "synthetic-account", "synthetic-actor")
            ))
            .body(())
            .unwrap();
        let response = service.handle_http(&receipt, &request).await.unwrap();
        assert_eq!(response.status(), 200);
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["ip"], "127.0.0.1");
        assert_eq!(body["hostname"], "custom:synthetic");
        receipt.cancellation().cancel();
        assert_eq!(
            service
                .handle_http(&receipt, &request)
                .await
                .unwrap()
                .status(),
            400
        );
    }
    #[tokio::test]
    async fn edge_receipt_binding_and_actual_websocket_log_lifecycle() {
        let context = Context::quiet().unwrap();
        let id = uuid::Uuid::new_v4();
        let service = Arc::new(Service::new(
            context.clone(),
            uuid::Uuid::new_v4(),
            "synthetic",
            None,
            true,
        ));
        let receipt = crate::runtime::scope::fixture_receipt(id, "synthetic-account");
        let token = token(id, "synthetic-account", "synthetic-actor");
        let query = format!("access_token={token}");
        let request = Request::builder()
            .uri(format!("/ping?{query}"))
            .body(())
            .unwrap();
        assert_eq!(
            service
                .handle_http(&receipt, &request)
                .await
                .unwrap()
                .status(),
            200
        );
        let other =
            crate::runtime::scope::fixture_receipt(uuid::Uuid::new_v4(), "synthetic-account");
        assert_eq!(
            service
                .handle_http(&other, &request)
                .await
                .unwrap()
                .status(),
            400
        );
        let wrong_account = crate::runtime::scope::fixture_receipt(id, "different-account");
        assert_eq!(
            service
                .handle_http(&wrong_account, &request)
                .await
                .unwrap()
                .status(),
            400
        );
        let (server, client) = tokio::io::duplex(1024);
        let cancel = receipt.cancellation();
        let serving = service.clone();
        let task =
            tokio::spawn(async move { serving.stream_logs(receipt, Some(&query), server).await });
        let mut ws = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        ws.send(Message::Text(
            r#"{"type":"start_streaming","filters":{"level":"info"}}"#.into(),
        ))
        .await
        .unwrap();
        for _ in 0..100 {
            context
                .logger
                .log(
                    super::super::logging::Level::Info,
                    super::super::logging::Event::Http,
                    "synthetic-log",
                    json!({"token":"sensitive"}),
                )
                .unwrap();
            tokio::task::yield_now().await;
        }
        let event = tokio::time::timeout(Duration::from_secs(1), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(event.to_text().unwrap()).unwrap();
        assert_eq!(json["type"], "logs");
        assert_eq!(json["logs"][0]["fields"]["token"], "[redacted]");
        cancel.cancel();
        // Keep draining while the bounded server stream sends its close frame.
        while let Ok(Some(Ok(message))) =
            tokio::time::timeout(Duration::from_secs(1), ws.next()).await
        {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    #[test]
    fn decoder_rejects_wrong_alg_empty_claims_and_cloudflare_origin_lookalikes() {
        assert!(decode_token("invalid").is_err());
        let signed = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(br#"{}"#),
            URL_SAFE_NO_PAD.encode([0u8; 64])
        );
        assert!(decode_token(&signed).is_err());
        for origin in [
            "http://dash.cloudflare.com",
            "https://cloudflare.com.attacker.test",
            "https://attacker.test",
        ] {
            let request = Request::builder()
                .header("origin", origin)
                .body(())
                .unwrap();
            assert!(cors_origin(&request).is_none());
        }
        assert!(websocket_origin_allowed(
            &Request::builder()
                .header("origin", "https://dash.cloudflare.com")
                .body(())
                .unwrap()
        ));
    }
}
