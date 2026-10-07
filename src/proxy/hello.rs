use anyhow::Result;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Body, Frame, Incoming};
use std::{
    collections::BTreeMap,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::Role},
};
type Event = Pin<Box<dyn Future<Output = ()> + Send>>;
type ResponseBody = BoxBody<Bytes, io::Error>;

pub(super) struct Server {
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct State {
    started: Instant,
    created: SystemTime,
}
pub(super) fn start() -> Result<(url::Url, Server)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let state = Arc::new(State {
        started: Instant::now(),
        created: SystemTime::now(),
    });
    let task = tokio::spawn(async move {
        let (events, mut receive) = mpsc::channel::<Event>(32);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream,peer)) = accepted else {
                        break;
                    };
                    let state = state.clone();
                    let events = events.clone();
                    tasks.spawn(async move {
                        let service = hyper::service::service_fn(move |request| {
                            serve(request, peer, state.clone(), events.clone())
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .with_upgrades()
                            .await;
                    });
                },
                event = receive.recv() => {
                    if let Some(event) = event {
                        tasks.spawn(event);
                    } else {
                        break;
                    }
                },
                _ = tasks.join_next(), if !tasks.is_empty() => {},
            }
        }
    });
    Ok((
        url::Url::parse(&format!("http://{address}"))?,
        Server { task },
    ))
}
fn full(bytes: impl Into<Bytes>) -> ResponseBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}
async fn serve(
    mut request: Request<Incoming>,
    peer: std::net::SocketAddr,
    state: Arc<State>,
    events: mpsc::Sender<Event>,
) -> io::Result<Response<ResponseBody>> {
    match request.uri().path() {
        "/_health" => Ok(Response::new(full("ok"))),
        "/uptime" => {
            let seconds = state
                .created
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            let date = rfc3339(seconds);
            let mut response=Response::new(full(serde_json::to_vec(&serde_json::json!({"startTime":date,"uptime":duration(state.started.elapsed())})).map_err(io::Error::other)?));
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            Ok(response)
        }
        "/sse" => {
            let frequency = request
                .uri()
                .query()
                .and_then(|query| {
                    url::form_urlencoded::parse(query.as_bytes())
                        .find(|(name, _)| name == "freq")
                        .map(|(_, value)| value.into_owned())
                })
                .and_then(|value| crate::config::parse_duration(&value).ok())
                .unwrap_or(Duration::from_secs(10));
            if frequency.is_zero() {
                return Err(io::Error::other("invalid SSE frequency"));
            }
            let body = Sse {
                interval: tokio::time::interval_at(
                    tokio::time::Instant::now() + frequency,
                    frequency,
                ),
                counter: 0,
            };
            let mut response = Response::new(body.boxed());
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/event-stream; charset=utf-8"),
            );
            Ok(response)
        }
        "/ws" => {
            if let Some(origin) = request
                .headers()
                .get(http::header::ORIGIN)
                .and_then(|value| value.to_str().ok())
            {
                let origin = url::Url::parse(origin).ok();
                let host = request
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("");
                if !origin
                    .as_ref()
                    .and_then(url::Url::host_str)
                    .is_some_and(|origin| origin.eq_ignore_ascii_case(host))
                {
                    return Ok(Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(full("Forbidden\n"))
                        .unwrap());
                }
            }
            let mut head = Request::builder()
                .method(request.method())
                .uri(request.uri())
                .body(())
                .unwrap();
            *head.headers_mut() = request.headers().clone();
            let response =
                match tokio_tungstenite::tungstenite::handshake::server::create_response(&head) {
                    Ok(response) => response,
                    Err(_) => {
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(full("Bad Request\n"))
                            .unwrap());
                    }
                };
            let upgrade = hyper::upgrade::on(&mut request);
            events
                .send(Box::pin(async move {
                    if let Ok(stream) = upgrade.await {
                        let mut websocket = WebSocketStream::from_raw_socket(
                            hyper_util::rt::TokioIo::new(stream),
                            Role::Server,
                            None,
                        )
                        .await;
                        while let Some(message) = websocket.next().await {
                            match message {
                                Ok(message @ (Message::Binary(_) | Message::Text(_))) => {
                                    if websocket.send(message).await.is_err() {
                                        break;
                                    }
                                }
                                Ok(Message::Ping(_)) => {
                                    if websocket.flush().await.is_err() {
                                        break;
                                    }
                                }
                                Ok(Message::Close(_)) => {
                                    let _ = websocket.flush().await;
                                    break;
                                }
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    }
                }))
                .await
                .map_err(|_| io::Error::other("Hello World origin closed"))?;
            let (parts, _) = response.into_parts();
            Ok(Response::from_parts(parts, full(Bytes::new())))
        }
        _ => {
            let method = request.method().to_string();
            let uri = request.uri().to_string();
            let host = request
                .headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let mut headers = BTreeMap::<String, Vec<String>>::new();
            for (name, value) in request.headers() {
                headers
                    .entry(super::canonical_header(name.as_str()))
                    .or_default()
                    .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
            }
            let encoding = if request
                .headers()
                .get(http::header::TRANSFER_ENCODING)
                .is_some()
            {
                "[chunked]"
            } else {
                "[]"
            };
            let body = request
                .into_body()
                .collect()
                .await
                .map(|body| String::from_utf8_lossy(&body.to_bytes()).into_owned())
                .unwrap_or_default();
            let html = render(
                &method,
                &uri,
                encoding,
                &host,
                &peer.to_string(),
                &headers,
                &body,
            );
            let mut response = Response::new(full(html));
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/html; charset=utf-8"),
            );
            Ok(response)
        }
    }
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
        .replace('+', "&#43;")
}
fn render(
    method: &str,
    uri: &str,
    encoding: &str,
    host: &str,
    peer: &str,
    headers: &BTreeMap<String, Vec<String>>,
    body: &str,
) -> String {
    let template = include_str!("hello.html");
    let start = template
        .find("{{range $key, $value := .Request.Header}}")
        .unwrap();
    let end = start + template[start..].find("{{end}}").unwrap() + 7;
    let lines = headers
        .iter()
        .map(|(name, values)| {
            format!(
                "\n\t\t\t\t\t\t<dd class=\"ml0 mb3 f5\">Header: {}, Value: [{}]</dd>\n",
                escape(name),
                escape(&values.join(" "))
            )
        })
        .collect::<String>();
    let mut html = format!("{}{}{}", &template[..start], lines, &template[end..]);
    for (name, value) in [
        ("Method", method),
        ("Proto", "HTTP/1.1"),
        ("URL", uri),
        ("TransferEncoding", encoding),
        ("Host", host),
        ("RemoteAddr", peer),
        ("RequestURI", uri),
    ] {
        html = html.replace(&format!("{{{{.Request.{name}}}}}"), &escape(value));
    }
    html.replace("{{.Body}}", &escape(body))
}
fn duration(value: Duration) -> String {
    let nanos = value.as_nanos();
    if nanos < 1000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return format!("{}µs", nanos as f64 / 1000.0);
    }
    if nanos < 1_000_000_000 {
        return format!("{}ms", nanos as f64 / 1_000_000.0);
    }
    let seconds = value.as_secs();
    let fraction = if value.subsec_nanos() == 0 {
        String::new()
    } else {
        format!(".{:09}", value.subsec_nanos())
            .trim_end_matches('0')
            .into()
    };
    if seconds < 60 {
        format!("{seconds}{fraction}s")
    } else if seconds < 3600 {
        format!("{}m{}{fraction}s", seconds / 60, seconds % 60)
    } else {
        format!(
            "{}h{}m{}{fraction}s",
            seconds / 3600,
            (seconds / 60) % 60,
            seconds % 60
        )
    }
}
fn rfc3339(value: Duration) -> String {
    let time = value.as_secs() as _;
    let mut calendar = std::mem::MaybeUninit::<libc::tm>::uninit();
    let valid = unsafe { libc::gmtime_r(&time, calendar.as_mut_ptr()) };
    if valid.is_null() {
        return String::new();
    }
    let calendar = unsafe { calendar.assume_init() };
    let fraction = if value.subsec_nanos() == 0 {
        String::new()
    } else {
        format!(".{:09}", value.subsec_nanos())
            .trim_end_matches('0')
            .into()
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fraction}Z",
        calendar.tm_year + 1900,
        calendar.tm_mon + 1,
        calendar.tm_mday,
        calendar.tm_hour,
        calendar.tm_min,
        calendar.tm_sec
    )
}
struct Sse {
    interval: tokio::time::Interval,
    counter: u64,
}
impl Body for Sse {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.interval.poll_tick(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => {
                let data = Bytes::from(format!("{}\n\n", self.counter));
                self.counter += 1;
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn real_origin_echo_health_uptime_sse_websocket_and_drop() {
        let (url, server) = start().unwrap();
        let client = crate::access::http_client().unwrap();
        let mut response = client
            .request(
                Request::builder()
                    .method("POST")
                    .uri(url.join("/echo?tag=value").unwrap().as_str())
                    .header("x-test", "<safe>")
                    .body(Full::new(Bytes::from_static(b"<body>")))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = crate::access::bounded_body(&mut response, 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains("Congrats! You created a tunnel!"));
        assert!(body.contains("Body: &lt;body&gt;"));
        assert!(body.contains("Value: [&lt;safe&gt;]"));
        let response = client
            .get(url.join("/_health").unwrap().as_str().parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            b"ok".as_slice()
        );
        let response = client
            .get(url.join("/uptime").unwrap().as_str().parse().unwrap())
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["startTime"].as_str().unwrap().ends_with('Z'));
        assert!(value["uptime"].as_str().unwrap().ends_with('s'));
        let mut response = client
            .get(url.join("/sse?freq=1ms").unwrap().as_str().parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.headers()[http::header::CONTENT_TYPE],
            "text/event-stream; charset=utf-8"
        );
        let frame = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert_eq!(frame.as_ref(), b"0\n\n");
        drop(response);
        let websocket_url = format!(
            "ws://{}/ws",
            url[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
        );
        let stream = tokio::net::TcpStream::connect((url.host_str().unwrap(), url.port().unwrap()))
            .await
            .unwrap();
        let (mut websocket, _) = tokio_tungstenite::client_async(&websocket_url, stream)
            .await
            .unwrap();
        websocket.send(Message::Text("hello".into())).await.unwrap();
        assert_eq!(
            websocket
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
            "hello"
        );
        websocket.close(None).await.unwrap();
        drop(server);
        tokio::task::yield_now().await;
        let mut disconnected = false;
        for _ in 0..10 {
            if tokio::net::TcpStream::connect((url.host_str().unwrap(), url.port().unwrap()))
                .await
                .is_err()
            {
                disconnected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(disconnected);
    }
}
