use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::{net::TcpListener, sync::mpsc, task::JoinSet};

pub(crate) struct Request {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
}
pub(crate) struct HttpPeer {
    pub address: SocketAddr,
    pub requests: mpsc::UnboundedReceiver<Request>,
    pub connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    _task: crate::runtime::AbortTask<()>,
}
impl HttpPeer {
    pub async fn start_gzip(body: Bytes) -> Self {
        use tokio::io::AsyncWriteExt;
        let mut encoder = async_compression::tokio::write::GzipEncoder::new(Vec::new());
        encoder.write_all(&body).await.unwrap();
        encoder.shutdown().await.unwrap();
        Self::start_with_headers(
            StatusCode::OK,
            Bytes::from(encoder.into_inner()),
            HeaderMap::from_iter([(
                http::header::CONTENT_ENCODING,
                http::HeaderValue::from_static("gzip"),
            )]),
        )
        .await
    }

    pub async fn start(status: StatusCode, body: Bytes) -> Self {
        Self::start_with_headers(status, body, HeaderMap::new()).await
    }
    pub async fn start_with_headers(
        status: StatusCode,
        body: Bytes,
        response_headers: HeaderMap,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests, receiver) = mpsc::unbounded_channel();
        let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = connections.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let requests = requests.clone();
                        let body = body.clone();
                        let response_headers = response_headers.clone();
                        connections.spawn(async move {
                            let service = hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                                let body = body.clone();
                                let response_headers = response_headers.clone();
                                let (parts, _) = request.into_parts();
                                let _ = requests.send(Request { method:parts.method,uri:parts.uri,headers:parts.headers });
                                async move {
                                    let mut response = http::Response::builder().status(status).body(Full::new(body)).unwrap();
                                    *response.headers_mut() = response_headers;
                                    Ok::<_, std::convert::Infallible>(response)
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        completed.unwrap().unwrap();
                    }
                }
            }
        });
        Self {
            address,
            requests: receiver,
            connections,
            _task: crate::runtime::AbortTask(task),
        }
    }
}
