use crate::runtime::AbortTask;
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, handshake::derive_accept_key, protocol::Role},
};

pub(crate) async fn start() -> (SocketAddr, AbortTask<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut flows = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut socket, _) = accepted.unwrap();
                    flows.spawn(async move {
                        let mut bytes = Vec::new();
                        while !bytes.ends_with(b"\r\n\r\n") {
                            match socket.read_u8().await {
                                Ok(byte) => bytes.push(byte),
                                Err(_) => return,
                            }
                            assert!(bytes.len() < 16 * 1024);
                        }
                        let head = String::from_utf8(bytes).unwrap();
                        let values = |name: &str| {
                            head.lines()
                                .filter_map(|line| {
                                    let (key, value) = line.split_once(':')?;
                                    key.eq_ignore_ascii_case(name)
                                        .then(|| value.trim().to_owned())
                                })
                                .collect::<Vec<_>>()
                        };
                        let body = serde_json::to_vec(&serde_json::json!({"id": values("cf-warp-tag-id"), "x": values("cf-warp-tag-x")})).unwrap();
                        if values("upgrade").iter().any(|value| value.eq_ignore_ascii_case("websocket")) {
                            let key = values("sec-websocket-key").into_iter().next().unwrap();
                            let response = format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n", derive_accept_key(key.as_bytes()));
                            socket.write_all(response.as_bytes()).await.unwrap();
                            let mut websocket = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
                            if websocket.send(Message::Binary(body.into())).await.is_err() {
                                return;
                            }
                            while let Some(message) = websocket.next().await {
                                match message {
                                    Ok(Message::Binary(body)) => {
                                        if websocket.send(Message::Binary(body)).await.is_err() {
                                            break;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        } else {
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", body.len());
                            socket.write_all(response.as_bytes()).await.unwrap();
                            socket.write_all(&body).await.unwrap();
                            socket.shutdown().await.unwrap();
                        }
                    });
                }
                result = flows.join_next(), if !flows.is_empty() => {
                    result.unwrap().unwrap();
                }
            }
        }
    });
    (address, AbortTask(task))
}
