use crate::crypto::EdgeTls;
use bytes::Bytes;
use h2::server::Connection;
use std::{io, net::SocketAddr, time::Duration};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

pub type H2Connection = Connection<SslStream<TcpStream>, Bytes>;

pub async fn dial(
    address: SocketAddr,
    server_name: &str,
    tls: &EdgeTls,
) -> io::Result<H2Connection> {
    dial_with_options(
        address,
        server_name,
        tls,
        &super::EdgeDialOptions::default(),
    )
    .await
}

pub async fn dial_with_options(
    address: SocketAddr,
    server_name: &str,
    tls: &EdgeTls,
    options: &super::EdgeDialOptions,
) -> io::Result<H2Connection> {
    Ok(
        dial_with_options_and_addr(address, server_name, tls, options)
            .await?
            .0,
    )
}

pub async fn dial_with_options_and_addr(
    address: SocketAddr,
    server_name: &str,
    tls: &EdgeTls,
    options: &super::EdgeDialOptions,
) -> io::Result<(H2Connection, SocketAddr)> {
    let (stream, local_addr) = dial_tls_with_options(address, server_name, tls, options).await?;
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        h2::server::Builder::new()
            .max_concurrent_streams(u32::MAX)
            .handshake(stream),
    )
    .await?
    .map_err(io::Error::other)?;
    Ok((connection, local_addr))
}

pub async fn dial_tls_with_options(
    address: SocketAddr,
    server_name: &str,
    tls: &EdgeTls,
    options: &super::EdgeDialOptions,
) -> io::Result<(SslStream<TcpStream>, SocketAddr)> {
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    if let Some(ip) = options.bind_ip {
        socket.bind(SocketAddr::new(ip, 0))?;
    }
    let socket = tokio::time::timeout(options.dial_timeout, socket.connect(address)).await??;
    let local_addr = socket.local_addr()?;
    let mut ssl = boring::ssl::Ssl::new(tls.context()).map_err(io::Error::other)?;
    crate::crypto::set_tls_name(&mut ssl, server_name).map_err(io::Error::other)?;
    let stream = tokio::time::timeout(
        options.dial_timeout,
        tokio_boring::SslStreamBuilder::new(ssl, socket).connect(),
    )
    .await?
    .map_err(io::Error::other)?;
    Ok((stream, local_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{TlsPolicy, tests::certificate};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn outbound_tls_client_serves_inbound_h2() {
        let (cert, key) = certificate();
        let mut ssl =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                .unwrap();
        ssl.set_certificate(&cert).unwrap();
        ssl.set_private_key(&key).unwrap();
        let acceptor = ssl.build();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let edge = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = tokio_boring::accept(&acceptor, socket).await.unwrap();
            assert!(tls.ssl().selected_alpn_protocol().is_none());
            let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            let (response, _) = client
                .send_request(
                    http::Request::builder()
                        .uri("https://edge.test/")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let mut response = response.await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "hello");
            task.abort();
        });
        let tls = EdgeTls::new(TlsPolicy::default(), Some(&cert.to_pem().unwrap())).unwrap();
        let mut server = dial(addr, "edge.test", &tls).await.unwrap();
        let (_, mut response) = server.accept().await.unwrap().unwrap();
        let mut stream = response
            .send_response(
                http::Response::builder().status(200).body(()).unwrap(),
                false,
            )
            .unwrap();
        stream
            .send_data(Bytes::from_static(b"hello"), true)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! { result = edge => result.unwrap(), _ = server.accept() => {} }
        })
        .await
        .unwrap();
    }
}
