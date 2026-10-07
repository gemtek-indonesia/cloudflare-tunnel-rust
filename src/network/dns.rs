use anyhow::{Context, Result, bail};
use hickory_resolver::proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::RwLock,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
pub(crate) const VIRTUAL_DNS: SocketAddr = SocketAddr::new(
    IpAddr::V6(std::net::Ipv6Addr::new(
        0x2606, 0x4700, 0xcf1, 0x2000, 0, 0, 0, 1,
    )),
    53,
);
pub(crate) struct DnsService {
    addresses: RwLock<Vec<SocketAddr>>,
    static_config: bool,
}
impl DnsService {
    pub(crate) fn new(addresses: Vec<SocketAddr>) -> Self {
        let static_config = !addresses.is_empty();
        Self {
            addresses: RwLock::new(if static_config {
                addresses
            } else {
                vec!["127.0.0.1:53".parse().unwrap()]
            }),
            static_config,
        }
    }
    pub(crate) fn destination(&self, requested: SocketAddr) -> SocketAddr {
        if requested != VIRTUAL_DNS {
            return requested;
        }
        let addresses = self.addresses.read().unwrap();
        let mut random = [0; 8];
        let index = if addresses.len() > 1 && boring::rand::rand_bytes(&mut random).is_ok() {
            u64::from_ne_bytes(random) as usize % addresses.len()
        } else {
            0
        };
        addresses[index]
    }
    async fn discover() -> Result<SocketAddr> {
        let text = tokio::fs::read_to_string("/etc/resolv.conf")
            .await
            .context("read local DNS resolver configuration")?;
        let servers: Vec<_> = text
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                if parts.next() != Some("nameserver") {
                    return None;
                }
                parts
                    .next()?
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| SocketAddr::new(ip, 53))
            })
            .collect();
        if servers.is_empty() {
            bail!("no local DNS nameservers");
        }
        for server in servers {
            if Self::probe(server).await.is_ok() {
                return Ok(server);
            }
        }
        bail!("local DNS discovery query failed")
    }
    async fn probe(server: SocketAddr) -> Result<()> {
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind).await?;
        socket.connect(server).await?;
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii("region1.v2.argotunnel.com.")?,
            RecordType::A,
        ));
        socket.send(&query.to_vec()?).await?;
        let mut buffer = [0; 65535];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buffer)).await??;
        let response = Message::from_vec(&buffer[..n])?;
        if response.metadata.id != query.metadata.id
            || response.queries != query.queries
            || response.metadata.response_code != ResponseCode::NoError
            || response.answers.is_empty()
        {
            bail!("invalid resolver discovery response");
        }
        Ok(())
    }
    pub(crate) async fn refresh_loop(&self, cancel: CancellationToken) {
        if self.static_config {
            return;
        }
        loop {
            let result = tokio::select! {_=cancel.cancelled()=>return,result=tokio::time::timeout(Duration::from_secs(5),Self::discover())=>result};
            match result {
                Ok(Ok(address)) => *self.addresses.write().unwrap() = vec![address],
                _ => eprintln!("Failed to refresh local DNS resolver; retaining previous address"),
            };
            tokio::select! {_=cancel.cancelled()=>return,_=tokio::time::sleep(Duration::from_secs(300))=>{}}
        }
    }
}
