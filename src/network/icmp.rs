use super::{
    Connection, DatagramVersion,
    packet::{IcmpPacket, checksum},
    tracing::{Identity, Trace},
};
use crate::protocol::datagram::{DatagramV2, DatagramV3};
use anyhow::{Context, Result};
use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub(crate) fn determine_sources(config: &mut crate::config::RunConfig) -> Result<()> {
    let ipv4 = config.icmpv4_src.unwrap_or_else(|| {
        let detected = (|| {
            let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            socket.connect((Ipv4Addr::new(192, 168, 0, 1), 53))?;
            match socket.local_addr()?.ip() {
                IpAddr::V4(ip) => Ok(ip),
                _ => Err(std::io::Error::other("expected IPv4 source")),
            }
        })();
        detected.unwrap_or(Ipv4Addr::UNSPECIFIED)
    });
    config.icmpv4_src = Some(ipv4);
    if config.icmpv6_src.is_none() {
        let (address, zone) = choose_ipv6(ipv4, &interfaces().unwrap_or_default());
        config.icmpv6_src = Some(if zone.is_empty() {
            address.to_string()
        } else {
            format!("{address}%{zone}")
        });
    }
    Ok(())
}
struct Interface {
    name: String,
    addresses: Vec<IpAddr>,
}
fn choose_ipv6(ipv4: Ipv4Addr, interfaces: &[Interface]) -> (Ipv6Addr, String) {
    let preferred = interfaces
        .iter()
        .find(|interface| interface.addresses.contains(&IpAddr::V4(ipv4)));
    preferred
        .into_iter()
        .chain(interfaces.iter())
        .find_map(|interface| {
            interface
                .addresses
                .iter()
                .find_map(|address| match address {
                    IpAddr::V6(address) => Some((*address, interface.name.clone())),
                    _ => None,
                })
        })
        .unwrap_or((Ipv6Addr::UNSPECIFIED, String::new()))
}
fn interfaces() -> Result<Vec<Interface>> {
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let mut head = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes head; the guard frees its linked allocation once.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let guard = Addresses(head);
    let mut current = guard.0;
    let mut interfaces = std::collections::BTreeMap::<u32, Interface>::new();
    while !current.is_null() {
        // SAFETY: the linked list and pointed sockaddr/name remain owned by guard.
        let item = unsafe { &*current };
        if !item.ifa_addr.is_null() && !item.ifa_name.is_null() {
            let address = unsafe {
                match (*item.ifa_addr).sa_family as i32 {
                    libc::AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                        (*(item.ifa_addr as *const libc::sockaddr_in))
                            .sin_addr
                            .s_addr
                            .to_ne_bytes(),
                    ))),
                    libc::AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(
                        (*(item.ifa_addr as *const libc::sockaddr_in6))
                            .sin6_addr
                            .s6_addr,
                    ))),
                    _ => None,
                }
            };
            if let Some(address) = address {
                let name = unsafe { std::ffi::CStr::from_ptr(item.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                let index = unsafe { libc::if_nametoindex(item.ifa_name) };
                interfaces
                    .entry(index)
                    .or_insert_with(|| Interface {
                        name,
                        addresses: vec![],
                    })
                    .addresses
                    .push(address);
            }
        }
        current = item.ifa_next;
    }
    Ok(interfaces.into_values().collect())
}
#[derive(Hash, Eq, PartialEq, Clone)]
struct Key(IpAddr, IpAddr, u16);
struct Flow {
    index: u8,
    generation: uuid::Uuid,
    cancel: CancellationToken,
    socket: Arc<tokio::net::UdpSocket>,
    echo_id: u16,
    activity: tokio::sync::watch::Sender<tokio::time::Instant>,
}
pub(crate) struct IcmpRouter {
    v4: Ipv4Addr,
    v6: Ipv6Addr,
    zone: u32,
    flows: Mutex<HashMap<Key, Arc<Flow>>>,
}
impl Drop for IcmpRouter {
    fn drop(&mut self) {
        for flow in self.flows.get_mut().unwrap().values() {
            flow.cancel.cancel();
        }
    }
}
impl IcmpRouter {
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.flows.lock().unwrap().len()
    }
    #[cfg(test)]
    pub(super) fn kernel_ids(&self) -> Vec<u16> {
        self.flows
            .lock()
            .unwrap()
            .values()
            .map(|flow| flow.echo_id)
            .collect()
    }
    pub(crate) fn sources(&self) -> Vec<String> {
        vec![
            self.v4.to_string(),
            if self.zone == 0 {
                self.v6.to_string()
            } else {
                format!("{}%{}", self.v6, self.zone)
            },
        ]
    }
    pub(crate) fn new(config: &crate::config::RunConfig) -> Result<Arc<Self>> {
        let (v6, zone) = if let Some(source) = &config.icmpv6_src {
            let (ip, zone) = source.split_once('%').unwrap_or((source, ""));
            let zone = if zone.is_empty() {
                0
            } else if let Ok(index) = zone.parse() {
                index
            } else {
                anyhow::ensure!(
                    !zone.contains('/') && !zone.contains('\0'),
                    "invalid IPv6 interface"
                );
                std::fs::read_to_string(format!("/sys/class/net/{zone}/ifindex"))
                    .context("read IPv6 interface index")?
                    .trim()
                    .parse()?
            };
            (ip.parse()?, zone)
        } else {
            (Ipv6Addr::UNSPECIFIED, 0)
        };
        Ok(Arc::new(Self {
            v4: config.icmpv4_src.unwrap_or(Ipv4Addr::UNSPECIFIED),
            v6,
            zone,
            flows: Mutex::new(HashMap::new()),
        }))
    }
    fn open(&self, ipv4: bool) -> Result<(tokio::net::UdpSocket, u16)> {
        let socket = Socket::new(
            if ipv4 { Domain::IPV4 } else { Domain::IPV6 },
            Type::DGRAM,
            Some(if ipv4 {
                Protocol::ICMPV4
            } else {
                Protocol::ICMPV6
            }),
        )?;
        socket.set_nonblocking(true)?;
        let address = if ipv4 {
            SocketAddr::new(IpAddr::V4(self.v4), 0)
        } else {
            SocketAddr::V6(SocketAddrV6::new(self.v6, 0, 0, self.zone))
        };
        socket.bind(&address.into())?;
        let echo_id = socket
            .local_addr()?
            .as_socket()
            .context("invalid ping socket address")?
            .port();
        let socket: std::net::UdpSocket = socket.into();
        Ok((tokio::net::UdpSocket::from_std(socket)?, echo_id))
    }
    pub(crate) async fn handle(
        self: &Arc<Self>,
        connection: Arc<Connection>,
        raw: Vec<u8>,
        identity: Option<[u8; 25]>,
    ) -> Result<()> {
        anyhow::ensure!(
            connection.state.icmp_enabled,
            "ICMP is unavailable for quick tunnels"
        );
        let packet = IcmpPacket::decode(&raw).map_err(anyhow::Error::msg)?;
        if packet.ttl <= 1 {
            let source = if packet.destination.is_ipv4() {
                IpAddr::V4(self.v4)
            } else {
                IpAddr::V6(self.v6)
            };
            return send_packet(
                &connection,
                packet
                    .ttl_exceeded(&raw, source)
                    .map_err(anyhow::Error::msg)?,
            )
            .await;
        }
        let echo = packet.echo_id().map_err(anyhow::Error::msg)?;
        let key = Key(packet.source, packet.destination, echo);
        let existing = self.flows.lock().unwrap().get(&key).cloned();
        let flow = if let Some(flow) = existing.filter(|f| {
            f.index == connection.index
                && f.generation == connection.generation
                && !f.cancel.is_cancelled()
        }) {
            flow
        } else {
            let (socket, echo_id) = self.open(packet.destination.is_ipv4())?;
            let (activity, _) = tokio::sync::watch::channel(tokio::time::Instant::now());
            let flow = Arc::new(Flow {
                index: connection.index,
                generation: connection.generation,
                cancel: CancellationToken::new(),
                socket: Arc::new(socket),
                echo_id,
                activity,
            });
            if let Some(previous) = self.flows.lock().unwrap().insert(key.clone(), flow.clone()) {
                previous.cancel.cancel();
            }
            let router = Arc::downgrade(self);
            let flow_reader = flow.clone();
            let conn = connection.clone();
            let request = packet.clone();
            tokio::task::spawn_local(async move {
                use opentelemetry_proto::tonic::common::v1::any_value::Value;
                let mut reply_trace = identity.map(|identity| {
                    Trace::with_identity(Identity(identity), "icmp-echo-reply")
                        .attribute("originalEchoID", Value::IntValue(i64::from(echo)))
                });
                let mut buffer = [0; 1500];
                let mut activity = flow_reader.activity.subscribe();
                let mut deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                loop {
                    tokio::select! {
                        _ = flow_reader.cancel.cancelled() => break,
                        _ = conn.cancel.cancelled() => break,
                        result = activity.changed() => {
                            if result.is_err() { break; }
                            deadline = *activity.borrow() + Duration::from_secs(10);
                        }
                        _ = tokio::time::sleep_until(deadline) => break,
                        result = flow_reader.socket.recv_from(&mut buffer) => {
                            let Ok((n, from)) = result else { break; };
                            if let Ok(reply) = request.echo_reply(from.ip(), buffer[..n].to_vec()) {
                                let result=tokio::select! {
                                    _ = conn.cancel.cancelled() => break,
                                    result = send_packet(&conn, reply) => result,
                                };
                                if let (Some(trace),Some(identity))=(reply_trace.take(),identity) {
                                    let trace=trace.attribute("dst",Value::StringValue(from.ip().to_string())).attribute("assignedEchoID",Value::IntValue(i64::from(flow_reader.echo_id))).attribute("seq",Value::IntValue(i64::from(u16::from_be_bytes(buffer[6..8].try_into().unwrap()))));
                                    let spans=trace.finish(result.as_ref().err().map(|e|e.to_string()).as_deref());
                                    if !spans.is_empty() {let packet=DatagramV2::TraceSpans{identity,payload:spans}.encode().unwrap();let _=conn.sender.send_datagram(Bytes::from(packet)).await;}
                                }
                                flow_reader.activity.send_replace(tokio::time::Instant::now());
                            }
                        }
                    }
                }
                if let Some(router) = router.upgrade() {
                    let mut flows = router.flows.lock().unwrap();
                    if flows
                        .get(&key)
                        .is_some_and(|f| Arc::ptr_eq(f, &flow_reader))
                    {
                        flows.remove(&key);
                    }
                }
            });
            flow
        };
        use opentelemetry_proto::tonic::common::v1::any_value::Value;
        let trace = identity.map(|identity| {
            Trace::with_identity(Identity(identity), "icmp-echo-request")
                .attribute("src", Value::StringValue(packet.source.to_string()))
                .attribute("dst", Value::StringValue(packet.destination.to_string()))
                .attribute("originalEchoID", Value::IntValue(i64::from(echo)))
                .attribute(
                    "seq",
                    Value::IntValue(i64::from(u16::from_be_bytes(
                        packet.message[6..8].try_into().unwrap(),
                    ))),
                )
                .attribute("port", Value::IntValue(i64::from(flow.echo_id)))
        });
        let mut message = packet.message.clone();
        message[4..6].copy_from_slice(&flow.echo_id.to_be_bytes());
        message[2..4].fill(0);
        if packet.destination.is_ipv4() {
            let value = checksum(&message);
            message[2..4].copy_from_slice(&value.to_be_bytes());
        }
        flow.activity.send_replace(tokio::time::Instant::now());
        let result = tokio::select! {
            _ = connection.cancel.cancelled() => return Ok(()),
            result = flow.socket.send_to(&message, SocketAddr::new(packet.destination, 0)) => result,
        };
        if let (Some(trace), Some(identity)) = (trace, identity) {
            let spans = trace.finish(result.as_ref().err().map(|e| e.to_string()).as_deref());
            if !spans.is_empty() {
                let bytes = DatagramV2::TraceSpans {
                    identity,
                    payload: spans,
                }
                .encode()
                .map_err(anyhow::Error::msg)?;
                let _ = connection.sender.send_datagram(Bytes::from(bytes)).await;
            }
        }
        result?;
        Ok(())
    }
}
async fn send_packet(connection: &Connection, packet: Vec<u8>) -> Result<()> {
    let bytes = match connection.version {
        DatagramVersion::V2 => DatagramV2::Ip(packet).encode(),
        DatagramVersion::V3 => DatagramV3::Icmp(packet).encode(),
    }
    .map_err(anyhow::Error::msg)?;
    connection.sender.send_datagram(Bytes::from(bytes)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_source_prefers_ipv4_interface_then_first_ipv6_then_unspecified() {
        let interfaces = vec![
            Interface {
                name: "loopback".into(),
                addresses: vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            },
            Interface {
                name: "synthetic0".into(),
                addresses: vec![
                    "192.0.2.10".parse().unwrap(),
                    "2001:db8::10".parse().unwrap(),
                ],
            },
        ];
        assert_eq!(
            choose_ipv6("192.0.2.10".parse().unwrap(), &interfaces),
            ("2001:db8::10".parse().unwrap(), "synthetic0".into())
        );
        assert_eq!(
            choose_ipv6(Ipv4Addr::UNSPECIFIED, &interfaces),
            (Ipv6Addr::LOCALHOST, "loopback".into())
        );
        assert_eq!(
            choose_ipv6(Ipv4Addr::UNSPECIFIED, &[]),
            (Ipv6Addr::UNSPECIFIED, String::new())
        );
    }
}
