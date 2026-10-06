use std::net::{IpAddr, SocketAddr};

pub const MAX_FRAME: usize = 1350;
pub const MAX_PAYLOAD: usize = 1280;
pub const TRACE_ID_LEN: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramV2 {
    Udp {
        session_id: [u8; 16],
        payload: Vec<u8>,
    },
    Ip(Vec<u8>),
    TracedIp {
        identity: [u8; TRACE_ID_LEN],
        payload: Vec<u8>,
    },
    TraceSpans {
        identity: [u8; TRACE_ID_LEN],
        payload: Vec<u8>,
    },
}
impl DatagramV2 {
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        let (kind, payload, metadata): (_, _, &[u8]) = match self {
            Self::Udp {
                session_id,
                payload,
            } => {
                if payload.len() > MAX_PAYLOAD {
                    return Err("UDP payload too large");
                }
                (0, payload, session_id)
            }
            Self::Ip(payload) => (1, payload, &[]),
            Self::TracedIp { identity, payload } => (2, payload, identity),
            Self::TraceSpans { identity, payload } => (3, payload, identity),
        };
        if payload.len() + metadata.len() + 1 > MAX_FRAME {
            return Err("datagram frame too large");
        }
        let mut out = payload.clone();
        out.extend_from_slice(metadata);
        out.push(kind);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_FRAME {
            return Err("datagram frame too large");
        }
        let (&kind, data) = bytes.split_last().ok_or("empty datagram")?;
        match kind {
            0 => {
                if data.len() < 16 {
                    return Err("truncated UDP session ID");
                }
                let (payload, id) = data.split_at(data.len() - 16);
                Ok(Self::Udp {
                    session_id: id.try_into().unwrap(),
                    payload: payload.to_vec(),
                })
            }
            1 => Ok(Self::Ip(data.to_vec())),
            2 | 3 => {
                if data.len() < TRACE_ID_LEN {
                    return Err("truncated tracing identity");
                }
                let (payload, id) = data.split_at(data.len() - TRACE_ID_LEN);
                let identity = id.try_into().unwrap();
                Ok(if kind == 2 {
                    Self::TracedIp {
                        identity,
                        payload: payload.to_vec(),
                    }
                } else {
                    Self::TraceSpans {
                        identity,
                        payload: payload.to_vec(),
                    }
                })
            }
            _ => Err("unknown v2 datagram type"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramV3 {
    Registration {
        id: [u8; 16],
        destination: SocketAddr,
        traced: bool,
        idle_seconds: u16,
        payload: Vec<u8>,
    },
    Payload {
        id: [u8; 16],
        payload: Vec<u8>,
    },
    Icmp(Vec<u8>),
    Response {
        id: [u8; 16],
        response_type: u8,
        error: String,
    },
}
impl DatagramV3 {
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::new();
        match self {
            Self::Registration {
                id,
                destination,
                traced,
                idle_seconds,
                payload,
            } => {
                let ip = destination.ip();
                out.push(0);
                out.push(
                    u8::from(ip.is_ipv6())
                        | if *traced { 2 } else { 0 }
                        | if payload.is_empty() { 0 } else { 4 },
                );
                out.extend_from_slice(&destination.port().to_be_bytes());
                out.extend_from_slice(&idle_seconds.to_be_bytes());
                out.extend_from_slice(id);
                match ip {
                    IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
                    IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
                }
                out.extend_from_slice(payload);
                let header_len = if ip.is_ipv6() { 38 } else { 26 };
                if payload.len() > MAX_PAYLOAD + header_len {
                    return Err("registration datagram too large");
                }
            }
            Self::Payload { id, payload } => {
                if payload.len() > MAX_PAYLOAD {
                    return Err("UDP payload too large");
                }
                out.push(1);
                out.extend_from_slice(id);
                out.extend_from_slice(payload);
            }
            Self::Icmp(payload) => {
                if payload.is_empty() || payload.len() > MAX_PAYLOAD {
                    return Err("invalid ICMP payload size");
                }
                out.push(2);
                out.extend_from_slice(payload);
            }
            Self::Response {
                id,
                response_type,
                error,
            } => {
                if error.len() > MAX_PAYLOAD - 20 {
                    return Err("response error too large");
                }
                out.push(3);
                out.push(*response_type);
                out.extend_from_slice(id);
                out.extend_from_slice(&(error.len() as u16).to_be_bytes());
                out.extend_from_slice(error.as_bytes());
            }
        }
        Ok(out)
    }
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        let kind = *data.first().ok_or("empty datagram")?;
        match kind {
            0 => {
                if data.len() < 26 {
                    return Err("truncated registration");
                }
                let flags = data[1];
                let end = if flags & 1 == 1 { 38 } else { 26 };
                if data.len() < end {
                    return Err("truncated destination IP");
                }
                let ip = if end == 38 {
                    IpAddr::from(<[u8; 16]>::try_from(&data[22..38]).unwrap())
                } else {
                    IpAddr::from(<[u8; 4]>::try_from(&data[22..26]).unwrap())
                };
                Ok(Self::Registration {
                    id: data[6..22].try_into().unwrap(),
                    destination: SocketAddr::new(
                        ip,
                        u16::from_be_bytes(data[2..4].try_into().unwrap()),
                    ),
                    traced: flags & 2 != 0,
                    idle_seconds: u16::from_be_bytes(data[4..6].try_into().unwrap()),
                    payload: if flags & 4 != 0 {
                        data[end..].to_vec()
                    } else {
                        Vec::new()
                    },
                })
            }
            1 => {
                if data.len() < 17 || data.len() > 17 + MAX_PAYLOAD {
                    return Err("invalid payload datagram size");
                }
                Ok(Self::Payload {
                    id: data[1..17].try_into().unwrap(),
                    payload: data[17..].to_vec(),
                })
            }
            2 => {
                if data.len() < 2 || data.len() > 1 + MAX_PAYLOAD {
                    return Err("invalid ICMP datagram size");
                }
                Ok(Self::Icmp(data[1..].to_vec()))
            }
            3 => {
                if data.len() < 20 {
                    return Err("truncated response");
                }
                let n = u16::from_be_bytes(data[18..20].try_into().unwrap()) as usize;
                if n > MAX_PAYLOAD - 20 || data.len() - 20 < n {
                    return Err("invalid response error size");
                }
                // Go exposes the complete suffix, including bytes beyond the declared length.
                Ok(Self::Response {
                    id: data[2..18].try_into().unwrap(),
                    response_type: data[1],
                    error: if n == 0 {
                        String::new()
                    } else {
                        String::from_utf8(data[20..].to_vec())
                            .map_err(|_| "invalid response error UTF-8")?
                    },
                })
            }
            _ => Err("unknown v3 datagram type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_roundtrips_and_short_packets_never_panic() {
        let variants = vec![
            DatagramV3::Registration {
                id: [1; 16],
                destination: "[2001:db8::1]:53".parse().unwrap(),
                traced: true,
                idle_seconds: 210,
                payload: vec![0, 255],
            },
            DatagramV3::Payload {
                id: [2; 16],
                payload: vec![0, 255],
            },
            DatagramV3::Icmp(vec![0, 255]),
            DatagramV3::Response {
                id: [3; 16],
                response_type: 255,
                error: "synthetic error".into(),
            },
        ];
        for packet in variants {
            assert_eq!(
                DatagramV3::decode(&packet.encode().unwrap()).unwrap(),
                packet
            );
        }
        let packet = DatagramV2::Udp {
            session_id: [1; 16],
            payload: vec![0, 255],
        };
        assert_eq!(
            DatagramV2::decode(&packet.encode().unwrap()).unwrap(),
            packet
        );
        for kind in 0..=255 {
            for n in 0..40 {
                let mut data = vec![kind; n];
                if n > 0 {
                    data[0] = kind;
                }
                let _ = DatagramV3::decode(&data);
                let _ = DatagramV2::decode(&data);
            }
        }
    }
}
