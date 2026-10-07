use std::net::IpAddr;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IcmpPacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub ttl: u8,
    pub message: Vec<u8>,
}
pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
impl IcmpPacket {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let version = bytes.first().ok_or("empty IP packet")? >> 4;
        let (source, destination, ttl, offset, end) = match version {
            4 => {
                if bytes.len() < 20 {
                    return Err("truncated IPv4 header");
                }
                let offset = usize::from(bytes[0] & 15) * 4;
                let end = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
                if offset < 20
                    || end < offset
                    || end > bytes.len()
                    || bytes[9] != 1
                    || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
                {
                    return Err("invalid or fragmented ICMPv4 packet");
                }
                (
                    IpAddr::from(<[u8; 4]>::try_from(&bytes[12..16]).unwrap()),
                    IpAddr::from(<[u8; 4]>::try_from(&bytes[16..20]).unwrap()),
                    bytes[8],
                    offset,
                    end,
                )
            }
            6 => {
                if bytes.len() < 40 || bytes[6] != 58 {
                    return Err("invalid ICMPv6 header");
                }
                let end = 40 + usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
                if end > bytes.len() {
                    return Err("truncated ICMPv6 packet");
                }
                (
                    IpAddr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap()),
                    IpAddr::from(<[u8; 16]>::try_from(&bytes[24..40]).unwrap()),
                    bytes[7],
                    40,
                    end,
                )
            }
            _ => return Err("unsupported IP version"),
        };
        if end - offset < 4 {
            return Err("truncated ICMP message");
        }
        Ok(Self {
            source,
            destination,
            ttl,
            message: bytes[offset..end].to_vec(),
        })
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, &'static str> {
        if self.message.len() < 4 {
            return Err("truncated ICMP message");
        }
        let mut message = self.message.clone();
        message[2..4].fill(0);
        match (self.source, self.destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                let total: u16 = (20 + message.len())
                    .try_into()
                    .map_err(|_| "IP packet too large")?;
                let check = checksum(&message);
                message[2..4].copy_from_slice(&check.to_be_bytes());
                let mut out = vec![0; 20];
                out[0] = 0x45;
                out[2..4].copy_from_slice(&total.to_be_bytes());
                out[8] = self.ttl;
                out[9] = 1;
                out[12..16].copy_from_slice(&source.octets());
                out[16..20].copy_from_slice(&destination.octets());
                let check = checksum(&out);
                out[10..12].copy_from_slice(&check.to_be_bytes());
                out.extend_from_slice(&message);
                Ok(out)
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                let len: u16 = message
                    .len()
                    .try_into()
                    .map_err(|_| "IP packet too large")?;
                let mut pseudo = Vec::with_capacity(40 + message.len());
                pseudo.extend_from_slice(&source.octets());
                pseudo.extend_from_slice(&destination.octets());
                pseudo.extend_from_slice(&(message.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, 58]);
                pseudo.extend_from_slice(&message);
                message[2..4].copy_from_slice(&checksum(&pseudo).to_be_bytes());
                let mut out = vec![0; 40];
                out[0] = 0x60;
                out[4..6].copy_from_slice(&len.to_be_bytes());
                out[6] = 58;
                out[7] = self.ttl;
                out[8..24].copy_from_slice(&source.octets());
                out[24..40].copy_from_slice(&destination.octets());
                out.extend_from_slice(&message);
                Ok(out)
            }
            _ => Err("ICMP address families differ"),
        }
    }
    pub(crate) fn echo_id(&self) -> Result<u16, &'static str> {
        let request_type = if self.destination.is_ipv4() { 8 } else { 128 };
        if self.message.len() < 8 || self.message[0] != request_type {
            return Err("expected ICMP echo request");
        }
        Ok(u16::from_be_bytes([self.message[4], self.message[5]]))
    }
    pub(crate) fn ttl_exceeded(
        &self,
        original: &[u8],
        router: IpAddr,
    ) -> Result<Vec<u8>, &'static str> {
        let mut message = vec![0; 8];
        message[0] = if self.destination.is_ipv4() { 11 } else { 3 };
        let max = if self.destination.is_ipv4() {
            548
        } else {
            1232
        };
        message.extend_from_slice(&original[..original.len().min(max)]);
        Self {
            source: router,
            destination: self.source,
            ttl: 255,
            message,
        }
        .encode()
    }
    pub(crate) fn echo_reply(
        &self,
        from: IpAddr,
        mut message: Vec<u8>,
    ) -> Result<Vec<u8>, &'static str> {
        let reply_type = if from.is_ipv4() { 0 } else { 129 };
        if message.len() < 8 || message[0] != reply_type {
            return Err("expected echo reply");
        }
        message[4..6].copy_from_slice(&self.echo_id()?.to_be_bytes());
        Self {
            source: from,
            destination: self.source,
            ttl: 255,
            message,
        }
        .encode()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv4_ipv6_checksums_echo_translation_and_ttl_truncation() {
        for (source, destination) in [
            (
                "192.0.2.1".parse().unwrap(),
                "192.0.2.2".parse::<IpAddr>().unwrap(),
            ),
            ("::1".parse().unwrap(), "2001:db8::1".parse().unwrap()),
        ] {
            let kind = if destination.is_ipv4() { 8 } else { 128 };
            let packet = IcmpPacket {
                source,
                destination,
                ttl: 1,
                message: vec![kind, 0, 0, 0, 0, 7, 0, 2, 1, 2, 3],
            };
            let encoded = packet.encode().unwrap();
            let decoded = IcmpPacket::decode(&encoded).unwrap();
            assert_eq!(decoded.echo_id().unwrap(), 7);
            let exceed = decoded.ttl_exceeded(&encoded, destination).unwrap();
            assert_eq!(IcmpPacket::decode(&exceed).unwrap().destination, source);
            let mut reply = decoded.message.clone();
            reply[0] = if destination.is_ipv4() { 0 } else { 129 };
            reply[4..6].copy_from_slice(&123u16.to_be_bytes());
            let reply =
                IcmpPacket::decode(&decoded.echo_reply(destination, reply).unwrap()).unwrap();
            assert_eq!(&reply.message[4..6], &7u16.to_be_bytes());
        }
        for n in 0..80 {
            let _ = IcmpPacket::decode(&vec![0x45; n]);
            let _ = IcmpPacket::decode(&vec![0x60; n]);
        }
    }
}
