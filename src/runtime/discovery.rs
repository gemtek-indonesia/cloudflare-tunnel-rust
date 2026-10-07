use crate::{
    config::RunConfig,
    crypto::{EdgeTls, TlsPolicy},
};
use anyhow::{Context, Result, bail};
use hickory_resolver::{
    Resolver,
    proto::{
        op::{Message, MessageType, Query, ResponseCode},
        rr::{Name, RData, RecordType, rdata::SRV},
    },
};
use std::{
    collections::HashSet,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) fn random_below(limit: u64) -> Result<u64> {
    if limit == 0 {
        return Ok(0);
    }
    let cutoff = u64::MAX - u64::MAX % limit;
    loop {
        let mut bytes = [0; 8];
        boring::rand::rand_bytes(&mut bytes)?;
        let value = u64::from_ne_bytes(bytes);
        if value < cutoff {
            return Ok(value % limit);
        }
    }
}

fn ordered_srv(mut records: Vec<SRV>) -> Result<Vec<SRV>> {
    records.sort_by_key(|r| r.priority);
    let mut result = Vec::new();
    while !records.is_empty() {
        let priority = records[0].priority;
        let end = records
            .iter()
            .take_while(|r| r.priority == priority)
            .count();
        let mut group: Vec<_> = records.drain(..end).collect();
        while !group.is_empty() {
            let total = group.iter().map(|r| u64::from(r.weight)).sum::<u64>();
            let mut selected = random_below(if total == 0 {
                group.len() as u64
            } else {
                total
            })?;
            let index = if total == 0 {
                selected as usize
            } else {
                let mut index = 0;
                for (i, r) in group.iter().enumerate() {
                    if selected < u64::from(r.weight) {
                        index = i;
                        break;
                    }
                    selected -= u64::from(r.weight);
                }
                index
            };
            result.push(group.remove(index));
        }
    }
    Ok(result)
}

async fn srv_over_tls(name: &str) -> Result<Vec<SRV>> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let tls = EdgeTls::new(TlsPolicy::PreferPostQuantum, None)?;
        let mut ssl = boring::ssl::Ssl::new(tls.context())?;
        ssl.set_hostname("cloudflare-dns.com")?;
        ssl.param_mut().set_host("cloudflare-dns.com")?;
        let socket = tokio::net::TcpStream::connect("1.1.1.1:853").await?;
        let mut stream = tokio_boring::SslStreamBuilder::new(ssl, socket)
            .connect()
            .await?;
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(name)?, RecordType::SRV));
        let encoded = query.to_vec()?;
        stream
            .write_all(&(encoded.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&encoded).await?;
        let size = stream.read_u16().await?;
        let mut bytes = vec![0; size as usize];
        stream.read_exact(&mut bytes).await?;
        let answer = Message::from_vec(&bytes)?;
        if answer.metadata.id != query.metadata.id
            || answer.metadata.message_type != MessageType::Response
            || answer.metadata.response_code != ResponseCode::NoError
            || answer.queries != query.queries
        {
            bail!("invalid edge discovery DNS response");
        }
        Ok(answer
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::SRV(record) => Some(record.clone()),
                _ => None,
            })
            .collect())
    })
    .await
    .context("edge discovery DoT timeout")?
}

pub(crate) async fn resolve(config: &RunConfig) -> Result<EdgePool> {
    let endpoint = config.credentials.endpoint.as_deref().unwrap_or("");
    if !config.region.is_empty() && !endpoint.is_empty() {
        bail!("region provided with a token that has an endpoint");
    }
    let region = if config.region.is_empty() {
        endpoint
    } else {
        &config.region
    };
    let mut groups = Vec::new();
    if !config.edge.is_empty() {
        let mut addresses = Vec::new();
        for edge in &config.edge {
            addresses.extend(
                tokio::net::lookup_host(edge)
                    .await
                    .with_context(|| "failed to resolve configured edge")?
                    .take(1),
            );
        }
        let mut a = Vec::new();
        let mut b = Vec::new();
        for (i, address) in addresses.into_iter().enumerate() {
            if i % 2 == 0 {
                a.push(address)
            } else {
                b.push(address)
            }
        }
        groups.extend([a, b]);
    } else {
        groups = resolve_groups(region).await?;
    }
    let family = match config.edge_bind_address {
        Some(ip) => {
            if ip.is_ipv4() {
                "4"
            } else {
                "6"
            }
        }
        None => config.edge_ip_version.as_str(),
    };
    let groups = groups
        .into_iter()
        .map(|group| {
            group
                .into_iter()
                .filter(|address| match family {
                    "4" => address.is_ipv4(),
                    "6" => address.is_ipv6(),
                    _ => true,
                })
                .collect()
        })
        .collect();
    EdgePool::new(groups)
}

pub(super) async fn resolve_groups(region: &str) -> Result<Vec<Vec<SocketAddr>>> {
    let service = if region.is_empty() {
        "v2-origintunneld".into()
    } else {
        format!("{region}-v2-origintunneld")
    };
    let name = format!("_{service}._tcp.argotunnel.com.");
    let resolver = Resolver::builder_tokio()?.build()?;
    let records = match resolver.srv_lookup(name.clone()).await {
        Ok(records) => records
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::SRV(record) => Some(record.clone()),
                _ => None,
            })
            .collect(),
        Err(_) => srv_over_tls(&name).await?,
    };
    let records = ordered_srv(records)?;
    if records.len() < 2 {
        bail!("expected at least 2 Cloudflare Regions; SRV returned fewer");
    }
    let mut groups = Vec::new();
    for record in records.into_iter().take(2) {
        groups.push(
            tokio::net::lookup_host((record.target.to_ascii().as_str(), record.port))
                .await?
                .collect(),
        );
    }
    Ok(groups)
}

struct Region {
    primary: Vec<SocketAddr>,
    secondary: Vec<SocketAddr>,
    use_primary: bool,
    restore_after: Instant,
}
pub(crate) struct EdgePool {
    regions: Vec<Region>,
    assigned: Vec<Option<SocketAddr>>,
}
impl EdgePool {
    pub(crate) fn new(groups: Vec<Vec<SocketAddr>>) -> Result<Self> {
        let mut regions = Vec::new();
        for group in groups {
            if let Some(first) = group.first() {
                let primary_v6 = first.is_ipv6();
                let (primary, secondary) =
                    group.into_iter().partition(|a| a.is_ipv6() == primary_v6);
                regions.push(Region {
                    primary,
                    secondary,
                    use_primary: true,
                    restore_after: Instant::now(),
                });
            }
        }
        if regions.is_empty() {
            bail!("failed to resolve any edge address");
        }
        Ok(Self {
            regions,
            assigned: vec![None; 256],
        })
    }
    fn active(region: &Region) -> &[SocketAddr] {
        if region.use_primary {
            &region.primary
        } else {
            &region.secondary
        }
    }
    pub(crate) fn available(&self) -> usize {
        self.regions
            .iter()
            .flat_map(Self::active)
            .copied()
            .collect::<HashSet<_>>()
            .len()
    }
    pub(crate) fn address(
        &mut self,
        index: u8,
        rotate: bool,
        connectivity: bool,
    ) -> Result<SocketAddr> {
        let previous = self.assigned[index as usize];
        if !rotate && let Some(address) = previous {
            return Ok(address);
        }
        self.assigned[index as usize] = None;
        if connectivity && let Some(previous) = previous {
            for region in &mut self.regions {
                if region.primary.contains(&previous)
                    && previous.is_ipv6()
                    && !region.secondary.is_empty()
                {
                    region.use_primary = false;
                    region.restore_after = Instant::now() + Duration::from_secs(600);
                } else if region.secondary.contains(&previous)
                    && (previous.is_ipv4() || Instant::now() > region.restore_after)
                {
                    region.use_primary = true;
                }
            }
        }
        let used: HashSet<_> = self.assigned.iter().flatten().copied().collect();
        let mut candidates: Vec<Vec<_>> = self
            .regions
            .iter()
            .map(|region| {
                Self::active(region)
                    .iter()
                    .copied()
                    .filter(|a| !used.contains(a) && Some(*a) != previous)
                    .collect()
            })
            .collect();
        candidates.sort_by_key(|group| std::cmp::Reverse(group.len()));
        let address = if let Some(group) = candidates.iter().find(|g| !g.is_empty()) {
            group[random_below(group.len() as u64)? as usize]
        } else {
            previous
                .filter(|a| !used.contains(a))
                .context("there are no free edge addresses left")?
        };
        self.assigned[index as usize] = Some(address);
        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ha_addresses_unique_and_ipv6_connectivity_falls_back() {
        let v6 = "[2001:db8::1]:7844".parse().unwrap();
        let v4 = "192.0.2.1:7844".parse().unwrap();
        let other = "192.0.2.2:7844".parse().unwrap();
        let mut pool = EdgePool::new(vec![vec![v6, v4], vec![other]]).unwrap();
        let a = pool.address(0, false, false).unwrap();
        let b = pool.address(1, false, false).unwrap();
        assert_ne!(a, b);
        let index = if a == v6 { 0 } else { 1 };
        assert_eq!(pool.address(index, true, true).unwrap(), v4);
        assert_eq!(pool.address(index, false, false).unwrap(), v4);
    }
}
