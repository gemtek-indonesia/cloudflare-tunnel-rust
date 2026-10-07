use crate::cli::Invocation;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use uuid::Uuid;

type Query = Vec<(&'static str, String)>;

#[cfg(test)]
mod tests;

fn max_fetch(invocation: &Invocation, query: &mut BTreeMap<&'static str, String>) -> Result<()> {
    if !invocation.string("max-fetch-size").is_empty() {
        let max = invocation.integer("max-fetch-size")?;
        if max > 0 {
            query.insert("per_page", max.to_string());
        }
    }
    Ok(())
}

fn uuid(invocation: &Invocation, flag: &str) -> Result<String> {
    Ok(Uuid::parse_str(invocation.string(flag))
        .with_context(|| format!("invalid UUID for --{flag}"))?
        .to_string())
}

pub(super) fn tunnels(invocation: &Invocation) -> Result<Query> {
    let mut query = BTreeMap::new();
    if !invocation.bool("show-deleted") {
        query.insert("is_deleted", "false".into());
    }
    for (flag, key) in [
        ("name", "name"),
        ("name-prefix", "name_prefix"),
        ("exclude-name-prefix", "exclude_prefix"),
    ] {
        let value = invocation.string(flag);
        if !value.is_empty() {
            query.insert(key, value.into());
        }
    }
    if !invocation.string("id").is_empty() {
        query.insert("uuid", uuid(invocation, "id")?);
    }
    if invocation.is_set("when") {
        super::models::ApiTime::parse(invocation.string("when"))
            .context("invalid --when timestamp")?;
        // The frozen command reads Timestamp("time"), which is not the declared flag.
    }
    max_fetch(invocation, &mut query)?;
    Ok(query.into_iter().collect())
}

fn cidr(value: &str) -> Result<String> {
    let network = value
        .parse::<ipnet::IpNet>()
        .context("invalid network filter CIDR")?
        .trunc();
    Ok(match network {
        ipnet::IpNet::V6(network) if network.prefix_len() >= 96 => {
            if let Some(address) = network.network().to_ipv4_mapped() {
                ipnet::Ipv4Net::new(address, network.prefix_len() - 96)?.to_string()
            } else {
                network.to_string()
            }
        }
        network => network.to_string(),
    })
}

pub(super) fn routes(invocation: &Invocation) -> Result<Query> {
    let mut query = BTreeMap::from([
        ("tun_types", "cfd_tunnel".into()),
        (
            "is_deleted",
            invocation.bool("filter-is-deleted").to_string(),
        ),
    ]);
    for flag in [
        "filter-network-is-subset-of",
        "filter-network-is-superset-of",
    ] {
        if invocation.is_set(flag) {
            query.insert("network_superset", cidr(invocation.string(flag))?);
        }
    }
    if !invocation.string("filter-comment-is").is_empty() {
        query.insert("comment", invocation.string("filter-comment-is").into());
    }
    for (flag, key) in [
        ("filter-tunnel-id", "tunnel_id"),
        ("filter-vnet-id", "virtual_network_id"),
    ] {
        if !invocation.string(flag).is_empty() {
            query.insert(key, uuid(invocation, flag)?);
        }
    }
    max_fetch(invocation, &mut query)?;
    Ok(query.into_iter().collect())
}

pub(super) fn vnets(invocation: &Invocation) -> Result<Query> {
    let mut query = BTreeMap::from([("is_deleted", invocation.bool("show-deleted").to_string())]);
    if !invocation.string("id").is_empty() {
        query.insert("id", uuid(invocation, "id")?);
    }
    if !invocation.string("name").is_empty() {
        query.insert("name", invocation.string("name").into());
    }
    if invocation.is_set("is-default") {
        query.insert("is_default", invocation.bool("is-default").to_string());
    }
    max_fetch(invocation, &mut query)?;
    Ok(query.into_iter().collect())
}
