use super::models::*;
use anyhow::Result;
use serde::{Serialize, Serializer};

struct Time<'a>(&'a ApiTime);
impl Serialize for Time<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.rfc3339(true))
    }
}

#[derive(Serialize)]
struct YamlConnection<'a> {
    coloname: &'a str,
    id: uuid::Uuid,
    ispendingreconnect: bool,
    originip: &'a ApiIp,
    openedat: Time<'a>,
}
fn connections(values: &[Connection]) -> Vec<YamlConnection<'_>> {
    values
        .iter()
        .map(|value| YamlConnection {
            coloname: &value.colo_name,
            id: value.id,
            ispendingreconnect: value.is_pending_reconnect,
            originip: &value.origin_ip,
            openedat: Time(&value.opened_at),
        })
        .collect()
}

#[derive(Serialize)]
struct YamlTunnel<'a> {
    id: uuid::Uuid,
    name: &'a str,
    createdat: Time<'a>,
    deletedat: Time<'a>,
    connections: Vec<YamlConnection<'a>>,
}
impl<'a> From<&'a Tunnel> for YamlTunnel<'a> {
    fn from(value: &'a Tunnel) -> Self {
        Self {
            id: value.id,
            name: &value.name,
            createdat: Time(&value.created_at),
            deletedat: Time(&value.deleted_at),
            connections: connections(value.connections.as_deref().unwrap_or_default()),
        }
    }
}
pub(super) fn created_tunnel(value: &TunnelWithToken) -> Result<String> {
    #[derive(Serialize)]
    struct Created<'a> {
        tunnel: YamlTunnel<'a>,
        token: &'a str,
    }
    Ok(serde_yaml_ng::to_string(&Created {
        tunnel: (&value.tunnel).into(),
        token: &value.token,
    })?)
}
pub(super) fn tunnels(values: &[Tunnel]) -> Result<String> {
    Ok(serde_yaml_ng::to_string(
        &values.iter().map(YamlTunnel::from).collect::<Vec<_>>(),
    )?)
}

#[derive(Serialize)]
struct YamlVnet<'a> {
    id: uuid::Uuid,
    comment: &'a str,
    name: &'a str,
    isdefault: bool,
    createdat: Time<'a>,
    deletedat: Time<'a>,
}
pub(super) fn vnets(values: &[VirtualNetwork]) -> Result<String> {
    Ok(serde_yaml_ng::to_string(
        &values
            .iter()
            .map(|value| YamlVnet {
                id: value.id,
                comment: &value.comment,
                name: &value.name,
                isdefault: value.is_default_network,
                createdat: Time(&value.created_at),
                deletedat: Time(&value.deleted_at),
            })
            .collect::<Vec<_>>(),
    )?)
}

#[derive(Serialize)]
struct YamlNetwork {
    ip: String,
    mask: Vec<u8>,
}
fn network(value: &Network) -> YamlNetwork {
    match value.0 {
        None => YamlNetwork {
            ip: String::new(),
            mask: Vec::new(),
        },
        Some(network) => {
            let bytes = if matches!(network, ipnet::IpNet::V4(_)) {
                4
            } else {
                16
            };
            let prefix = network.prefix_len() as usize;
            let mask = (0..bytes)
                .map(|index| {
                    if prefix >= index * 8 + 8 {
                        255
                    } else if prefix <= index * 8 {
                        0
                    } else {
                        255 << (8 - (prefix - index * 8))
                    }
                })
                .collect();
            YamlNetwork {
                ip: network.network().to_canonical().to_string(),
                mask,
            }
        }
    }
}
#[derive(Serialize)]
struct YamlRoute<'a> {
    id: uuid::Uuid,
    network: YamlNetwork,
    tunnelid: uuid::Uuid,
    vnetid: Option<uuid::Uuid>,
    comment: &'a str,
    createdat: Time<'a>,
    deletedat: Time<'a>,
    tunnelname: &'a str,
}
pub(super) fn routes(values: &[DetailedRoute]) -> Result<String> {
    Ok(serde_yaml_ng::to_string(
        &values
            .iter()
            .map(|value| YamlRoute {
                id: value.id,
                network: network(&value.network),
                tunnelid: value.tunnel_id,
                vnetid: value.vnet_id,
                comment: &value.comment,
                createdat: Time(&value.created_at),
                deletedat: Time(&value.deleted_at),
                tunnelname: &value.tunnel_name,
            })
            .collect::<Vec<_>>(),
    )?)
}

#[derive(Serialize)]
struct YamlClient<'a> {
    id: uuid::Uuid,
    features: &'a [String],
    version: &'a str,
    arch: &'a str,
    runat: Time<'a>,
    connections: Vec<YamlConnection<'a>>,
}
#[derive(Serialize)]
struct YamlInfo<'a> {
    id: uuid::Uuid,
    name: &'a str,
    createdat: Time<'a>,
    connectors: Vec<YamlClient<'a>>,
}
pub(super) fn info(value: &Info) -> Result<String> {
    Ok(serde_yaml_ng::to_string(&YamlInfo {
        id: value.id,
        name: &value.name,
        createdat: Time(&value.created_at),
        connectors: value
            .conns
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|value| YamlClient {
                id: value.id,
                features: value.features.as_deref().unwrap_or_default(),
                version: &value.version,
                arch: &value.arch,
                runat: Time(&value.run_at),
                connections: connections(value.conns.as_deref().unwrap_or_default()),
            })
            .collect(),
    })?)
}
