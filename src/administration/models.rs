use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{NaiveDateTime, Timelike};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn decode_api_base64(value: &str) -> Result<Vec<u8>> {
    const ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::PAD.with_decode_allow_trailing_bits(true),
    );
    ENGINE
        .decode(
            value
                .bytes()
                .filter(|byte| !matches!(byte, b'\r' | b'\n'))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| anyhow::anyhow!("Provided Tunnel token is not valid."))
}

fn serialize_api_secret<S: Serializer>(
    secret: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match secret {
        Some(secret) => serializer.serialize_str(&STANDARD.encode(secret)),
        None => serializer.serialize_none(),
    }
}

#[derive(Default, Serialize)]
pub(super) struct ApiTunnelToken {
    #[serde(rename = "a")]
    account_tag: String,
    #[serde(rename = "s", serialize_with = "serialize_api_secret")]
    tunnel_secret: Option<Vec<u8>>,
    #[serde(rename = "t")]
    tunnel_id: uuid::Uuid,
    #[serde(rename = "e", skip_serializing_if = "String::is_empty")]
    endpoint: String,
}

impl<'de> Deserialize<'de> for ApiTunnelToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenVisitor;
        impl<'de> serde::de::Visitor<'de> for TokenVisitor {
            type Value = ApiTunnelToken;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a token object or null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ApiTunnelToken::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                #[derive(Deserialize)]
                #[serde(untagged)]
                enum Secret {
                    Encoded(String),
                    Bytes(Vec<u8>),
                }
                let mut token = ApiTunnelToken::default();
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "a" | "A" => {
                            if let Some(value) = map.next_value::<Option<String>>()? {
                                token.account_tag = value;
                            }
                        }
                        "e" | "E" => {
                            if let Some(value) = map.next_value::<Option<String>>()? {
                                token.endpoint = value;
                            }
                        }
                        "t" | "T" => {
                            if let Some(value) = map.next_value::<Option<uuid::Uuid>>()? {
                                token.tunnel_id = value;
                            }
                        }
                        "s" | "S" | "ſ" => {
                            token.tunnel_secret = match map.next_value::<Option<Secret>>()? {
                                None => None,
                                Some(Secret::Bytes(bytes)) => Some(bytes),
                                Some(Secret::Encoded(value)) => Some(
                                    decode_api_base64(&value).map_err(serde::de::Error::custom)?,
                                ),
                            };
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(token)
            }
        }
        deserializer.deserialize_any(TokenVisitor)
    }
}

impl ApiTunnelToken {
    pub fn parse(encoded: &str) -> Result<Self> {
        serde_json::from_slice(&decode_api_base64(encoded)?)
            .map_err(|_| anyhow::anyhow!("Provided Tunnel token is not valid."))
    }
    pub fn encode(&self) -> Result<String> {
        Ok(STANDARD.encode(serde_json::to_vec(self)?))
    }
    pub fn credentials(&self) -> Result<String> {
        #[derive(Serialize)]
        struct File<'a> {
            #[serde(rename = "AccountTag")]
            account: &'a str,
            #[serde(rename = "TunnelSecret", serialize_with = "serialize_api_secret")]
            secret: &'a Option<Vec<u8>>,
            #[serde(rename = "TunnelID")]
            id: uuid::Uuid,
            #[serde(rename = "Endpoint")]
            endpoint: &'a str,
        }
        super::output::compact_json(&File {
            account: &self.account_tag,
            secret: &self.tunnel_secret,
            id: self.tunnel_id,
            endpoint: &self.endpoint,
        })
    }
}

#[derive(Clone, Debug, Eq)]
pub(super) struct ApiTime {
    local: NaiveDateTime,
    offset: i32,
}

impl PartialEq for ApiTime {
    fn eq(&self, other: &Self) -> bool {
        self.unix() == other.unix() && self.nanoseconds() == other.nanoseconds()
    }
}

impl Default for ApiTime {
    fn default() -> Self {
        Self::parse("0001-01-01T00:00:00Z").expect("constant zero timestamp")
    }
}

impl Serialize for ApiTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.json_timestamp().map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for ApiTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<String>::deserialize(deserializer)?.map_or_else(
            || Ok(Self::default()),
            |value| Self::parse(&value).map_err(serde::de::Error::custom),
        )
    }
}

#[cfg(test)]
mod date_tests;

impl ApiTime {
    pub fn parse(value: &str) -> Result<Self> {
        if !value.is_ascii() || value.as_bytes().get(10) != Some(&b'T') {
            bail!("invalid API timestamp");
        }
        let (local, offset) = if let Some(local) = value.strip_suffix('Z') {
            (local, 0)
        } else {
            let start = value
                .len()
                .checked_sub(6)
                .context("invalid API timestamp offset")?;
            let suffix = &value[start..];
            let bytes = suffix.as_bytes();
            if !matches!(bytes[0], b'+' | b'-')
                || bytes[3] != b':'
                || !bytes[1..3]
                    .iter()
                    .chain(&bytes[4..6])
                    .all(u8::is_ascii_digit)
            {
                bail!("invalid API timestamp offset");
            }
            let hours: i32 = suffix[1..3].parse()?;
            let minutes: i32 = suffix[4..6].parse()?;
            if hours > 24 || minutes > 60 {
                bail!("invalid API timestamp offset");
            }
            let offset = (hours * 3600 + minutes * 60) * if bytes[0] == b'-' { -1 } else { 1 };
            (&value[..start], offset)
        };
        let (base, fraction) = local.find(['.', ',']).map_or((local, None), |index| {
            (&local[..index], Some(&local[index + 1..]))
        });
        let clock = base
            .get(11..)
            .context("invalid API timestamp clock")?
            .split(':')
            .collect::<Vec<_>>();
        if clock.len() != 3
            || ![1, 2].contains(&clock[0].len())
            || clock[1].len() != 2
            || clock[2].len() != 2
            || !clock
                .iter()
                .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            bail!("invalid API timestamp clock");
        }
        let mut normalized = format!("{}T{:0>2}:{}:{}", &base[..10], clock[0], clock[1], clock[2]);
        if let Some(fraction) = fraction {
            if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                bail!("invalid API timestamp fraction");
            }
            normalized.push('.');
            normalized.push_str(&fraction[..fraction.len().min(9)]);
        }
        normalized.push('Z');
        let local = chrono::DateTime::parse_from_rfc3339(&normalized)
            .context("invalid API timestamp")?
            .naive_local();
        if local.nanosecond() >= 1_000_000_000 {
            bail!("invalid API timestamp second");
        }
        Ok(Self { local, offset })
    }

    pub fn unix(&self) -> i64 {
        self.local.and_utc().timestamp() - i64::from(self.offset)
    }

    pub fn nanoseconds(&self) -> u32 {
        self.local.nanosecond()
    }

    pub fn rfc3339(&self, fractional: bool) -> String {
        let mut value = self.local.format("%Y-%m-%dT%H:%M:%S").to_string();
        if fractional && self.local.nanosecond() != 0 {
            value.push('.');
            value.push_str(format!("{:09}", self.local.nanosecond()).trim_end_matches('0'));
        }
        if self.offset == 0 {
            value.push('Z');
        } else {
            let magnitude = self.offset.unsigned_abs();
            value.push_str(&format!(
                "{}{:02}:{:02}",
                if self.offset < 0 { '-' } else { '+' },
                magnitude / 3600,
                (magnitude / 60) % 60
            ));
        }
        value
    }

    pub fn json_timestamp(&self) -> Result<String> {
        if self.offset.unsigned_abs() / 3600 >= 24 {
            bail!("API timestamp timezone is outside JSON range");
        }
        Ok(self.rfc3339(true))
    }

    pub fn go_string(&self) -> String {
        let mut value = self.local.format("%Y-%m-%d %H:%M:%S").to_string();
        if self.local.nanosecond() != 0 {
            value.push('.');
            value.push_str(format!("{:09}", self.local.nanosecond()).trim_end_matches('0'));
        }
        let magnitude = self.offset.unsigned_abs();
        let offset = format!(
            "{}{:02}{:02}",
            if self.offset < 0 { '-' } else { '+' },
            magnitude / 3600,
            (magnitude / 60) % 60
        );
        value + " " + &offset + " " + if self.offset == 0 { "UTC" } else { &offset }
    }
}

fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    deserializer: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct Pagination {
    #[serde(deserialize_with = "null_default")]
    pub count: i64,
    #[serde(deserialize_with = "null_default")]
    pub page: i64,
    #[serde(deserialize_with = "null_default")]
    pub per_page: i64,
    #[serde(deserialize_with = "null_default")]
    pub total_count: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct Tunnel {
    #[serde(deserialize_with = "null_default")]
    pub id: uuid::Uuid,
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    pub created_at: ApiTime,
    pub deleted_at: ApiTime,
    pub connections: Option<Vec<Connection>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct Connection {
    #[serde(deserialize_with = "null_default")]
    pub colo_name: String,
    #[serde(deserialize_with = "null_default")]
    pub id: uuid::Uuid,
    #[serde(deserialize_with = "null_default")]
    pub is_pending_reconnect: bool,
    pub origin_ip: ApiIp,
    pub opened_at: ApiTime,
}

#[derive(Clone, Debug, Default)]
pub(super) struct ApiIp(Option<std::net::IpAddr>);

impl ApiIp {
    pub fn display(&self) -> String {
        self.0
            .map_or_else(|| "<nil>".into(), |ip| ip.to_canonical().to_string())
    }
}
impl Serialize for ApiIp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(
            &self
                .0
                .map_or_else(String::new, |ip| ip.to_canonical().to_string()),
        )
    }
}
impl<'de> Deserialize<'de> for ApiIp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Option::<String>::deserialize(deserializer)?;
        Ok(Self(
            value
                .filter(|value| !value.is_empty())
                .map(|value| value.parse())
                .transpose()
                .map_err(serde::de::Error::custom)?,
        ))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct ActiveClient {
    #[serde(deserialize_with = "null_default")]
    pub id: uuid::Uuid,
    pub features: Option<Vec<String>>,
    #[serde(deserialize_with = "null_default")]
    pub version: String,
    #[serde(deserialize_with = "null_default")]
    pub arch: String,
    pub run_at: ApiTime,
    pub conns: Option<Vec<Connection>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct VirtualNetwork {
    #[serde(deserialize_with = "null_default")]
    pub id: uuid::Uuid,
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    #[serde(deserialize_with = "null_default")]
    pub is_default_network: bool,
    pub created_at: ApiTime,
    pub deleted_at: ApiTime,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Network(pub Option<ipnet::IpNet>);

impl Network {
    pub fn display(&self) -> String {
        match self.0 {
            None => "<nil>".into(),
            Some(ipnet::IpNet::V6(network))
                if network.prefix_len() >= 96 && network.network().to_ipv4_mapped().is_some() =>
            {
                ipnet::Ipv4Net::new(
                    network.network().to_ipv4_mapped().unwrap(),
                    network.prefix_len() - 96,
                )
                .unwrap()
                .to_string()
            }
            Some(network) => network.to_string(),
        }
    }
}
impl Serialize for Network {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.display())
    }
}
impl<'de> Deserialize<'de> for Network {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(Self(Some(
            value
                .parse::<ipnet::IpNet>()
                .map_err(serde::de::Error::custom)?
                .trunc(),
        )))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct DetailedRoute {
    #[serde(deserialize_with = "null_default")]
    pub id: uuid::Uuid,
    pub network: Network,
    #[serde(deserialize_with = "null_default")]
    pub tunnel_id: uuid::Uuid,
    #[serde(rename = "virtual_network_id", skip_serializing_if = "Option::is_none")]
    pub vnet_id: Option<uuid::Uuid>,
    #[serde(deserialize_with = "null_default")]
    pub comment: String,
    pub created_at: ApiTime,
    pub deleted_at: ApiTime,
    #[serde(deserialize_with = "null_default")]
    pub tunnel_name: String,
}

#[derive(Deserialize, Serialize)]
pub(super) struct Info {
    pub id: uuid::Uuid,
    pub name: String,
    #[serde(rename = "createdAt")]
    pub created_at: ApiTime,
    pub conns: Option<Vec<ActiveClient>>,
}
