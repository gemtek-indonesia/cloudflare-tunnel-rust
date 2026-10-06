mod credentials;
mod ingress;

pub use credentials::{Credentials, credentials_from_token, resolve_credentials};
pub use ingress::{
    AccessConfig, DurationValue, IngressRule, OriginRequest, canonical_path, validate_ingress,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_yaml_ng as yaml;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

pub const UPSTREAM_VERSION: &str = "2026.10.0";
pub const UPSTREAM_COMMIT: &str = "18cdfe0a6fc7b72a0702d255a1f984e776ce0498";

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct LoadedConfig {
    #[serde(default, rename = "tunnel")]
    pub tunnel: String,
    #[serde(default)]
    pub ingress: Vec<IngressRule>,
    #[serde(default, rename = "originRequest")]
    pub origin_request: OriginRequest,
    #[serde(default, rename = "warp-routing")]
    pub warp_routing: BTreeMap<String, yaml::Value>,
    #[serde(flatten)]
    pub settings: BTreeMap<String, yaml::Value>,
    #[serde(skip)]
    pub source: Option<PathBuf>,
}

impl std::fmt::Debug for LoadedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedConfig")
            .field("ingress_rules", &self.ingress.len())
            .finish_non_exhaustive()
    }
}

impl LoadedConfig {
    pub fn read(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read configuration file {}", path.display()))?;
        // YAML parse errors can include credential-bearing source excerpts.
        let mut config = if body.trim().is_empty() {
            Self::default()
        } else {
            yaml::from_str::<Self>(&body)
                .map_err(|_| anyhow::anyhow!("error parsing YAML in config file"))?
        };
        config.source = Some(path.to_owned());
        Ok(config)
    }

    pub fn from_json(body: &str) -> Result<Self> {
        serde_json::from_str(body).map_err(|_| anyhow::anyhow!("invalid ingress JSON"))
    }
}

pub fn search_directories(home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = home {
        for name in [".cloudflared", ".cloudflare-warp", "cloudflare-warp"] {
            dirs.push(home.join(name));
        }
    }
    dirs.extend([
        PathBuf::from("/etc/cloudflared"),
        PathBuf::from("/usr/local/etc/cloudflared"),
    ]);
    dirs
}

pub fn discover_config(dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter()
        .flat_map(|dir| [dir.join("config.yml"), dir.join("config.yaml")])
        .find(|path| path.is_file())
}

pub fn expand_home(path: &str, home: Option<&Path>) -> Result<PathBuf> {
    if path == "~" || path.starts_with("~/") {
        let home = home.context("Cannot expand home directory")?;
        return Ok(home.join(path.strip_prefix("~/").unwrap_or("")));
    }
    Ok(PathBuf::from(path))
}

pub fn parse_duration(input: &str) -> Result<Duration> {
    if input == "0" {
        return Ok(Duration::ZERO);
    }
    let input = input.strip_prefix('+').unwrap_or(input);
    let mut rest = input;
    let mut nanoseconds = 0f64;
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if end == 0 {
            bail!("invalid duration");
        }
        let amount: f64 = rest[..end]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid duration"))?;
        rest = &rest[end..];
        let units = [
            ("ns", 1f64),
            ("us", 1_000f64),
            ("µs", 1_000f64),
            ("μs", 1_000f64),
            ("ms", 1_000_000f64),
            ("s", 1_000_000_000f64),
            ("m", 60_000_000_000f64),
            ("h", 3_600_000_000_000f64),
        ];
        let (unit, factor) = units
            .into_iter()
            .find(|(unit, _)| rest.starts_with(unit))
            .context("invalid duration unit")?;
        nanoseconds += amount * factor;
        rest = &rest[unit.len()..];
    }
    if input.is_empty() || !nanoseconds.is_finite() || nanoseconds >= i64::MAX as f64 {
        bail!("duration outside supported range");
    }
    Ok(Duration::from_nanos(nanoseconds as u64))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Auto,
    Quic,
    Http2,
}

impl std::str::FromStr for Protocol {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "quic" => Ok(Self::Quic),
            "http2" => Ok(Self::Http2),
            _ => bail!("protocol must be auto, quic, or http2"),
        }
    }
}

#[derive(Clone)]
pub struct RunConfig {
    pub credentials: Credentials,
    pub ingress: Vec<IngressRule>,
    pub origin_request: OriginRequest,
    pub source: Option<PathBuf>,
    pub protocol: Protocol,
    pub edge_ip_version: String,
    pub metrics: String,
    pub ha_connections: u8,
    pub grace_period: Duration,
    pub region: String,
    pub edge_bind_address: Option<std::net::IpAddr>,
    pub post_quantum: bool,
    pub quic_disable_pmtu_discovery: bool,
    pub connection_window: u64,
    pub stream_window: u64,
    pub edge_ca: Option<PathBuf>,
    pub token_authenticated: bool,
    pub rpc_timeout: Duration,
    pub write_stream_timeout: Duration,
    pub dial_edge_timeout: Duration,
    pub retries: u32,
    pub max_edge_addr_retries: u8,
    pub edge: Vec<String>,
    pub no_prechecks: bool,
    pub pidfile: Option<PathBuf>,
    pub disable_path_normalization: bool,
    pub configuration: LoadedConfig,
}

impl std::fmt::Debug for RunConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunConfig")
            .field("protocol", &self.protocol)
            .field("ingress_rules", &self.ingress.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn go_duration_and_config_serialization() {
        assert_eq!(
            parse_duration("1h2m3.5s").unwrap(),
            Duration::from_millis(3_723_500)
        );
        assert_eq!(parse_duration("500µs").unwrap(), Duration::from_micros(500));
        assert!(parse_duration("1d").is_err());
        assert!(parse_duration("-1s").is_err());
        assert!(parse_duration("999999999999999h").is_err());
        let config = LoadedConfig::from_json(
            r#"{"ingress":[{"service":"http_status:404"}],"originRequest":{"connectTimeout":3}}"#,
        )
        .unwrap();
        assert_eq!(
            config.origin_request.connect_timeout.unwrap().0,
            Duration::from_secs(3)
        );
    }
}
