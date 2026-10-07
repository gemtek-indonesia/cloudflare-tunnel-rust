//! Environment routing compatible with Go 1.26 `http.ProxyFromEnvironment`.
pub mod client;
#[cfg(test)]
pub(crate) mod fixtures;
pub mod transport;
use std::{collections::BTreeMap, net::IpAddr, sync::OnceLock};

#[derive(Clone, PartialEq, Eq)]
pub struct Proxy {
    pub scheme: String,
    authority: Vec<u8>,
    username: Option<Vec<u8>>,
    password: Option<Vec<u8>>,
}
impl Proxy {
    pub fn authority(&self) -> &[u8] {
        &self.authority
    }
    pub fn username(&self) -> Option<&[u8]> {
        self.username.as_deref()
    }
    pub fn password(&self) -> Option<&[u8]> {
        self.password.as_deref()
    }
}
impl std::fmt::Debug for Proxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Proxy")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
enum Bypass {
    All,
    Network(ipnet::IpNet),
    Ip(IpAddr, String),
    Domain {
        suffix: String,
        root: bool,
        port: String,
    },
}

pub struct EnvironmentProxy {
    http: Option<Proxy>,
    https: Option<Proxy>,
    bypass: Vec<Bypass>,
    cgi: bool,
}
impl std::fmt::Debug for EnvironmentProxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvironmentProxy")
            .field("cgi", &self.cgi)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct CgiProxyError;
impl std::fmt::Display for CgiProxyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy",
        )
    }
}
impl std::error::Error for CgiProxyError {}

impl EnvironmentProxy {
    /// Process settings are captured once, when an environment-enabled consumer first asks for them.
    pub fn current() -> &'static Self {
        static SETTINGS: OnceLock<EnvironmentProxy> = OnceLock::new();
        SETTINGS.get_or_init(|| {
            let environment = [
                "HTTP_PROXY",
                "http_proxy",
                "HTTPS_PROXY",
                "https_proxy",
                "NO_PROXY",
                "no_proxy",
                "REQUEST_METHOD",
            ]
            .into_iter()
            .filter_map(|key| {
                std::env::var_os(key)
                    .map(|value| (key.to_owned(), value.as_encoded_bytes().to_vec()))
            })
            .collect();
            Self::from_bytes(&environment)
        })
    }

    pub fn from_environment(environment: &BTreeMap<String, String>) -> Self {
        Self::from_bytes(
            &environment
                .iter()
                .map(|(key, value)| (key.clone(), value.as_bytes().to_vec()))
                .collect(),
        )
    }

    fn from_bytes(environment: &BTreeMap<String, Vec<u8>>) -> Self {
        let value = |upper: &str, lower: &str| {
            [upper, lower]
                .into_iter()
                .filter_map(|key| environment.get(key))
                .find(|value| !value.is_empty())
                .map_or(&[][..], Vec::as_slice)
        };
        let bypass = go_utf8(value("NO_PROXY", "no_proxy"))
            .split(',')
            .filter_map(|item| {
                let item = simple_lower(item.trim());
                if item.is_empty() {
                    return None;
                }
                if item == "*" {
                    return Some(Bypass::All);
                }
                if let Ok(network) = item.parse() {
                    return Some(Bypass::Network(network));
                }
                let (host, port) = split_host_port(&item).unwrap_or((&item, ""));
                if host.is_empty() {
                    return None;
                }
                if let Ok(address) = host.parse() {
                    return Some(Bypass::Ip(address, port.to_owned()));
                }
                let host = host
                    .strip_prefix("*.")
                    .map_or_else(|| host.to_owned(), |host| format!(".{host}"));
                let root = !host.starts_with('.');
                let suffix = if root {
                    format!(".{host}")
                } else {
                    host.clone()
                };
                Some(Bypass::Domain {
                    suffix: idna_ascii(&suffix),
                    root,
                    port: port.to_owned(),
                })
            })
            .collect();
        Self {
            http: parse_proxy(value("HTTP_PROXY", "http_proxy")),
            https: parse_proxy(value("HTTPS_PROXY", "https_proxy")),
            bypass,
            cgi: environment
                .get("REQUEST_METHOD")
                .is_some_and(|value| !value.is_empty()),
        }
    }

    /// Uses parsed URL facts; explicit ports and hostname spelling are retained by the caller.
    pub fn select(
        &self,
        scheme: &str,
        hostname: &str,
        explicit_port: Option<&str>,
    ) -> Result<Option<&Proxy>, CgiProxyError> {
        let proxy = match scheme {
            "http" => {
                if self.http.is_some() && self.cgi {
                    return Err(CgiProxyError);
                }
                self.http.as_ref()
            }
            "https" => self.https.as_ref(),
            _ => None,
        };
        let Some(proxy) = proxy else {
            return Ok(None);
        };
        let hostname = idna_ascii(hostname);
        let address = if hostname.contains(':') {
            hostname
                .split_once('%')
                .map_or(hostname.as_str(), |(host, _)| host)
        } else {
            hostname.as_str()
        }
        .parse::<IpAddr>()
        .ok()
        .map(unmap);
        if hostname == "localhost" || address.is_some_and(|address| address.is_loopback()) {
            return Ok(None);
        }
        let port = explicit_port
            .filter(|port| !port.is_empty())
            .unwrap_or(if scheme == "https" { "443" } else { "80" });
        let hostname = simple_lower(hostname.trim());
        let excluded = self.bypass.iter().any(|rule| match rule {
            Bypass::All => true,
            Bypass::Network(network) => {
                address.is_some_and(|address| network_contains(*network, address))
            }
            Bypass::Ip(expected, expected_port) => {
                address.is_some_and(|address| address == unmap(*expected))
                    && (expected_port.is_empty() || expected_port == port)
            }
            Bypass::Domain {
                suffix,
                root,
                port: expected_port,
            } => {
                address.is_none()
                    && (hostname.ends_with(suffix) || *root && hostname == suffix[1..])
                    && (expected_port.is_empty() || expected_port == port)
            }
        });
        Ok((!excluded).then_some(proxy))
    }
}

// Go lowers each rune independently, without expansion or context-sensitive sigma.
fn simple_lower(value: &str) -> String {
    value
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect()
}

fn unmap(address: IpAddr) -> IpAddr {
    address.to_canonical()
}
fn network_contains(network: ipnet::IpNet, address: IpAddr) -> bool {
    if let (ipnet::IpNet::V6(network), IpAddr::V4(address)) = (network, address) {
        return network.network().to_ipv4_mapped().is_some()
            && network.contains(&address.to_ipv6_mapped());
    }
    network.contains(&address)
}
fn idna_ascii(host: &str) -> String {
    if host.is_ascii() {
        host.to_owned()
    } else {
        idna::domain_to_ascii(host).unwrap_or_else(|_| host.to_owned())
    }
}
fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(value) = value.strip_prefix('[') {
        let (host, suffix) = value.split_once(']')?;
        Some((host, suffix.strip_prefix(':')?))
    } else {
        let (host, port) = value.split_once(':')?;
        (!port.contains(':')).then_some((host, port))
    }
}

fn go_utf8(bytes: &[u8]) -> String {
    if let Ok(value) = std::str::from_utf8(bytes) {
        return value.to_owned();
    }
    let escaped =
        percent_encoding::percent_encode(bytes, percent_encoding::NON_ALPHANUMERIC).to_string();
    crate::config::matcher_path(&escaped).expect("generated percent escapes")
}

fn parse_proxy(value: &[u8]) -> Option<Proxy> {
    if value.is_empty() {
        return None;
    }
    let first = parse_route(value);
    if first
        .as_ref()
        .is_none_or(|proxy| proxy.scheme.is_empty() || proxy.authority.is_empty())
    {
        let mut fallback = b"http://".to_vec();
        fallback.extend_from_slice(value);
        if let Some(fallback) = parse_route(&fallback) {
            return Some(fallback);
        }
    }
    first
}

fn cut(value: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = value.iter().position(|byte| *byte == delimiter)?;
    Some((&value[..index], &value[index + 1..]))
}
fn rcut(value: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = value.iter().rposition(|byte| *byte == delimiter)?;
    Some((&value[..index], &value[index + 1..]))
}

// Only dialing components are interpreted; paths and default ports are not normalized.
fn parse_route(value: &[u8]) -> Option<Proxy> {
    if value.iter().any(|byte| *byte < 0x20 || *byte == 0x7f) {
        return None;
    }
    let (value, fragment) =
        cut(value, b'#').map_or((value, None), |(value, fragment)| (value, Some(fragment)));
    if fragment.is_some_and(|fragment| !valid_escapes(fragment)) {
        return None;
    }
    let value = cut(value, b'?').map_or(value, |(value, _)| value);
    let first_segment = cut(value, b'/').map_or(value, |(value, _)| value);
    let (scheme, rest) = if let Some((scheme, rest)) = cut(value, b':') {
        if first_segment.contains(&b':') {
            if scheme.is_empty()
                || !scheme.iter().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphabetic()
                        || index > 0 && (byte.is_ascii_digit() || b"+-.".contains(byte))
                })
            {
                return None;
            }
            (std::str::from_utf8(scheme).ok()?.to_ascii_lowercase(), rest)
        } else {
            (String::new(), value)
        }
    } else {
        (String::new(), value)
    };
    let mut proxy = Proxy {
        scheme,
        authority: Vec::new(),
        username: None,
        password: None,
    };
    if !rest.starts_with(b"/") && !proxy.scheme.is_empty() {
        return Some(proxy);
    }
    if let Some(rest) = rest
        .strip_prefix(b"//")
        .filter(|_| !proxy.scheme.is_empty() || !rest.starts_with(b"///"))
    {
        let (authority, path) = cut(rest, b'/').unwrap_or((rest, &[]));
        if !valid_escapes(path) {
            return None;
        }
        let host = if let Some((user, host)) = rcut(authority, b'@') {
            if !user
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(byte))
                || !valid_escapes(user)
            {
                return None;
            }
            let (username, password) =
                cut(user, b':').map_or((user, None), |(name, password)| (name, Some(password)));
            proxy.username = Some(percent_encoding::percent_decode(username).collect());
            proxy.password =
                password.map(|password| percent_encoding::percent_decode(password).collect());
            host
        } else {
            authority
        };
        proxy.authority = parse_authority(host, &proxy.scheme)?;
    } else if !valid_escapes(rest) {
        return None;
    }
    Some(proxy)
}
fn valid_escapes(value: &[u8]) -> bool {
    let mut bytes = value.iter();
    while let Some(byte) = bytes.next() {
        if *byte == b'%'
            && (!bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit()))
        {
            return false;
        }
    }
    true
}
fn host_character(byte: u8) -> bool {
    byte >= 0x80 || byte.is_ascii_alphanumeric() || b"!$&'()*+,;=:[]<>\"-._~".contains(&byte)
}
fn decode_host(value: &[u8], zone: bool) -> Option<Vec<u8>> {
    let mut bytes = value.iter();
    while let Some(byte) = bytes.next() {
        if *byte == b'%' {
            let high = (*bytes.next()? as char).to_digit(16)?;
            let low = (*bytes.next()? as char).to_digit(16)?;
            let decoded = (high * 16 + low) as u8;
            if (!zone && decoded < 0x80 && decoded != b'%')
                || (zone && decoded != b'%' && decoded != b' ' && !host_character(decoded))
            {
                return None;
            }
        } else if !host_character(*byte) {
            return None;
        }
    }
    Some(percent_encoding::percent_decode(value).collect())
}
fn parse_authority(value: &[u8], scheme: &str) -> Option<Vec<u8>> {
    let valid_port = |value: &[u8]| {
        value.is_empty()
            || value
                .strip_prefix(b":")
                .is_some_and(|port| port.iter().all(|byte| byte.is_ascii_digit()))
    };
    if let Some(open) = value.iter().rposition(|byte| *byte == b'[') {
        let closing = value.iter().rposition(|byte| *byte == b']')?;
        if closing < open {
            return None;
        }
        let suffix = &value[closing + 1..];
        if !valid_port(suffix) {
            return None;
        }
        let host = &value[open + 1..closing];
        let host = if let Some(zone) = host.windows(3).position(|value| value == b"%25") {
            [
                decode_host(&host[..zone], false)?,
                decode_host(&host[zone..], true)?,
            ]
            .concat()
        } else {
            decode_host(host, false)?
        };
        let address = cut(&host, b'%').map_or(host.as_slice(), |(address, _)| address);
        if std::str::from_utf8(address)
            .ok()?
            .parse::<std::net::Ipv6Addr>()
            .is_err()
            || host.ends_with(b"%")
        {
            return None;
        }
        return Some([b"[".as_slice(), host.as_slice(), b"]", suffix].concat());
    }
    let colon = if ["postgresql", "postgres"].contains(&scheme) {
        value.iter().rposition(|byte| *byte == b':')
    } else {
        value.iter().position(|byte| *byte == b':')
    };
    if let Some(colon) = colon
        && !valid_port(&value[colon..])
    {
        return None;
    }
    decode_host(value, false)
}

#[cfg(test)]
mod tests;
