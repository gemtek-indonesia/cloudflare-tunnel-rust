use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderValue, Uri};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use std::net::Ipv6Addr;

const PATH: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b',')
    .remove(b'/')
    .remove(b':')
    .remove(b';')
    .remove(b'=')
    .remove(b'@');
const USER: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=');

/// A parsed application address retains Go request-URI path/authority semantics.
#[derive(Clone)]
pub struct ApplicationUrl {
    scheme: String,
    host: String,
    socket_host: String,
    port: Option<String>,
    path: String,
    query: Option<String>,
    userinfo: Option<(Vec<u8>, Option<Vec<u8>>)>,
    serialized: String,
}
impl std::fmt::Debug for ApplicationUrl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApplicationUrl")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}
impl ApplicationUrl {
    pub fn access(input: &str) -> Result<Self> {
        if input.is_empty() {
            bail!("no input provided");
        }
        let input = if input.starts_with("https://") || input.starts_with("http://") {
            input.to_owned()
        } else {
            format!("https://{input}")
        };
        let (_, rest) = input
            .split_once("://")
            .context("invalid Access application URL")?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let input = if authority.parse::<Ipv6Addr>().is_ok() {
            format!("https://[{}]{}", authority, &rest[end..])
        } else {
            format!("https://{rest}")
        };
        Self::parse(&input, true)
    }
    pub fn curl(input: &str) -> Result<Self> {
        let mut target = Self::parse(input, false)?;
        target.port = target.port.take().filter(|port| !port.is_empty());
        target.host = if let Some(port) = &target.port {
            format!("{}:{port}", target.socket_host)
        } else {
            target.socket_host.clone()
        };
        target.rebuild();
        Ok(target)
    }
    pub(crate) fn remote(input: &str) -> Result<Self> {
        Self::parse(input, false)
    }
    fn parse(input: &str, validate_header: bool) -> Result<Self> {
        if input.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            bail!("invalid control character in application URL");
        }
        let (scheme, rest) = input
            .split_once("://")
            .context("application URL requires a scheme and hostname")?;
        if scheme.is_empty()
            || !scheme.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphabetic()
                    || (index > 0 && (byte.is_ascii_digit() || b"+-.".contains(&byte)))
            })
        {
            bail!("invalid application URL scheme");
        }
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let remainder = &rest[end..];
        let (userinfo, authority) = if let Some((user, host)) = authority.rsplit_once('@') {
            if !user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:%".contains(&byte))
            {
                bail!("invalid application URL user information");
            }
            let (name, password) = user
                .split_once(':')
                .map_or((user, None), |(name, password)| (name, Some(password)));
            (
                Some((decode(name)?, password.map(decode).transpose()?)),
                host,
            )
        } else {
            (None, authority)
        };
        let raw_port = if authority.starts_with('[') {
            authority
                .find(']')
                .and_then(|closing| authority[closing + 1..].strip_prefix(':'))
        } else {
            authority.rsplit_once(':').map(|(_, port)| port)
        };
        if raw_port.is_some_and(|port| !port.bytes().all(|byte| byte.is_ascii_digit())) {
            bail!("invalid application port");
        }
        let decoded = decode(authority)?;
        let authority =
            String::from_utf8(decoded).context("invalid application hostname encoding")?;
        let (hostname, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let closing = bracketed
                .find(']')
                .context("invalid IPv6 application hostname")?;
            let suffix = &bracketed[closing + 1..];
            if !suffix.is_empty() && !suffix.starts_with(':') {
                bail!("invalid application port");
            }
            (
                &bracketed[..closing],
                suffix.strip_prefix(':').map(str::to_owned),
            )
        } else {
            if authority.matches(':').count() > 1 {
                bail!("IPv6 application hostname requires brackets");
            }
            authority
                .rsplit_once(':')
                .map_or((authority.as_str(), None), |(hostname, port)| {
                    (hostname, Some(port.to_owned()))
                })
        };
        if hostname.is_empty()
            || port
                .as_ref()
                .is_some_and(|port| !port.bytes().all(|byte| byte.is_ascii_digit()))
        {
            bail!("invalid application hostname or port");
        }
        let hostname = punycode(hostname)?;
        let host = if authority.starts_with('[') {
            format!("[{hostname}]")
        } else {
            hostname.clone()
        };
        let host = port
            .as_ref()
            .map_or(host.clone(), |port| format!("{host}:{port}"));
        if validate_header
            && !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!$%&()*+,-.:;=[]_~".contains(&byte))
        {
            bail!("invalid Host provided");
        }
        if !validate_header && host.contains([' ', '#', '\\']) {
            bail!("invalid application hostname");
        }
        let (path, query) = remainder
            .split_once('?')
            .map_or((remainder, None), |(path, query)| {
                (path, Some(query.to_owned()))
            });
        let decoded_path = decode(path)?;
        let path = if path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,/:;=@[]%".contains(&byte))
        {
            path.to_owned()
        } else {
            percent_encoding::percent_encode(&decoded_path, PATH).to_string()
        };
        let mut result = Self {
            scheme: scheme.to_ascii_lowercase(),
            host,
            socket_host: hostname,
            port,
            path,
            query,
            userinfo,
            serialized: String::new(),
        };
        result.rebuild();
        Ok(result)
    }
    fn rebuild(&mut self) {
        let user = self
            .userinfo
            .as_ref()
            .map_or(String::new(), |(name, password)| {
                let name = percent_encoding::percent_encode(name, USER);
                let password = password.as_ref().map_or(String::new(), |password| {
                    format!(":{}", percent_encoding::percent_encode(password, USER))
                });
                format!("{name}{password}@")
            });
        let host = self.host.replace('%', "%25");
        self.serialized = format!(
            "{}://{user}{host}{}{}",
            self.scheme,
            self.path,
            self.query
                .as_ref()
                .map_or(String::new(), |query| format!("?{query}"))
        );
    }
    pub fn as_str(&self) -> &str {
        &self.serialized
    }
    pub(crate) fn without_userinfo(&self) -> String {
        let mut target = self.clone();
        target.userinfo = None;
        target.rebuild();
        target.serialized
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn hostname(&self) -> &str {
        &self.socket_host
    }
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
    pub(crate) fn port(&self) -> Result<u16> {
        self.port
            .as_ref()
            .filter(|port| !port.is_empty())
            .map_or_else(
                || match self.scheme.as_str() {
                    "https" | "wss" => Ok(443),
                    "http" | "ws" => Ok(80),
                    _ => bail!("unsupported application URL scheme"),
                },
                |port| port.parse().context("invalid application port"),
            )
    }
    pub fn request_uri(&self) -> Result<Uri> {
        if self.host.matches(':').count() > 1 && !self.host.starts_with('[') {
            bail!("application request requires a bracketed IPv6 authority");
        }
        let mut result = self.clone();
        result.userinfo = None;
        if result.port.as_deref() == Some("") {
            result.host.pop();
            result.port = None;
        }
        result.rebuild();
        result
            .as_str()
            .parse()
            .context("invalid application request URI")
    }
    pub(crate) fn basic_auth(&self, headers: &mut HeaderMap) -> Result<()> {
        if !headers.contains_key(http::header::AUTHORIZATION)
            && let Some((username, password)) = &self.userinfo
        {
            let mut credential = username.clone();
            credential.push(b':');
            credential.extend(password.as_deref().unwrap_or_default());
            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(credential)))?,
            );
        }
        Ok(())
    }
    pub(crate) fn set_path(&mut self, path: &str) {
        self.path = path.into();
        self.rebuild();
    }
    pub(crate) fn set_query(&mut self, query: Option<&str>) {
        self.query = query.map(str::to_owned);
        self.rebuild();
    }
    pub(crate) fn query_pairs(&self) -> url::form_urlencoded::Parse<'_> {
        url::form_urlencoded::parse(self.query.as_deref().unwrap_or("").as_bytes())
    }
    pub(crate) fn join(&self, location: &str) -> Result<Self> {
        let resolved = ::url::Url::parse(self.as_str())?.join(location)?;
        Self::remote(resolved.as_str())
    }
    pub(crate) fn authority_prefix(&self) -> String {
        let mut value = self.clone();
        value.path.clear();
        value.query = None;
        value.rebuild();
        value.serialized
    }
}
fn decode(value: &str) -> Result<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                bail!("invalid URL escape");
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(percent_encoding::percent_decode_str(value).collect())
}
fn punycode(host: &str) -> Result<String> {
    if host.is_ascii() {
        return Ok(host.into());
    }
    host.split('.')
        .map(|label| {
            if label.is_ascii() {
                Ok(label.to_owned())
            } else {
                idna::punycode::encode_str(label)
                    .map(|value| format!("xn--{value}"))
                    .context("invalid application IDNA hostname")
            }
        })
        .collect::<Result<Vec<_>>>()
        .map(|labels| labels.join("."))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn https_preserves_raw_target_explicit_port_case_and_user_information() {
        let application =
            ApplicationUrl::access("http://UPPER.example.invalid:80/a/%2e%2e/b#fragment?x=1")
                .unwrap();
        assert_eq!(
            application.as_str(),
            "https://UPPER.example.invalid:80/a/../b%23fragment?x=1"
        );
        assert_eq!(application.port().unwrap(), 80);
        assert_eq!(
            ApplicationUrl::access("http://::1/path").unwrap().host(),
            "[::1]"
        );
        let application = ApplicationUrl::access(
            "https://synthetic-user:synthetic-pass@app.example.invalid/a/../b",
        )
        .unwrap();
        assert_eq!(
            application.request_uri().unwrap().to_string(),
            "https://app.example.invalid/a/../b"
        );
        let mut headers = HeaderMap::new();
        application.basic_auth(&mut headers).unwrap();
        assert!(headers.contains_key(http::header::AUTHORIZATION));
    }
}
