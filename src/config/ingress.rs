use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurationValue(pub Duration);

impl<'de> Deserialize<'de> for DurationValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = serde_yaml_ng::Value::deserialize(deserializer)?;
        let duration = match value {
            serde_yaml_ng::Value::String(text) => super::parse_duration(&text),
            serde_yaml_ng::Value::Number(number) => number
                .as_u64()
                .map(Duration::from_secs)
                .context("duration must be nonnegative whole seconds"),
            _ => Err(anyhow::anyhow!(
                "duration must be a Go duration string or whole seconds"
            )),
        };
        duration.map(Self).map_err(serde::de::Error::custom)
    }
}

impl Serialize for DurationValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        if self.0.subsec_nanos() == 0 {
            serializer.serialize_u64(self.0.as_secs())
        } else {
            serializer.serialize_f64(self.0.as_secs_f64())
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub team_name: String,
    #[serde(default)]
    pub aud_tag: Vec<String>,
    #[serde(default)]
    pub environment: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<DurationValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_timeout: Option<DurationValue>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "tcpKeepAlive")]
    pub tcp_keep_alive: Option<DurationValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_happy_eyeballs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive_connections: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive_timeout: Option<DurationValue>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "httpHostHeader")]
    pub http_host_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "matchSNItoHost")]
    pub match_sni_to_host: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_pool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "noTLSVerify")]
    pub no_tls_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_chunked_encoding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bastion_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_rules: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http2_origin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<AccessConfig>,
}

impl OriginRequest {
    pub fn merged(&self, rule: &Self) -> Self {
        macro_rules! override_fields {
            ($($field:ident),* $(,)?) => { Self { $($field: rule.$field.clone().or_else(|| self.$field.clone()),)* ip_rules: if rule.ip_rules.is_empty() { self.ip_rules.clone() } else { rule.ip_rules.clone() } } };
        }
        override_fields!(
            connect_timeout,
            tls_timeout,
            tcp_keep_alive,
            no_happy_eyeballs,
            keep_alive_connections,
            keep_alive_timeout,
            http_host_header,
            origin_server_name,
            match_sni_to_host,
            ca_pool,
            no_tls_verify,
            disable_chunked_encoding,
            bastion_mode,
            proxy_address,
            proxy_port,
            proxy_type,
            http2_origin,
            access
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IngressRule {
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub path: String,
    pub service: String,
    #[serde(default, rename = "originRequest")]
    pub origin_request: OriginRequest,
}

pub fn validate_ingress(rules: &[IngressRule]) -> Result<()> {
    validate_ingress_paths(rules).map(|_| ())
}

pub fn validate_ingress_paths(rules: &[IngressRule]) -> Result<Vec<Option<regex::Regex>>> {
    if rules.is_empty() {
        bail!("The config file doesn't contain any ingress rules");
    }
    let mut paths = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let catch_all = (rule.hostname.is_empty() || rule.hostname == "*") && rule.path.is_empty();
        if rule
            .hostname
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
        {
            bail!("Hostname cannot contain a port");
        }
        if rule
            .hostname
            .rfind('*')
            .is_some_and(|position| position > 0)
        {
            bail!(
                "Hostname patterns can have at most one wildcard character (\"*\") and it can only be used for subdomains, e.g. \"*.example.com\""
            );
        }
        if index == rules.len() - 1 && !catch_all {
            bail!(
                "The last ingress rule must match all URLs (i.e. it should not have a hostname or path filter)"
            );
        }
        if index < rules.len() - 1 && catch_all {
            bail!(
                "Rule #{} is matching the hostname '{}', but this will match every hostname, meaning the rules which follow it will never be triggered.",
                index + 1,
                rule.hostname
            );
        }
        paths.push(if rule.path.is_empty() {
            None
        } else {
            Some(
                super::compile_ingress_path(&rule.path)
                    .with_context(|| format!("Rule #{} has an invalid regex", index + 1))?,
            )
        });
        if let Some(access) = &rule.origin_request.access
            && access.required
            && access.team_name.is_empty()
            && !access.aud_tag.is_empty()
        {
            bail!("access.TeamName cannot be blank when access.audTags are present");
        }
        validate_service(&rule.service)?;
    }
    Ok(paths)
}

fn validate_service(service: &str) -> Result<()> {
    if let Some(code) = service.strip_prefix("http_status:") {
        let code: u16 = code.parse().context("invalid HTTP status code")?;
        if !(100..=999).contains(&code) {
            bail!("invalid HTTP status code");
        }
    } else if !["hello_world", "hello-world", "socks-proxy", "bastion"].contains(&service)
        && !service.starts_with("unix:")
        && !service.starts_with("unix+tls:")
    {
        let url = url::Url::parse(service).context("invalid origin service URL")?;
        if url.host_str().is_none() {
            bail!("origin service must have a scheme and hostname");
        }
        // Url supplies '/' for an empty HTTP path; only explicitly supplied paths are disallowed.
        let after_authority = service
            .split_once("://")
            .map(|(_, tail)| tail)
            .unwrap_or("");
        if after_authority.contains('/') {
            bail!("ingress rules don't support proxying to a different path on the origin service");
        }
    }
    Ok(())
}

impl IngressRule {
    pub fn matches(&self, hostname: &str, path: &str, normalize: bool) -> Result<bool> {
        let matches_host = self.matches_hostname(hostname);
        let path = if normalize {
            canonical_path(path)
        } else {
            path.to_owned()
        };
        Ok(matches_host
            && (self.path.is_empty() || super::compile_ingress_path(&self.path)?.is_match(&path)))
    }

    pub fn matches_hostname(&self, hostname: &str) -> bool {
        self.hostname.is_empty()
            || self.hostname == "*"
            || self.hostname == hostname
            || self
                .hostname
                .strip_prefix("*.")
                .is_some_and(|suffix| hostname.ends_with(&format!(".{suffix}")))
            || url::Host::parse(&self.hostname)
                .ok()
                .is_some_and(|host| host.to_string() == hostname)
    }
}

pub fn canonical_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let trailing_slash = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    let mut result = format!("/{}", parts.join("/"));
    if trailing_slash && result != "/" {
        result.push('/');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_matches_ordered_ingress() {
        let rules: Vec<IngressRule> = serde_yaml_ng::from_str("- hostname: '*.example.com'\n  path: ^/admin/\n  service: https://127.0.0.1:8443\n- service: http_status:404\n").unwrap();
        validate_ingress(&rules).unwrap();
        assert!(
            rules[0]
                .matches("api.example.com", "/public/../admin/", true)
                .unwrap()
        );
        assert!(!rules[0].matches("example.com", "/admin/", true).unwrap());
        assert!(
            !rules[0]
                .matches("api.example.com", "/public/../admin/", false)
                .unwrap()
        );
        assert_eq!(canonical_path("/a\\b//../c/."), "/a/c/");
        assert!(validate_ingress(&rules[..1]).is_err());
    }
}
