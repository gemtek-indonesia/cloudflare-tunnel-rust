use super::{ApplicationUrl, FRAGMENT, PATH, decode, escaped_component};
use anyhow::{Context, Result, bail};
use oxiri::{Iri, IriRef};
use std::net::Ipv6Addr;

impl ApplicationUrl {
    pub(crate) fn join(&self, location: &str) -> Result<Self> {
        let base_parts = reference_parts(self.as_str())?;
        let base = Iri::parse(base_parts.core.as_str())
            .map_err(|_| anyhow::anyhow!("invalid redirect base URL"))?;
        let reference_parts = reference_parts(location)?;
        let reference = IriRef::parse(reference_parts.core.as_str())
            .map_err(|_| anyhow::anyhow!("invalid redirect URL"))?;
        let inherit = reference.scheme().is_none()
            && reference.authority().is_none()
            && reference.path().is_empty();
        let fragment =
            if reference_parts.fragment.is_none() && reference_parts.query.is_none() && inherit {
                base_parts.fragment
            } else {
                reference_parts.fragment
            };
        let query = reference_parts
            .query
            .or_else(|| inherit.then_some(base_parts.query).flatten());
        let authority = if reference.authority().is_some() {
            reference_parts.authority
        } else if reference.scheme().is_none() {
            base_parts.authority
        } else {
            None
        };
        let resolved = base
            .resolve(&reference)
            .map_err(|_| anyhow::anyhow!("invalid redirect URL"))?;
        // Go removes literal base dot segments even for query/fragment-only references.
        let absolute = IriRef::parse(resolved.as_str())
            .map_err(|_| anyhow::anyhow!("invalid redirect URL"))?;
        let resolved = base
            .resolve(&absolute)
            .map_err(|_| anyhow::anyhow!("invalid redirect URL"))?;
        let authority = authority.context("redirect URL requires an authority")?;
        let mut result = Self::remote(&format!(
            "{}://{authority}{}",
            resolved.scheme(),
            resolved.path()
        ))?;
        result.query = query;
        result.fragment = fragment;
        result.rebuild();
        Ok(result)
    }
}

struct RedirectReference {
    core: String,
    authority: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
}
fn reference_parts(input: &str) -> Result<RedirectReference> {
    if input.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        bail!("invalid control character in redirect URL");
    }
    let (input, fragment) = input
        .split_once('#')
        .map_or((input, None), |(input, fragment)| (input, Some(fragment)));
    let fragment = fragment
        .map(|value| escaped_component(value, FRAGMENT, true))
        .transpose()?
        .filter(|value| !value.is_empty());
    let (core, query) = input
        .split_once('?')
        .map_or((input, None), |(core, query)| {
            (core, Some(query.to_owned()))
        });
    // This view only locates components; the prepared reference is checked below.
    let components = IriRef::parse_unchecked(core);
    let path = escaped_component(components.path(), PATH, false)?;
    let prefix = &core[..core.len() - components.path().len()];
    let authority = components.authority().map(str::to_owned);
    let prefix = if let Some(authority) = &authority {
        let projected = redirect_authority(authority)?;
        format!("{}{projected}", &prefix[..prefix.len() - authority.len()])
    } else {
        prefix.to_owned()
    };
    let prepared = format!("{prefix}{path}");
    IriRef::parse(prepared.as_str()).map_err(|_| anyhow::anyhow!("invalid redirect URL"))?;
    Ok(RedirectReference {
        core: prepared,
        authority,
        query,
        fragment,
    })
}
pub(super) fn redirect_authority(authority: &str) -> Result<String> {
    let normalized;
    let authority = if let Some((userinfo, host)) = authority.rsplit_once('@') {
        normalized = format!("{}@{host}", userinfo.replace('@', "%40"));
        normalized.as_str()
    } else {
        authority
    };
    let host_port = authority.rsplit('@').next().unwrap_or("");
    if let Some(bracketed) = host_port.strip_prefix('[') {
        let closing = bracketed
            .find(']')
            .context("invalid redirect IPv6 authority")?;
        let host = &bracketed[..closing];
        if let Some((address, zone)) = host.split_once("%25") {
            address
                .parse::<Ipv6Addr>()
                .map_err(|_| anyhow::anyhow!("invalid redirect IPv6 address"))?;
            let decoded = decode(zone)?;
            if decoded.is_empty() {
                bail!("invalid redirect IPv6 zone");
            }
            let allowed = |byte: u8| {
                byte.is_ascii_alphanumeric() || b"!$&'()*+,-.:;=[]_~\"<>".contains(&byte)
            };
            let mut bytes = zone.as_bytes().iter().copied();
            while let Some(byte) = bytes.next() {
                if byte == b'%' {
                    let pair = [bytes.next().unwrap(), bytes.next().unwrap()];
                    let value =
                        u8::from_str_radix(std::str::from_utf8(&pair).unwrap(), 16).unwrap();
                    if value != b'%' && value != b' ' && !allowed(value) {
                        bail!("invalid redirect IPv6 zone escape");
                    }
                } else if byte.is_ascii() && !allowed(byte) {
                    bail!("invalid redirect IPv6 zone");
                }
            }
            let start = authority.len() - host_port.len() + 1 + address.len();
            let end = authority.len() - host_port.len() + 1 + closing;
            return Ok(format!("{}{}", &authority[..start], &authority[end..]));
        }
        // Checked Oxiri validates unzoned bracketed addresses.
        decode(host)?;
    } else {
        let host = host_port.split(':').next().unwrap_or("");
        decode(host)?;
        let mut bytes = host.as_bytes().iter().copied();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let pair = [bytes.next().unwrap(), bytes.next().unwrap()];
                let value = u8::from_str_radix(std::str::from_utf8(&pair).unwrap(), 16).unwrap();
                if value.is_ascii() && value != b'%' {
                    bail!("invalid redirect hostname escape");
                }
            }
        }
    }
    Ok(authority.to_owned())
}
pub(super) fn restore_redirect_zone(result: &mut ApplicationUrl, authority: &str) -> Result<()> {
    let host_port = authority.rsplit('@').next().unwrap_or("");
    if let Some(bracketed) = host_port.strip_prefix('[')
        && let Some(closing) = bracketed.find(']')
        && let Some((address, zone)) = bracketed[..closing].split_once("%25")
    {
        let zone = String::from_utf8(decode(zone)?)
            .map_err(|_| anyhow::anyhow!("invalid redirect IPv6 zone encoding"))?;
        result.socket_host = format!("{address}%{zone}");
        result.host = format!("[{}]{}", result.socket_host, &bracketed[closing + 1..]);
    }
    Ok(())
}
