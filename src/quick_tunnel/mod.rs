pub mod auth;
use crate::{
    cli::Invocation,
    config::{Credentials, Protocol, RunConfig},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::Full;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

#[derive(Deserialize)]
struct Provision {
    success: bool,
    result: Option<Tunnel>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}
#[derive(Deserialize)]
struct Tunnel {
    id: uuid::Uuid,
    hostname: String,
    account_tag: String,
    secret: String,
}

pub async fn prepare(invocation: &Invocation) -> Result<RunConfig> {
    let recipients = invocation.list("allowed-mail");
    if !recipients.is_empty() {
        auth::recipient_policy(&recipients)?;
    }
    let mut endpoint = url::Url::parse(invocation.string("quick-service"))
        .map_err(|_| anyhow::anyhow!("invalid Quick Tunnel provisioning endpoint"))?;
    if !["http", "https"].contains(&endpoint.scheme())
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("invalid Quick Tunnel provisioning endpoint");
    }
    endpoint.set_path(&format!("{}/tunnel", endpoint.path().trim_end_matches('/')));
    let request = http::Request::builder()
        .method("POST")
        .uri(endpoint.as_str())
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(
            http::header::USER_AGENT,
            format!("cloudflared/{}", crate::config::UPSTREAM_VERSION),
        )
        .body(Full::new(Bytes::from_static(if recipients.is_empty() {
            b""
        } else {
            br#"{"auth_mode":"otp"}"#
        })))?;
    let fetch = async {
        let client = crate::access::direct_http_client()?;
        let mut response = crate::http_redirect::direct(&client, request)
            .await
            .context("Quick Tunnel provisioning request failed")?;
        let status = response.status();
        let bytes = crate::access::bounded_body(&mut response, 1 << 20).await?;
        if !status.is_success() {
            bail!(
                "Quick Tunnel provisioning failed with HTTP {}",
                status.as_u16()
            );
        }
        let result: Provision = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid Quick Tunnel provisioning response"))?;
        if !result.success || !result.errors.is_empty() {
            bail!("Quick Tunnel provisioning was rejected");
        }
        result
            .result
            .context("Quick Tunnel provisioning response has no tunnel")
    };
    let tunnel = tokio::time::timeout(Duration::from_secs(15), fetch)
        .await
        .context("Quick Tunnel provisioning timeout")??;
    if tunnel.id.is_nil() || tunnel.account_tag.is_empty() {
        bail!("Quick Tunnel provisioning returned invalid credentials");
    }
    let secret = STANDARD
        .decode(tunnel.secret)
        .context("invalid Quick Tunnel secret encoding")?;
    if secret.is_empty() {
        bail!("Quick Tunnel provisioning returned an empty secret");
    }
    let credentials = Credentials {
        account_tag: tunnel.account_tag,
        tunnel_secret: secret,
        tunnel_id: tunnel.id,
        endpoint: None,
    };
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let mut config = invocation.run_config_for_credentials(credentials, false, home.as_deref())?;
    config.quick_authorizer = if recipients.is_empty() {
        None
    } else {
        Some(Arc::new(auth::Authorizer::new(
            &tunnel.hostname,
            recipients,
        )?))
    };
    config.quick_hostname = tunnel.hostname;
    config.ha_connections = 1;
    if !invocation.is_set("protocol") {
        config.protocol = Protocol::Quic;
    }
    eprintln!(
        "Your {}quick Tunnel has been created: https://{}",
        if config.quick_authorizer.is_some() {
            "protected "
        } else {
            ""
        },
        config.quick_hostname
    );
    Ok(config)
}
#[cfg(test)]
mod tests;
