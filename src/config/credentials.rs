use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Clone, Deserialize)]
pub struct Credentials {
    #[serde(rename = "AccountTag", alias = "a")]
    pub account_tag: String,
    #[serde(
        rename = "TunnelSecret",
        alias = "s",
        deserialize_with = "decode_secret"
    )]
    pub tunnel_secret: Vec<u8>,
    #[serde(default, rename = "TunnelID", alias = "t")]
    pub tunnel_id: Uuid,
    #[serde(default, rename = "Endpoint", alias = "e")]
    pub endpoint: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("tunnel_id", &self.tunnel_id)
            .finish_non_exhaustive()
    }
}

fn decode_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    let encoded = String::deserialize(deserializer)?;
    STANDARD
        .decode(encoded)
        .map_err(|_| serde::de::Error::custom("invalid tunnel secret encoding"))
}

impl Credentials {
    fn validate(&self) -> Result<()> {
        if self.account_tag.is_empty() || self.tunnel_secret.is_empty() || self.tunnel_id.is_nil() {
            bail!("Tunnel credentials require AccountTag, TunnelSecret and TunnelID");
        }
        Ok(())
    }
}

pub fn credentials_from_token(token: &str) -> Result<Credentials> {
    let body = STANDARD
        .decode(token)
        .map_err(|_| anyhow::anyhow!("Provided Tunnel token is not valid."))?;
    let credentials: Credentials = serde_json::from_slice(&body)
        .map_err(|_| anyhow::anyhow!("Provided Tunnel token is not valid."))?;
    credentials.validate()?;
    Ok(credentials)
}

pub fn resolve_credentials(
    token: Option<&str>,
    token_file: Option<&Path>,
    contents: Option<&str>,
    file: Option<&Path>,
    tunnel: &str,
    origin_cert: Option<&Path>,
    search_dirs: &[PathBuf],
) -> Result<(Credentials, bool)> {
    if let Some(token) = token.filter(|token| !token.is_empty()) {
        return credentials_from_token(token).map(|credentials| (credentials, true));
    }
    if let Some(file) = token_file {
        let token = std::fs::read_to_string(file).context("Failed to read token file")?;
        if !token.trim().is_empty() {
            return credentials_from_token(token.trim()).map(|credentials| (credentials, true));
        }
    }
    let tunnel_id = Uuid::parse_str(tunnel).map_err(|_| {
        anyhow::anyhow!(
            "Tunnel name lookup requires the administration API; provide a tunnel UUID or token"
        )
    })?;
    let body = if let Some(contents) = contents.filter(|contents| !contents.is_empty()) {
        contents.to_owned()
    } else {
        let path = if let Some(file) = file {
            if !file.is_file() {
                bail!("Tunnel credentials file doesn't exist or is not a file");
            }
            file.to_owned()
        } else {
            origin_cert
                .and_then(|cert| cert.is_file().then(|| cert.parent()).flatten())
                .map(|dir| dir.join(format!("{tunnel_id}.json")))
                .filter(|path| path.is_file())
                .or_else(|| {
                    search_dirs
                        .iter()
                        .map(|dir| dir.join(format!("{tunnel_id}.json")))
                        .find(|path| path.is_file())
                })
                .context("tunnel credentials file not found")?
        };
        std::fs::read_to_string(path).context("couldn't read tunnel credentials")?
    };
    let mut credentials: Credentials = serde_json::from_str(&body).map_err(|_| anyhow::anyhow!("The tunnel credentials contained invalid JSON; use the JSON file created by tunnel create"))?;
    // Upstream enriches old credentials and overrides a conflicting JSON TunnelID.
    credentials.tunnel_id = tunnel_id;
    credentials.validate()?;
    Ok((credentials, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_wins_over_bad_files_and_debug_redacts() {
        let token = STANDARD.encode(br#"{"a":"synthetic-account","s":"c3ludGhldGljLXNlY3JldA==","t":"00000000-0000-4000-8000-000000000001"}"#);
        let (credentials, remote) = resolve_credentials(
            Some(&token),
            Some(Path::new("missing-token")),
            Some("invalid"),
            None,
            "invalid",
            None,
            &[],
        )
        .unwrap();
        assert!(remote);
        assert_eq!(credentials.tunnel_secret, b"synthetic-secret");
        assert!(!format!("{credentials:?}").contains("synthetic-secret"));
        assert!(
            !credentials_from_token("DO-NOT-ECHO")
                .unwrap_err()
                .to_string()
                .contains("DO-NOT-ECHO")
        );
    }

    #[test]
    fn old_json_credentials_gain_resolved_tunnel_id() {
        let contents = serde_json::json!({
            "AccountTag": "synthetic-account",
            "TunnelSecret": STANDARD.encode(b"synthetic-secret"),
        })
        .to_string();
        let (credentials, remote) = resolve_credentials(
            None,
            None,
            Some(&contents),
            Some(Path::new("missing")),
            "00000000-0000-4000-8000-000000000001",
            None,
            &[],
        )
        .unwrap();
        assert!(!remote);
        assert!(!credentials.tunnel_id.is_nil());
    }
}
