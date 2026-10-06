use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

#[derive(Deserialize, Serialize)]
pub struct AccountCredentials {
    #[serde(rename = "zoneID")]
    pub zone_id: String,
    #[serde(default, rename = "accountID")]
    pub account_id: String,
    #[serde(rename = "apiToken")]
    pub(crate) api_token: String,
    #[serde(default)]
    pub endpoint: String,
}

impl std::fmt::Debug for AccountCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountCredentials").finish_non_exhaustive()
    }
}

impl AccountCredentials {
    pub fn decode(pem: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(pem)
            .map_err(|_| anyhow::anyhow!("invalid origin certificate encoding"))?;
        let mut cert = None;
        for block in text.split("-----BEGIN ").skip(1) {
            let (kind, rest) = block
                .split_once("-----")
                .context("invalid origin certificate PEM")?;
            let (body, _) = rest
                .split_once(&format!("-----END {kind}-----"))
                .context("invalid origin certificate PEM")?;
            match kind {
                "PRIVATE KEY" | "CERTIFICATE" => {}
                "ARGO TUNNEL TOKEN" => {
                    if cert.is_some() {
                        bail!("found multiple tokens in the certificate");
                    }
                    let bytes = STANDARD
                        .decode(body.split_whitespace().collect::<String>())
                        .map_err(|_| {
                            anyhow::anyhow!("invalid origin certificate token encoding")
                        })?;
                    let mut value: Self = serde_json::from_slice(&bytes)
                        .map_err(|_| anyhow::anyhow!("invalid origin certificate token JSON"))?;
                    value.endpoint.make_ascii_lowercase();
                    if value.zone_id.is_empty() || value.api_token.is_empty() {
                        bail!("missing token in the certificate");
                    }
                    cert = Some(value);
                }
                _ => bail!("unknown block in the certificate"),
            }
        }
        cert.context("missing token in the certificate")
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = STANDARD.encode(serde_json::to_vec(self)?);
        let lines = body
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(
            format!(
                "-----BEGIN ARGO TUNNEL TOKEN-----\n{lines}\n-----END ARGO TUNNEL TOKEN-----\n"
            )
            .into_bytes(),
        )
    }

    pub fn read(path: &Path) -> Result<Self> {
        let cert = Self::decode(&std::fs::read(path).context("cannot read origin certificate")?)?;
        if cert.account_id.is_empty() {
            bail!(
                "Origin certificate needs to be refreshed before creating new tunnels. Run cloudflared login to obtain a new cert."
            );
        }
        Ok(cert)
    }
}

pub fn cert_path(explicit: &str) -> Result<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if !explicit.is_empty() {
        return crate::config::expand_home(explicit, home.as_deref());
    }
    crate::config::search_directories(home.as_deref()).into_iter().map(|dir| dir.join("cert.pem")).find(|path| path.is_file()).context("Cannot determine default origin certificate path. Specify --origincert or run cloudflared login.")
}

pub fn atomic_create(path: &Path, body: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".cloudflared-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(body)?;
        file.sync_all()?;
        std::fs::hard_link(&temporary, path)
            .context("credential destination already exists or cannot be created")?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let cleanup = std::fs::remove_file(&temporary);
    if result.is_ok() {
        cleanup?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn account_pem_roundtrip_redaction_and_atomic_no_clobber() {
        let cert = AccountCredentials {
            zone_id: "test-zone".into(),
            account_id: "test-account".into(),
            api_token: "synthetic-token".into(),
            endpoint: "fed".into(),
        };
        let body = cert.encode().unwrap();
        assert_eq!(
            AccountCredentials::decode(&body).unwrap().api_token,
            cert.api_token
        );
        assert!(AccountCredentials::decode(&[body.clone(), body.clone()].concat()).is_err());
        assert!(!format!("{cert:?}").contains("synthetic-token"));
        let dir =
            std::env::temp_dir().join(format!("cloudflared-admin-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("credentials.json");
        atomic_create(&path, b"original", 0o400).unwrap();
        assert!(atomic_create(&path, b"replacement", 0o400).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
