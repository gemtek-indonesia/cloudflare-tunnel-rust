use super::{
    bounded_body, http_client,
    token::{AppInfo, TokenClient},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use boring::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
};
use bytes::Bytes;
use http_body_util::Full;
use std::{ffi::OsStr, io::Write, os::unix::ffi::OsStrExt, path::Path, time::Duration};

pub(super) fn configuration(invocation: &crate::cli::Invocation) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_default();
    let hostname = if invocation.string("hostname").is_empty() {
        "[your hostname]"
    } else {
        invocation.string("hostname")
    };
    let executable = std::env::current_exe().unwrap_or_else(|_| "cloudflared".into());
    std::io::stdout().write_all(
        render_config(
            &home,
            hostname,
            executable.as_os_str(),
            invocation.bool("short-lived-cert"),
        )?
        .as_bytes(),
    )?;
    Ok(())
}
fn render_config(
    home: &str,
    hostname: &str,
    executable: impl AsRef<OsStr>,
    short: bool,
) -> Result<String> {
    if hostname != "[your hostname]"
        && (hostname.is_empty()
            || !hostname
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-*?!:[]".contains(&byte)))
    {
        bail!("invalid OpenSSH hostname pattern");
    }
    let executable = executable.as_ref().as_bytes();
    if executable
        .iter()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        bail!("executable path cannot be represented in OpenSSH configuration");
    }
    let quoted = std::str::from_utf8(executable)
        .map(|path| format!("'{}'", path.replace('%', "%%").replace('\'', "'\"'\"'")));
    let proxy_executable = quoted
        .clone()
        .unwrap_or_else(|_| octal_proxy_executable(executable));
    let mut output = format!("\nAdd to your {home}/.ssh/config:\n\n");
    if short {
        // Older OpenSSH Match parsers do not recognize escaped quotes; octal bytes survive both parsers.
        let match_executable = if executable.iter().any(|byte| b"'\"\\".contains(byte)) {
            octal_executable(executable)
        } else {
            quoted.unwrap_or_else(|_| octal_executable(executable))
        };
        output.push_str(&format!("Match host {hostname} exec \"{match_executable} access ssh-gen --hostname %h\"\n  ProxyCommand {proxy_executable} access ssh --hostname %h\n  IdentityFile ~/.cloudflared/%h-cf_key\n  CertificateFile ~/.cloudflared/%h-cf_key-cert.pub\n"));
    } else {
        output.push_str(&format!(
            "Host {hostname}\n  ProxyCommand {proxy_executable} access ssh --hostname %h\n\n"
        ));
    }
    Ok(output)
}
fn octal_executable(executable: &[u8]) -> String {
    format!("set -f; IFS=; exec $(printf '{}')", octal_bytes(executable))
}
fn octal_proxy_executable(executable: &[u8]) -> String {
    format!(
        "/bin/sh -c 'set -f; IFS=; exec $(printf \"{}\") \"$@\"' --",
        octal_bytes(executable)
    )
}
fn octal_bytes(executable: &[u8]) -> String {
    executable
        .iter()
        .map(|byte| format!("\\{byte:03o}"))
        .collect()
}
async fn key_pair(path: &Path) -> Result<Vec<u8>> {
    let _guard =
        super::token::credential_guard(path, std::time::Instant::now() + Duration::from_secs(600))
            .await?;
    let mut filename = path.as_os_str().to_os_string();
    filename.push(".pub");
    let public = std::path::PathBuf::from(filename);
    let existed = path.exists();
    if public.exists() && !existed {
        bail!("Access SSH public key exists without its private key");
    }
    let generated_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = if existed {
        EcKey::private_key_from_pem(
            &std::fs::read(path).context("cannot read Access SSH private key")?,
        )
        .context("invalid Access SSH private key")?
    } else {
        EcKey::generate(&generated_group)?
    };
    key.check_key()?;
    if key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        bail!("Access SSH private key must use P-256");
    }
    let group = key.group();
    let mut context = BigNumContext::new()?;
    let point =
        key.public_key()
            .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut context)?;
    let mut encoded = Vec::new();
    for value in [
        b"ecdsa-sha2-nistp256".as_slice(),
        b"nistp256".as_slice(),
        point.as_slice(),
    ] {
        encoded.extend_from_slice(&(value.len() as u32).to_be_bytes());
        encoded.extend_from_slice(value);
    }
    let public_body = format!("ecdsa-sha2-nistp256 {}\n", STANDARD.encode(encoded)).into_bytes();
    if public.exists() {
        let contents = std::fs::read(&public).context("cannot read Access SSH public key")?;
        let expected = std::str::from_utf8(&public_body)?
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>();
        if std::str::from_utf8(&contents)?
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            != expected
        {
            bail!("Access SSH public key does not match its private key");
        }
        return Ok(contents);
    }
    if !existed {
        crate::administration::credentials::atomic_create(path, &key.private_key_to_pem()?, 0o600)?;
    }
    if let Err(error) =
        crate::administration::credentials::atomic_create(&public, &public_body, 0o600)
    {
        // Remove only the new private key created by this invocation.
        if !existed {
            let _ = std::fs::remove_file(path);
        }
        return Err(error);
    }
    Ok(public_body)
}
pub(super) async fn generate(
    app: &super::ApplicationUrl,
    info: &AppInfo,
    jwt: &str,
    _tokens: &TokenClient,
) -> Result<()> {
    let directory = TokenClient::default_directory()?;
    let name = format!(
        "{}{}-cf_key",
        app.hostname(),
        app.path().trim_end_matches('/')
    )
    .replace('/', "-");
    let path = directory.join(name);
    let public = key_pair(&path).await?;
    let body = serde_json::to_vec(
        &serde_json::json!({"public_key":String::from_utf8(public)?,"jwt":jwt,"issuer":info.issuer()}),
    )?;
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("{}/cdn-cgi/access/cert_sign", info.issuer()))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?;
    let fetch = async {
        let mut response = http_client()?
            .request(request)
            .await
            .context("Access SSH signing request failed")?;
        if response.status() != 200 {
            bail!("Access SSH signing request was rejected");
        }
        let bytes = bounded_body(&mut response, 1 << 20).await?;
        #[derive(serde::Deserialize)]
        struct Certificate {
            certificate: String,
        }
        let certificate: Certificate = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid Access SSH signing response"))?;
        if certificate.certificate.is_empty() {
            bail!("Access SSH signing returned an empty certificate");
        }
        crate::administration::credentials::atomic_replace(
            &path.with_file_name(format!(
                "{}-cert.pub",
                path.file_name().unwrap().to_string_lossy()
            )),
            certificate.certificate.as_bytes(),
            0o600,
        )?;
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(10), fetch)
        .await
        .context("Access SSH signing timeout")?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn generated_p256_key_is_reused_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!("access-key-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("ssh.example.invalid-cf_key");
        let first = key_pair(&path).await.unwrap();
        assert_eq!(first, key_pair(&path).await.unwrap());
        let private = std::fs::read(&path).unwrap();
        let key = EcKey::private_key_from_pem(&private).unwrap();
        key.check_key().unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(first.starts_with(b"ecdsa-sha2-nistp256 "));
        let public = directory.join("ssh.example.invalid-cf_key.pub");
        assert!(public.is_file());
        assert!(!directory.join("ssh.example.pub").exists());
        std::fs::remove_file(&public).unwrap();
        assert_eq!(first, key_pair(&path).await.unwrap());
        std::fs::remove_file(&path).unwrap();
        assert!(
            key_pair(&path)
                .await
                .unwrap_err()
                .to_string()
                .contains("without its private key")
        );
        std::fs::remove_file(&public).unwrap();
        key_pair(&path).await.unwrap();
        std::fs::write(&public, b"ecdsa-sha2-nistp256 mismatching-public-key\n").unwrap();
        assert!(
            key_pair(&path)
                .await
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[tokio::test]
    async fn concurrent_key_pair_creation_keeps_matching_private_public() {
        let directory =
            std::env::temp_dir().join(format!("access-concurrent-key-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("ssh.example.invalid-cf_key");
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let path = path.clone();
            tasks.spawn(async move { key_pair(&path).await });
        }
        let expected = key_pair(&path).await.unwrap();
        while let Some(result) = tasks.join_next().await {
            assert_eq!(expected, result.unwrap().unwrap());
        }
        assert!(path.is_file());
        assert!(directory.join("ssh.example.invalid-cf_key.pub").is_file());
        assert_eq!(expected, key_pair(&path).await.unwrap());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ssh_configuration_quotes_executable_and_validates_host_pattern() {
        let config = render_config(
            "/synthetic/home",
            "*.example.invalid",
            "/synthetic/bin with 'quote'/cloud%flared",
            true,
        )
        .unwrap();
        assert!(config.contains("cloud%%flared"));
        assert!(config.contains(
            "ProxyCommand '/synthetic/bin with '\"'\"'quote'\"'\"'/cloud%%flared' access ssh"
        ));
        assert!(config.contains("exec \"set -f; IFS=; exec $(printf '\\057\\163"));
        for invalid in [
            "host\nProxyCommand unwanted",
            "host with space",
            "host%h",
            "host\"quote",
        ] {
            assert!(render_config("/synthetic/home", invalid, "cloudflared", false).is_err());
        }
    }

    #[tokio::test]
    async fn actual_openssh_parser_executes_only_owned_quoted_mock() {
        use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};
        let directory =
            std::env::temp_dir().join(format!("access-ssh-config-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let ssh = std::env::var_os("CLOUDFLARED_SSH_TEST_BINARY").unwrap_or_else(|| "ssh".into());
        let libraries = std::env::var_os("CLOUDFLARED_SSH_TEST_LIBRARY_PATH");
        let mut version_command = std::process::Command::new(&ssh);
        version_command.arg("-V");
        if let Some(libraries) = &libraries {
            version_command.env("LD_LIBRARY_PATH", libraries);
        }
        let version = version_command.output().unwrap();
        let version = String::from_utf8_lossy(&version.stderr);
        for filename in [
            "cloudflared with 'quote'%literal".as_bytes(),
            b"cloudflared with \"double\"\\backslash$(touch unintended-dollar)`touch unintended-backtick`*?[glob]%literal",
            b"cloudflared with $(touch unintended-dollar)`touch unintended-backtick`*?[glob]%literal",
            "cloudflared with 'unicode-\u{3bb}'%h".as_bytes(),
            b"cloudflared with non-UTF8-\xff",
        ] {
            let executable = directory.join(std::ffi::OsString::from_vec(filename.to_vec()));
            std::fs::write(&executable, b"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SSH_CAPTURE\"\nexec 0<&- 1>&-\n").unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            let capture = directory.join("arguments");
            let rendered = render_config("/synthetic/home", "synthetic.invalid", &executable, true).unwrap();
            let config = directory.join("ssh_config");
            std::fs::write(&config, &rendered[rendered.find("Match host").unwrap()..]).unwrap();
            let mut command = tokio::process::Command::new(&ssh);
            command.kill_on_drop(true);
            command.args(["-G", "-F"]).arg(&config).arg("synthetic.invalid").env_clear().env("PATH", "/usr/bin:/bin")
                .env("SSH_CAPTURE", &capture).env("HOME", &directory).current_dir(&directory);
            if let Some(libraries) = &libraries { command.env("LD_LIBRARY_PATH", libraries); }
            let output = tokio::time::timeout(Duration::from_secs(3), command.output()).await.expect("owned SSH parser did not exit").unwrap();
            let error = String::from_utf8_lossy(&output.stderr).replace(directory.to_string_lossy().as_ref(), "<fixture>");
            assert!(output.status.success(), "OpenSSH mock configuration rejected ({version}): {error}");
            let arguments = std::fs::read_to_string(&capture).unwrap();
            assert_eq!(arguments, "access\nssh-gen\n--hostname\nsynthetic.invalid\n");
            assert!(!directory.join("unintended-dollar").exists());
            assert!(!directory.join("unintended-backtick").exists());
            let configuration = String::from_utf8(output.stdout).unwrap();
            assert!(configuration.lines().any(|line| line.starts_with("proxycommand ") && (line.contains("cloudflared with") || line.contains("/bin/sh -c 'set -f; IFS=; exec $(printf "))));
            std::fs::remove_file(&capture).unwrap();

            let rendered = render_config("/synthetic/home", "synthetic.invalid", &executable, false).unwrap();
            std::fs::write(&config, &rendered[rendered.find("Host synthetic.invalid").unwrap()..]).unwrap();
            let mut command = tokio::process::Command::new(&ssh);
            command.kill_on_drop(true).arg("-F").arg(&config).args([
                "-T", "-o", "CanonicalizeHostname=no", "-o", "CanonicalDomains=none",
                "-o", "CheckHostIP=no", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "IdentityAgent=none", "-o", "IdentityFile=none", "-o", "CertificateFile=none",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "ProxyUseFdpass=no", "-o", "ConnectTimeout=1", "-o", "ConnectionAttempts=1",
                "synthetic.invalid",
            ]).env_clear().env("PATH", "/usr/bin:/bin").env("SSH_CAPTURE", &capture).env("HOME", &directory).current_dir(&directory);
            if let Some(libraries) = &libraries { command.env("LD_LIBRARY_PATH", libraries); }
            let output = tokio::time::timeout(Duration::from_secs(3), command.output()).await.expect("owned SSH proxy did not exit").unwrap();
            let error = String::from_utf8_lossy(&output.stderr).replace(directory.to_string_lossy().as_ref(), "<fixture>");
            assert_eq!(output.status.code(), Some(255), "Unexpected SSH mock exit ({version}): {error}");
            assert!(error.contains("Connection closed"), "Expected mock handshake EOF ({version}): {error}");
            assert_eq!(std::fs::read_to_string(&capture).unwrap(), "access\nssh\n--hostname\nsynthetic.invalid\n");
            assert!(!directory.join("unintended-dollar").exists());
            assert!(!directory.join("unintended-backtick").exists());
            std::fs::remove_file(capture).unwrap();
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
