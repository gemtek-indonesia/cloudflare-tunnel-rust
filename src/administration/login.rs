use super::credentials::{AccountCredentials, atomic_create, atomic_replace};
use crate::cli::Invocation;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use std::{os::unix::fs::DirBuilderExt, path::PathBuf, time::Duration};

pub async fn execute(invocation: &Invocation) -> Result<()> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("cannot determine home directory")?;
    let dir = home.join(".cloudflared");
    if !dir.exists() {
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    let path = dir.join("cert.pem");
    if std::fs::metadata(&path).is_ok_and(|meta| meta.len() > 0) {
        eprintln!(
            "Existing certificate would be overwritten; move or delete it before running cloudflared login again."
        );
        return Ok(());
    }
    let fed = invocation.bool("fedramp");
    let base = if fed {
        "https://dash.fed.cloudflare.com/argotunnel"
    } else {
        match invocation.string("loginURL") {
            "" => "https://dash.cloudflare.com/argotunnel",
            url => url,
        }
    };
    let store = if fed {
        "https://login.fed.cloudflareaccess.org/"
    } else {
        "https://login.cloudflareaccess.org/"
    };
    let callback = match invocation.string("callbackURL") {
        "" => store,
        url => url,
    };
    let key = boring::pkey::PKey::generate(boring::pkey::Id::X25519)?;
    let mut public = [0; 32];
    let identifier = URL_SAFE.encode(key.raw_public_key(&mut public)?);
    let mut login = url::Url::parse(base)?;
    login
        .query_pairs_mut()
        .append_pair("callback", &format!("{callback}{identifier}"))
        .append_pair("aud", "");
    let opened = tokio::process::Command::new("xdg-open")
        .arg(login.as_str())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success());
    eprintln!(
        "{}\n\n{login}\n\nLeave cloudflared running to download the certificate automatically.",
        if opened {
            "A browser window should have opened at the following URL:"
        } else {
            "Please open the following URL and log in with your Cloudflare account:"
        }
    );
    let body = fetch_certificate(&format!("{store}{identifier}")).await?;
    let mut cert = AccountCredentials::decode(&body)?;
    if fed {
        cert.endpoint = "fed".into();
    }
    save_certificate(&path, &cert.encode()?)?;
    println!(
        "You have successfully logged in. Your credentials have been saved to {}",
        path.display()
    );
    Ok(())
}

fn save_certificate(path: &std::path::Path, body: &[u8]) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() == 0 =>
        {
            atomic_replace(path, body, 0o600)
        }
        Ok(_) => bail!(
            "Existing certificate would be overwritten; move or delete it before running cloudflared login again."
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_create(path, body, 0o600)
        }
        Err(error) => Err(error).context("cannot inspect certificate destination"),
    }
}

async fn fetch_certificate(request_url: &str) -> Result<Vec<u8>> {
    let connector = crate::proxy_environment::client::Connector::platform()?;
    let client = crate::proxy_environment::client::HttpClient::<Empty<Bytes>>::new(connector);
    for _ in 0..10 {
        let request = http::Request::builder()
            .uri(request_url)
            .header(http::header::USER_AGENT, "cloudflared")
            .body(Empty::<Bytes>::new())?;
        let (status, body) = tokio::time::timeout(Duration::from_secs(60), async {
            let response = client.request_following(request).await?;
            let status = response.status();
            let body = response.into_body().collect().await?.to_bytes();
            Ok::<_, anyhow::Error>((status, body))
        })
        .await??;
        if status.is_server_error() {
            bail!("login callback server returned {status}");
        }
        if status != http::StatusCode::OK || body.is_empty() {
            eprintln!("Waiting for login...");
            continue;
        }
        AccountCredentials::decode(&body)?;
        return Ok(body.to_vec());
    }
    bail!("Failed to fetch resource")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_certificate_replaced_and_existing_credentials_preserved() {
        let dir = std::env::temp_dir().join(format!(
            "cloudflared-login-file-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("cert.pem");
        atomic_create(&path, b"", 0o644).unwrap();
        save_certificate(&path, b"synthetic-certificate").unwrap();
        assert!(save_certificate(&path, b"must not overwrite").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic-certificate");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    use http_body_util::Full;
    use hyper_util::rt::TokioIo;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    #[tokio::test]
    async fn callback_polls_and_validates_account_certificate() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let counts = count.clone();
        let cert = AccountCredentials {
            zone_id: "test-zone".into(),
            account_id: "test-account".into(),
            api_token: "synthetic-login-token".into(),
            endpoint: String::new(),
        }
        .encode()
        .unwrap();
        let expected = cert.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let service =
                hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                    if request.uri().path() == "/synthetic-capability" {
                        return std::future::ready(Ok::<_, Infallible>(
                            http::Response::builder()
                                .status(302)
                                .header(http::header::LOCATION, "/certificate")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        ));
                    }
                    assert_eq!(request.uri().path(), "/certificate");
                    let poll = counts.fetch_add(1, Ordering::Relaxed);
                    let body = if poll < 2 { Vec::new() } else { cert.clone() };
                    std::future::ready(Ok::<_, Infallible>(
                        http::Response::builder()
                            .status(if poll < 2 { 404 } else { 200 })
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    ))
                });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await;
        });
        assert_eq!(
            fetch_certificate(&format!("http://{address}/synthetic-capability"))
                .await
                .unwrap(),
            expected
        );
        assert_eq!(count.load(Ordering::Relaxed), 3);
        server.abort();
    }
}
