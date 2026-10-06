use anyhow::{Context, Result};
use cloudflare_tunnel_rust::{
    cli::{self, Action, Invocation},
    config,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    if let Err(error) = dispatch().await {
        eprintln!("{error:#}");
        std::process::exit(
            error
                .downcast_ref::<cli::ExitFailure>()
                .map_or(1, |error| i32::from(error.code)),
        );
    }
}

async fn dispatch() -> Result<()> {
    let invocation = Invocation::from_env(std::env::args().skip(1))?;
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    match invocation.action(home.as_deref())? {
        Action::Help(command) => print!("{}", cli::help(&command)),
        Action::Version { short } => {
            if short {
                println!("{}", env!("CARGO_PKG_VERSION"));
            } else {
                println!(
                    "cloudflared version {} (Rust; upstream compatibility {})",
                    env!("CARGO_PKG_VERSION"),
                    config::UPSTREAM_VERSION
                );
            }
        }
        Action::IngressValidate(configuration) => {
            if configuration.source.is_some() {
                println!("Validating rules from configuration file");
            } else {
                println!("Validating rules from cmdline flag --json");
            }
            println!("OK");
        }
        Action::IngressRule { configuration, url } => {
            let request = url::Url::parse(&url)?;
            let raw_uri: http::Uri = url.parse()?;
            let path = decoded_path(raw_uri.path())?;
            let (index, rule) = configuration
                .ingress
                .iter()
                .enumerate()
                .find(|(_, rule)| {
                    rule.matches(request.host_str().unwrap_or(""), &path, false)
                        .unwrap_or(false)
                })
                .context("No matching ingress rule")?;
            println!("Using rules from configuration file\nMatched rule #{index}");
            if !rule.hostname.is_empty() {
                println!("\thostname: {}", rule.hostname);
            }
            if !rule.path.is_empty() {
                println!("\tpath: {}", rule.path);
            }
            println!("\tservice: {}", rule.service);
        }
        Action::Ready { metrics } => {
            let endpoint = url::Url::parse(&format!("http://{metrics}/ready"))
                .context("invalid metrics server address")?;
            if !endpoint.username().is_empty() || endpoint.password().is_some() {
                anyhow::bail!("metrics address must not include credentials");
            }
            let hostname = endpoint
                .host_str()
                .context("metrics address requires a hostname")?;
            let port = endpoint
                .port_or_known_default()
                .context("metrics address requires a port")?;
            let mut connection = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect((hostname, port)),
            )
            .await??;
            connection
                .write_all(
                    format!("GET /ready HTTP/1.1\r\nHost: {metrics}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            let mut response = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                (&mut connection).take(65_536).read_to_end(&mut response),
            )
            .await??;
            if !response.starts_with(b"HTTP/1.1 200 ") && !response.starts_with(b"HTTP/1.0 200 ") {
                anyhow::bail!("/ready endpoint did not return HTTP 200");
            }
        }
        Action::Run(configuration) => cloudflare_tunnel_rust::runtime::run(*configuration).await?,
        Action::Admin(invocation) => {
            cloudflare_tunnel_rust::administration::execute(invocation).await?
        }
        Action::Service(invocation) => cloudflare_tunnel_rust::service::execute(invocation).await?,
    }
    Ok(())
}

fn decoded_path(path: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let mut chars = path.as_bytes().iter().copied();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let high = chars
                .next()
                .and_then(|byte| (byte as char).to_digit(16))
                .context("invalid URL path escape")?;
            let low = chars
                .next()
                .and_then(|byte| (byte as char).to_digit(16))
                .context("invalid URL path escape")?;
            bytes.push((high * 16 + low) as u8);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).context("URL path is not UTF-8")
}
