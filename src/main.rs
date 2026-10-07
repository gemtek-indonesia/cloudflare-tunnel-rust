mod tunnel_runner;

use anyhow::{Context, Result};
use cloudflare_tunnel_rust::{
    cli::{self, Action, Invocation},
    config,
};
use http_body_util::BodyExt;

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
        Action::IngressRule {
            configuration,
            url,
            normalize,
        } => {
            let request = url::Url::parse(&url)?;
            let raw_uri: http::Uri = url.parse()?;
            let path = config::matcher_path(raw_uri.path())?;
            let (index, rule) = configuration
                .ingress
                .iter()
                .enumerate()
                .find(|(_, rule)| {
                    rule.matches(request.host_str().unwrap_or(""), &path, normalize)
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
        Action::Ready { metrics } => ready(&metrics).await?,
        Action::Run(configuration) => tunnel_runner::run(*configuration).await?,
        Action::RunNamed(invocation) => {
            tunnel_runner::run(invocation.named_config(home.as_deref()).await?).await?
        }
        Action::Admin(invocation) => {
            cloudflare_tunnel_rust::administration::execute(invocation).await?
        }
        Action::Service(invocation) => cloudflare_tunnel_rust::service::execute(invocation).await?,
        Action::Access(invocation) => cloudflare_tunnel_rust::access::execute(invocation).await?,
        Action::Watch(invocation) => {
            cloudflare_tunnel_rust::access::watcher::execute(invocation).await?
        }
        Action::Operations(invocation) => {
            cloudflare_tunnel_rust::observability::tail::execute(invocation).await?
        }
        Action::Diagnostics(invocation) => {
            cloudflare_tunnel_rust::observability::bundle::execute(invocation).await?
        }
        Action::Quick(invocation) => {
            let config = cloudflare_tunnel_rust::quick_tunnel::prepare(&invocation).await?;
            tunnel_runner::run(config).await?;
        }
        Action::Adhoc(invocation) => {
            let credentials =
                cloudflare_tunnel_rust::administration::prepare_adhoc(&invocation).await?;
            tunnel_runner::run(invocation.run_config_for_credentials(
                credentials,
                false,
                home.as_deref(),
            )?)
            .await?;
        }
    }
    Ok(())
}

async fn ready(metrics: &str) -> Result<()> {
    let endpoint: http::Uri = format!("http://{metrics}/ready")
        .parse()
        .context("invalid metrics server address")?;
    let client =
        cloudflare_tunnel_rust::proxy_environment::client::HttpClient::<
            http_body_util::Empty<bytes::Bytes>,
        >::new(cloudflare_tunnel_rust::proxy_environment::client::Connector::platform()?);
    let response = client
        .request_following(
            http::Request::builder()
                .uri(endpoint)
                .body(http_body_util::Empty::new())?,
        )
        .await?;
    if response.status() != http::StatusCode::OK {
        let status = response.status().as_u16();
        let body = response.into_body().collect().await?.to_bytes();
        anyhow::bail!(
            "http://{metrics}/ready endpoint returned status code {status}\n{}",
            String::from_utf8_lossy(&body)
        );
    }
    Ok(())
}

#[cfg(test)]
mod proxy_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn ready_uses_environment_route_and_status_instead_of_direct_tcp_parser() {
        const CHILD: &str = "CLOUDFLARED_READY_PROXY_CHILD";
        if std::env::var_os(CHILD).is_some() {
            ready("synthetic.invalid:080").await.unwrap();
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (path, reply) in [
                ("/ready", b"HTTP/1.1 302 Found\r\nLocation: /ready-next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()),
                ("/ready-next", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()),
            ] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(socket.read_u8().await.unwrap());
                assert!(head.len() < 16 * 1024);
            }
            assert!(head.starts_with(format!("GET http://synthetic.invalid:080{path} HTTP/1.1\r\n").as_bytes()));
            socket
                .write_all(reply)
                .await
                .unwrap();
            }
        });
        let output=tokio::time::timeout(std::time::Duration::from_secs(3),tokio::process::Command::new(std::env::current_exe().unwrap())
            .env_clear().env(CHILD,"1").env("HTTP_PROXY",format!("http://{address}"))
            .args(["--exact","proxy_tests::ready_uses_environment_route_and_status_instead_of_direct_tcp_parser","--nocapture"]).output()).await.unwrap().unwrap();
        assert!(
            output.status.success(),
            "owned readiness proxy child failed"
        );
        server.await.unwrap();
    }
}
