pub(crate) mod forward;
pub mod jwt;
mod ssh;
#[path = "url.rs"]
mod target;
pub mod token;
pub use target::ApplicationUrl;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};

pub(crate) type HttpClient = Client<hyper_boring::HttpsConnector<HttpConnector>, Full<Bytes>>;

pub(crate) fn http_client() -> Result<HttpClient> {
    Ok(Client::builder(TokioExecutor::new()).build(crate::administration::verified_connector()?))
}

pub(crate) async fn bounded_body(
    response: &mut http::Response<hyper::body::Incoming>,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        if let Ok(data) = frame.context("HTTP response body failed")?.into_data() {
            if body
                .len()
                .checked_add(data.len())
                .is_none_or(|length| length > limit)
            {
                bail!("HTTP response exceeds maximum size");
            }
            body.extend_from_slice(&data);
        }
    }
    Ok(body)
}

pub async fn execute(invocation: crate::cli::Invocation) -> Result<()> {
    if invocation.command == "access ssh-config" {
        return ssh::configuration(&invocation);
    }
    if invocation.command == "access tcp" {
        return forward::execute(invocation).await;
    }
    let client = token::TokenClient::new(
        token::TokenClient::default_directory()?,
        invocation.bool("fedramp"),
    )?;
    let mut arguments = invocation.args.clone();
    let allow_request = invocation.command == "access curl"
        && arguments.len() > 1
        && ["--allow-request", "-ar"].contains(&arguments[0].as_str());
    if allow_request {
        arguments.remove(0);
    }
    let raw = if invocation.command == "access ssh-gen" {
        invocation.string("hostname")
    } else {
        arguments
            .first()
            .map_or(invocation.string("app"), String::as_str)
    };
    let app = if invocation.command == "access curl" {
        ApplicationUrl::curl(raw)?
    } else {
        application_url(raw)?
    };
    let info = client.discover(&app).await?;
    match invocation.command.as_str() {
        "access token" => print!("{}", client.cached(&info).await?),
        "access login" => {
            let jwt = client
                .verify_at_edge(&app, &info, invocation.bool("auto-close"), open_browser)
                .await?;
            if !invocation.bool("quiet") {
                if invocation.bool("no-verbose") || invocation.is_set("app") {
                    print!("{jwt}");
                } else {
                    println!("Successfully fetched your token:\n\n{jwt}\n");
                }
            }
        }
        "access curl" => {
            let mut command = tokio::process::Command::new("curl");
            command.args(arguments);
            run_curl(
                &client,
                &app,
                &info,
                allow_request,
                invocation.bool("auto-close"),
                open_browser,
                command,
            )
            .await?;
        }
        "access ssh-gen" => {
            let jwt = client
                .fetch(
                    &app,
                    &info,
                    false,
                    invocation.bool("auto-close"),
                    open_browser,
                )
                .await?;
            ssh::generate(&app, &info, &jwt, &client).await?;
        }
        _ => bail!("unknown Access command"),
    }
    Ok(())
}

async fn run_curl(
    client: &token::TokenClient,
    app: &ApplicationUrl,
    info: &token::AppInfo,
    allow_request: bool,
    auto_close: bool,
    browser: impl Fn(&str) -> Result<()>,
    mut command: tokio::process::Command,
) -> Result<()> {
    client
        .verify_at_edge(app, info, auto_close, &browser)
        .await?;
    let jwt = match client.cached(info).await {
        Ok(jwt) => Some(jwt),
        Err(_) if allow_request => None,
        Err(_) => Some(client.fetch(app, info, true, auto_close, &browser).await?),
    };
    // Curl reads the sensitive header from a private file, never process argv.
    let header = jwt
        .map(|jwt| PrivateHeader::new(&format!("cf-access-token: {jwt}\n")))
        .transpose()?;
    if let Some(header) = &header {
        command.arg("-H").arg(format!("@{}", header.0.display()));
    }
    let status = command
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .context("cannot execute curl")?;
    if !status.success() {
        return Err(crate::cli::ExitFailure {
            code: status
                .code()
                .and_then(|code| code.try_into().ok())
                .unwrap_or(1),
            message: "curl exited unsuccessfully".into(),
        }
        .into());
    }
    Ok(())
}

pub(crate) fn application_url(raw: &str) -> Result<ApplicationUrl> {
    ApplicationUrl::access(raw)
}

pub(crate) fn open_browser(url: &str) -> Result<()> {
    let display = ApplicationUrl::remote(url)?.without_userinfo();
    eprintln!(
        "A browser window should open at the following URL:\n{display}\nIf the browser fails to open, visit the URL above directly."
    );
    // Starting the native URL handler is best-effort; the printed transfer URL supports headless hosts.
    let _ = std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    Ok(())
}

struct PrivateHeader(std::path::PathBuf);
impl PrivateHeader {
    fn new(body: &str) -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "cloudflared-access-header-{}",
            uuid::Uuid::new_v4()
        ));
        crate::administration::credentials::atomic_create(&path, body.as_bytes(), 0o600)?;
        Ok(Self(path))
    }
}
impl Drop for PrivateHeader {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
