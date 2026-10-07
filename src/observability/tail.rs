use super::{
    logging::{Event, Filters, Level, Log},
    management::decode_token,
};
use crate::{
    administration::{
        AccountClient,
        credentials::{AccountCredentials, cert_path},
    },
    cli::Invocation,
};
use anyhow::{Context, Result, bail};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::{io::Write, time::Duration};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

pub async fn execute(invocation: Invocation) -> Result<()> {
    let resource = if invocation.command == "management token" {
        invocation.string("resource")
    } else {
        "logs"
    };
    if matches!(
        invocation.command.as_str(),
        "management token" | "tail token"
    ) {
        let token = token(&invocation, resource).await?;
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({"token":token}))?
        );
        return Ok(());
    }
    let options = super::logging::Options {
        level: Level::parse(invocation.string("loglevel"))?,
        ..Default::default()
    };
    let logger = super::logging::Logger::new(options, vec![invocation.string("token").into()])?;
    if let Err(error) = run(&invocation).await {
        // Source tail reports operational failures but exits successfully.
        let _ = logger.log(
            Level::Error,
            Event::Cloudflared,
            "unable to stream management logs",
            serde_json::json!({"error":error.to_string()}),
        );
    }
    Ok(())
}
async fn token(invocation: &Invocation, resource: &str) -> Result<String> {
    let id: uuid::Uuid = invocation
        .args
        .first()
        .context("no tunnel ID provided")?
        .parse()
        .context("unable to parse provided tunnel id as a valid UUID")?;
    let credentials = AccountCredentials::read(&cert_path(invocation.string("origincert"))?)?;
    AccountClient::new(credentials, invocation.string("api-url"))?
        .management_token(id, resource)
        .await
}
fn filters(invocation: &Invocation) -> Result<Filters> {
    let level = if invocation.string("level").is_empty() {
        None
    } else {
        Some(Level::parse(invocation.string("level"))?)
    };
    if level == Some(Level::Fatal) {
        bail!(
            "invalid --level filter provided, please use one of the following Log Levels: debug, info, warn, error"
        );
    }
    let events = invocation
        .list("event")
        .iter()
        .map(|event| serde_json::from_value::<Event>(serde_json::json!(event)))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let sampling: f64 = if invocation.string("sample").is_empty() {
        1.0
    } else {
        invocation.string("sample").parse()?
    };
    if !sampling.is_finite() || sampling <= 0.0 || sampling > 1.0 {
        bail!("invalid --sample value provided, please make sure it is in the range (0.0 .. 1.0)");
    }
    Ok(Filters {
        level,
        events,
        sampling,
    })
}
fn url(invocation: &Invocation, token: &str) -> Result<http::Uri> {
    let claims = decode_token(token)?;
    let hostname = if claims.iss == "fed-tunnelstore" {
        "management.fed.argotunnel.com"
    } else {
        invocation.string("management-hostname")
    };
    let authority: http::uri::Authority =
        hostname.parse().context("invalid management hostname")?;
    if authority.as_str().contains('@') {
        bail!("invalid management hostname");
    }
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("access_token", token);
    if !invocation.string("connector-id").is_empty() {
        let id: uuid::Uuid = invocation
            .string("connector-id")
            .parse()
            .context("unable to parse connector-id flag into a valid UUID")?;
        query.append_pair("connector_id", &id.to_string());
    }
    http::Uri::builder()
        .scheme("wss")
        .authority(authority)
        .path_and_query(format!("/logs?{}", query.finish()))
        .build()
        .context("invalid management URL")
}
async fn run(invocation: &Invocation) -> Result<()> {
    let filters = filters(invocation)?;
    let token = if invocation.string("token").is_empty() {
        token(invocation, "logs").await?
    } else {
        invocation.string("token").to_owned()
    };
    let url = url(invocation, &token)?;
    let mut target = url.clone().into_parts();
    target.scheme = Some(http::uri::Scheme::HTTPS);
    let target = http::Uri::from_parts(target)?;
    let connector = crate::proxy_environment::client::Connector::platform()?;
    let stream = tokio::time::timeout(
        Duration::from_secs(15),
        connector.dial_with_reference(
            target,
            crate::proxy_environment::client::Profile::Http1,
            None,
        ),
    )
    .await
    .context("management connection timed out")??;
    let mut request = url.into_client_request()?;
    request.headers_mut().insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_str(&format!("cloudflared/{}", crate::config::UPSTREAM_VERSION))?,
    );
    if !invocation.string("trace").is_empty() {
        request.headers_mut().insert(
            "cf-trace-id",
            http::HeaderValue::from_str(invocation.string("trace"))?,
        );
    }
    let (mut ws, _) = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_tungstenite::client_async(request, stream),
    )
    .await
    .context("management WebSocket handshake timed out")?
    .map_err(|_| anyhow::anyhow!("management WebSocket handshake failed"))?;
    ws.send(Message::Text(
        serde_json::to_string(&serde_json::json!({"type":"start_streaming","filters":filters}))?
            .into(),
    ))
    .await?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    loop {
        let message = tokio::select! {_=terminate.recv()=>break,_=interrupt.recv()=>break,message=ws.next()=>message};
        match message {
            Some(Ok(Message::Text(text))) => {
                #[derive(Deserialize)]
                struct Logs {
                    #[serde(rename = "type")]
                    kind: String,
                    #[serde(default)]
                    logs: Vec<Log>,
                }
                if let Ok(event) = serde_json::from_str::<Logs>(&text)
                    && event.kind == "logs"
                {
                    let mut stdout = std::io::stdout().lock();
                    for log in event.logs {
                        if invocation.string("output") == "json" {
                            writeln!(stdout, "{}", serde_json::to_string(&log)?)?;
                        } else {
                            writeln!(
                                stdout,
                                "{} {} {} {} {}",
                                log.time,
                                serde_json::to_value(log.level)?
                                    .as_str()
                                    .unwrap_or_default(),
                                serde_json::to_value(log.event)?
                                    .as_str()
                                    .unwrap_or_default(),
                                log.message,
                                serde_json::to_string(&log.fields)?
                            )?;
                        }
                    }
                }
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(Message::Close(_))) | None => break,
            Some(Ok(_)) => bail!("invalid management event type"),
            Some(Err(_)) => bail!("management WebSocket closed unexpectedly"),
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), ws.close(None)).await;
    Ok(())
}

#[cfg(test)]
mod proxy_tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn management_target_preserves_raw_host_kind_case_and_port() {
        let token = format!("{}.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"alg":"ES256"})).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"tun":{"id":"synthetic-tunnel","account_tag":"synthetic-account"},"actor":{"id":"synthetic-actor"}})).unwrap()),
            URL_SAFE_NO_PAD.encode([0u8;64]),
        );
        for hostname in ["LOCALHOST:080", "127.0.0.1.:00443", "[::1]:443"] {
            let invocation = Invocation::parse(
                ["tail", "--management-hostname", hostname].map(str::to_owned),
                &std::collections::BTreeMap::new(),
                None,
            )
            .unwrap();
            let target = url(&invocation, &token).unwrap();
            assert_eq!(target.authority().unwrap().as_str(), hostname);
            let request = target.into_client_request().unwrap();
            assert_eq!(request.headers()[http::header::HOST], hostname);
        }
    }
}
