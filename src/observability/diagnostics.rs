use super::Context;
use anyhow::{Result, bail};
use bytes::Bytes;
use http::{Response, StatusCode};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

/// Runtime supplies a current snapshot; diagnostics never owns connection authority.
pub struct Snapshot {
    pub tunnel_id: uuid::Uuid,
    pub connector_id: uuid::Uuid,
    pub connections: Vec<Value>,
    pub icmp_sources: Vec<String>,
    pub cli_flags: BTreeMap<String, String>,
    pub versioned_config: Value,
    pub quick_hostname: String,
}

pub async fn handle(
    path: &str,
    context: &Arc<Context>,
    snapshot: Snapshot,
) -> Result<Response<Bytes>> {
    let mut status = StatusCode::OK;
    let (content_type, body) = match path {
        "/metrics" => ("text/plain; version=0.0.4", context.metrics.encode()?),
        "/healthcheck" => ("text/plain; charset=utf-8", b"OK\n".to_vec()),
        "/ready" => {
            status = if snapshot.connections.is_empty() {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            };
            (
                "application/json",
                serde_json::to_vec(
                    &json!({"status":status.as_u16(),"readyConnections":snapshot.connections.len(),"connectorId":snapshot.connector_id}),
                )?,
            )
        }
        "/quicktunnel" => (
            "application/json",
            serde_json::to_vec(&json!({"hostname":snapshot.quick_hostname}))?,
        ),
        "/config" => (
            "application/json",
            serde_json::to_vec(&context.logger.redact_value(&snapshot.versioned_config))?,
        ),
        "/diag/configuration" => {
            let mut flags = snapshot.cli_flags;
            // SAFETY: getuid has no preconditions.
            flags.insert("uid".into(), unsafe { libc::getuid() }.to_string());
            (
                "application/json",
                serde_json::to_vec(&context.logger.redact_value(&serde_json::to_value(flags)?))?,
            )
        }
        "/diag/tunnel" => (
            "application/json",
            serde_json::to_vec(
                &json!({"tunnelID":snapshot.tunnel_id,"connectorID":snapshot.connector_id,"connections":snapshot.connections,"icmp_sources":snapshot.icmp_sources}),
            )?,
        ),
        "/diag/system" => (
            "application/json",
            serde_json::to_vec(&system_information().await)?,
        ),
        "/debug/pprof/cmdline" => {
            status = StatusCode::FORBIDDEN;
            ("text/plain; charset=utf-8", b"forbidden\n".to_vec())
        }
        path if path.starts_with("/debug/") => {
            status = StatusCode::NOT_IMPLEMENTED;
            (
                "text/plain; charset=utf-8",
                b"Go runtime profiling and tracing are unavailable in the Rust implementation\n"
                    .to_vec(),
            )
        }
        _ => {
            status = StatusCode::NOT_FOUND;
            (
                "text/plain; charset=utf-8",
                b"404 page not found\n".to_vec(),
            )
        }
    };
    Ok(Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(Bytes::from(body))?)
}

async fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await?;
    if !output.status.success() {
        bail!("system collector command failed: {program}");
    }
    Ok(String::from_utf8(output.stdout)?)
}

pub async fn system_information() -> Value {
    match tokio::time::timeout(Duration::from_secs(10), collect_system()).await {
        Ok(value) => value,
        Err(_) => json!({"info":null,"errors":{"error":"system collection timed out"}}),
    }
}
async fn collect_system() -> Value {
    let mut info = serde_json::Map::new();
    let mut errors = serde_json::Map::new();
    info.insert(
        "cloudflaredVersion".into(),
        json!(crate::config::UPSTREAM_VERSION),
    );
    let (memory, files, os, disks) = tokio::join!(
        tokio::fs::read_to_string("/proc/meminfo"),
        tokio::fs::read_to_string("/proc/sys/fs/file-nr"),
        command("uname", &["-a"]),
        command("df", &["-k"])
    );
    match memory
        .map_err(anyhow::Error::from)
        .and_then(|raw| parse_memory(&raw))
    {
        Ok((maximum, current)) => {
            info.insert("memoryMaximum".into(), json!(maximum));
            info.insert("memoryCurrent".into(), json!(current));
        }
        Err(_) => {
            errors.insert(
                "memoryInformationError".into(),
                json!({"error":"cannot collect memory information","rawInfo":""}),
            );
        }
    }
    match files
        .map_err(anyhow::Error::from)
        .and_then(|raw| parse_files(&raw))
    {
        Ok((maximum, current)) => {
            info.insert("fileDescriptorMaximum".into(), json!(maximum));
            info.insert("fileDescriptorCurrent".into(), json!(current));
        }
        Err(_) => {
            errors.insert(
                "fileDescriptorsInformationError".into(),
                json!({"error":"cannot collect file descriptor information","rawInfo":""}),
            );
        }
    }
    match os {
        Ok(raw) => {
            let fields: Vec<_> = raw.split_whitespace().collect();
            if fields.len() >= 6 {
                for (key, value) in [
                    ("osSystem", fields[0].to_string()),
                    ("hostName", fields[1].to_string()),
                    ("osVersion", fields[2].to_string()),
                    ("osRelease", fields[3..fields.len() - 2].join(" ")),
                    ("architecture", fields[fields.len() - 2].to_string()),
                ] {
                    info.insert(key.into(), json!(value));
                }
            } else {
                errors.insert(
                    "operatingSystemInformationError".into(),
                    json!({"error":"invalid uname output","rawInfo":""}),
                );
            }
        }
        Err(_) => {
            errors.insert(
                "operatingSystemInformationError".into(),
                json!({"error":"cannot collect operating system information","rawInfo":""}),
            );
        }
    }
    match disks.and_then(|raw| parse_disks(&raw)) {
        Ok(disks) => {
            info.insert("disk".into(), json!(disks));
        }
        Err(_) => {
            errors.insert(
                "diskVolumeInformationError".into(),
                json!({"error":"cannot collect disk information","rawInfo":""}),
            );
        }
    }
    json!({"info":info,"errors":errors})
}
fn parse_memory(raw: &str) -> Result<(u64, u64)> {
    let values: BTreeMap<_, _> = raw
        .lines()
        .filter_map(|line| line.split_once(':'))
        .collect();
    let value = |key| -> Result<u64> {
        Ok(values
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("missing memory field"))?
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing memory value"))?
            .parse()?)
    };
    let maximum = value("MemTotal")?;
    Ok((
        maximum,
        maximum
            .checked_sub(value("MemAvailable")?)
            .ok_or_else(|| anyhow::anyhow!("invalid available memory"))?,
    ))
}
fn parse_files(raw: &str) -> Result<(u64, u64)> {
    let fields: Vec<_> = raw.split_whitespace().collect();
    if fields.len() != 3 {
        bail!("invalid file descriptor information");
    }
    Ok((fields[2].parse()?, fields[0].parse()?))
}
fn parse_disks(raw: &str) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    for line in raw.lines().skip(1).filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 3 {
            bail!("invalid disk information");
        }
        if let (Ok(maximum), Ok(current)) = (fields[1].parse::<u64>(), fields[2].parse::<u64>()) {
            result.push(json!({"name":fields[0],"sizeMaximum":maximum,"sizeCurrent":current}));
        }
    }
    if result.is_empty() {
        bail!("no disk volumes found");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> Snapshot {
        Snapshot {
            tunnel_id: uuid::Uuid::nil(),
            connector_id: uuid::Uuid::nil(),
            connections: vec![],
            icmp_sources: vec![],
            cli_flags: BTreeMap::from([("token".into(), "synthetic-secret".into())]),
            versioned_config: json!({"version":1,"config":{"secret":"synthetic-secret"}}),
            quick_hostname: String::new(),
        }
    }
    #[tokio::test]
    async fn endpoints_preserve_readiness_redact_secrets_and_block_profiles() {
        let context = Context::quiet().unwrap();
        assert_eq!(
            handle("/ready", &context, snapshot())
                .await
                .unwrap()
                .status(),
            503
        );
        let mut ready = snapshot();
        ready
            .connections
            .push(json!({"isConnected":true,"protocol":"quic","index":0}));
        assert_eq!(
            handle("/ready", &context, ready).await.unwrap().status(),
            200
        );
        assert_eq!(
            handle("/debug/pprof/cmdline", &context, snapshot())
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            handle("/debug/pprof/heap", &context, snapshot())
                .await
                .unwrap()
                .status(),
            501
        );
        for path in ["/diag/configuration", "/config"] {
            let response = handle(path, &context, snapshot()).await.unwrap();
            assert!(!String::from_utf8_lossy(response.body()).contains("synthetic-secret"));
        }
        assert_eq!(
            handle("/logs", &context, snapshot())
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            parse_memory("MemTotal: 100 kB\nMemAvailable: 40 kB\n").unwrap(),
            (100, 60)
        );
        assert_eq!(parse_files("50 0 100").unwrap(), (100, 50));
    }
}
