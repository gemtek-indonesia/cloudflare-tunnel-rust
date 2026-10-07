use futures::StreamExt;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub(super) async fn collect() -> (Value, String, Option<String>) {
    collect_with_programs(Path::new("traceroute"), Path::new("traceroute6")).await
}
async fn collect_with_programs(v4: &Path, v6: &Path) -> (Value, String, Option<String>) {
    let targets = [
        ("region1.v2.argotunnel.com", true),
        ("region1.v2.argotunnel.com", false),
        ("region2.v2.argotunnel.com", true),
        ("region2.v2.argotunnel.com", false),
    ];
    let results = futures::stream::iter(targets)
        .map(|(host, ipv4)| async move {
            let name = format!("{host}-v{}", if ipv4 { 4 } else { 6 });
            let output = tokio::time::timeout(
                Duration::from_secs(45),
                tokio::process::Command::new(if ipv4 { v4 } else { v6 })
                    .args(["-I", "-w", "5", "-m", "5", host])
                    .kill_on_drop(true)
                    .output(),
            )
            .await;
            let parsed = match output {
                Ok(Ok(output)) if output.status.success() => String::from_utf8(output.stdout)
                    .map(|raw| {
                        let hops = decode(&raw);
                        (hops, raw)
                    })
                    .map_err(|_| "invalid traceroute output"),
                Ok(Ok(_)) => Err("traceroute command failed"),
                Ok(Err(_)) => Err("cannot run traceroute command"),
                Err(_) => Err("traceroute command timed out"),
            };
            (name, parsed)
        })
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;
    let mut json = serde_json::Map::new();
    let mut raw = String::new();
    let mut failure = None;
    for (name, result) in results {
        raw.push_str(&name);
        raw.push('\n');
        match result {
            Ok((hops, output)) => {
                json.insert(name, Value::Array(hops));
                raw.push_str(&output);
                raw.push('\n');
            }
            Err(error) => {
                json.insert(name, Value::Null);
                raw.push_str("no content\n");
                failure.get_or_insert(error.to_string());
            }
        }
    }
    (Value::Object(json), raw, failure)
}
fn decode(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter_map(|line| {
            let mut fields = line
                .split_whitespace()
                .filter(|field| !matches!(*field, "*" | "ms"));
            let index = fields.next()?.parse::<u8>().ok()?;
            let parts: Vec<_> = fields.collect();
            if parts.is_empty() {
                return Some(json!({"hop":index,"domain":"*"}));
            }
            let mut domain = Vec::new();
            let mut rtts = Vec::new();
            for part in parts {
                match part.parse::<f64>() {
                    Ok(value) if value.is_finite() && value >= 0.0 => {
                        rtts.push((value * 1000.0) as i64)
                    }
                    _ => domain.push(part),
                }
            }
            if domain.is_empty() {
                return None;
            }
            let mut hop = json!({"hop":index,"domain":domain.join(" ")});
            if !rtts.is_empty() {
                hop["rtts"] = json!(rtts);
            }
            Some(hop)
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn source_traceroute_arguments_and_hop_json_with_mock_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "cloudflared-diagnostic-command-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).unwrap();
        let program = dir.join("trace");
        std::fs::write(&program,b"#!/bin/sh\n[ \"$1 $2 $3 $4 $5\" = \"-I -w 5 -m 5\" ] || exit 2\nprintf 'header\\n 1 * * *\\n 2 loopback (127.0.0.1) 1.250 ms 2.500 ms\\n'\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (value, raw, failure) = collect_with_programs(&program, &program).await;
        assert!(failure.is_none());
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(
            value["region1.v2.argotunnel.com-v4"][1]["rtts"],
            json!([1250, 2500])
        );
        assert!(raw.contains("region2.v2.argotunnel.com-v6"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
