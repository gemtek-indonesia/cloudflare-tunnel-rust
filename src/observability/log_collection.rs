use crate::cli::Invocation;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

pub(super) async fn collect(flags: &Value, invocation: &Invocation) -> Result<Vec<u8>> {
    let since =
        super::logging::timestamp_at(SystemTime::now() - Duration::from_secs(14 * 24 * 60 * 60));
    let pod = invocation.string("diag-pod-id");
    let container = invocation.string("diag-container-id");
    if !pod.is_empty() {
        let mut args = vec!["logs", pod, "--since-time", &since, "--tail", "10000"];
        if !container.is_empty() {
            args.extend(["-c", container]);
        }
        return output(Path::new("kubectl"), &args).await;
    }
    if !container.is_empty() {
        return output(
            Path::new("docker"),
            &["logs", "--tail", "10000", "--since", &since, container],
        )
        .await;
    }
    if flags["uid"].as_str() == Some("0") {
        if tokio::fs::try_exists("/etc/systemd/system/cloudflared.service").await? {
            return output(
                Path::new("journalctl"),
                &["--since", "2 weeks ago", "-u", "cloudflared.service"],
            )
            .await;
        }
        return Ok(tokio::fs::read("/var/log/cloudflared.err").await?);
    }
    if let Some(path) = flags["logfile"].as_str().filter(|path| !path.is_empty()) {
        return Ok(tokio::fs::read(path).await?);
    }
    let directory = flags["log-directory"]
        .as_str()
        .filter(|path| !path.is_empty())
        .context("no configured log output")?;
    directory_logs(Path::new(directory)).await
}
async fn output(program: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = tokio::time::timeout(
        Duration::from_secs(45),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("log collection timed out")??;
    if !output.status.success() {
        bail!("log collector command failed");
    }
    Ok([output.stdout, output.stderr].concat())
}
async fn directory_logs(directory: &Path) -> Result<Vec<u8>> {
    let mut entries = tokio::fs::read_dir(directory).await?;
    let mut paths = Vec::<PathBuf>::new();
    while let Some(entry) = entries.next_entry().await? {
        paths.push(entry.path());
    }
    paths.sort();
    let mut body = Vec::new();
    for path in paths {
        body.extend(tokio::fs::read(path).await?);
    }
    // The frozen collector appends the current log after directory traversal.
    body.extend(tokio::fs::read(directory.join("cloudflared.log")).await?);
    Ok(body)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn directory_and_mock_command_collectors_preserve_source_output_order() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "cloudflared-log-collection-test-{}",
            uuid::Uuid::new_v4()
        ));
        tokio::fs::create_dir(&dir).await.unwrap();
        tokio::fs::write(dir.join("cloudflared-1.log"), b"old\n")
            .await
            .unwrap();
        tokio::fs::write(dir.join("cloudflared.log"), b"current\n")
            .await
            .unwrap();
        assert_eq!(
            directory_logs(&dir).await.unwrap(),
            b"old\ncurrent\ncurrent\n"
        );
        let program = dir.join("collector");
        tokio::fs::write(
            &program,
            b"#!/bin/sh\n[ \"$1\" = logs ] || exit 2\nprintf 'stdout\\n'\nprintf 'stderr\\n' >&2\n",
        )
        .await
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            output(&program, &["logs"]).await.unwrap(),
            b"stdout\nstderr\n"
        );
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
