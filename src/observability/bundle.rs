use crate::cli::Invocation;
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::Empty;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

type HttpClient = Client<hyper_boring::HttpsConnector<HttpConnector>, Empty<Bytes>>;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_COLLECTION_BYTES: usize = 64 * 1024 * 1024;
struct Collector {
    client: HttpClient,
    base: url::Url,
    remaining: Arc<AtomicUsize>,
}
impl Collector {
    fn new(client: HttpClient, base: url::Url) -> Self {
        Self {
            client,
            base,
            remaining: Arc::new(AtomicUsize::new(MAX_COLLECTION_BYTES)),
        }
    }
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let url = self.base.join(path)?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let request = http::Request::builder()
                .uri(url.as_str())
                .header(http::header::ACCEPT, "application/json;version=1")
                .body(Empty::<Bytes>::new())?;
            let mut response = crate::http_redirect::direct(&self.client, request).await?;
            if !response.status().is_success() {
                bail!(
                    "diagnostic endpoint {path} returned HTTP {}",
                    response.status().as_u16()
                );
            }
            let body = crate::access::bounded_body(&mut response, MAX_RESPONSE_BYTES)
                .await
                .context("diagnostic response body exceeds its limit or failed")?;
            self.remaining
                .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(body.len())
                })
                .map_err(|_| {
                    anyhow::anyhow!("diagnostic responses exceed the total collection budget")
                })?;
            Ok(body)
        })
        .await
        .context("diagnostic request timed out")?
    }
}
pub async fn execute(invocation: Invocation) -> Result<()> {
    let connector = crate::administration::verified_connector()?;
    let client = Client::builder(TokioExecutor::new()).build(connector);
    let defaults: Vec<_> = (20241..=20245)
        .map(|port| format!("http://127.0.0.1:{port}/"))
        .collect();
    let collector = select_collector(&invocation, client, &defaults).await?;
    let (files, failures) = collect(&collector, &invocation).await;
    let filename = format!(
        "cloudflared-diag-{}.zip",
        super::logging::timestamp().replace(':', "-")
    );
    let path = write_archive(Path::new("."), &filename, files)?;
    eprintln!("Diagnostic file written: {}", path.display());
    if !failures.is_empty() {
        bail!(
            "diagnostic bundle written with failed tasks: {}",
            failures.join(", ")
        );
    }
    Ok(())
}
async fn select_collector(
    invocation: &Invocation,
    client: HttpClient,
    defaults: &[String],
) -> Result<Collector> {
    let auto = invocation.string("metrics").is_empty()
        || (!invocation.is_set("metrics") && invocation.string("metrics") == "localhost:0");
    let addresses = if auto {
        defaults.to_vec()
    } else {
        vec![format!(
            "{}/",
            if invocation.string("metrics").starts_with("http://")
                || invocation.string("metrics").starts_with("https://")
            {
                invocation
                    .string("metrics")
                    .trim_end_matches('/')
                    .to_owned()
            } else {
                format!("http://{}", invocation.string("metrics"))
            }
        )]
    };
    let mut found = Vec::new();
    for address in addresses {
        let collector = Collector::new(client.clone(), url::Url::parse(&address)?);
        let reachable = if auto {
            collector
                .get("/diag/tunnel")
                .await
                .ok()
                .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
                .is_some_and(|value| value.is_object() || value.is_null())
        } else {
            true
        };
        if reachable {
            found.push(collector);
        }
    }
    if found.is_empty() {
        bail!("no metrics server found");
    }
    if found.len() > 1 {
        bail!("multiple metrics servers found; specify --metrics");
    }
    let collector = found.pop().unwrap();
    collector
        .remaining
        .store(MAX_COLLECTION_BYTES, Ordering::Release);
    Ok(collector)
}
async fn collect(
    collector: &Collector,
    invocation: &Invocation,
) -> (BTreeMap<String, Vec<u8>>, Vec<String>) {
    let jobs = [
        ("tunnel state", "tunnelstate.json", "/diag/tunnel", false),
        (
            "system information",
            "systeminformation.json",
            "/diag/system",
            invocation.bool("no-diag-system"),
        ),
        (
            "goroutine profile",
            "goroutine.pprof",
            "/debug/pprof/goroutine",
            invocation.bool("no-diag-runtime"),
        ),
        (
            "heap profile",
            "heap.pprof",
            "/debug/pprof/heap",
            invocation.bool("no-diag-runtime"),
        ),
        (
            "metrics",
            "metrics.txt",
            "/metrics",
            invocation.bool("no-diag-metrics"),
        ),
        (
            "cli configuration",
            "cli-configuration.json",
            "/diag/configuration",
            false,
        ),
        ("configuration", "configuration.json", "/config", false),
    ];
    let mut files = BTreeMap::new();
    let mut report = serde_json::Map::new();
    let mut failures = Vec::new();
    let endpoints = futures::stream::iter(jobs)
        .filter(|(_, _, _, skip)| futures::future::ready(!skip))
        .map(|(name, file, path, _)| async move { (name, file, collector.get(path).await) })
        .buffer_unordered(jobs.len())
        .collect::<Vec<_>>();
    let network = async {
        if invocation.bool("no-diag-network") {
            None
        } else {
            Some(super::network_diagnostic::collect().await)
        }
    };
    let prechecks = async {
        if invocation.bool("no-diag-network") {
            None
        } else {
            let report = crate::runtime::prechecks::collect(
                invocation.string("region"),
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
            Some(serde_json::to_vec_pretty(&report))
        }
    };
    let logs = async {
        if invocation.bool("no-diag-logs") {
            return None;
        }
        Some(
            tokio::time::timeout(Duration::from_secs(45), async {
                let flags: Value =
                    serde_json::from_slice(&collector.get("/diag/configuration").await?)?;
                super::log_collection::collect(&flags, invocation).await
            })
            .await
            .map_err(|_| anyhow::anyhow!("log collection timed out"))
            .and_then(|result| result),
        )
    };
    let (results, network, logs, prechecks) = tokio::join!(endpoints, network, logs, prechecks);
    for (name, file, result) in results {
        match result {
            Ok(body) => {
                files.insert(file.into(), body);
                report.insert(name.into(), json!({"result":"success"}));
            }
            Err(error) => {
                failures.push(name.into());
                report.insert(
                    name.into(),
                    json!({"result":"failure","error":error.to_string()}),
                );
            }
        }
    }
    if let Some(result) = logs {
        match result {
            Ok(body) => {
                files.insert("cloudflared_logs.txt".into(), body);
                report.insert("log information".into(), json!({"result":"success"}));
            }
            Err(_) => {
                failures.push("log information".into());
                report.insert(
                    "log information".into(),
                    json!({"result":"failure","error":"unable to collect configured log output"}),
                );
            }
        }
    }
    if let Some((network, raw, error)) = network {
        files.insert(
            "network.json".into(),
            serde_json::to_vec_pretty(&network).unwrap(),
        );
        files.insert("raw-network.txt".into(), raw.into_bytes());
        for name in ["network information", "raw network information"] {
            if let Some(error) = &error {
                failures.push(name.into());
                report.insert(name.into(), json!({"result":"failure","error":error}));
            } else {
                report.insert(name.into(), json!({"result":"success"}));
            }
        }
    }
    if let Some(result) = prechecks {
        store_precheck(result, &mut files, &mut report, &mut failures);
    }
    report.insert("job report".into(), json!({"result":"success"}));
    files.insert(
        "task-result.json".into(),
        serde_json::to_vec_pretty(&report).unwrap(),
    );
    (files, failures)
}
fn store_precheck(
    result: serde_json::Result<Vec<u8>>,
    files: &mut BTreeMap<String, Vec<u8>>,
    report: &mut serde_json::Map<String, Value>,
    failures: &mut Vec<String>,
) {
    match result {
        Ok(body) => {
            files.insert("prechecks.json".into(), body);
            report.insert(
                "connectivity pre-checks".into(),
                json!({"result":"success"}),
            );
        }
        Err(_) => {
            failures.push("connectivity pre-checks".into());
            report.insert(
                "connectivity pre-checks".into(),
                json!({"result":"failure","error":"cannot encode connectivity pre-check report"}),
            );
        }
    }
}
fn write_archive(
    directory: &Path,
    filename: &str,
    files: BTreeMap<String, Vec<u8>>,
) -> Result<PathBuf> {
    let path = directory.join(filename);
    let temporary = directory.join(format!(".cloudflared-diag-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let mut zip = zip::ZipWriter::new(file);
        for (name, body) in files {
            if Path::new(&name)
                .file_name()
                .is_none_or(|base| base != name.as_str())
            {
                bail!("invalid diagnostic archive entry name");
            }
            zip.start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(0o600),
            )?;
            zip.write_all(&body)?;
        }
        zip.finish()?.sync_all()?;
        std::fs::hard_link(&temporary, &path)
            .context("diagnostic archive destination exists or cannot be created")?;
        std::fs::File::open(directory)?.sync_all()?;
        Ok(path)
    })();
    if temporary.exists() {
        std::fs::remove_file(temporary)?;
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn real_mock_probe_report_is_included_in_diagnostic_zip() {
        let report = crate::runtime::prechecks::fixture_report().await;
        let expected = serde_json::to_value(&report).unwrap();
        let mut files = BTreeMap::new();
        let mut jobs = serde_json::Map::new();
        let mut failures = Vec::new();
        store_precheck(
            serde_json::to_vec_pretty(&report),
            &mut files,
            &mut jobs,
            &mut failures,
        );
        assert!(failures.is_empty());
        assert_eq!(jobs["connectivity pre-checks"]["result"], "success");
        let dir = std::env::temp_dir().join(format!(
            "cloudflared-precheck-zip-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = write_archive(&dir, "bundle.zip", files).unwrap();
        let mut zip = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
        let entry = zip.by_name("prechecks.json").unwrap();
        let actual: Value = serde_json::from_reader(entry).unwrap();
        assert_eq!(actual, expected);
        std::fs::remove_dir_all(dir).unwrap();
    }
    async fn mock(
        body: Vec<u8>,
    ) -> (
        String,
        tokio_util::sync::CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::AsyncWriteExt;
        let mut encoder = async_compression::tokio::write::GzipEncoder::new(Vec::new());
        encoder.write_all(&body).await.unwrap();
        encoder.shutdown().await.unwrap();
        let body = encoder.into_inner();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}/", listener.local_addr().unwrap());
        let cancel = tokio_util::sync::CancellationToken::new();
        let stopping = cancel.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopping.cancelled() => break,
                    incoming = listener.accept() => {
                        let (socket, _) = incoming.unwrap();
                        let body = body.clone();
                        tasks.spawn(async move {
                            let service = hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                                let body = body.clone();
                                async move {
                                    assert_eq!(request.headers()[http::header::ACCEPT_ENCODING], "gzip");
                                    if !request.uri().path().starts_with("/redirected/") {
                                        return Ok::<_, std::convert::Infallible>(http::Response::builder()
                                            .status(302).header(http::header::LOCATION, format!("/redirected{}", request.uri().path()))
                                            .body(http_body_util::Full::new(Bytes::new())).unwrap());
                                    }
                                    Ok::<_, std::convert::Infallible>(http::Response::builder()
                                        .header(http::header::CONTENT_ENCODING, "gzip")
                                        .body(http_body_util::Full::new(Bytes::from(body))).unwrap())
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(hyper_util::rt::TokioIo::new(socket), service).await;
                        });
                    }
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        (address, cancel, task)
    }
    fn client() -> HttpClient {
        Client::builder(TokioExecutor::new())
            .build(crate::administration::verified_connector().unwrap())
    }
    #[tokio::test]
    async fn parsed_default_discovers_and_explicit_metrics_selects_actual_peer() {
        let (first, stop_first, task_first) = mock(b"{}".to_vec()).await;
        let (second, stop_second, task_second) = mock(b"{}".to_vec()).await;
        let defaults = Invocation::parse(
            ["tunnel", "diag"].map(str::to_owned),
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(defaults.string("metrics"), "localhost:0");
        assert!(!defaults.is_set("metrics"));
        let selected = select_collector(&defaults, client(), std::slice::from_ref(&first))
            .await
            .unwrap();
        assert_eq!(selected.base.as_str(), first);
        assert_eq!(selected.get("/diag/tunnel").await.unwrap(), b"{}");
        let explicit = Invocation::parse(
            vec![
                "tunnel".into(),
                "diag".into(),
                "--metrics".into(),
                second.clone(),
            ],
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        let selected = select_collector(&explicit, client(), std::slice::from_ref(&first))
            .await
            .unwrap();
        assert_eq!(selected.base.as_str(), second);
        assert_eq!(selected.get("/diag/tunnel").await.unwrap(), b"{}");
        stop_first.cancel();
        stop_second.cancel();
        task_first.await.unwrap();
        task_second.await.unwrap();
    }
    #[tokio::test]
    async fn streamed_response_and_total_collection_limits_report_errors() {
        let (address, stop, task) = mock(vec![0; MAX_RESPONSE_BYTES + 1]).await;
        let collector = Collector::new(client(), url::Url::parse(&address).unwrap());
        assert!(
            collector
                .get("/metrics")
                .await
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
        stop.cancel();
        task.await.unwrap();
        let (address, stop, task) = mock(b"bounded".to_vec()).await;
        let collector = Collector::new(client(), url::Url::parse(&address).unwrap());
        collector.remaining.store(8, Ordering::Release);
        assert_eq!(collector.get("/metrics").await.unwrap(), b"bounded");
        assert!(
            collector
                .get("/metrics")
                .await
                .unwrap_err()
                .to_string()
                .contains("total collection budget")
        );
        stop.cancel();
        task.await.unwrap();
    }
    #[tokio::test]
    async fn actual_http_collectors_archive_successes_and_report_profile_failures() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let stopping = cancel.clone();
        let server = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopping.cancelled() => break,
                    connection = listener.accept() => {
                        let (socket, _) = connection.unwrap();
                        tasks.spawn(async move {
                            let service = hyper::service::service_fn(|request: http::Request<hyper::body::Incoming>| async move {
                                let status = if request.uri().path().starts_with("/debug/") { 501 } else { 200 };
                                let body = if request.uri().path() == "/metrics" {
                                    b"real_metrics 1\n".to_vec()
                                } else {
                                    b"{}".to_vec()
                                };
                                Ok::<_, std::convert::Infallible>(http::Response::builder().status(status)
                                    .body(http_body_util::Full::new(Bytes::from(body))).unwrap())
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(hyper_util::rt::TokioIo::new(socket), service).await;
                        });
                    }
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        let collector = Collector::new(
            Client::builder(TokioExecutor::new())
                .build(crate::administration::verified_connector().unwrap()),
            url::Url::parse(&format!("http://{addr}/")).unwrap(),
        );
        let invocation = Invocation::parse(
            ["tunnel", "diag", "--no-diag-logs", "--no-diag-network"].map(str::to_owned),
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        let (files, failures) = collect(&collector, &invocation).await;
        assert_eq!(failures.len(), 2);
        assert!(failures.contains(&"heap profile".to_string()));
        assert!(failures.contains(&"goroutine profile".to_string()));
        assert_eq!(files["metrics.txt"], b"real_metrics 1\n");
        assert!(!files.contains_key("heap.pprof"));
        let report: Value = serde_json::from_slice(&files["task-result.json"]).unwrap();
        assert_eq!(report["metrics"]["result"], "success");
        assert_eq!(report["heap profile"]["result"], "failure");
        cancel.cancel();
        server.await.unwrap();
    }
    #[test]
    fn archive_is_valid_private_and_no_clobber() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("cloudflared-bundle-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = write_archive(
            &dir,
            "bundle.zip",
            BTreeMap::from([
                ("metrics.txt".into(), b"real_metrics 1\n".to_vec()),
                ("task-result.json".into(), b"{}".to_vec()),
            ]),
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut archive = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(archive.len(), 2);
        let mut body = String::new();
        std::io::Read::read_to_string(&mut archive.by_name("metrics.txt").unwrap(), &mut body)
            .unwrap();
        assert_eq!(body, "real_metrics 1\n");
        assert!(write_archive(&dir, "bundle.zip", BTreeMap::new()).is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
