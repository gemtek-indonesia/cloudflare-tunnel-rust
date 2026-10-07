use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::Full;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("admin-execution-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("config.yml"), b"{}\n").unwrap();
        std::fs::write(path.join("empty.pem"), b"").unwrap();
        let token = STANDARD.encode(serde_json::to_vec(&json!({"accountID":"synthetic-account","zoneID":"synthetic-zone","apiToken":"synthetic-token"})).unwrap());
        std::fs::write(
            path.join("cert.pem"),
            format!(
                "-----BEGIN ARGO TUNNEL TOKEN-----\n{token}\n-----END ARGO TUNNEL TOKEN-----\n"
            ),
        )
        .unwrap();
        Self(path)
    }
    fn command(&self, binary: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("HOME", &self.0)
            .env("TZ", "UTC")
            .env("SSL_CERT_FILE", self.0.join("empty.pem"))
            .env("SSL_CERT_DIR", self.0.join("missing"));
        command
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

async fn execute(
    directory: &Directory,
    command: &str,
    args: &[String],
    pages: Vec<Value>,
) -> (std::process::Output, Vec<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let pages = Arc::new(pages);
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let captured = captured.clone();
            let pages = pages.clone();
            connections.spawn(async move {
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| {
                        let captured = captured.clone();
                        let pages = pages.clone();
                        async move {
                            assert_eq!(
                                request.headers()[http::header::AUTHORIZATION],
                                "Bearer synthetic-token"
                            );
                            let mut requests = captured.lock().unwrap();
                            let index = requests.len();
                            requests.push(format!("{} {}", request.method(), request.uri()));
                            let page = pages
                                .get(index)
                                .cloned()
                                .unwrap_or(json!({"success":false}));
                            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                                Bytes::from(serde_json::to_vec(&page).unwrap()),
                            )))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let words = match command {
        "list" => vec!["tunnel", "list"],
        "info" => vec!["tunnel", "info"],
        "vnets" => vec!["tunnel", "vnet", "list"],
        "routes" => vec!["tunnel", "route", "ip", "show"],
        _ => unreachable!(),
    };
    let output = directory
        .command(env!("CARGO_BIN_EXE_cloudflared"))
        .arg("--config")
        .arg(directory.0.join("config.yml"))
        .arg("--origincert")
        .arg(directory.0.join("cert.pem"))
        .arg("--api-url")
        .arg(format!("http://{address}/client/v4"))
        .args(words)
        .args(args)
        .output()
        .unwrap();
    server.abort();
    let _ = server.await;
    let requests = requests.lock().unwrap().clone();
    (output, requests)
}

fn page(rows: Value) -> Value {
    let count = rows.as_array().map_or(0, Vec::len);
    json!({"success":true,"result":rows,"result_info":{"count":count,"per_page":20,"total_count":count}})
}

fn sort_logs(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter_map(|line| {
            let start = line.find("invalid-sort is not a valid sort field.")?;
            let end = line[start..].find("Defaulting to 'name'.")?
                + start
                + "Defaulting to 'name'.".len();
            Some(&line[start..end])
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_sort_logs_only_after_comparison_and_redacts_credentials() {
    let directory = Directory::new();
    for count in 0..=2 {
        let rows: Vec<_> = (0..count)
            .map(|index| json!({"name":format!("fixture-{index}")}))
            .collect();
        let args = ["--sort-by", "synthetic-token", "--output", "json"].map(str::to_owned);
        let (output, requests) = execute(&directory, "list", &args, vec![page(json!(rows))]).await;
        assert!(output.status.success());
        assert_eq!(requests.len(), 1);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains("synthetic-token"));
        assert_eq!(
            stderr.contains("[redacted] is not a valid sort field."),
            count >= 2
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn collection_rows_require_objects_before_followup_requests() {
    let directory = Directory::new();
    for command in ["list", "routes", "vnets", "info"] {
        let mut args = vec!["--output".into(), "json".into()];
        if command == "info" {
            args.push("11111111-1111-1111-1111-111111111111".into());
        }
        let (output, requests) = execute(&directory, command, &args, vec![page(json!([[]]))]).await;
        assert!(!output.status.success());
        assert_eq!(requests.len(), 1);
        assert!(output.stdout.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pinned Go administration oracle; run scripts/test-interop.sh"]
async fn go_administration_execution_contract() {
    let directory = Directory::new();
    let id = "11111111-1111-1111-1111-111111111111";
    let mut cases: Vec<(&str, Vec<String>, Vec<Value>, &str)> = Vec::new();
    for command in ["list", "info"] {
        for count in 0..=3 {
            for format in ["json", "yaml", ""] {
                for level in ["error", "fatal"] {
                    let rows: Vec<_> = (0..count).map(|index| json!({"name":format!("fixture-{}", 3-index),"version":format!("v{index}"),"created_at":"2026-01-01T00:00:00Z","run_at":"2026-01-01T00:00:00Z","conns":[{"colo_name":"test-a","origin_ip":"192.0.2.1"}]})).collect();
                    let mut args = vec![
                        "--sort-by".into(),
                        "invalid-sort".into(),
                        "--loglevel".into(),
                        level.into(),
                        "--invert-sort".into(),
                    ];
                    if !format.is_empty() {
                        args.extend(["--output".into(), format.into()]);
                    }
                    let mut pages = vec![page(json!(rows))];
                    if command == "info" {
                        args.push(id.into());
                        pages.push(page(
                            json!([{"id":id,"name":"fixture","created_at":"2026-01-01T00:00:00Z"}]),
                        ));
                    }
                    cases.push((command, args, pages, format));
                }
            }
        }
    }
    for command in ["list", "routes", "vnets"] {
        let row = match command {
            "routes" => json!({"network":"192.0.2.129/24","comment":"fixture"}),
            _ => json!({"name":"fixture"}),
        };
        for format in ["json", "yaml", "", "default", "JSON"] {
            let mut args = vec!["--loglevel".into(), "fatal".into()];
            if !format.is_empty() {
                args.extend(["--output".into(), format.into()]);
            }
            cases.push((command, args, vec![page(json!([row.clone()]))], format));
        }
    }
    for command in ["list", "routes", "vnets", "info"] {
        for rows in [
            json!([[]]),
            json!([{"id":"invalid"}]),
            json!([{"created_at":"invalid","run_at":"invalid"}]),
            json!(null),
        ] {
            let mut args = vec![
                "--loglevel".into(),
                "fatal".into(),
                "--output".into(),
                "json".into(),
            ];
            let mut pages = vec![page(rows)];
            if command == "info" {
                args.push(id.into());
                pages.push(page(
                    json!([{"id":id,"name":"fixture","created_at":"2026-01-01T00:00:00Z"}]),
                ));
            }
            cases.push((command, args, pages, "json"));
        }
    }
    for (index, (command, args, pages, format)) in cases.into_iter().enumerate() {
        let input = directory.0.join("input.json");
        let level = args
            .windows(2)
            .find(|pair| pair[0] == "--loglevel")
            .unwrap()[1]
            .clone();
        let source_args: Vec<_> = args
            .chunks(2)
            .filter(|pair| pair[0] != "--loglevel")
            .flatten()
            .cloned()
            .collect();
        std::fs::write(
            &input,
            serde_json::to_vec(&json!({"command":command,"args":source_args,"parent_args":["--loglevel",level],"pages":pages})).unwrap(),
        )
        .unwrap();
        let source = directory
            .command(
                std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE")
                    .expect("run scripts/test-interop.sh"),
            )
            .arg(input)
            .output()
            .unwrap();
        assert!(source.status.success(), "oracle case{index}");
        let source: Value = serde_json::from_slice(&source.stdout).unwrap();
        let (native, requests) = execute(&directory, command, &args, pages).await;
        assert_eq!(json!(requests), source["requests"], "requests case{index}");
        assert_eq!(
            !native.status.success(),
            source["failure"].as_bool().unwrap(),
            "exit case{index}"
        );
        let stdout = String::from_utf8(native.stdout).unwrap();
        let stderr = String::from_utf8(native.stderr).unwrap();
        assert_eq!(
            sort_logs(&stderr),
            sort_logs(source["stderr"].as_str().unwrap()),
            "stderr case{index}"
        );
        if format == "yaml" && native.status.success() {
            assert_eq!(
                serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&stdout).unwrap(),
                serde_yaml_ng::from_str::<serde_yaml_ng::Value>(source["output"].as_str().unwrap())
                    .unwrap(),
                "yaml case{index}"
            );
        } else {
            assert_eq!(
                stdout,
                source["output"].as_str().unwrap(),
                "stdout case{index}"
            );
        }
        if native.status.success() && sort_logs(&stderr).is_empty() {
            assert!(stderr.is_empty(), "unexpected native stderr case{index}");
        }
    }
}
