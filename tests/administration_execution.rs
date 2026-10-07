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
    statuses: &[u16],
) -> (std::process::Output, Vec<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let pages = Arc::new(pages);
    let statuses = Arc::new(statuses.to_vec());
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let captured = captured.clone();
            let pages = pages.clone();
            let statuses = statuses.clone();
            connections.spawn(async move {
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| {
                        let captured = captured.clone();
                        let pages = pages.clone();
                        let statuses = statuses.clone();
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
                            Ok::<_, std::convert::Infallible>(
                                http::Response::builder()
                                    .status(statuses.get(index).copied().unwrap_or(200))
                                    .body(Full::new(Bytes::from(
                                        serde_json::to_vec(&page).unwrap(),
                                    )))
                                    .unwrap(),
                            )
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
        "delete" => vec!["tunnel", "delete"],
        "cleanup" => vec!["tunnel", "cleanup"],
        _ => unreachable!(),
    };
    let mut native = directory.command(env!("CARGO_BIN_EXE_cloudflared"));
    native
        .arg("--config")
        .arg(directory.0.join("config.yml"))
        .arg("--origincert")
        .arg(directory.0.join("cert.pem"))
        .arg("--api-url")
        .arg(format!("http://{address}/client/v4"))
        .args(words);
    if command == "delete" {
        native
            .arg("--credentials-file")
            .arg(directory.0.join("credentials.json"));
    }
    let output = native.args(args).output().unwrap();
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

struct BulkCase {
    args: Vec<String>,
    pages: Vec<Value>,
    statuses: Vec<u16>,
}

fn bulk_cases(command: &str) -> Vec<BulkCase> {
    let a = "11111111-1111-1111-1111-111111111111";
    let b = "22222222-2222-2222-2222-222222222222";
    let c = "33333333-3333-3333-3333-333333333333";
    let row = |id| json!({"id":id,"name":"fixture","deleted_at":"0001-01-01T00:00:00Z"});
    let success = || json!({"success":true});
    let error = || json!({"success":false,"errors":[{"code":1000,"message":"synthetic failure"}]});
    let mut cases = Vec::new();
    for (args, lookups, ids) in [
        (vec![a, b], vec![], vec![a, b]),
        (
            vec!["name-a", b, "name-c"],
            vec![page(json!([row(a)])), page(json!([row(c)]))],
            vec![b, a, c],
        ),
        (vec![a, a], vec![], vec![a, a]),
        (
            vec!["name-a", "name-a"],
            vec![page(json!([row(a)])), page(json!([row(a)]))],
            vec![a, a],
        ),
    ] {
        let mut pages = lookups;
        for id in ids {
            if command == "delete" {
                pages.push(json!({"success":true,"result":row(id)}));
            }
            pages.push(success());
        }
        cases.push(BulkCase {
            args: args.into_iter().map(str::to_owned).collect(),
            pages,
            statuses: vec![],
        });
    }
    for pages in [
        vec![page(json!([]))],
        vec![page(json!([row(a), row(c)]))],
        vec![page(json!([{"id":"invalid"}]))],
    ] {
        cases.push(BulkCase {
            args: vec![b.into(), "missing".into()],
            pages,
            statuses: vec![],
        });
    }
    cases.push(BulkCase {
        args: vec!["name-a".into(), b.into(), "missing".into()],
        pages: vec![page(json!([row(a)])), page(json!([]))],
        statuses: vec![],
    });
    cases.push(BulkCase {
        args: vec![b.into(), "name-a".into()],
        pages: vec![error()],
        statuses: vec![500],
    });
    let mut flagged = vec![page(json!([row(a)]))];
    for id in [b, a] {
        if command == "delete" {
            flagged.push(json!({"success":true,"result":row(id)}));
        }
        flagged.push(success());
    }
    let mut args = if command == "delete" {
        vec!["--force".into()]
    } else {
        vec!["--connector-id".into(), c.into()]
    };
    args.extend(["name-a".into(), b.into()]);
    cases.push(BulkCase {
        args,
        pages: flagged,
        statuses: vec![],
    });
    if command == "cleanup" {
        cases.push(BulkCase {
            args: vec![a.into(), b.into()],
            pages: vec![error(), success()],
            statuses: vec![500, 200],
        });
        cases.push(BulkCase {
            args: vec![
                "--connector-id".into(),
                "invalid".into(),
                b.into(),
                "name-a".into(),
            ],
            pages: vec![page(json!([row(a)]))],
            statuses: vec![],
        });
    } else {
        cases.push(BulkCase {
            args: vec![a.into(), b.into()],
            pages: vec![json!({"success":true,"result":row(a)}), error()],
            statuses: vec![200, 500],
        });
        cases.push(BulkCase {
            args: vec!["name-a".into(), b.into()],
            pages: vec![
                page(json!([row(a)])),
                json!({"success":true,"result":{"id":b,"deleted_at":"2026-01-01T00:00:00Z"}}),
            ],
            statuses: vec![],
        });
    }
    cases
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_resolution_errors_prevent_target_requests_and_mutations() {
    let directory = Directory::new();
    for command in ["delete", "cleanup"] {
        for name in ["missing", "synthetic-token"] {
            let args = [
                "--loglevel",
                "fatal",
                "22222222-2222-2222-2222-222222222222",
                name,
            ]
            .map(str::to_owned);
            let (output, requests) =
                execute(&directory, command, &args, vec![page(json!([]))], &[]).await;
            assert!(!output.status.success());
            assert_eq!(
                requests,
                [format!(
                    "GET /client/v4/accounts/synthetic-account/cfd_tunnel?is_deleted=false&name={name}&page=1"
                )]
            );
            assert!(output.stdout.is_empty());
            assert!(
                !String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("synthetic-token")
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pinned Go administration oracle; run scripts/test-interop.sh"]
async fn go_administration_bulk_resolution_contract() {
    let directory = Directory::new();
    for command in ["delete", "cleanup"] {
        for (index, case) in bulk_cases(command).into_iter().enumerate() {
            let file = directory.0.join("input.json");
            std::fs::write(&file, serde_json::to_vec(&json!({"command":command,"args":case.args,"parent_args":["--loglevel","fatal"],"pages":case.pages,"statuses":case.statuses})).unwrap()).unwrap();
            let source = directory
                .command(
                    std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE")
                        .expect("run scripts/test-interop.sh"),
                )
                .arg(file)
                .output()
                .unwrap();
            assert!(source.status.success(), "oracle {command} case{index}");
            let source: Value = serde_json::from_slice(&source.stdout).unwrap();
            let mut args = vec!["--loglevel".into(), "fatal".into()];
            args.extend(case.args);
            let (native, requests) =
                execute(&directory, command, &args, case.pages, &case.statuses).await;
            assert_eq!(
                json!(requests),
                source["requests"],
                "API order {command} case{index}"
            );
            assert_eq!(
                !native.status.success(),
                source["failure"].as_bool().unwrap(),
                "exit {command} case{index}"
            );
            assert_eq!(
                String::from_utf8(native.stdout).unwrap(),
                source["output"].as_str().unwrap(),
                "stdout {command} case{index}"
            );
            if native.status.success() {
                assert!(
                    native.stderr.is_empty(),
                    "fatal logger {command} case{index}"
                );
                assert_eq!(
                    source["stderr"], "",
                    "source fatal logger {command} case{index}"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_sort_logs_only_after_comparison_and_redacts_credentials() {
    let directory = Directory::new();
    for count in 0..=2 {
        let rows: Vec<_> = (0..count)
            .map(|index| json!({"name":format!("fixture-{index}")}))
            .collect();
        let args = ["--sort-by", "synthetic-token", "--output", "json"].map(str::to_owned);
        let (output, requests) =
            execute(&directory, "list", &args, vec![page(json!(rows))], &[]).await;
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
        let (output, requests) =
            execute(&directory, command, &args, vec![page(json!([[]]))], &[]).await;
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
        let (native, requests) = execute(&directory, command, &args, pages, &[]).await;
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
