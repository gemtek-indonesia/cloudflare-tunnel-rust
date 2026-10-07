use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
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
    let (output, requests, _) =
        execute_with_bodies(directory, command, args, pages, statuses).await;
    (output, requests)
}

async fn execute_with_bodies(
    directory: &Directory,
    command: &str,
    args: &[String],
    pages: Vec<Value>,
    statuses: &[u16],
) -> (std::process::Output, Vec<String>, Vec<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let captured_bodies = bodies.clone();
    let pages = Arc::new(pages);
    let statuses = Arc::new(statuses.to_vec());
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let captured = captured.clone();
            let captured_bodies = captured_bodies.clone();
            let pages = pages.clone();
            let statuses = statuses.clone();
            connections.spawn(async move {
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| {
                        let captured = captured.clone();
                        let captured_bodies = captured_bodies.clone();
                        let pages = pages.clone();
                        let statuses = statuses.clone();
                        async move {
                            assert_eq!(
                                request.headers()[http::header::AUTHORIZATION],
                                "Bearer synthetic-token"
                            );
                            let method_uri = format!("{} {}", request.method(), request.uri());
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            captured_bodies
                                .lock()
                                .unwrap()
                                .push(String::from_utf8(body.to_vec()).unwrap());
                            let mut requests = captured.lock().unwrap();
                            let index = requests.len();
                            requests.push(method_uri);
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
        "token" => vec!["tunnel", "token"],
        "create" => vec!["tunnel", "create"],
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
    let bodies = bodies.lock().unwrap().clone();
    (output, requests, bodies)
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
async fn malformed_api_token_errors_hide_payload_and_extra_arguments_make_no_request() {
    let directory = Directory::new();
    let id = "11111111-1111-1111-1111-111111111111";
    let (output, requests) = execute(
        &directory,
        "token",
        &[id.into()],
        vec![json!({"success":true,"result":"DO-NOT-ECHO-TOKEN"})],
        &[],
    )
    .await;
    assert_eq!(requests.len(), 1);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("DO-NOT-ECHO-TOKEN")
    );
    let (output, requests) = execute(
        &directory,
        "token",
        &[id.into(), "extra".into()],
        vec![],
        &[],
    )
    .await;
    assert_eq!(output.status.code(), Some(255));
    assert!(requests.is_empty());
}

struct CreateCase {
    args: Vec<String>,
    mode: &'static str,
    pages: Vec<Value>,
    statuses: Vec<u16>,
}

fn create_cases() -> Vec<CreateCase> {
    let id = "11111111-1111-1111-1111-111111111111";
    let secret = STANDARD.encode([b'x'; 32]);
    let row = json!({"id":id,"name":"returned","token":"synthetic-output-token"});
    let response = |row| json!({"success":true,"result":row});
    let error = json!({"success":false,"errors":[{"code":1000,"message":format!("synthetic failure {secret} synthetic-token")}]});
    let mut cases = Vec::new();
    for value in [
        row.clone(),
        json!({"id":id,"name":"<&>\u{2028}","token":"<&>\u{2029}","created_at":"2026-10-07T01:02:03.123456789+02:00","connections":[{"id":id,"colo_name":"fixture","origin_ip":"192.0.2.1","opened_at":"2026-10-07T01:02:03Z"}],"unknown":"discard"}),
    ] {
        for format in ["", "json", "yaml", "invalid-format"] {
            for mode in ["", "absent"] {
                let mut args = vec!["--secret".into(), secret.clone()];
                if !format.is_empty() {
                    args.extend(["--output".into(), format.into()]);
                }
                args.push("requested".into());
                cases.push(CreateCase {
                    args,
                    mode,
                    pages: vec![response(value.clone())],
                    statuses: vec![],
                });
            }
        }
    }
    for mode in ["existing", "missing-parent", "directory"] {
        for rollback_error in [false, true] {
            cases.push(CreateCase {
                args: vec!["--secret".into(), secret.clone(), "requested".into()],
                mode,
                pages: vec![
                    response(row.clone()),
                    if rollback_error {
                        error.clone()
                    } else {
                        json!({"success":true})
                    },
                ],
                statuses: vec![200, if rollback_error { 500 } else { 200 }],
            });
        }
    }
    for (value, status) in [
        (error, 500),
        (json!({"success":false}), 409),
        (
            response(json!({"id":"DO-NOT-ECHO-ID","name":"returned"})),
            200,
        ),
    ] {
        cases.push(CreateCase {
            args: vec!["--secret".into(), secret.clone(), "requested".into()],
            mode: "absent",
            pages: vec![value],
            statuses: vec![status],
        });
    }
    for encoded in [
        secret.replace('=', "\r\n="),
        secret.replace("Hg=", "Hh="),
        STANDARD.encode([b'x'; 31]),
        "DO-NOT-ECHO-SECRET".into(),
        secret.replace('=', ""),
    ] {
        cases.push(CreateCase {
            args: vec!["--secret".into(), encoded, "requested".into()],
            mode: "absent",
            pages: vec![response(row.clone())],
            statuses: vec![],
        });
    }
    for names in [vec![], vec!["requested", "extra"], vec![id], vec![""]] {
        let mut args = vec!["--secret".into(), secret.clone()];
        args.extend(names.into_iter().map(str::to_owned));
        cases.push(CreateCase {
            args,
            mode: "absent",
            pages: vec![],
            statuses: vec![],
        });
    }
    cases
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pinned Go administration oracle; run scripts/test-interop.sh"]
async fn go_administration_create_execution_contract() {
    use std::os::unix::fs::PermissionsExt;
    for (index, case) in create_cases().into_iter().enumerate() {
        let directory = Directory::new();
        let credential = directory.0.join(match case.mode {
            "" => "11111111-1111-1111-1111-111111111111.json",
            "missing-parent" => "missing/credentials.json",
            _ => "credentials.json",
        });
        match case.mode {
            "existing" => {
                std::fs::write(&credential, b"preserved").unwrap();
                std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o400))
                    .unwrap();
            }
            "directory" => std::fs::create_dir(&credential).unwrap(),
            _ => {}
        }
        let input = directory.0.join("input.json");
        std::fs::write(&input, serde_json::to_vec(&json!({"command":"create","args":case.args,"pages":case.pages,"statuses":case.statuses,"file_mode":case.mode})).unwrap()).unwrap();
        let source = directory
            .command(
                std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE")
                    .expect("run scripts/test-interop.sh"),
            )
            .arg(input)
            .output()
            .unwrap();
        assert!(
            source.status.success(),
            "create source {index}: {}",
            String::from_utf8_lossy(&source.stderr)
        );
        let source: Value = serde_json::from_slice(&source.stdout).unwrap();
        let mut args = vec!["--loglevel".into(), "fatal".into()];
        if !case.mode.is_empty() {
            args.extend([
                "--credentials-file".into(),
                credential.to_str().unwrap().into(),
            ]);
        }
        args.extend(case.args);
        let (native, requests, bodies) =
            execute_with_bodies(&directory, "create", &args, case.pages, &case.statuses).await;
        assert_eq!(
            json!(requests),
            source["requests"],
            "create requests {index}"
        );
        let decoded = |bodies: Vec<String>| {
            bodies
                .into_iter()
                .map(|body| {
                    if body.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_str(&body).unwrap()
                    }
                })
                .collect::<Vec<_>>()
        };
        let source_bodies: Vec<String> = serde_json::from_value(source["bodies"].clone()).unwrap();
        assert_eq!(
            decoded(bodies),
            decoded(source_bodies),
            "create bodies {index}"
        );
        assert_eq!(
            native.status.code().unwrap(),
            source["exit_code"].as_i64().unwrap() as i32,
            "create exit {index}: {}",
            String::from_utf8_lossy(&native.stderr)
        );
        let stdout = String::from_utf8(native.stdout)
            .unwrap()
            .replace(directory.0.to_str().unwrap(), "<directory>");
        if args.iter().any(|arg| arg == "yaml") && native.status.success() {
            assert_eq!(
                serde_yaml_ng::from_str::<Value>(&stdout).unwrap(),
                serde_yaml_ng::from_str::<Value>(source["output"].as_str().unwrap()).unwrap(),
                "create yaml {index}"
            );
        } else {
            assert_eq!(stdout, source["output"], "create stdout {index}");
        }
        let stderr = String::from_utf8(native.stderr).unwrap();
        for secret in [
            STANDARD.encode([b'x'; 32]),
            "synthetic-token".into(),
            "DO-NOT-ECHO-SECRET".into(),
            "DO-NOT-ECHO-ID".into(),
        ] {
            assert!(
                !stderr.contains(&secret),
                "create diagnostic leaked synthetic credential {index}"
            );
        }
        if source["error"]
            .as_str()
            .unwrap()
            .contains("synthetic failure")
        {
            assert!(stderr.contains("synthetic failure"));
            assert!(stderr.contains("[redacted]"));
        }
        if requests.len() == 2 {
            assert!(requests[1].ends_with("?cascade=true"));
            assert!(stderr.contains("Your tunnel 'returned' was created with ID"));
            assert_eq!(
                stderr.contains("The tunnel was deleted"),
                case.statuses[1] == 200
            );
            assert_eq!(
                stderr.contains("The delete tunnel error is:"),
                case.statuses[1] != 200
            );
        }
        assert_eq!(
            credential.is_file(),
            source["file_exists"].as_bool().unwrap(),
            "create file {index}"
        );
        if credential.is_file() {
            assert_eq!(
                std::fs::read_to_string(&credential).unwrap(),
                source["credentials"],
                "create credential bytes {index}"
            );
            assert_eq!(
                std::fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
                source["file_perm"].as_u64().unwrap() as u32,
                "create credential mode {index}"
            );
        }
        assert_eq!(
            std::fs::read_dir(&directory.0).unwrap().count(),
            4 + usize::from(credential.exists()),
            "create temporary files {index}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_generated_secret_owns_file_and_api_identity() {
    let directory = Directory::new();
    let id = "11111111-1111-1111-1111-111111111111";
    let (output, requests, bodies) = execute_with_bodies(
        &directory,
        "create",
        &["requested".into()],
        vec![json!({"success":true,"result":{"id":id,"name":"returned"}})],
        &[],
    )
    .await;
    assert!(output.status.success());
    assert_eq!(
        requests,
        ["POST /client/v4/accounts/synthetic-account/cfd_tunnel"]
    );
    let body: Value = serde_json::from_str(&bodies[0]).unwrap();
    let secret = body["tunnel_secret"].as_str().unwrap();
    assert_eq!(STANDARD.decode(secret).unwrap().len(), 32);
    let file: Value =
        serde_json::from_slice(&std::fs::read(directory.0.join(format!("{id}.json"))).unwrap())
            .unwrap();
    assert_eq!(file["TunnelSecret"], secret);
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Created tunnel returned")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_invalid_output_format_redacts_known_credentials_after_private_write() {
    use std::os::unix::fs::PermissionsExt;
    let id = "11111111-1111-1111-1111-111111111111";
    let secret = STANDARD.encode([b'x'; 32]);
    for format in ["synthetic-token".to_owned(), secret.clone()] {
        let directory = Directory::new();
        let args = vec![
            "--secret".into(),
            secret.clone(),
            "--output".into(),
            format.clone(),
            "requested".into(),
        ];
        let (output, requests) = execute(
            &directory,
            "create",
            &args,
            vec![json!({"success":true,"result":{"id":id,"name":"returned"}})],
            &[],
        )
        .await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            requests,
            ["POST /client/v4/accounts/synthetic-account/cfd_tunnel"]
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("Unknown output format '[redacted]'"));
        assert!(!stderr.contains(&format));
        let file = directory.0.join(format!("{id}.json"));
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o400
        );
        let credentials: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        assert_eq!(credentials["TunnelSecret"], secret);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pinned Go administration oracle; run scripts/test-interop.sh"]
async fn go_administration_token_execution_contract() {
    use std::os::unix::fs::PermissionsExt;
    let directory = Directory::new();
    let id = "11111111-1111-1111-1111-111111111111";
    let mut tokens: Vec<String> = [
        "{}", "null", "{\"s\":null}", "{\"s\":\"\"}",
        "{\"s\":[0,255],\"a\":\"fixture\",\"t\":\"11111111-1111-1111-1111-111111111111\"}",
        "{\"a\":\"first\",\"a\":null,\"s\":\"AA==\",\"s\":null,\"e\":\"fed\"}",
        "{\"a\":\"<&>\u{2028}\u{2029}\",\"s\":\"AB==\",\"t\":\"11111111-1111-1111-1111-111111111111\",\"e\":\"\"}",
        "{\"z\":1,\"A\":\"upper\",\"S\":\"AA\\r\\n==\",\"T\":\"11111111-1111-1111-1111-111111111111\",\"E\":\"fed\"}",
        "[]", "{\"s\":false}", "{\"t\":\"invalid\"}",
    ].into_iter().map(|value| STANDARD.encode(value)).collect();
    tokens.extend(["e31=", "e3\r\n0=", "e30", "e3 0=", "DO-NOT-ECHO-TOKEN"].map(str::to_owned));
    for (index, token) in tokens.into_iter().enumerate() {
        for mode in ["", "absent", "existing", "missing-parent", "directory"] {
            let credential = if mode == "missing-parent" {
                directory.0.join("missing/credentials.json")
            } else {
                directory.0.join("credentials.json")
            };
            match mode {
                "existing" => {
                    std::fs::write(&credential, b"preserved").unwrap();
                    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o400))
                        .unwrap();
                }
                "directory" => std::fs::create_dir(&credential).unwrap(),
                _ => {}
            }
            let pages = vec![json!({"success":true,"result":token})];
            let input = directory.0.join("input.json");
            std::fs::write(&input, serde_json::to_vec(&json!({"command":"token","args":[id],"parent_args":["--loglevel","fatal"],"pages":pages,"file_mode":mode})).unwrap()).unwrap();
            let source = directory
                .command(
                    std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE")
                        .expect("run scripts/test-interop.sh"),
                )
                .arg(input)
                .output()
                .unwrap();
            assert!(source.status.success());
            let source: Value = serde_json::from_slice(&source.stdout).unwrap();
            let mut args = vec!["--loglevel".into(), "fatal".into()];
            if !mode.is_empty() {
                args.extend([
                    "--credentials-file".into(),
                    credential.to_str().unwrap().into(),
                ]);
            }
            args.push(id.into());
            let (native, requests) = execute(&directory, "token", &args, pages, &[]).await;
            assert_eq!(
                json!(requests),
                source["requests"],
                "token requests {index}/{mode}"
            );
            assert_eq!(
                native.status.code().unwrap(),
                source["exit_code"].as_i64().unwrap() as i32,
                "token exit {index}/{mode}"
            );
            assert_eq!(
                String::from_utf8(native.stdout).unwrap(),
                source["output"],
                "token stdout {index}/{mode}"
            );
            let exists = credential.is_file();
            assert_eq!(
                exists,
                source["file_exists"].as_bool().unwrap(),
                "token file {index}/{mode}"
            );
            if exists {
                assert_eq!(
                    std::fs::read_to_string(&credential).unwrap(),
                    source["credentials"],
                    "credential bytes {index}/{mode}"
                );
                assert_eq!(
                    std::fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
                    source["file_perm"].as_u64().unwrap() as u32,
                    "credential mode {index}/{mode}"
                );
                std::fs::remove_file(&credential).unwrap();
            } else if credential.is_dir() {
                std::fs::remove_dir(&credential).unwrap();
            }
        }
    }
    for args in [vec![], vec![id, "extra"]] {
        let file = directory.0.join("input.json");
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({"command":"token","args":args,"pages":[]})).unwrap(),
        )
        .unwrap();
        let source = directory
            .command(
                std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE")
                    .expect("run scripts/test-interop.sh"),
            )
            .arg(file)
            .output()
            .unwrap();
        let source: Value = serde_json::from_slice(&source.stdout).unwrap();
        let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        let (native, requests) = execute(&directory, "token", &args, vec![], &[]).await;
        assert_eq!(json!(requests), source["requests"]);
        assert_eq!(
            native.status.code().unwrap(),
            source["exit_code"].as_i64().unwrap() as i32
        );
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
