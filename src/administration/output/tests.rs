use super::*;
use serde_json::{Value, json};

fn invocation(mode: &str, args: Vec<String>, config: &std::path::Path) -> Invocation {
    let mut command = vec![
        "tunnel".into(),
        "--config".into(),
        config.to_str().unwrap().into(),
    ];
    command.extend(
        match mode {
            "list" => vec!["list"],
            "vnets" => vec!["vnet", "list"],
            "routes" => vec!["route", "ip", "show"],
            "info" => vec!["info"],
            _ => unreachable!(),
        }
        .into_iter()
        .map(str::to_owned),
    );
    command.extend(args);
    Invocation::parse(command, &Default::default(), None).unwrap()
}

fn native(
    mode: &str,
    args: Vec<String>,
    pages: &[Value],
    config: &std::path::Path,
) -> Result<String> {
    let invocation = invocation(mode, args, config);
    let logger = Logger::new(
        crate::observability::logging::Options {
            disable_terminal: true,
            ..Default::default()
        },
        vec![],
    )?;
    match mode {
        "list" => tunnels(
            &invocation,
            tunnel_rows(pages[0]["result"].as_array().unwrap().clone())?,
            &logger,
        ),
        "vnets" => vnets(&invocation, &pages[0]["result"]),
        "routes" => routes(&invocation, &pages[0]["result"]),
        "info" => {
            let mut value: Info = serde_json::from_value(
                json!({"id":pages[1]["result"][0]["id"],"name":pages[1]["result"][0]["name"],"createdAt":pages[1]["result"][0]["created_at"],"conns":pages[0]["result"]}),
            )?;
            if let Some(clients) = &mut value.conns {
                sort_clients(&invocation, clients, &logger);
            }
            info(&invocation, &value)
        }
        _ => unreachable!(),
    }
}

#[test]
fn typed_tunnel_json_keeps_zero_fields_null_slices_and_html_escaping() {
    let rows = tunnel_rows(vec![json!({"name":"<&>","ignored":"not emitted"})]).unwrap();
    let encoded = json(&rows).unwrap();
    assert!(encoded.contains("\\u003c\\u0026\\u003e"));
    assert!(encoded.contains("00000000-0000-0000-0000-000000000000"));
    assert!(encoded.contains("0001-01-01T00:00:00Z"));
    assert!(encoded.contains("\"connections\": null"));
    assert!(!encoded.contains("ignored"));
}

fn token_cases() -> Vec<String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut cases: Vec<String> = [
        "{}", "null", "[]", "{\"s\":null}", "{\"s\":\"\"}", "{\"ſ\":\"AQ==\"}",
        "{\"s\":[0,255]}", "{\"s\":\"AB==\"}", "{\"s\":\"AA\\r\\n==\"}",
        "{\"A\":\"upper\",\"S\":\"AA==\",\"T\":\"11111111-1111-1111-1111-111111111111\",\"E\":\"fed\"}",
        "{\"a\":\"<&>\u{2028}\u{2029}\",\"e\":\"<&>\u{2028}\u{2029}\"}",
        "{\"z\":1,\"e\":\"\",\"t\":\"11111111-1111-1111-1111-111111111111\",\"s\":\"AA==\",\"a\":\"fixture\"}",
        "{\"a\":\"first\",\"a\":null,\"e\":\"fed\",\"e\":null,\"t\":\"11111111-1111-1111-1111-111111111111\",\"t\":null}",
        "{\"a\":\"first\",\"a\":\"last\",\"s\":\"AA==\",\"s\":null}",
        "{\"s\":[256]}", "{\"s\":[1.0]}", "{\"s\":false}", "{\"s\":\"A A==\"}",
        "{\"t\":\"invalid\"}", "{\"t\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}",
        "{\"a\":1}", "{\"e\":false}", "true", "{", "\"string\"",
    ].into_iter().map(|value| STANDARD.encode(value)).collect();
    cases.extend(
        [
            "e30=",
            "e31=",
            "e30",
            "e30==",
            "e3\r\n0=",
            "e3 0=",
            "e3\t0=",
            "bnVsbA==",
            "bnVsbB==",
            "bnVsbA",
            "bnVsbA===",
            "-___",
        ]
        .map(str::to_owned),
    );
    cases
}

#[test]
fn api_token_encoding_preserves_source_data_without_runtime_admission() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let token = ApiTunnelToken::parse("e31=").unwrap();
    let encoded = token.encode().unwrap();
    assert_eq!(
        STANDARD.decode(&encoded).unwrap(),
        br#"{"a":"","s":null,"t":"00000000-0000-0000-0000-000000000000"}"#
    );
    assert!(crate::config::credentials_from_token(&encoded).is_err());
    let token = ApiTunnelToken::parse(
        &STANDARD.encode("{\"a\":\"first\",\"a\":null,\"s\":\"\",\"e\":\"<&>\u{2028}\"}"),
    )
    .unwrap();
    let encoded = String::from_utf8(STANDARD.decode(token.encode().unwrap()).unwrap()).unwrap();
    assert!(encoded.contains("\"a\":\"first\""));
    assert!(encoded.contains("\"s\":\"\""));
    assert!(encoded.contains("<&>\u{2028}"));
    assert!(
        token
            .credentials()
            .unwrap()
            .contains("\\u003c\\u0026\\u003e\\u2028")
    );
}

#[test]
#[ignore = "requires pinned Go administration oracle; run scripts/test-interop.sh"]
fn go_administration_token_codec_contract() {
    let directory = std::env::temp_dir().join(format!("token-codec-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    for (index, encoded) in token_cases().into_iter().enumerate() {
        let file = directory.join("input.json");
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({"command":"token-codec","args":[encoded]})).unwrap(),
        )
        .unwrap();
        let output = std::process::Command::new(
            std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE").expect("run scripts/test-interop.sh"),
        )
        .arg(file)
        .env_clear()
        .output()
        .unwrap();
        assert!(output.status.success(), "oracle token case{index}");
        let source: Value = serde_json::from_slice(&output.stdout).unwrap();
        let native = ApiTunnelToken::parse(&encoded);
        assert_eq!(
            native.is_err(),
            source["failure"].as_bool().unwrap(),
            "token case{index}"
        );
        if let Ok(token) = native {
            assert_eq!(
                token.encode().unwrap(),
                source["output"],
                "canonical token case{index}"
            );
            assert_eq!(
                token.credentials().unwrap(),
                source["credentials"],
                "credential bytes case{index}"
            );
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires pinned Go administration oracle; run scripts/test-interop.sh"]
fn go_administration_output_contract() {
    let directory =
        std::env::temp_dir().join(format!("admin-output-oracle-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let config = directory.join("config.yml");
    std::fs::write(&config, b"{}").unwrap();
    let empty = directory.join("empty.pem");
    std::fs::write(&empty, b"").unwrap();
    let tunnels_data = json!([{"id":"11111111-1111-1111-1111-111111111111","name":"beta <&>","created_at":"2026-01-01T01:00:00.1+02:00","connections":[]},{"id":"22222222-2222-2222-2222-222222222222","name":"alpha","created_at":"2025-12-31T23:30:00Z","connections":[{"id":"33333333-3333-3333-3333-333333333333","colo_name":"test-a","origin_ip":"::ffff:192.0.2.1","opened_at":"2026-01-01T00:00:00Z"}]}]);
    let datasets = vec![
        ("list", tunnels_data),
        ("list", json!([{"name":"missing-fields"}])),
        ("list", json!([])),
        ("vnets", json!([{"name":"missing-fields"}])),
        ("vnets", json!([])),
        (
            "routes",
            json!([{"network":"192.0.2.129/24","tunnel_id":"11111111-1111-1111-1111-111111111111","tunnel_name":"fixture"}]),
        ),
        ("routes", json!([])),
        (
            "info",
            json!([{"id":"22222222-2222-2222-2222-222222222222","features":null,"arch":"synthetic","version":"1","run_at":"2026-01-01T00:00:00Z","conns":[{"colo_name":"test-a","origin_ip":"192.0.2.1"}]}]),
        ),
        ("info", json!([])),
    ];
    for (index, (mode, data)) in datasets.into_iter().enumerate() {
        for format in ["json", "yaml", "", "default", "JSON", "invalid"] {
            let mut args = if format.is_empty() {
                vec![]
            } else {
                vec!["--output".to_owned(), format.to_owned()]
            };
            if mode == "list" {
                args.extend(["--sort-by".into(), "createdAt".into()]);
            }
            if mode == "info" {
                args.push("11111111-1111-1111-1111-111111111111".into());
            }
            let mut pages = vec![
                json!({"success":true,"result":data,"result_info":{"count":data.as_array().unwrap().len(),"per_page":20,"total_count":data.as_array().unwrap().len()}}),
            ];
            if mode == "info" {
                pages.push(json!({"success":true,"result":[{"id":"11111111-1111-1111-1111-111111111111","name":"fixture","created_at":"2026-01-01T00:00:00Z"}],"result_info":{"count":1,"per_page":20,"total_count":1}}));
            }
            let file = directory.join("input.json");
            std::fs::write(
                &file,
                serde_json::to_vec(&json!({"command":mode,"args":args,"pages":pages})).unwrap(),
            )
            .unwrap();
            let output = std::process::Command::new(
                std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE")
                    .expect("run scripts/test-interop.sh"),
            )
            .arg(&file)
            .env_clear()
            .env("HOME", &directory)
            .env("SSL_CERT_FILE", &empty)
            .env("SSL_CERT_DIR", directory.join("missing"))
            .env("TZ", "UTC")
            .output()
            .unwrap();
            assert!(output.status.success());
            let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
            let actual = native(mode, args, &pages, &config);
            assert_eq!(
                actual.is_err(),
                expected["failure"].as_bool().unwrap(),
                "case{index}/{format}"
            );
            if let Ok(actual) = actual {
                let wanted = expected["output"].as_str().unwrap();
                if format == "yaml" {
                    assert_eq!(
                        serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&actual).unwrap(),
                        serde_yaml_ng::from_str::<serde_yaml_ng::Value>(wanted).unwrap(),
                        "case{index}/{format}"
                    );
                } else {
                    assert_eq!(actual, wanted, "case{index}/{format}");
                }
            }
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}
