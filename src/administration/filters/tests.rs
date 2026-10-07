use super::*;
use serde_json::json;

fn invocation(
    mode: &str,
    parent: &[&str],
    arguments: &[&str],
    config: &std::path::Path,
) -> Result<Invocation> {
    let mut values = vec![
        "tunnel".to_owned(),
        "--config".into(),
        config.to_str().unwrap().into(),
    ];
    values.extend(parent.iter().map(|value| value.to_string()));
    values.extend(
        match mode {
            "list" => vec!["list"],
            "routes" => vec!["route", "ip", "show"],
            "vnets" => vec!["vnet", "list"],
            _ => unreachable!(),
        }
        .into_iter()
        .map(str::to_owned),
    );
    values.extend(arguments.iter().map(|value| value.to_string()));
    Invocation::parse(values, &Default::default(), None)
}

fn query(mode: &str, invocation: &Invocation) -> Result<Query> {
    match mode {
        "list" => tunnels(invocation),
        "routes" => routes(invocation),
        "vnets" => vnets(invocation),
        _ => unreachable!(),
    }
}

#[test]
fn canonical_route_filters_replace_prior_values_and_keep_explicit_false() {
    let directory = std::env::temp_dir().join(format!("admin-filter-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let config = directory.join("config.yml");
    std::fs::write(&config, b"{}").unwrap();
    let input = invocation(
        "routes",
        &["--max-fetch-size", "7"],
        &[
            "--nsub",
            "::ffff:192.0.2.129/120",
            "--nsup",
            "198.51.100.123/24",
            "--filter-tunnel-id",
            "{11111111-1111-1111-1111-111111111111}",
        ],
        &config,
    )
    .unwrap();
    let actual = routes(&input)
        .unwrap()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(actual["network_superset"], "198.51.100.0/24");
    assert_eq!(actual["tunnel_id"], "11111111-1111-1111-1111-111111111111");
    assert_eq!(actual["per_page"], "7");
    let input = invocation("vnets", &[], &["--is-default=false"], &config).unwrap();
    assert_eq!(
        vnets(&input)
            .unwrap()
            .into_iter()
            .collect::<BTreeMap<_, _>>()["is_default"],
        "false"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires pinned Go administration oracle; run scripts/test-interop.sh"]
fn go_administration_filter_contract() {
    let directory = std::env::temp_dir().join(format!("admin-oracle-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let config = directory.join("config.yml");
    std::fs::write(&config, b"{}").unwrap();
    let empty_root = directory.join("empty.pem");
    std::fs::write(&empty_root, b"").unwrap();
    let cases: Vec<(&str, Vec<&str>, Vec<&str>)> = vec![
        ("list", vec![], vec![]),
        (
            "list",
            vec![],
            vec!["--name", "alpha beta", "--np", "pré", "--enp", "other"],
        ),
        ("list", vec!["--max-fetch-size", "7"], vec![]),
        ("list", vec!["--max-fetch-size", "0x7"], vec![]),
        ("list", vec!["--max-fetch-size", "0o7"], vec![]),
        ("list", vec!["--max-fetch-size", "+7"], vec![]),
        (
            "list",
            vec!["--max-fetch-size", "9223372036854775807"],
            vec![],
        ),
        (
            "list",
            vec!["--max-fetch-size", "9223372036854775808"],
            vec![],
        ),
        (
            "list",
            vec!["--max-fetch-size", "-9223372036854775808"],
            vec![],
        ),
        ("list", vec!["--max-fetch-size", "0"], vec![]),
        ("list", vec!["--max-fetch-size", "-1"], vec![]),
        (
            "list",
            vec![],
            vec!["--id", "{11111111-1111-1111-1111-111111111111}"],
        ),
        ("list", vec![], vec!["--id", "invalid"]),
        ("list", vec![], vec!["--when", "2026-01-01T02:03:04+03:00"]),
        ("list", vec![], vec!["--when", "invalid"]),
        ("list", vec![], vec!["--show-deleted"]),
        ("routes", vec![], vec![]),
        ("routes", vec!["--max-fetch-size", "7"], vec![]),
        (
            "routes",
            vec![],
            vec!["--filter-network-is-subset-of", "192.0.2.123/24"],
        ),
        (
            "routes",
            vec![],
            vec!["--filter-network-is-superset-of", "198.51.100.123/24"],
        ),
        (
            "routes",
            vec![],
            vec!["--nsub", "192.0.2.123/24", "--nsup", "198.51.100.123/24"],
        ),
        ("routes", vec![], vec!["--nsub", "::ffff:192.0.2.129/120"]),
        ("routes", vec![], vec!["--nsub", "2001:db8::123/64"]),
        ("routes", vec![], vec!["--nsub="]),
        (
            "routes",
            vec![],
            vec![
                "--filter-tunnel-id",
                "{11111111-1111-1111-1111-111111111111}",
            ],
        ),
        (
            "routes",
            vec![],
            vec!["--filter-vnet-id", "{22222222-2222-2222-2222-222222222222}"],
        ),
        (
            "routes",
            vec![],
            vec![
                "--filter-comment-is",
                "héllo & space",
                "--filter-is-deleted",
            ],
        ),
        ("vnets", vec![], vec![]),
        ("vnets", vec!["--max-fetch-size", "7"], vec![]),
        ("vnets", vec![], vec!["--is-default=false"]),
        ("vnets", vec![], vec!["--is-default=true"]),
        (
            "vnets",
            vec![],
            vec![
                "--id",
                "{11111111-1111-1111-1111-111111111111}",
                "--name",
                "alpha & beta",
            ],
        ),
        ("vnets", vec![], vec!["--id", "invalid"]),
    ];
    for (index, (mode, parent, args)) in cases.into_iter().enumerate() {
        let input = directory.join("input.json");
        let mut go_args = args.clone();
        go_args.extend(["--output", "json"]);
        std::fs::write(&input, serde_json::to_vec(&json!({"command":mode,"parent_args":parent,"args":go_args,"pages":[{"success":true,"result":[],"result_info":{"count":0,"per_page":10,"total_count":0}}]})).unwrap()).unwrap();
        let output = std::process::Command::new(
            std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE").expect("run scripts/test-interop.sh"),
        )
        .arg(&input)
        .env_clear()
        .env("HOME", &directory)
        .env("SSL_CERT_FILE", &empty_root)
        .env("SSL_CERT_DIR", directory.join("absent"))
        .env("TZ", "UTC")
        .output()
        .unwrap();
        assert!(output.status.success(), "source oracle case{index}");
        let expected: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let actual =
            invocation(mode, &parent, &args, &config).and_then(|input| query(mode, &input));
        assert_eq!(
            actual.is_err(),
            expected["failure"].as_bool().unwrap(),
            "case{index}"
        );
        if let Ok(query) = actual {
            let mut query = query.into_iter().collect::<BTreeMap<_, _>>();
            if mode != "vnets" {
                query.insert("page", "1".into());
            }
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query)
                .finish();
            assert_eq!(expected["queries"], json!([encoded]), "case{index}");
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}
