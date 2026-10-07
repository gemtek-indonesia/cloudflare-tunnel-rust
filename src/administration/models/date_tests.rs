use super::*;
use serde_json::json;

#[test]
fn timestamps_keep_offset_parse_and_json_errors_separate() {
    let value = ApiTime::parse("2026-01-01T1:02:03,1234567899+01:60").unwrap();
    assert_eq!(
        value.json_timestamp().unwrap(),
        "2026-01-01T01:02:03.123456789+02:00"
    );
    assert_eq!(
        value,
        ApiTime::parse("2025-12-31T23:02:03.123456789Z").unwrap()
    );
    assert!(
        ApiTime::parse("2026-01-01T01:02:03+24:00")
            .unwrap()
            .json_timestamp()
            .is_err()
    );
    for input in [
        "2026-01-01t01:02:03Z",
        "2026-01-01T01:02:03z",
        "2026-01-01T01:02:60Z",
        "2026-02-30T01:02:03Z",
    ] {
        assert!(ApiTime::parse(input).is_err(), "{input}");
    }
    assert_eq!(
        ApiTime::parse("0000-01-01T00:00:00Z")
            .unwrap()
            .json_timestamp()
            .unwrap(),
        "0000-01-01T00:00:00Z"
    );
    assert_eq!(
        serde_json::to_string(&serde_json::from_str::<ApiTime>("null").unwrap()).unwrap(),
        "\"0001-01-01T00:00:00Z\""
    );
}

#[test]
#[ignore = "requires pinned Go administration oracle; run scripts/test-interop.sh"]
fn go_administration_timestamp_contract() {
    let directory =
        std::env::temp_dir().join(format!("admin-time-oracle-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    for (index, value) in [
        "2026-01-01T01:02:03Z",
        "2026-01-01T01:02:03.1Z",
        "2026-01-01T01:02:03.1234567899Z",
        "2026-01-01T01:02:03,1Z",
        "2026-01-01t01:02:03Z",
        "2026-01-01T01:02:03z",
        "2026-01-01T01:02:60Z",
        "0000-01-01T00:00:00Z",
        "2026-01-01T01:02:03+24:00",
        "2026-01-01T01:02:03+25:00",
        "2026-01-01T01:02:03+23:60",
        "2026-01-01T01:02:03+01:60",
        "2026-01-01T1:02:03Z",
        "2026-01-01T01:02:03-00:00",
        "2026-01-01T01:02:03-24:00",
        "2026-01-01T01:02:03-00:60",
        "9999-12-31T23:59:59.000000001+23:59",
        "2026-01-01T01:02:03.123456789xZ",
        "2026-01-01T01:02:03.Z",
        "2026-01-01T01:02:03.0Z",
        "2026-02-30T01:02:03Z",
        "2024-02-29T01:02:03Z",
        "2026-01-01T24:02:03Z",
        "2026-01-01T01:60:03Z",
        "2026-01-01T01:02:03+24:60",
        "2026-01-01T01:02:03-24:60",
        "0001-01-01T00:00:00Z",
        "invalid",
        "",
        "2026-01-01T01:02:03\0Z",
    ]
    .into_iter()
    .enumerate()
    {
        let file = directory.join("input.json");
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({"command":"date","args":[value]})).unwrap(),
        )
        .unwrap();
        let output = std::process::Command::new(
            std::env::var_os("CLOUDFLARED_GO_ADMIN_ORACLE").expect("run scripts/test-interop.sh"),
        )
        .arg(&file)
        .env_clear()
        .env("HOME", &directory)
        .env("TZ", "UTC")
        .output()
        .unwrap();
        assert!(output.status.success());
        let expected: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let parsed = ApiTime::parse(value);
        assert_eq!(
            parsed.is_err(),
            expected["parse_failure"].as_bool().unwrap(),
            "case{index} {value:?}"
        );
        if let Ok(value) = parsed {
            assert_eq!(
                value.unix(),
                expected["unix"].as_i64().unwrap(),
                "case{index}"
            );
            assert_eq!(
                value.nanoseconds() as u64,
                expected["nanoseconds"].as_u64().unwrap(),
                "case{index}"
            );
            let encoded = serde_json::to_string(&value);
            assert_eq!(
                encoded.is_err(),
                expected["failure"].as_bool().unwrap(),
                "case{index}"
            );
            if let Ok(encoded) = encoded {
                assert_eq!(encoded, expected["output"].as_str().unwrap(), "case{index}");
            }
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}
