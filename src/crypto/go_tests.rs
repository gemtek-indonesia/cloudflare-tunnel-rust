use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

fn oracle(input: Value) -> Value {
    let dir = std::env::temp_dir().join(format!("trust-oracle-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("input.json");
    std::fs::write(&file, serde_json::to_vec(&input).unwrap()).unwrap();
    let result = std::process::Command::new(
        std::env::var_os("CLOUDFLARED_GO_TRUST_ORACLE").expect("run scripts/test-interop.sh"),
    )
    .arg(&file)
    .output()
    .unwrap();
    assert!(result.status.success(), "pinned Go trust oracle failed");
    let output = serde_json::from_slice(&result.stdout).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    output
}

#[test]
#[ignore = "requires pinned Go trust oracle; run scripts/test-interop.sh"]
fn go_certificate_framing_hostname_and_process_cache_contract() {
    let cert = tests::certificate().0;
    let good = cert.to_pem().unwrap();
    let text = String::from_utf8(good.clone()).unwrap();
    let invalid = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    let vectors = vec![
        good.clone(),
        [good.as_slice(), invalid].concat(),
        [invalid, good.as_slice()].concat(),
        invalid.to_vec(),
        Vec::new(),
        [
            b"-----BEGIN CERTIFICATE-----\n!!bad!!\n-----END CERTIFICATE-----\n".as_slice(),
            good.as_slice(),
        ]
        .concat(),
        [
            b"-----BEGIN CERTIFICATE-----\n!!bad!!\n".as_slice(),
            good.as_slice(),
        ]
        .concat(),
        text.replace("-----END CERTIFICATE-----", "-----END CERTIFICATE-----junk")
            .into_bytes(),
        text.replace(
            "-----BEGIN CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nComment: synthetic\n\n",
        )
        .into_bytes(),
        text.replace('\n', "\r\n").into_bytes(),
        text.replace(
            "-----BEGIN CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE----- \t\n",
        )
        .into_bytes(),
        text.replace(
            "-----END CERTIFICATE-----\n",
            "-----END CERTIFICATE----- \t\n",
        )
        .into_bytes(),
        text.replace("-----END CERTIFICATE-----\n", "").into_bytes(),
        text.replace("-----END CERTIFICATE-----", "-----END OTHER-----")
            .into_bytes(),
        [
            text.replace("-----END CERTIFICATE-----", "-----END OTHER-----")
                .as_bytes(),
            good.as_slice(),
        ]
        .concat(),
        text.replace("CERTIFICATE", "PUBLIC KEY").into_bytes(),
        [
            text.replace(
                "-----BEGIN CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n",
            )
            .as_bytes(),
            good.as_slice(),
        ]
        .concat(),
        [b" ".as_slice(), good.as_slice()].concat(),
        [b"\xff\x00\n".as_slice(), good.as_slice()].concat(),
        [good.strip_suffix(b"\n").unwrap(), b"\r"].concat(),
    ];
    for (index, pem) in vectors.into_iter().enumerate() {
        let output = oracle(json!({"kind":"append","pem":STANDARD.encode(&pem)}));
        let parsed = pem_certificates(&pem);
        assert_eq!(output["ok"], !parsed.is_empty(), "PEM case{index}");
        assert_eq!(
            output["count"].as_u64().unwrap(),
            parsed.len() as u64,
            "PEM case{index}"
        );
    }
    for (names, host, succeeds) in [
        (vec![], "edge.test", false),
        (vec!["edge.test"], "edge.test", true),
        (vec!["*.edge.test"], "foo.edge.test", true),
        (vec!["f*.edge.test"], "foo.edge.test", false),
    ] {
        let cert = tests::certificate_for_names("edge.test", &names).0;
        let output = oracle(
            json!({"kind":"hostname","pem":STANDARD.encode(cert.to_pem().unwrap()),"name":host}),
        );
        assert_eq!(output["ok"], succeeds);
    }
    for mode in ["success", "empty", "failure"] {
        let output = oracle(json!({"kind":"cache","name":mode}));
        assert_eq!(output["first_ok"], mode != "failure");
        assert_eq!(output["second_ok"], true);
        assert_eq!(output["second_count"], if mode == "empty" { 0 } else { 1 });
        assert_eq!(output["explicit_verify_ok"], mode != "empty");
        assert_eq!(output["default_verify_ok"], mode == "success");
    }
}
