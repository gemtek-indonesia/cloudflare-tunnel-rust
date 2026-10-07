use super::*;
use serde_json::{Value, json};

#[test]
fn joins_preserve_raw_authority_encoded_dots_and_fragments() {
    let base = ApplicationUrl::remote("http://synthetic.invalid:080/a/b?base=one#old").unwrap();
    for (reference, expected) in [
        ("%2e", "http://synthetic.invalid:080/a/%2e"),
        ("%2e%2e", "http://synthetic.invalid:080/a/%2e%2e"),
        ("?q=1", "http://synthetic.invalid:080/a/b?q=1"),
        ("", "http://synthetic.invalid:080/a/b?base=one#old"),
        ("#", "http://synthetic.invalid:080/a/b?base=one#old"),
        ("..\\next", "http://synthetic.invalid:080/a/..%5Cnext"),
    ] {
        assert_eq!(base.join(reference).unwrap().as_str(), expected);
    }
    let joined = base.join("/%63dn-cgi/access/login#fragment").unwrap();
    assert_eq!(joined.path(), "/%63dn-cgi/access/login");
    assert!(!joined.request_uri().unwrap().to_string().contains('#'));
}

#[test]
fn malformed_redirect_errors_do_not_expose_credentials_or_query() {
    let base = ApplicationUrl::remote("https://synthetic.invalid/").unwrap();
    for reference in [
        "https://synthetic-private-user:synthetic-private-pass@bad\\host/path?synthetic-private-query",
        "/%zz?synthetic-private-query",
        "https://synthetic.invalid/\n?synthetic-private-query",
    ] {
        let error = format!("{:#}", base.join(reference).unwrap_err());
        assert!(!error.contains("synthetic-private"));
    }
}

#[test]
#[ignore = "requires pinned Go URL and Access response oracle"]
fn go_url_join_wire_and_access_response_contract() {
    let bases = [
        "http://synthetic.invalid:080/a/b?base=one#old",
        "https://User%3AName:Pa%2Fss@MiXeD.invalid:0443/a//b?x=%2F#base",
        "http://synthetic.invalid:080/a/%2e/b?x=one",
        "http://[::1]:080/a/b?x=one#base",
        "http://synthetic.invalid:080",
        "http://synthetic.invalid:080/a/./b?base=one#old",
        "http://synthetic.invalid:080/a/b/..?base=one#old",
    ];
    let references = [
        "",
        "#",
        "#new",
        "?",
        "?q=%FF",
        "../next",
        "%2E",
        "%2e%2e",
        ".%2E",
        "%2e.",
        "/a/%2e/../c",
        "//other.invalid:080/p",
        "https://User%40X:Pa%3Ass@Other.invalid:0443/%2e?q=%2f#f",
        "..\\next",
        "\\\\other.invalid/p",
        "/a\\b?q=x\\y#z\\t",
        "//host\\invalid/p",
        "https://user\\name:pass@h.invalid/p",
        "path with space",
        "路径?q=值#片段",
        "?q=a b",
        "/%",
        "/a%2fb?x=%zz",
        "#frag%zz",
        ":scheme",
        "http:x",
        "http://other.invalid:",
        "/%63dn-cgi/access/login",
        "/a/%63dn-cgi/access/authorized",
        "/%ff/cdn-cgi/access/login",
    ];
    let mut cases: Vec<_> = bases
        .iter()
        .flat_map(|base| {
            references
                .iter()
                .map(move |reference| json!({"base": base, "ref": reference}))
        })
        .collect();
    for reference in [
        "https://b%C3%BCcher.invalid/path",
        "https://synthetic%25invalid/path",
        "https://%73ynthetic.invalid/",
        "//synthetic%2einvalid/path",
        "https://synthetic%2Finvalid/path",
        "https://synthetic%3Ainvalid/path",
        "http://[fe80::1%25]/",
        "http://[fe80::1%25界]/",
        "http://[fe80::1%25%E7%95%8C]/",
        "http://[fe80::1%25space%20name]/",
        "http://[fe80::1%25bad%2Fzone]/",
        "http://[fe80::zz%25zone]/",
        "https://user:p@ss@synthetic.invalid/path",
        "https://us@er:pass@synthetic.invalid/path",
        "https://user:p%40ss@synthetic.invalid/path",
        "https://us%40er:pass@synthetic.invalid/path",
    ] {
        cases.push(json!({"base":"https://synthetic.invalid/base","ref":reference}));
    }
    for reference in [
        "relative",
        "?q=1",
        "#new",
        "https://replacement.invalid:0443/path",
        "//replacement.invalid:0443/path",
        "http://[::1]:080/path",
        "//[::1]:080/path",
    ] {
        cases.push(
            json!({"base":"http://[fe80::1%25synthetic0]:080/a/b?base=one#old","ref":reference}),
        );
    }
    for reference in [
        "https://[fe80::1%25synthetic0]:0443/path",
        "//[fe80::1%25synthetic0]:0443/path",
    ] {
        cases.push(json!({"base":"https://synthetic.invalid/base","ref":reference}));
    }
    let oracle =
        std::env::var_os("CLOUDFLARED_GO_HTTP_POLICY_ORACLE").expect("pinned Go URL oracle");
    let mut child = std::process::Command::new(oracle)
        .arg("resolve")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&cases).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    for (case, expected) in cases.iter().zip(expected) {
        let base = ApplicationUrl::remote(case["base"].as_str().unwrap()).unwrap();
        let result = base.join(case["ref"].as_str().unwrap());
        assert_eq!(
            result.is_ok(),
            expected["valid"].as_bool().unwrap(),
            "{case}"
        );
        if let Ok(result) = result {
            let source_host = expected["host"].as_str().unwrap();
            if source_host.is_ascii() || source_host.starts_with('[') {
                assert_eq!(
                    result.as_str(),
                    expected["url"].as_str().unwrap(),
                    "URL {case}"
                );
                assert_eq!(result.host(), source_host, "Host {case}");
            } else {
                assert_eq!(
                    result.host(),
                    expected["wire_host"].as_str().unwrap(),
                    "wire IDNA Host {case}"
                );
            }
            assert_eq!(
                result.path(),
                expected["path"].as_str().unwrap(),
                "path {case}"
            );
            assert_eq!(
                result.query().unwrap_or(""),
                expected["query"].as_str().unwrap(),
                "query {case}"
            );
            let decoded = result.decoded_path();
            assert_eq!(
                STANDARD.encode(decoded.as_ref()),
                expected["decoded_path"].as_str().unwrap(),
                "decoded path {case}"
            );
            assert_eq!(
                decoded.starts_with(b"/cdn-cgi/access/login"),
                expected["login"].as_bool().unwrap(),
                "Access response {case}"
            );
            assert_eq!(
                decoded
                    .windows(b"/cdn-cgi/access/login".len())
                    .any(|part| part == b"/cdn-cgi/access/login"),
                expected["login_contains"].as_bool().unwrap(),
                "login callback {case}"
            );
            assert_eq!(
                decoded
                    .windows(b"/cdn-cgi/access/authorized".len())
                    .any(|part| part == b"/cdn-cgi/access/authorized"),
                expected["authorized_contains"].as_bool().unwrap(),
                "authorized callback {case}"
            );
            let request = result.request_uri();
            if result.query().is_some_and(|query| query.contains(' '))
                || !result.host().starts_with('[') && result.host().contains('%')
            {
                // The existing HTTP URI carrier cannot represent these source-valid wire forms.
                assert!(request.is_err());
            } else {
                let request =
                    request.unwrap_or_else(|error| panic!("wire carrier {case}: {error}"));
                assert_eq!(
                    request.path_and_query().unwrap().as_str(),
                    expected["request_uri"].as_str().unwrap(),
                    "wire {case}"
                );
            }
        }
    }
}
