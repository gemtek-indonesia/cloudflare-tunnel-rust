use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

fn environment(values: &[(&str, &str)]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).into(), (*value).into()))
        .collect()
}
fn selected(policy: &EnvironmentProxy, scheme: &str, host: &str, port: Option<&str>) -> Value {
    match policy.select(scheme, host, port) {
        Err(_) => json!({"error":true,"proxy":null}),
        Ok(proxy) => json!({"error":false,"proxy":proxy.map(|proxy| json!({
            "scheme":proxy.scheme,"authority":STANDARD.encode(proxy.authority()),
            "username":proxy.username().map(|value| STANDARD.encode(value)),
            "password":proxy.password().map(|value| STANDARD.encode(value)),
        }))}),
    }
}

#[test]
fn precedence_cgi_bypass_and_credentials_are_bound_to_settings() {
    let policy = EnvironmentProxy::from_environment(&environment(&[
        ("HTTP_PROXY", "http://proxy.invalid:80"),
        ("http_proxy", "http://lower.invalid"),
        ("HTTPS_PROXY", "http://user:synthetic@secure.invalid:443"),
        (
            "NO_PROXY",
            ".example.invalid:443,10.0.0.0/8,[2001:db8::1]:443",
        ),
        ("ALL_PROXY", "http://ignored.invalid"),
    ]));
    assert_eq!(
        policy
            .select("http", "public.invalid", None)
            .unwrap()
            .unwrap()
            .authority(),
        b"proxy.invalid:80"
    );
    assert!(
        policy
            .select("https", "app.example.invalid", None)
            .unwrap()
            .is_none()
    );
    assert!(
        policy
            .select("https", "example.invalid", None)
            .unwrap()
            .is_some()
    );
    assert!(policy.select("http", "10.1.2.3", None).unwrap().is_none());
    assert!(
        policy
            .select("https", "2001:db8::1", None)
            .unwrap()
            .is_none()
    );
    assert!(policy.select("http", "127.0.0.2", None).unwrap().is_none());
    assert!(
        policy
            .select("http", "::ffff:127.0.0.1", None)
            .unwrap()
            .is_none()
    );
    assert!(policy.select("http", "LOCALHOST", None).unwrap().is_some());
    let debug = format!("{policy:?} {:?}", policy.https);
    assert!(!debug.contains("synthetic"));
    assert!(!debug.contains("user"));
    let cgi = EnvironmentProxy::from_environment(&environment(&[
        ("HTTP_PROXY", "proxy.invalid"),
        ("REQUEST_METHOD", "GET"),
        ("NO_PROXY", "*"),
    ]));
    assert_eq!(cgi.select("http", "localhost", None), Err(CgiProxyError));
    let empty = EnvironmentProxy::from_environment(&environment(&[
        ("HTTP_PROXY", ""),
        ("http_proxy", "lower.invalid"),
        ("REQUEST_METHOD", ""),
    ]));
    assert_eq!(
        empty
            .select("http", "public.invalid", None)
            .unwrap()
            .unwrap()
            .authority(),
        b"lower.invalid"
    );
}

#[test]
fn native_settings_capture_first_use() {
    use std::os::unix::ffi::OsStringExt;
    const CHILD: &str = "CLOUDFLARED_PROXY_SETTINGS_TEST_CHILD";
    if let Some(kind) = std::env::var_os(CHILD) {
        let first = EnvironmentProxy::current();
        match kind.to_str().unwrap() {
            "raw-cgi" => assert_eq!(first.select("http", "localhost", None), Err(CgiProxyError)),
            "ignored" => assert!(
                first
                    .select("http", "synthetic.invalid", None)
                    .unwrap()
                    .is_none()
            ),
            "raw-bypass" => {
                assert!(
                    first
                        .select("http", "example.invalid", None)
                        .unwrap()
                        .is_none()
                );
                assert!(first.select("http", "10.2.3.4", None).unwrap().is_none());
                assert_eq!(
                    first
                        .select("http", "synthetic.invalid", None)
                        .unwrap()
                        .unwrap()
                        .authority(),
                    b"first.invalid:80"
                );
            }
            kind => assert_eq!(
                first
                    .select("http", "synthetic.invalid", None)
                    .unwrap()
                    .unwrap()
                    .authority(),
                if kind == "raw-proxy" {
                    b"first\xff.invalid:80".as_slice()
                } else {
                    b"first.invalid:80".as_slice()
                },
            ),
        }
        // Only this test runs in the child; no other task reads its environment.
        unsafe {
            std::env::set_var("HTTP_PROXY", "http://second.invalid:80");
            std::env::remove_var("REQUEST_METHOD");
            std::env::remove_var("NO_PROXY");
        }
        let second = EnvironmentProxy::current();
        assert!(std::ptr::eq(first, second));
        assert_eq!(
            selected(first, "http", "synthetic.invalid", None),
            selected(second, "http", "synthetic.invalid", None)
        );
        return;
    }
    for kind in ["utf8", "raw-proxy", "raw-cgi", "raw-bypass", "ignored"] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .env_clear()
            .env(CHILD, kind)
            .env("HTTP_PROXY", "http://first.invalid:80");
        let raw: Option<(&str, &[u8])> = match kind {
            "raw-proxy" => Some(("HTTP_PROXY", b"http://first\xff.invalid:80")),
            "raw-cgi" => Some(("REQUEST_METHOD", b"\xff")),
            "raw-bypass" => Some(("NO_PROXY", b"example.invalid,\xe2\x82,10.0.0.0/8")),
            "ignored" => Some(("HTTP_PROXY", b"\xff\nproxy.invalid")),
            _ => None,
        };
        if let Some((key, value)) = raw {
            child.env(key, std::ffi::OsString::from_vec(value.to_vec()));
        }
        let output = child
            .args([
                "--exact",
                "proxy_environment::tests::native_settings_capture_first_use",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "owned cache test child failed: {kind}"
        );
    }
}

#[test]
#[ignore = "requires the pinned Go proxy environment oracle"]
fn go_proxy_environment_contract() {
    let oracle = std::env::var_os("CLOUDFLARED_GO_PROXY_ORACLE").expect("pinned Go proxy oracle");
    let targets: &[&str] = &[
        "http://public.invalid/",
        "https://public.invalid/",
        "ftp://public.invalid/",
        "http://localhost/",
        "http://LOCALHOST/",
        "https://127.0.0.2/",
        "https://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "https://example.invalid/",
        "https://app.example.invalid/",
        "https://app.example.invalid:80/",
        "http://app.example.invalid:443/",
        "http://otherexample.invalid/",
        "http://10.2.3.4/",
        "https://192.0.2.1/",
        "https://192.0.2.1:80/",
        "https://[2001:db8::1]/",
        "https://[2001:db8::1]:80/",
        "http://[::ffff:10.2.3.4]/",
        "https://bücher.invalid/",
        "https://app.bücher.invalid/",
        "https://xn--bcher-kva.invalid/",
        "http://[::1%25zone]/",
        "https://[2001:db8::1%25zone]/",
        "http://LOCALHOST./",
        "http://i.invalid/",
        "http://İ.invalid/",
        "http://xn--i-9bb.invalid/",
        "http://ΑΣ.invalid/",
        "http://ασ.invalid/",
        "http://ας.invalid/",
        "http://xn--mxa6a.invalid/",
        "http://xn--mxa8a.invalid/",
        "http://ΟΣ.invalid/",
        "http://οσ.invalid/",
        "http://ος.invalid/",
    ];
    let mut cases = vec![BTreeMap::new()];
    for proxy in [
        "proxy.invalid:3128",
        "http://proxy.invalid:80",
        "HTTPS://USER:p%40ss@Proxy.invalid:443/path#fragment",
        "socks5://proxy.invalid",
        "socks5h://proxy.invalid",
        "ftp://proxy.invalid:21",
        "http:///foo",
        "foo://",
        "//proxy.invalid",
        "http:proxy",
        "http://proxy.invalid:bad",
        "proxy.invalid:bad",
        "http://proxy.invalid:",
        "http://[::1]:80",
        "http://proxy.invalid:99999",
        "http://bücher.invalid",
        "http://%65xample.invalid",
        "http://a%25b",
        "http://a b",
        "proxy.invalid",
        "/foo",
        "http://",
        "\nproxy.invalid",
        "http://proxy.invalid/path%zz",
        "http://proxy.invalid/?q=%zz",
        "http://proxy.invalid/#%zz",
        "http://user@proxy.invalid",
        "http://user:p%ff@proxy.invalid",
        "http://u:p@ss@proxy.invalid",
        "http://[not-ipv6]/",
        "http://prefix[::1]:80/",
        "http://[fe80::1%25eth0]:80/",
        "http://[::ffff:192.0.2.1]/",
    ] {
        cases.push(environment(&[
            ("HTTP_PROXY", proxy),
            ("HTTPS_PROXY", proxy),
        ]));
    }
    for no_proxy in [
        "",
        "*",
        "example.invalid",
        ".example.invalid",
        "*.example.invalid",
        "example.invalid:443",
        "example.invalid:80",
        "app.example.invalid:443",
        "192.0.2.1",
        "192.0.2.1:443",
        "[2001:db8::1]:443",
        "2001:db8::1",
        "10.0.0.0/8",
        "2001:db8::/32",
        "::/0",
        "::ffff:10.0.0.0/104",
        "bücher.invalid",
        ".bücher.invalid",
        " ,EXAMPLE.INVALID:443, invalid/garbage, :80",
        "[bad]:80",
        "[2001:db8::1]",
        "example.invalid:bad",
        "İ.invalid",
        ".İ.invalid",
        "ΑΣ.invalid",
        ".ΑΣ.invalid",
        "ΟΣ.invalid",
        ".ΟΣ.invalid",
    ] {
        cases.push(environment(&[
            ("HTTP_PROXY", "http://proxy.invalid"),
            ("HTTPS_PROXY", "http://secure.invalid"),
            ("NO_PROXY", no_proxy),
        ]));
    }
    cases.extend([
        environment(&[("ALL_PROXY", "http://ignored.invalid")]),
        environment(&[("all_proxy", "http://ignored.invalid")]),
        environment(&[
            ("HTTP_PROXY", ""),
            ("http_proxy", "lower.invalid"),
            ("NO_PROXY", ""),
            ("no_proxy", "example.invalid"),
        ]),
        environment(&[
            ("HTTP_PROXY", "upper.invalid"),
            ("http_proxy", "lower.invalid"),
            ("REQUEST_METHOD", "GET"),
            ("NO_PROXY", "*"),
        ]),
        environment(&[
            ("HTTP_PROXY", "upper.invalid"),
            ("HTTPS_PROXY", "secure.invalid"),
            ("REQUEST_METHOD", ""),
        ]),
        environment(&[("http_proxy", "lower.invalid"), ("REQUEST_METHOD", "POST")]),
    ]);
    let query = |input: &Value| -> Vec<Value> {
        let mut child = std::process::Command::new(&oracle)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let initial = environment(&[("HTTP_PROXY", "first.invalid:80")]);
    let cached = query(&json!({
        "environment": initial,
        "after": {"HTTP_PROXY":"second.invalid:80"},
        "targets":["http://synthetic.invalid/","http://synthetic.invalid/"],
    }));
    assert_eq!(cached.len(), 2);
    assert_eq!(cached[0]["proxy"], cached[1]["proxy"]);
    assert_eq!(
        cached[0]["proxy"]["authority"],
        STANDARD.encode(b"first.invalid:80")
    );
    for (index, (key, bytes)) in [
        ("HTTP_PROXY", b"http://u\xff:p@proxy.invalid".as_slice()),
        ("HTTP_PROXY", b"http://proxy\xff.invalid".as_slice()),
        ("HTTP_PROXY", b"http\xff://proxy.invalid".as_slice()),
        ("HTTP_PROXY", b"\xff\nproxy.invalid".as_slice()),
        ("HTTP_PROXY", b"http://\xff.invalid/path".as_slice()),
        ("HTTP_PROXY", b"http://proxy.invalid/%ff".as_slice()),
        ("HTTP_PROXY", b"http://%ff.invalid".as_slice()),
        ("HTTPS_PROXY", b"http://%e2%82.invalid".as_slice()),
        ("REQUEST_METHOD", b"\xff".as_slice()),
        (
            "NO_PROXY",
            b"example.invalid,\xe2\x82,10.0.0.0/8".as_slice(),
        ),
        ("HTTP_PROXY", b"http://[::1%25zone\xff]:80".as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let environment = environment(&[
            ("HTTP_PROXY", "http://proxy.invalid"),
            ("HTTPS_PROXY", "http://secure.invalid"),
        ]);
        let source = query(
            &json!({"environment":environment,"bytes":{key:STANDARD.encode(bytes)},"targets":targets}),
        );
        let mut settings: BTreeMap<String, Vec<u8>> = environment
            .into_iter()
            .map(|(key, value)| (key, value.into_bytes()))
            .collect();
        settings.insert(key.to_owned(), bytes.to_vec());
        let policy = EnvironmentProxy::from_bytes(&settings);
        assert_eq!(source.len(), targets.len());
        for (target, expected) in targets.iter().zip(source) {
            let actual = selected(
                &policy,
                expected["scheme"].as_str().unwrap(),
                expected["hostname"].as_str().unwrap(),
                expected["port"].as_str(),
            );
            assert_eq!(
                actual,
                json!({"error":expected["error"],"proxy":expected["proxy"]}),
                "byte environment case {index}, target {target}"
            );
        }
    }
    for (index, environment) in cases.into_iter().enumerate() {
        let input = json!({"environment": environment, "targets":targets});
        let source = query(&input);
        assert_eq!(source.len(), targets.len());
        let policy = EnvironmentProxy::from_environment(&environment);
        for (target, expected) in targets.iter().zip(source) {
            assert_ne!(expected["invalid"], true);
            let actual = selected(
                &policy,
                expected["scheme"].as_str().unwrap(),
                expected["hostname"].as_str().unwrap(),
                expected["port"].as_str(),
            );
            assert_eq!(
                actual,
                json!({"error":expected["error"],"proxy":expected["proxy"]}),
                "environment case {index}, target {target}"
            );
        }
    }
}
