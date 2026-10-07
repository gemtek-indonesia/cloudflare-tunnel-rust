use anyhow::{Result, bail};
use boring::ssl::{SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::{X509, store::X509StoreBuilder};
use std::{
    io,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsPolicy {
    #[default]
    PreferPostQuantum,
    RequirePostQuantum,
}

impl TlsPolicy {
    pub fn groups(self) -> &'static str {
        match self {
            Self::PreferPostQuantum => "X25519MLKEM768:P256Kyber768Draft00:P-256",
            Self::RequirePostQuantum => "X25519MLKEM768:P256Kyber768Draft00",
        }
    }
}

#[derive(Clone)]
pub struct EdgeTls {
    context: SslContext,
    policy: TlsPolicy,
    roots: Arc<[u8]>,
}

impl EdgeTls {
    pub fn new(policy: TlsPolicy, roots_pem: Option<&[u8]>) -> Result<Self> {
        let mut roots = Vec::new();
        for cert in edge_root_certificates(roots_pem)? {
            roots.extend(cert.to_pem()?);
        }
        Ok(Self {
            context: Self::builder(policy, Some(&roots))?.build(),
            policy,
            roots: roots.into(),
        })
    }

    pub fn builder(policy: TlsPolicy, roots_pem: Option<&[u8]>) -> Result<SslContextBuilder> {
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;
        builder.set_min_proto_version(Some(match policy {
            TlsPolicy::PreferPostQuantum => SslVersion::TLS1_2,
            TlsPolicy::RequirePostQuantum => SslVersion::TLS1_3,
        }))?;
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_curves_list(policy.groups())?;
        let mut roots = X509StoreBuilder::new()?;
        for cert in edge_root_certificates(roots_pem)? {
            roots.add_cert(&cert)?;
        }
        builder.set_cert_store_builder(roots);
        Ok(builder)
    }

    pub fn context(&self) -> &SslContext {
        &self.context
    }
    pub fn quic_builder(&self) -> Result<SslContextBuilder> {
        let mut builder = Self::builder(self.policy, Some(&self.roots))?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        Ok(builder)
    }
}

fn edge_root_certificates(pem: Option<&[u8]>) -> Result<Vec<X509>> {
    match pem {
        Some(pem) => {
            let certs = pem_certificates(pem);
            if certs.is_empty() {
                bail!("custom CA bundle contains no certificates");
            }
            Ok(certs)
        }
        None => {
            let mut certs = native_roots()?;
            certs.extend(X509::stack_from_pem(include_bytes!(
                "cloudflare-roots.pem"
            ))?);
            Ok(certs)
        }
    }
}

pub(crate) fn enforce_hostname_policy(ssl: &mut boring::ssl::SslRef) {
    use boring::x509::verify::X509CheckFlags;
    ssl.param_mut()
        .set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS | X509CheckFlags::NEVER_CHECK_SUBJECT);
}

pub(crate) fn pem_certificates(pem: &[u8]) -> Vec<X509> {
    let mut output = Vec::new();
    let mut offset = 0;
    let mut start = None;
    let mut headers = false;
    for chunk in pem.split_inclusive(|byte| *byte == b'\n') {
        let mut line = chunk;
        if let Some(no_lf) = line.strip_suffix(b"\n") {
            line = no_lf.strip_suffix(b"\r").unwrap_or(no_lf);
        }
        while line.last().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
            line = &line[..line.len() - 1];
        }
        if line.starts_with(b"-----BEGIN ") {
            start = (line == b"-----BEGIN CERTIFICATE-----").then_some(offset);
            headers = false;
        } else if line.starts_with(b"-----END ") {
            if let Some(begin) = start.take()
                && !headers
                && line == b"-----END CERTIFICATE-----"
                && let Ok(cert) = X509::from_pem(&pem[begin..offset + chunk.len()])
            {
                output.push(cert);
            }
        } else if start.is_some() && line.contains(&b':') {
            headers = true;
        }
        offset += chunk.len();
    }
    output
}

pub(crate) fn native_roots() -> Result<Vec<X509>> {
    match initial_native_roots() {
        Ok(certs) => Ok(certs.to_vec()),
        Err(_) => load_native_roots(),
    }
}

pub(crate) fn configure_platform_trust(
    ssl: &mut boring::ssl::SslRef,
) -> Result<(), boring::error::ErrorStack> {
    enforce_hostname_policy(ssl);
    if !ssl.verify_mode().contains(SslVerifyMode::PEER) {
        return Ok(());
    }
    let mut store = X509StoreBuilder::new()?;
    if let Ok(certs) = initial_native_roots() {
        for cert in certs.iter() {
            store.add_cert(cert)?;
        }
    }
    ssl.set_verify_cert_store(store.build())?;
    Ok(())
}

fn initial_native_roots() -> &'static std::result::Result<Arc<[X509]>, String> {
    static ROOTS: OnceLock<std::result::Result<Arc<[X509]>, String>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        load_native_roots()
            .map(Arc::from)
            .map_err(|error| error.to_string())
    })
}

fn load_native_roots() -> Result<Vec<X509>> {
    let files = match std::env::var_os("SSL_CERT_FILE").filter(|value| !value.is_empty()) {
        Some(file) => vec![PathBuf::from(file)],
        None => [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/pki/tls/cacert.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "/etc/ssl/cert.pem",
        ]
        .map(PathBuf::from)
        .to_vec(),
    };
    let dirs = match std::env::var_os("SSL_CERT_DIR").filter(|value| !value.is_empty()) {
        Some(dirs) => std::env::split_paths(&dirs).collect(),
        None => ["/etc/ssl/certs", "/etc/pki/tls/certs"]
            .map(PathBuf::from)
            .to_vec(),
    };
    linux_roots(&files, &dirs)
}

fn linux_roots(files: &[PathBuf], dirs: &[PathBuf]) -> Result<Vec<X509>> {
    let mut certs = Vec::new();
    let mut first_error = None;
    for file in files {
        match std::fs::read(file) {
            Ok(pem) => {
                certs.extend(pem_certificates(&pem));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    for dir in dirs {
        let entries =
            std::fs::read_dir(dir).and_then(|entries| entries.collect::<io::Result<Vec<_>>>());
        let mut entries = match entries {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        };
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if std::fs::read_link(entry.path())
                .is_ok_and(|target| !target.as_os_str().as_encoded_bytes().contains(&b'/'))
            {
                continue;
            }
            if let Ok(pem) = std::fs::read(entry.path()) {
                certs.extend(pem_certificates(&pem));
            }
        }
    }
    if certs.is_empty()
        && let Some(error) = first_error
    {
        bail!("cannot load platform CA certificates: {}", error.kind());
    }
    Ok(certs)
}

#[cfg(test)]
mod go_tests;
#[cfg(test)]
mod trust_tests;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use boring::{
        asn1::{Asn1Integer, Asn1Time},
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        x509::{
            X509NameBuilder,
            extension::{BasicConstraints, SubjectAlternativeName},
        },
    };

    pub fn certificate() -> (X509, PKey<Private>) {
        certificate_for_names("edge.test", &["edge.test"])
    }

    pub fn certificate_for_names(common_name: &str, names: &[&str]) -> (X509, PKey<Private>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        let serial = Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap();
        cert.set_serial_number(&serial).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.append_extension(&BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        if !names.is_empty() {
            let mut san = SubjectAlternativeName::new();
            for name in names {
                san.dns(name);
            }
            let san = san.build(&cert.x509v3_context(None, None)).unwrap();
            cert.append_extension(&san).unwrap();
        }
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        (cert.build(), key)
    }
    #[test]
    fn provider_accepts_exact_pq_policies_and_rejects_bad_roots() {
        for policy in [TlsPolicy::PreferPostQuantum, TlsPolicy::RequirePostQuantum] {
            EdgeTls::new(policy, None).unwrap();
        }
        assert!(EdgeTls::new(TlsPolicy::default(), Some(b"invalid PEM")).is_err());
        assert!(EdgeTls::new(TlsPolicy::default(), Some(b"")).is_err());
    }

    #[tokio::test]
    async fn tls_groups_hostname_and_strict_downgrade() {
        for (policy, group, version, succeeds) in [
            (
                TlsPolicy::PreferPostQuantum,
                "P-256",
                SslVersion::TLS1_2,
                true,
            ),
            (
                TlsPolicy::RequirePostQuantum,
                "P-256",
                SslVersion::TLS1_2,
                false,
            ),
            (
                TlsPolicy::RequirePostQuantum,
                "P-256",
                SslVersion::TLS1_3,
                false,
            ),
            (
                TlsPolicy::RequirePostQuantum,
                "X25519MLKEM768",
                SslVersion::TLS1_3,
                true,
            ),
            (
                TlsPolicy::RequirePostQuantum,
                "P256Kyber768Draft00",
                SslVersion::TLS1_3,
                true,
            ),
        ] {
            let (cert, key) = certificate();
            let mut acceptor =
                boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
            acceptor.set_certificate(&cert).unwrap();
            acceptor.set_private_key(&key).unwrap();
            acceptor.set_curves_list(group).unwrap();
            acceptor.set_min_proto_version(Some(version)).unwrap();
            acceptor.set_max_proto_version(Some(version)).unwrap();
            let acceptor = acceptor.build();
            let tls = EdgeTls::new(policy, Some(&cert.to_pem().unwrap())).unwrap();
            let mut ssl = boring::ssl::Ssl::new(tls.context()).unwrap();
            ssl.set_hostname("edge.test").unwrap();
            ssl.param_mut().set_host("edge.test").unwrap();
            let (a, b) = tokio::io::duplex(8192);
            let (client, server) = tokio::join!(
                tokio_boring::SslStreamBuilder::new(ssl, a).connect(),
                tokio_boring::accept(&acceptor, b)
            );
            assert_eq!(client.is_ok(), succeeds, "{policy:?} {group} {version:?}");
            if succeeds {
                assert_eq!(server.unwrap().ssl().curve_name(), Some(group));
            }
        }
    }

    #[test]
    fn native_root_env_child() {
        let Some(mode) = std::env::var_os("CLOUDFLARED_ROOT_TEST") else {
            return;
        };
        if mode == "unreadable" {
            assert!(EdgeTls::new(TlsPolicy::default(), None).is_err());
            return;
        }
        if mode == "empty" {
            assert!(native_roots().unwrap().is_empty());
            assert!(EdgeTls::new(TlsPolicy::default(), None).is_ok());
            return;
        }
        let path = std::env::var_os("SSL_CERT_FILE").unwrap();
        let cert = X509::from_pem(&std::fs::read(&path).unwrap()).unwrap();
        let tls = EdgeTls::new(TlsPolicy::default(), None).unwrap();
        let chain = boring::stack::Stack::new().unwrap();
        let mut context = boring::x509::X509StoreContext::new().unwrap();
        assert!(
            context
                .init(tls.context().cert_store(), &cert, &chain, |ctx| ctx
                    .verify_cert())
                .unwrap()
        );
        if mode == "snapshot" {
            std::fs::write(&path, b"changed native CA input").unwrap();
            let quic = tls.quic_builder().unwrap().build();
            assert!(
                context
                    .init(quic.cert_store(), &cert, &chain, |ctx| ctx.verify_cert())
                    .unwrap()
            );
        }
    }

    #[test]
    fn static_provider_uses_runtime_ca_environment() {
        let dir =
            std::env::temp_dir().join(format!("cloudflared-root-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("ca.pem");
        let (cert, _) = certificate();
        std::fs::write(&path, cert.to_pem().unwrap()).unwrap();
        for mode in ["good", "snapshot", "empty", "unreadable"] {
            if mode == "empty" {
                std::fs::write(&path, b"invalid CA input").unwrap();
            }
            let file = if mode == "unreadable" { &dir } else { &path };
            let cert_dir = dir.join("absent");
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "crypto::tests::native_root_env_child",
                    "--nocapture",
                ])
                .env("SSL_CERT_FILE", file)
                .env("SSL_CERT_DIR", cert_dir)
                .env("CLOUDFLARED_ROOT_TEST", mode)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "CA environment child failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
