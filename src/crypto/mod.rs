use anyhow::{Result, bail};
use boring::ssl::{SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::{X509, store::X509StoreBuilder};

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
    roots: Option<Vec<u8>>,
}

impl EdgeTls {
    pub fn new(policy: TlsPolicy, roots_pem: Option<&[u8]>) -> Result<Self> {
        Ok(Self {
            context: Self::builder(policy, roots_pem)?.build(),
            policy,
            roots: roots_pem.map(<[u8]>::to_vec),
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
        match roots_pem {
            Some(pem) => {
                let certs = X509::stack_from_pem(pem)?;
                if certs.is_empty() {
                    bail!("custom CA bundle contains no certificates");
                }
                for cert in certs {
                    roots.add_cert(&cert)?;
                }
            }
            None => {
                for cert in native_roots()? {
                    roots.add_cert(&cert)?;
                }
                for cert in X509::stack_from_pem(include_bytes!("cloudflare-roots.pem"))? {
                    roots.add_cert(&cert)?;
                }
            }
        }
        builder.set_cert_store_builder(roots);
        Ok(builder)
    }

    pub fn context(&self) -> &SslContext {
        &self.context
    }
    pub fn quic_builder(&self) -> Result<SslContextBuilder> {
        let mut builder = Self::builder(self.policy, self.roots.as_deref())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        Ok(builder)
    }
}

pub(crate) fn native_roots() -> Result<Vec<X509>> {
    let configured = ["SSL_CERT_FILE", "SSL_CERT_DIR"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()));
    let loaded = rustls_native_certs::load_native_certs();
    for error in &loaded.errors {
        if !configured
            && matches!(&error.kind, rustls_native_certs::ErrorKind::Io { inner, .. } if inner.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        bail!("cannot load platform CA certificates: {}", error.context);
    }
    if configured && loaded.certs.is_empty() {
        bail!("configured platform CA inputs contain no certificates");
    }
    loaded
        .certs
        .iter()
        .map(|cert| X509::from_der(cert.as_ref()).map_err(Into::into))
        .collect()
}

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
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "edge.test").unwrap();
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
        let san = SubjectAlternativeName::new()
            .dns("edge.test")
            .build(&cert.x509v3_context(None, None))
            .unwrap();
        cert.append_extension(&san).unwrap();
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
        if mode == "bad" {
            assert!(EdgeTls::new(TlsPolicy::default(), None).is_err());
            return;
        }
        let path = std::env::var_os("SSL_CERT_FILE").unwrap();
        let cert = X509::from_pem(&std::fs::read(path).unwrap()).unwrap();
        let tls = EdgeTls::new(TlsPolicy::default(), None).unwrap();
        let chain = boring::stack::Stack::new().unwrap();
        let mut context = boring::x509::X509StoreContext::new().unwrap();
        assert!(
            context
                .init(tls.context().cert_store(), &cert, &chain, |ctx| ctx
                    .verify_cert())
                .unwrap()
        );
    }

    #[test]
    fn static_provider_uses_runtime_ca_environment() {
        let dir =
            std::env::temp_dir().join(format!("cloudflared-root-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("ca.pem");
        let (cert, _) = certificate();
        std::fs::write(&path, cert.to_pem().unwrap()).unwrap();
        for mode in ["good", "bad"] {
            if mode == "bad" {
                std::fs::write(&path, b"invalid CA input").unwrap();
            }
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "crypto::tests::native_root_env_child",
                    "--nocapture",
                ])
                .env("SSL_CERT_FILE", &path)
                .env("SSL_CERT_DIR", &dir)
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
