use super::{HttpClient, bounded_body, http_client};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::Full;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde_json::Value;
use std::{
    sync::{Arc, Once},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub(super) fn crypto_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    });
}

struct CachedKeys {
    keys: JwkSet,
    expires: Instant,
}

pub struct JwtVerifier {
    issuer: String,
    audience: Vec<String>,
    algorithm: Algorithm,
    endpoint: http::Uri,
    client: HttpClient,
    keys: Mutex<Option<CachedKeys>>,
    refreshed: Mutex<Option<Instant>>,
    refresh: Mutex<()>,
    cooldown: Duration,
}

impl JwtVerifier {
    pub(crate) fn quick_tunnel() -> Result<Arc<Self>> {
        Self::new(
            "https://login.trycloudflare.com/.well-known/jwks.json",
            "https://login.trycloudflare.com",
            vec!["cloudflared-quick-tunnel".into()],
            Algorithm::ES256,
            Duration::from_secs(60),
        )
        .map(Arc::new)
    }

    pub(crate) async fn verify_broker(&self, token: &str) -> Result<Value> {
        if self.algorithm != Algorithm::ES256
            || self.issuer != "https://login.trycloudflare.com"
            || self.audience != ["cloudflared-quick-tunnel"]
        {
            bail!("JWT verifier is not bound to the Quick Tunnel broker");
        }
        self.verify_with(token, &self.validation(), true).await
    }
    pub fn access(config: &crate::config::AccessConfig) -> Result<Arc<Self>> {
        if config.team_name.is_empty()
            || config.team_name.len() > 63
            || config.team_name.starts_with('-')
            || config.team_name.ends_with('-')
            || !config
                .team_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("Access teamName must be a nonempty DNS label");
        }
        let suffix = if config.environment == "fed" {
            "fed.cloudflareaccess.com"
        } else {
            "cloudflareaccess.com"
        };
        let issuer = format!("https://{}.{}", config.team_name, suffix);
        Self::new(
            &format!("{issuer}/cdn-cgi/access/certs"),
            &issuer,
            config.aud_tag.clone(),
            Algorithm::RS256,
            // The frozen Access JWKS discovery cache limits refreshes to one per minute.
            Duration::from_secs(60),
        )
        .map(Arc::new)
    }

    fn new(
        endpoint: &str,
        issuer: &str,
        audience: Vec<String>,
        algorithm: Algorithm,
        cooldown: Duration,
    ) -> Result<Self> {
        crypto_provider();
        let endpoint: http::Uri = endpoint.parse().context("invalid JWKS endpoint")?;
        if endpoint.scheme_str() != Some("https") {
            bail!("JWKS endpoint requires HTTPS");
        }
        Self::build(endpoint, issuer, audience, algorithm, cooldown)
    }

    fn build(
        endpoint: http::Uri,
        issuer: &str,
        audience: Vec<String>,
        algorithm: Algorithm,
        cooldown: Duration,
    ) -> Result<Self> {
        Ok(Self {
            issuer: issuer.into(),
            audience,
            algorithm,
            endpoint,
            client: http_client()?,
            keys: Mutex::new(None),
            refreshed: Mutex::new(None),
            refresh: Mutex::new(()),
            cooldown,
        })
    }

    fn validation(&self) -> Validation {
        let mut validation = Validation::new(self.algorithm);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.audience);
        validation.validate_nbf = true;
        validation.leeway = if self.algorithm == Algorithm::ES256 {
            30
        } else {
            0
        };
        validation
    }

    pub async fn verify(&self, token: &str) -> Result<Value> {
        self.verify_with(token, &self.validation(), false).await
    }

    async fn verify_with(
        &self,
        token: &str,
        validation: &Validation,
        strict_header: bool,
    ) -> Result<Value> {
        if validation != &self.validation() {
            bail!("JWT validation cannot weaken the bound policy");
        }
        if token.len() > 64 * 1024 {
            bail!("JWT exceeds maximum size");
        }
        let header = decode_header(token).context("invalid JWT header")?;
        if header.alg != self.algorithm
            || header.jwk.is_some()
            || header.jku.is_some()
            || header.x5u.is_some()
            || header
                .crit
                .as_ref()
                .is_some_and(|fields| !fields.is_empty())
        {
            bail!("unsupported JWT header or algorithm");
        }
        if strict_header && header.typ.as_deref() != Some("JWT") {
            bail!("JWT type header must be JWT");
        }
        let key_id = header.kid.as_deref().context("JWT key ID is missing")?;
        if key_id.is_empty() || key_id.len() > 128 || key_id.trim() != key_id {
            bail!("invalid JWT key ID");
        }
        let key = self.key(key_id, false).await?;
        match decode::<Value>(token, &key, validation) {
            Ok(data) => Ok(data.claims),
            Err(error)
                if matches!(
                    error.kind(),
                    jsonwebtoken::errors::ErrorKind::InvalidSignature
                ) =>
            {
                let key = self.key(key_id, true).await?;
                Ok(decode::<Value>(token, &key, validation)?.claims)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn audience(&self) -> &[String] {
        &self.audience
    }

    #[cfg(test)]
    pub(crate) fn test_endpoint(
        endpoint: &str,
        issuer: &str,
        audience: Vec<String>,
        algorithm: Algorithm,
        cooldown: Duration,
    ) -> Result<Self> {
        crypto_provider();
        let endpoint: http::Uri = endpoint.parse()?;
        if endpoint.scheme_str() != Some("http")
            || !endpoint.host().is_some_and(|host| {
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            })
        {
            bail!("synthetic JWKS endpoint must be loopback HTTP");
        }
        Self::build(endpoint, issuer, audience, algorithm, cooldown)
    }

    async fn key(&self, key_id: &str, force: bool) -> Result<DecodingKey> {
        if !force && let Some(key) = self.cached_key(key_id).await? {
            return Ok(key);
        }
        let generation = *self.refreshed.lock().await;
        let _refresh = self.refresh.lock().await;
        if *self.refreshed.lock().await != generation {
            return self
                .cached_key(key_id)
                .await?
                .context("JWT verification key unavailable after refresh");
        }
        if !force && let Some(key) = self.cached_key(key_id).await? {
            return Ok(key);
        }
        if self
            .refreshed
            .lock()
            .await
            .is_some_and(|last| last.elapsed() < self.cooldown)
        {
            bail!("JWKS refresh cooldown active; verification key unavailable");
        }
        *self.refreshed.lock().await = Some(Instant::now());
        let fetch = async {
            let attempts = if self.algorithm == Algorithm::ES256 {
                3
            } else {
                1
            };
            for attempt in 0..attempts {
                match self.fetch_keys().await {
                    Ok(keys) => return Ok(keys),
                    Err(error) if attempt + 1 == attempts => return Err(error),
                    Err(_) => tokio::time::sleep(Duration::from_millis(100 * (1 << attempt))).await,
                }
            }
            unreachable!()
        };
        let keys = tokio::time::timeout(Duration::from_secs(5), fetch)
            .await
            .context("JWKS refresh timeout")??;
        *self.keys.lock().await = Some(CachedKeys {
            keys,
            expires: Instant::now() + Duration::from_secs(24 * 3600),
        });
        self.cached_key(key_id)
            .await?
            .context("JWT verification key unavailable")
    }

    async fn fetch_keys(&self) -> Result<JwkSet> {
        let request = http::Request::builder()
            .uri(self.endpoint.clone())
            .header(http::header::USER_AGENT, "cloudflared-rust")
            .body(Full::new(Bytes::new()))?;
        let mut response = self
            .client
            .request(request)
            .await
            .context("JWKS request failed")?;
        if response.status() != 200 {
            bail!("JWKS endpoint did not return HTTP 200");
        }
        let body = bounded_body(&mut response, 1 << 20).await?;
        serde_json::from_slice(&body).map_err(|_| anyhow::anyhow!("invalid JWKS response"))
    }

    async fn cached_key(&self, key_id: &str) -> Result<Option<DecodingKey>> {
        let keys = self.keys.lock().await;
        let Some(cache) = keys.as_ref().filter(|cache| cache.expires > Instant::now()) else {
            return Ok(None);
        };
        let mut matching = cache
            .keys
            .keys
            .iter()
            .filter(|key| key.common.key_id.as_deref() == Some(key_id));
        let Some(key) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            bail!("JWKS contains duplicate key IDs");
        }
        let value = serde_json::to_value(key)?;
        let expected = if self.algorithm == Algorithm::RS256 {
            "RS256"
        } else if self.algorithm == Algorithm::ES256 {
            "ES256"
        } else {
            bail!("unsupported verification algorithm");
        };
        if value
            .get("alg")
            .and_then(Value::as_str)
            .is_some_and(|alg| alg != expected)
            || value
                .get("use")
                .and_then(Value::as_str)
                .is_some_and(|usage| usage != "sig")
        {
            bail!("JWKS key does not permit the required signature algorithm");
        }
        if self.algorithm == Algorithm::ES256
            && (value.get("kty").and_then(Value::as_str) != Some("EC")
                || value.get("crv").and_then(Value::as_str) != Some("P-256"))
        {
            bail!("Quick Tunnel JWKS key must be P-256");
        }
        Ok(Some(DecodingKey::from_jwk(key)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn verifies_signature_issuer_audience_expiry_and_rejects_algorithm_confusion() {
        crypto_provider();
        let rsa = boring::rsa::Rsa::generate(2048).unwrap();
        let jwks = serde_json::json!({"keys":[{"kty":"RSA","kid":"synthetic","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_vec())}]});
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = requests.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let body = Bytes::from(serde_json::to_vec(&jwks).unwrap());
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(socket),
                    hyper::service::service_fn(move |_| {
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let body = body.clone();
                        async move { Ok::<_, std::io::Error>(http::Response::new(Full::new(body))) }
                    }),
                )
                .await;
        });
        let verifier = Arc::new(
            JwtVerifier::test_endpoint(
                &format!("http://{address}/certs"),
                "https://synthetic.cloudflareaccess.com",
                vec!["app-aud".into()],
                Algorithm::RS256,
                Duration::from_secs(60),
            )
            .unwrap(),
        );
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("synthetic".into());
        let key = EncodingKey::from_rsa_pem(&rsa.private_key_to_pem().unwrap()).unwrap();
        let now = jsonwebtoken::get_current_timestamp();
        let claims =
            serde_json::json!({"iss":verifier.issuer,"aud":["app-aud"],"exp":now+60,"nbf":now-1});
        let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        verifier.verify(&token).await.unwrap();
        let mut tampered = token.as_bytes().to_vec();
        let signature = token.rfind('.').unwrap() + 1;
        tampered[signature] = if tampered[signature] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(
            verifier
                .verify(std::str::from_utf8(&tampered).unwrap())
                .await
                .is_err()
        );
        let mut weakened = verifier.validation();
        weakened.validate_exp = false;
        assert!(
            verifier
                .verify_with(&token, &weakened, false)
                .await
                .is_err()
        );
        weakened = verifier.validation();
        weakened.validate_aud = false;
        assert!(
            verifier
                .verify_with(&token, &weakened, false)
                .await
                .is_err()
        );
        for (name, value) in [
            (
                "iss",
                serde_json::json!("https://wrong.cloudflareaccess.com"),
            ),
            ("aud", serde_json::json!(["wrong"])),
            ("exp", serde_json::json!(now - 60)),
            ("nbf", serde_json::json!(now + 600)),
        ] {
            let mut bad = claims.clone();
            bad[name] = value;
            assert!(
                verifier
                    .verify(&jsonwebtoken::encode(&header, &bad, &key).unwrap())
                    .await
                    .is_err()
            );
        }
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("synthetic".into());
        assert!(
            verifier
                .verify(
                    &jsonwebtoken::encode(
                        &header,
                        &claims,
                        &EncodingKey::from_secret(b"synthetic")
                    )
                    .unwrap()
                )
                .await
                .is_err()
        );
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..64 {
            let verifier = verifier.clone();
            let mut unknown = Header::new(Algorithm::RS256);
            unknown.kid = Some(format!("unknown-{index}"));
            let token = jsonwebtoken::encode(&unknown, &claims, &key).unwrap();
            tasks.spawn(async move {
                assert!(verifier.verify(&token).await.is_err());
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        verifier.verify(&token).await.unwrap();
        server.abort();
    }

    #[test]
    fn production_policy_rejects_empty_team_and_plaintext_jwks() {
        for team in ["", "-team", "team-", "team/escape", "team.example"] {
            let config = crate::config::AccessConfig {
                team_name: team.into(),
                ..Default::default()
            };
            assert!(JwtVerifier::access(&config).is_err());
        }
        assert!(
            JwtVerifier::new(
                "http://127.0.0.1:1234/certs",
                "https://synthetic.cloudflareaccess.com",
                vec!["app-aud".into()],
                Algorithm::RS256,
                Duration::from_secs(60)
            )
            .is_err()
        );
    }
}
