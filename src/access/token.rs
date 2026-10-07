use super::{ApplicationUrl, HttpClient, bounded_body, http_client, jwt::JwtVerifier};
use anyhow::{Context, Result, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use bytes::Bytes;
use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, generic_array::GenericArray},
};
use http_body_util::Full;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Clone)]
pub struct AppInfo {
    auth_domain: String,
    audience: String,
    hostname: String,
}
impl AppInfo {
    pub fn issuer(&self) -> String {
        format!("https://{}", self.auth_domain)
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
}
#[derive(Deserialize)]
struct MetadataClaims {
    #[serde(rename = "type")]
    kind: String,
    hostname: String,
    auth_domain: String,
    aud: String,
    #[serde(default)]
    app_hostname: String,
    iat: u64,
}
pub struct TokenClient {
    client: HttpClient,
    directory: PathBuf,
    transfer_store: String,
    verifiers: std::sync::Mutex<std::collections::BTreeMap<String, Arc<JwtVerifier>>>,
    #[cfg(test)]
    jwks_override: Option<String>,
}
impl TokenClient {
    pub fn new(directory: PathBuf, fedramp: bool) -> Result<Self> {
        super::jwt::crypto_provider();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .context("cannot create Access credential directory")?;
        Ok(Self {
            client: http_client()?,
            directory,
            transfer_store: if fedramp {
                "https://login.fed.cloudflareaccess.org/"
            } else {
                "https://login.cloudflareaccess.org/"
            }
            .into(),
            verifiers: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(test)]
            jwks_override: None,
        })
    }
    pub fn default_directory() -> Result<PathBuf> {
        Ok(
            PathBuf::from(std::env::var_os("HOME").context("home directory unavailable")?)
                .join(".cloudflared"),
        )
    }
    pub async fn discover(&self, application: &ApplicationUrl) -> Result<AppInfo> {
        if application.scheme() != "https" {
            #[cfg(test)]
            if Some(application.hostname()).is_some_and(|host| {
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            }) {
                return self.discover_inner(application).await;
            }
            bail!("Access discovery requires an HTTPS application URL");
        }
        self.discover_inner(application).await
    }
    async fn discover_inner(&self, application: &ApplicationUrl) -> Result<AppInfo> {
        let mut request = http::Request::builder()
            .method("HEAD")
            .uri(application.request_uri()?)
            .header("cf-access-metadata-request", "true")
            .header(http::header::USER_AGENT, "cloudflared-rust")
            .body(Full::new(Bytes::new()))?;
        application.basic_auth(request.headers_mut())?;
        let response = tokio::time::timeout(Duration::from_secs(7), self.client.request(request))
            .await
            .context("Access discovery timeout")?
            .context("Access discovery request failed")?;
        let token = response
            .headers()
            .get("cf-access-metadata")
            .context("failed to find Access application metadata")?
            .to_str()
            .context("invalid Access metadata header")?;
        if token.len() > 64 * 1024 {
            bail!("Access metadata exceeds maximum size");
        }
        // Unverified claims select only a constrained Cloudflare JWKS namespace.
        let unverified: MetadataClaims = jsonwebtoken::dangerous::insecure_decode_claims(token)
            .map_err(|_| anyhow::anyhow!("invalid Access metadata JWT"))?;
        let domain = canonical_auth_domain(&unverified.auth_domain)?;
        let endpoint = self.certs_endpoint(&domain);
        let keys = self.jwks(&domain, &endpoint, false).await?;
        let header = decode_header(token)
            .map_err(|_| anyhow::anyhow!("invalid Access metadata JWT header"))?;
        if header.alg != Algorithm::RS256
            || header.jwk.is_some()
            || header.jku.is_some()
            || header.x5u.is_some()
            || header.crit.as_ref().is_some_and(|crit| !crit.is_empty())
        {
            bail!("unsupported Access metadata JWT header");
        }
        let decode_claims = |keys: &JwkSet| -> Result<MetadataClaims> {
            let kid = header
                .kid
                .as_deref()
                .context("Access metadata key ID missing")?;
            let mut matches = keys
                .keys
                .iter()
                .filter(|key| key.common.key_id.as_deref() == Some(kid));
            let key = matches
                .next()
                .context("Access metadata verification key unavailable")?;
            if matches.next().is_some() {
                bail!("Access metadata key ID ambiguous");
            }
            let mut validation = Validation::new(Algorithm::RS256);
            // Signed discovery metadata uses iat freshness, not identity-token exp/iss.
            validation.required_spec_claims.clear();
            validation.validate_exp = false;
            validation.set_audience(&[&unverified.aud]);
            Ok(
                decode::<MetadataClaims>(token, &DecodingKey::from_jwk(key)?, &validation)
                    .map_err(|_| anyhow::anyhow!("Access metadata signature validation failed"))?
                    .claims,
            )
        };
        let claims = match decode_claims(&keys) {
            Ok(claims) => claims,
            Err(_) => decode_claims(&self.jwks(&domain, &endpoint, true).await?)?,
        };
        if claims.kind != "match"
            || !claims.hostname.eq_ignore_ascii_case(application.hostname())
            || claims.aud.is_empty()
            || canonical_auth_domain(&claims.auth_domain)? != domain
        {
            bail!("Access metadata does not bind the requested application");
        }
        let now = jsonwebtoken::get_current_timestamp();
        if claims.iat == 0
            || claims.iat.saturating_add(24 * 3600) < now
            || claims.iat > now.saturating_add(300)
        {
            bail!("Access metadata issued-at time is invalid or stale");
        }
        let hostname = if claims.app_hostname.is_empty() {
            claims.hostname
        } else {
            claims.app_hostname
        };
        safe_component(&hostname)?;
        safe_component(&claims.aud)?;
        Ok(AppInfo {
            auth_domain: domain,
            audience: claims.aud,
            hostname,
        })
    }
    fn certs_endpoint(&self, domain: &str) -> String {
        #[cfg(test)]
        if let Some(endpoint) = &self.jwks_override {
            return endpoint.clone();
        }
        format!("https://{domain}/cdn-cgi/access/certs")
    }
    async fn jwks(&self, domain: &str, endpoint: &str, force: bool) -> Result<JwkSet> {
        let path = self.directory.join(format!("{domain}-jwks"));
        if let Ok(metadata) = std::fs::metadata(&path)
            && let Ok(age) = metadata.modified()?.elapsed()
            && age <= Duration::from_secs(24 * 3600)
            && (!force || age < Duration::from_secs(60))
        {
            let bytes = read_bounded(&path, 1 << 20)?;
            if let Ok(keys) = serde_json::from_slice::<JwkSet>(&bytes)
                && !keys.keys.is_empty()
            {
                return Ok(keys);
            }
        }
        let request = http::Request::builder()
            .uri(endpoint)
            .body(Full::new(Bytes::new()))?;
        let fetch = async {
            let mut response = self
                .client
                .request(request)
                .await
                .context("Access JWKS request failed")?;
            if response.status() != 200 {
                bail!("Access JWKS did not return HTTP 200");
            }
            let bytes = bounded_body(&mut response, 1 << 20).await?;
            let keys: JwkSet = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid Access JWKS"))?;
            crate::administration::credentials::atomic_replace(&path, &bytes, 0o600)?;
            Ok(keys)
        };
        tokio::time::timeout(Duration::from_secs(10), fetch)
            .await
            .context("Access JWKS timeout")?
    }
    fn token_path(&self, info: &AppInfo) -> Result<PathBuf> {
        safe_component(&info.hostname)?;
        safe_component(&info.audience)?;
        Ok(self.directory.join(format!(
            "{}-{}-token",
            info.hostname.replace(['/', '*'], "-"),
            info.audience.replace(['/', '*'], "-")
        )))
    }
    fn identity_verifier(&self, info: &AppInfo) -> Result<Arc<JwtVerifier>> {
        let identity = format!("{}|{}", info.auth_domain, info.audience);
        let mut verifiers = self
            .verifiers
            .lock()
            .map_err(|_| anyhow::anyhow!("Access verifier cache lock poisoned"))?;
        if let Some(verifier) = verifiers.get(&identity) {
            return Ok(verifier.clone());
        }
        #[cfg(test)]
        if let Some(endpoint) = &self.jwks_override {
            let verifier = JwtVerifier::test_endpoint(
                endpoint,
                &info.issuer(),
                vec![info.audience.clone()],
                Algorithm::RS256,
                Duration::from_secs(60),
            )
            .map(Arc::new)?;
            verifiers.insert(identity, verifier.clone());
            return Ok(verifier);
        }
        let team = info
            .auth_domain
            .strip_suffix(".fed.cloudflareaccess.com")
            .or_else(|| info.auth_domain.strip_suffix(".cloudflareaccess.com"))
            .context("invalid Access authentication domain")?;
        let verifier = JwtVerifier::access(&crate::config::AccessConfig {
            team_name: team.into(),
            aud_tag: vec![info.audience.clone()],
            required: true,
            environment: if info.auth_domain.ends_with(".fed.cloudflareaccess.com") {
                "fed"
            } else {
                ""
            }
            .into(),
        })?;
        verifiers.insert(identity, verifier.clone());
        Ok(verifier)
    }
    pub async fn cached(&self, info: &AppInfo) -> Result<String> {
        let path = self.token_path(info)?;
        let token = String::from_utf8(read_bounded(&path, 64 * 1024)?)
            .context("invalid Access token encoding")?;
        if self.identity_verifier(info)?.verify(&token).await.is_err() {
            bail!("cached Access token is expired or invalid for the application");
        }
        Ok(token)
    }
    pub async fn invalidate(&self, info: &AppInfo, rejected: &str) -> Result<()> {
        let path = self.token_path(info)?;
        let _lease = CacheLock::acquire(&path).await?;
        if std::fs::read(&path).ok().as_deref() != Some(rejected.as_bytes()) {
            return Ok(());
        }
        match std::fs::remove_file(self.token_path(info)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    pub async fn fetch(
        &self,
        application: &ApplicationUrl,
        info: &AppInfo,
        host_only: bool,
        auto_close: bool,
        browser: impl FnOnce(&str) -> Result<()>,
    ) -> Result<String> {
        if let Ok(token) = self.cached(info).await {
            return Ok(token);
        }
        let path = self.token_path(info)?;
        let _lock = CacheLock::acquire(&path).await?;
        if let Ok(token) = self.cached(info).await {
            return Ok(token);
        }
        let org_path = self
            .directory
            .join(format!("{}-org-token", info.auth_domain));
        if let Ok(org) = read_bounded(&org_path, 64 * 1024)
            && let Ok(org) = String::from_utf8(org)
            && let Ok(token) = self.exchange_org(application, &org, info).await
            && self.identity_verifier(info)?.verify(&token).await.is_ok()
        {
            crate::administration::credentials::atomic_replace(&path, token.as_bytes(), 0o600)?;
            return Ok(token);
        }
        let key = TransferKey::new()?;
        let login = transfer_url(
            application,
            &info.audience,
            &key.public_key(),
            host_only,
            auto_close,
        )?;
        let companion = companion_path(&path);
        crate::administration::credentials::atomic_replace(&companion, login.as_bytes(), 0o600)?;
        browser(&login)?;
        let mut endpoint = url::Url::parse(&self.transfer_store)?;
        endpoint.set_path(&format!("/transfer/{}", key.public_key()));
        for _ in 0..10 {
            let request = http::Request::builder()
                .uri(endpoint.as_str())
                .header(http::header::USER_AGENT, "cloudflared-rust")
                .body(Full::new(Bytes::new()))?;
            let poll = async {
                let mut response = self
                    .client
                    .request(request)
                    .await
                    .context("Access transfer request failed")?;
                if response.status().as_u16() >= 500 {
                    bail!("Access transfer service returned a server error");
                }
                if response.status() != 200 {
                    return Ok(None);
                }
                let server_key = response
                    .headers()
                    .get("service-public-key")
                    .context("Access transfer key missing")?
                    .to_str()?
                    .to_owned();
                let body = bounded_body(&mut response, 1 << 20).await?;
                let encrypted = STANDARD
                    .decode(&body)
                    .context("invalid Access transfer encoding")?;
                let plaintext = key.decrypt(&encrypted, &server_key)?;
                let result: TransferResult = serde_json::from_slice(&plaintext)
                    .map_err(|_| anyhow::anyhow!("invalid Access transfer response"))?;
                Ok(Some(result))
            };
            if let Some(result) = tokio::time::timeout(Duration::from_secs(60), poll)
                .await
                .context("Access transfer timeout")??
            {
                self.identity_verifier(info)?
                    .verify(&result.app_token)
                    .await
                    .context("transferred token does not bind the Access application")?;
                if !result.org_token.is_empty() {
                    crate::administration::credentials::atomic_replace(
                        &org_path,
                        result.org_token.as_bytes(),
                        0o600,
                    )?;
                }
                crate::administration::credentials::atomic_replace(
                    &path,
                    result.app_token.as_bytes(),
                    0o600,
                )?;
                let _ = std::fs::remove_file(&companion);
                return Ok(result.app_token);
            }
        }
        bail!("Failed to fetch Access token")
    }
    async fn exchange_org(
        &self,
        application: &ApplicationUrl,
        org: &str,
        info: &AppInfo,
    ) -> Result<String> {
        let mut current = application.clone();
        let mut session = None;
        let mut was_authorized = false;
        for _ in 0..10 {
            let mut request = http::Request::builder()
                .method("HEAD")
                .uri(current.request_uri()?)
                .header(http::header::USER_AGENT, "cloudflared-rust");
            if current.path().contains("/cdn-cgi/access/login")
                && current.hostname() == info.auth_domain
            {
                request = request.header(http::header::COOKIE, format!("CF_Authorization={org}"));
            }
            if current.path().contains("/cdn-cgi/access/authorized")
                && let Some(session) = &session
            {
                request = request.header(http::header::COOKIE, format!("CF_AppSession={session}"));
            }
            let mut request = request.body(Full::new(Bytes::new()))?;
            current.basic_auth(request.headers_mut())?;
            let response =
                tokio::time::timeout(Duration::from_secs(7), self.client.request(request))
                    .await??;
            for header in response.headers().get_all(http::header::SET_COOKIE) {
                if let Ok(header) = header.to_str()
                    && let Some((name, value)) =
                        header.split(';').next().unwrap_or("").split_once('=')
                {
                    if name == "CF_Authorization" {
                        return Ok(value.into());
                    }
                    if name == "CF_AppSession" {
                        session = Some(value.to_owned());
                    }
                }
            }
            if was_authorized || !response.status().is_redirection() {
                break;
            }
            let next = current.join(
                response
                    .headers()
                    .get(http::header::LOCATION)
                    .context("Access redirect missing location")?
                    .to_str()?,
            )?;
            if next.scheme() != "https"
                || !(next.hostname() == application.hostname()
                    || next.hostname() == info.auth_domain)
            {
                bail!("Access SSO redirect left the bound application/authentication hosts");
            }
            was_authorized = current.path().contains("/cdn-cgi/access/authorized");
            current = next;
        }
        bail!("Access SSO exchange did not return an application token")
    }
    pub async fn verify_at_edge(
        &self,
        application: &ApplicationUrl,
        info: &AppInfo,
        auto_close: bool,
        browser: impl Fn(&str) -> Result<()>,
    ) -> Result<String> {
        for _ in 0..2 {
            let token = self
                .fetch(application, info, false, auto_close, &browser)
                .await?;
            let mut check = application.clone();
            let mut query = check
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>();
            query.retain(|(key, _)| key != "cloudflared_token_check");
            query.push(("cloudflared_token_check".into(), "true".into()));
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query)
                .finish();
            check.set_query(Some(&encoded));
            let mut request = http::Request::builder()
                .uri(check.request_uri()?)
                .header("cf-access-token", &token)
                .header(http::header::USER_AGENT, "cloudflared-rust")
                .body(Full::new(Bytes::new()))?;
            check.basic_auth(request.headers_mut())?;
            let response =
                tokio::time::timeout(Duration::from_secs(5), self.client.request(request))
                    .await??;
            let login = response.status() == 302
                && response
                    .headers()
                    .get(http::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|location| check.join(location).ok())
                    .is_some_and(|url| url.path().starts_with("/cdn-cgi/access/login"));
            if !login {
                return Ok(token);
            }
            self.invalidate(info, &token).await?;
        }
        bail!("failed to verify Access token")
    }
}
fn canonical_auth_domain(raw: &str) -> Result<String> {
    let url = url::Url::parse(&format!("https://{raw}"))
        .context("invalid Access authentication domain")?;
    let host = url
        .host_str()
        .context("Access authentication hostname missing")?
        .to_ascii_lowercase();
    if !host.ends_with(".cloudflareaccess.com") {
        bail!("Access authentication domain is outside Cloudflare Access");
    }
    Ok(host)
}
fn safe_component(value: &str) -> Result<()> {
    if value.is_empty() || value.contains(['\0', '\\']) || value == ".." {
        bail!("invalid Access cache identity");
    }
    Ok(())
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut body)?;
    if body.len() > limit {
        bail!("Access cache exceeds maximum size");
    }
    Ok(body)
}
fn companion_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.url", path.to_string_lossy()))
}
#[derive(Deserialize)]
struct TransferResult {
    app_token: String,
    #[serde(default)]
    org_token: String,
}
struct TransferKey(SecretKey);
impl TransferKey {
    fn new() -> Result<Self> {
        let mut secret = [0; 32];
        boring::rand::rand_bytes(&mut secret)?;
        Ok(Self(SecretKey::from_bytes(secret)))
    }
    fn public_key(&self) -> String {
        URL_SAFE.encode(self.0.public_key().as_bytes())
    }
    fn decrypt(&self, body: &[u8], server_key: &str) -> Result<Vec<u8>> {
        if body.len() < 24 {
            bail!("Access transfer missing nonce");
        }
        let key: [u8; 32] = URL_SAFE
            .decode(server_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Access transfer key must be 32 bytes"))?;
        SalsaBox::new(&PublicKey::from(key), &self.0)
            .decrypt(GenericArray::from_slice(&body[..24]), &body[24..])
            .map_err(|_| anyhow::anyhow!("Access transfer authentication failed"))
    }
}
pub(crate) fn transfer_url(
    application: &ApplicationUrl,
    audience: &str,
    key: &str,
    host_only: bool,
    auto_close: bool,
) -> Result<String> {
    let mut base = application.clone();
    if host_only {
        base.set_path("");
    }
    let mut query: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (key, value) in application.query_pairs() {
        query
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    query.insert("aud".into(), vec![audience.into()]);
    query.insert("token".into(), vec![key.into()]);
    base.set_query(Some(&query_string(&query)));
    let redirect = if host_only {
        format!("{}?{}", base.authority_prefix(), query_string(&query))
    } else {
        base.as_str().to_owned()
    };
    query.insert("redirect_url".into(), vec![redirect]);
    query.insert("send_org_token".into(), vec!["true".into()]);
    query.insert("edge_token_transfer".into(), vec!["true".into()]);
    if auto_close {
        query.insert("close_interstitial".into(), vec!["true".into()]);
    }
    base.set_path("/cdn-cgi/access/cli");
    base.set_query(Some(&query_string(&query)));
    Ok(base.as_str().to_owned())
}
fn query_string(query: &std::collections::BTreeMap<String, Vec<String>>) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, values) in query {
        for value in values {
            serializer.append_pair(key, value);
        }
    }
    serializer.finish()
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
struct LockOwner {
    pid: u32,
    start_time: u64,
    #[serde(default)]
    id: String,
}
struct CacheLock {
    path: PathBuf,
    owner: LockOwner,
    identity: std::fs::Metadata,
    _guard: std::fs::File,
}
impl CacheLock {
    async fn acquire(token: &Path) -> Result<Self> {
        let path = PathBuf::from(format!("{}.lock", token.to_string_lossy()));
        let mut random = [0; 16];
        boring::rand::rand_bytes(&mut random)?;
        let owner = LockOwner {
            pid: std::process::id(),
            start_time: process_start(std::process::id())?,
            id: random.iter().map(|byte| format!("{byte:02x}")).collect(),
        };
        let started = std::time::Instant::now();
        let guard = credential_guard(token, started + Duration::from_secs(600)).await?;
        loop {
            if crate::administration::credentials::atomic_create(
                &path,
                &serde_json::to_vec(&owner)?,
                0o600,
            )
            .is_ok()
            {
                let identity = std::fs::symlink_metadata(&path)?;
                return Ok(Self {
                    path,
                    owner,
                    identity,
                    _guard: guard,
                });
            }
            if !path.exists() {
                bail!("cannot acquire Access cache lock");
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("Access cache lock cannot be a symlink");
            }
            let body = read_bounded(&path, 16 * 1024)?;
            let stale = match serde_json::from_slice::<LockOwner>(&body) {
                Ok(previous) => owner_is_stale(&previous)?,
                // An incomplete Go write or unreadable owner is not evidence of death.
                Err(_) => false,
            };
            if stale {
                match remove_unchanged(&path, &metadata, &body) {
                    Ok(()) => continue,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            if started.elapsed() > Duration::from_secs(600) {
                bail!("timed out waiting for Access cache lock");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}
impl Drop for CacheLock {
    fn drop(&mut self) {
        if let Ok(body) = serde_json::to_vec(&self.owner) {
            let _ = remove_unchanged(&self.path, &self.identity, &body);
        }
    }
}
pub(super) async fn credential_guard(
    path: &Path,
    deadline: std::time::Instant,
) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let guard_path = path.with_file_name(format!(
        "{}.guard",
        path.file_name()
            .context("Access credential filename missing")?
            .to_string_lossy()
    ));
    let guard = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(guard_path)
        .context("cannot open Access credential guard")?;
    loop {
        match guard.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                if std::time::Instant::now() >= deadline {
                    bail!("timed out waiting for Access credential guard");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(std::fs::TryLockError::Error(_)) => bail!("cannot lock Access credential guard"),
        }
    }
    Ok(guard)
}
fn owner_is_stale(owner: &LockOwner) -> Result<bool> {
    match std::fs::metadata(format!("/proc/{}/stat", owner.pid)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(_) => bail!("cannot determine Access cache lock ownership"),
        Ok(_) => Ok(process_start(owner.pid)
            .context("cannot determine Access cache lock ownership")?
            .abs_diff(owner.start_time)
            > 1000),
    }
}
fn remove_unchanged(path: &Path, previous: &std::fs::Metadata, body: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let current = std::fs::symlink_metadata(path)?;
    if current.file_type().is_symlink()
        || current.dev() != previous.dev()
        || current.ino() != previous.ino()
        || std::fs::read(path)? != body
    {
        return Ok(());
    }
    std::fs::remove_file(path)
}
fn process_start(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, rest) = stat.rsplit_once(')').context("invalid process stat")?;
    let ticks: u64 = rest
        .split_whitespace()
        .nth(19)
        .context("process start missing")?
        .parse()?;
    let boot: u64 = std::fs::read_to_string("/proc/stat")?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .context("boot time missing")?
        .parse()?;
    let frequency = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if frequency <= 0 {
        bail!("clock tick frequency unavailable");
    }
    Ok(boot * 1000 + ticks * 1000 / frequency as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{EncodingKey, Header};
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn lock_preserves_live_unknown_and_replacement_owners() {
        let directory = std::env::temp_dir().join(format!("access-lock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let token = directory.join("app-token");
        let lock = CacheLock::acquire(&token).await.unwrap();
        assert!(!owner_is_stale(&lock.owner).unwrap());
        let waiting =
            tokio::time::timeout(Duration::from_millis(20), CacheLock::acquire(&token)).await;
        assert!(waiting.is_err());
        let replacement = LockOwner {
            pid: std::process::id(),
            start_time: process_start(std::process::id()).unwrap(),
            id: "replacement-owner".into(),
        };
        crate::administration::credentials::atomic_replace(
            &lock.path,
            &serde_json::to_vec(&replacement).unwrap(),
            0o600,
        )
        .unwrap();
        let path = lock.path.clone();
        drop(lock);
        assert_eq!(
            serde_json::from_slice::<LockOwner>(&std::fs::read(&path).unwrap())
                .unwrap()
                .id,
            replacement.id
        );
        std::fs::write(&path, b"incomplete").unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), CacheLock::acquire(&token))
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"incomplete");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn curl_never_spawns_after_auth_or_verification_failure() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use std::os::unix::fs::PermissionsExt;
        super::super::jwt::crypto_provider();
        let rsa = boring::rsa::Rsa::generate(2048).unwrap();
        let signing = EncodingKey::from_rsa_pem(&rsa.private_key_to_pem().unwrap()).unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("synthetic".into());
        let now = jsonwebtoken::get_current_timestamp();
        let jwt=jsonwebtoken::encode(&header,&serde_json::json!({"iss":"https://synthetic.cloudflareaccess.com","aud":"synthetic-aud","exp":now+300}),&signing).unwrap();
        let metadata=jsonwebtoken::encode(&header,&serde_json::json!({"type":"match","hostname":"127.0.0.1","app_hostname":"app.example.invalid","auth_domain":"synthetic.cloudflareaccess.com","aud":"synthetic-aud","iat":now}),&signing).unwrap();
        let keys=serde_json::to_vec(&serde_json::json!({"keys":[{"kty":"RSA","kid":"synthetic","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_vec())}]})).unwrap();
        let mode = Arc::new(AtomicUsize::new(0));
        let checks = Arc::new(AtomicUsize::new(0));
        let cache = Arc::new(std::sync::Mutex::new(None::<PathBuf>));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_mode = mode.clone();
        let server_checks = checks.clone();
        let server_cache = cache.clone();
        let server_jwt = jwt.clone();
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mode = server_mode.clone();
                let checks = server_checks.clone();
                let cache = server_cache.clone();
                let jwt = server_jwt.clone();
                let metadata = metadata.clone();
                let keys = keys.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |request: http::Request<hyper::body::Incoming>| {
                            let mode = mode.clone();
                            let checks = checks.clone();
                            let cache = cache.clone();
                            let jwt = jwt.clone();
                            let metadata = metadata.clone();
                            let keys = keys.clone();
                            async move {
                                let response = if request.uri().path() == "/certs" {
                                    http::Response::new(Full::new(Bytes::from(keys)))
                                } else if request.method() == http::Method::HEAD {
                                    assert_eq!(request.uri().path(), "/a/../b");
                                    http::Response::builder()
                                        .header("cf-access-metadata", metadata)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap()
                                } else {
                                    assert_eq!(request.headers()["cf-access-token"], jwt);
                                    assert!(
                                        request
                                            .uri()
                                            .query()
                                            .unwrap()
                                            .contains("cloudflared_token_check=true")
                                    );
                                    checks.fetch_add(1, Ordering::SeqCst);
                                    match mode.load(Ordering::SeqCst) {
                                        1 => {
                                            return Err(std::io::Error::other(
                                                "synthetic verification transport failure",
                                            ));
                                        }
                                        2 => {
                                            if let Some(path) = cache.lock().unwrap().as_ref() {
                                                std::fs::remove_file(path).unwrap();
                                            }
                                        }
                                        _ => {}
                                    }
                                    http::Response::new(Full::new(Bytes::new()))
                                };
                                Ok::<_, std::io::Error>(response)
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        let directory = std::env::temp_dir().join(format!("access-curl-{}", uuid::Uuid::new_v4()));
        let mut client = TokenClient::new(directory.clone(), false).unwrap();
        client.jwks_override = Some(format!("http://{address}/certs"));
        let app = ApplicationUrl::curl(&format!("http://{address}/a/../b")).unwrap();
        let info = client.discover(&app).await.unwrap();
        let token = client.token_path(&info).unwrap();
        *cache.lock().unwrap() = Some(token.clone());
        let executable = directory.join("mock-curl");
        std::fs::write(
            &executable,
            br#"#!/bin/sh
printf '%s\n' "$@" > "$0.called"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let called = directory.join("mock-curl.called");
        let command = || {
            let mut command = tokio::process::Command::new(&executable);
            command.arg(app.as_str());
            command
        };
        let browser = |_: &str| -> Result<()> { bail!("synthetic authentication canceled") };
        let auth =
            super::super::run_curl(&client, &app, &info, true, false, browser, command()).await;
        assert!(auth.is_err());
        assert!(!called.exists());
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        crate::administration::credentials::atomic_create(&token, jwt.as_bytes(), 0o600).unwrap();
        mode.store(1, Ordering::SeqCst);
        let verification =
            super::super::run_curl(&client, &app, &info, true, false, browser, command()).await;
        assert!(verification.is_err());
        assert!(!called.exists());
        assert!(checks.load(Ordering::SeqCst) > 0);
        mode.store(0, Ordering::SeqCst);
        super::super::run_curl(&client, &app, &info, true, false, browser, command())
            .await
            .unwrap();
        let arguments = std::fs::read_to_string(&called).unwrap();
        assert!(arguments.contains("-H"));
        assert!(arguments.contains("@"));
        assert!(!arguments.contains(&jwt));
        std::fs::remove_file(&called).unwrap();
        mode.store(2, Ordering::SeqCst);
        super::super::run_curl(&client, &app, &info, true, false, browser, command())
            .await
            .unwrap();
        let arguments = std::fs::read_to_string(&called).unwrap();
        assert!(!arguments.contains("-H"));
        assert!(!arguments.contains(&jwt));
        server.abort();
        let _ = server.await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn transfer_keys_are_ephemeral_and_authenticated() {
        let alice = TransferKey::new().unwrap();
        let bob = TransferKey::new().unwrap();
        assert_ne!(alice.public_key(), bob.public_key());
        let nonce = [7; 24];
        let cipher = SalsaBox::new(&alice.0.public_key(), &bob.0)
            .encrypt(
                GenericArray::from_slice(&nonce),
                b"synthetic payload".as_slice(),
            )
            .unwrap();
        let mut packet = nonce.to_vec();
        packet.extend(cipher);
        assert_eq!(
            alice.decrypt(&packet, &bob.public_key()).unwrap(),
            b"synthetic payload"
        );
        packet[25] ^= 1;
        assert!(alice.decrypt(&packet, &bob.public_key()).is_err());
        assert!(alice.decrypt(&[0; 23], &bob.public_key()).is_err());
        let url = ApplicationUrl::access("https://app.example.invalid/path?keep=value").unwrap();
        let login = url::Url::parse(
            &transfer_url(&url, "synthetic-aud", &alice.public_key(), false, true).unwrap(),
        )
        .unwrap();
        assert_eq!(login.path(), "/cdn-cgi/access/cli");
        let pairs = login
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(pairs["edge_token_transfer"], "true");
        assert!(pairs["redirect_url"].contains("/path?"));
    }

    #[tokio::test]
    async fn signed_discovery_encrypted_transfer_cache_and_stale_lock_recovery() {
        super::super::jwt::crypto_provider();
        let rsa = boring::rsa::Rsa::generate(2048).unwrap();
        let key = EncodingKey::from_rsa_pem(&rsa.private_key_to_pem().unwrap()).unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("synthetic".into());
        let now = jsonwebtoken::get_current_timestamp();
        let metadata=jsonwebtoken::encode(&header,&serde_json::json!({"type":"match","hostname":"127.0.0.1","app_hostname":"app.example.invalid","auth_domain":"synthetic.cloudflareaccess.com","aud":"synthetic-aud","iat":now}),&key).unwrap();
        let app_token=jsonwebtoken::encode(&header,&serde_json::json!({"iss":"https://synthetic.cloudflareaccess.com","aud":["synthetic-aud"],"exp":now+120,"nbf":now-1}),&key).unwrap();
        let jwks=Bytes::from(serde_json::to_vec(&serde_json::json!({"keys":[{"kty":"RSA","kid":"synthetic","alg":"RS256","n":URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_vec())}]})).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let transfers = Arc::new(AtomicUsize::new(0));
        let counter = transfers.clone();
        let service_key = Arc::new(TransferKey::new().unwrap());
        let expected = app_token.clone();
        let server = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (metadata, token, jwks, service_key, counter) = (
                    metadata.clone(),
                    app_token.clone(),
                    jwks.clone(),
                    service_key.clone(),
                    counter.clone(),
                );
                tokio::spawn(async move {
                    let _=hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(socket),hyper::service::service_fn(move|request:http::Request<hyper::body::Incoming>|{
                        let (metadata,token,jwks,service_key,counter)=(metadata.clone(),token.clone(),jwks.clone(),service_key.clone(),counter.clone());
                        async move {
                            let response=if request.uri().path()=="/certs" {
                                http::Response::new(Full::new(jwks))
                            } else if let Some(public)=request.uri().path().strip_prefix("/transfer/") {
                                counter.fetch_add(1,Ordering::SeqCst);
                                let public:[u8;32]=URL_SAFE.decode(public).unwrap().try_into().unwrap();
                                let payload=serde_json::to_vec(&serde_json::json!({"app_token":token,"org_token":""})).unwrap();
                                let mut nonce=[0;24];boring::rand::rand_bytes(&mut nonce).unwrap();
                                let cipher=SalsaBox::new(&PublicKey::from(public),&service_key.0).encrypt(GenericArray::from_slice(&nonce),payload.as_slice()).unwrap();
                                let mut packet=nonce.to_vec();packet.extend(cipher);
                                http::Response::builder().header("service-public-key",service_key.public_key()).body(Full::new(Bytes::from(STANDARD.encode(packet)))).unwrap()
                            } else {
                                assert_eq!(request.method(),http::Method::HEAD);
                                assert_eq!(request.headers()["cf-access-metadata-request"],"true");
                                http::Response::builder().header("cf-access-metadata",metadata).body(Full::new(Bytes::new())).unwrap()
                            };
                            Ok::<_,std::io::Error>(response)
                        }
                    })).await;
                });
            }
        });
        let directory = std::env::temp_dir().join(format!("access-cache-{}", uuid::Uuid::new_v4()));
        let mut client = TokenClient::new(directory.clone(), false).unwrap();
        client.jwks_override = Some(format!("http://{address}/certs"));
        client.transfer_store = format!("http://{address}/");
        let application = ApplicationUrl::remote(&format!("http://{address}/application")).unwrap();
        let info = client.discover(&application).await.unwrap();
        assert_eq!(info.hostname(), "app.example.invalid");
        assert_eq!(info.audience(), "synthetic-aud");
        let path = client.token_path(&info).unwrap();
        let lock = PathBuf::from(format!("{}.lock", path.display()));
        crate::administration::credentials::atomic_create(
            &lock,
            &serde_json::to_vec(&LockOwner {
                pid: u32::MAX,
                start_time: 0,
                id: "stale".into(),
            })
            .unwrap(),
            0o600,
        )
        .unwrap();
        let token = client
            .fetch(&application, &info, false, true, |login| {
                let url = url::Url::parse(login)?;
                assert_eq!(url.path(), "/cdn-cgi/access/cli");
                assert!(url.query_pairs().any(|(key, value)| {
                    key == "token"
                        && URL_SAFE
                            .decode(value.as_bytes())
                            .is_ok_and(|key| key.len() == 32)
                }));
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(token, expected);
        assert_eq!(transfers.load(Ordering::SeqCst), 1);
        assert_eq!(client.cached(&info).await.unwrap(), expected);
        assert!(!lock.exists());
        assert!(!companion_path(&path).exists());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(directory).unwrap();
        server.abort();
    }
}
