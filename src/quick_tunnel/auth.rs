use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const CALLBACK: &str = "/.cloudflared/qt-auth/callback";
const STATE_PREFIX: &str = "__Secure-cloudflared-qt-auth-state-";
const SESSION: &str = "__Host-cloudflared-qt-auth-session";

pub struct Authorizer {
    hostname: String,
    recipients: Vec<String>,
    state_key: [u8; 32],
    session_key: [u8; 32],
    verifier: Arc<crate::access::jwt::JwtVerifier>,
}
pub(crate) struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}
#[derive(Serialize, Deserialize)]
struct State {
    state: String,
    hostname: String,
    return_path: String,
    exp: u64,
}
#[derive(Serialize, Deserialize)]
struct Session {
    nonce: String,
    exp: u64,
}

pub(crate) fn recipient_policy(recipients: &[String]) -> Result<Vec<String>> {
    if recipients.is_empty() {
        bail!("Quick Tunnel recipient policy cannot be empty");
    }
    recipients
        .iter()
        .map(|recipient| {
            let recipient = recipient.trim().to_ascii_lowercase();
            if let Some(domain) = recipient.strip_prefix("*@") {
                validate_domain(domain)?;
            } else {
                validate_email(&recipient)?;
            }
            Ok(recipient)
        })
        .collect()
}
fn validate_domain(domain: &str) -> Result<()> {
    if domain.len() > 253
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        bail!("invalid Quick Tunnel recipient domain");
    }
    Ok(())
}
fn validate_email(email: &str) -> Result<()> {
    let (local, domain) = email
        .split_once('@')
        .context("invalid Quick Tunnel recipient email")?;
    if local.is_empty()
        || local.len() > 64
        || local.contains('@')
        || !local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_{}|~".contains(&byte))
    {
        bail!("invalid Quick Tunnel recipient email");
    }
    validate_domain(domain)
}
impl Authorizer {
    pub fn new(hostname: &str, recipients: Vec<String>) -> Result<Self> {
        let hostname = hostname.to_ascii_lowercase();
        let label = hostname
            .strip_suffix(".trycloudflare.com")
            .context("invalid protected Quick Tunnel hostname")?;
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("invalid protected Quick Tunnel hostname");
        }
        let mut state_key = [0; 32];
        let mut session_key = [0; 32];
        boring::rand::rand_bytes(&mut state_key)?;
        boring::rand::rand_bytes(&mut session_key)?;
        Ok(Self {
            hostname,
            recipients: recipient_policy(&recipients)?,
            state_key,
            session_key,
            verifier: crate::access::jwt::JwtVerifier::quick_tunnel()?,
        })
    }
    pub(crate) fn response_headers(&self, headers: &HeaderMap) -> HeaderMap {
        let mut result = headers.clone();
        let cookies = result
            .get_all(http::header::SET_COOKIE)
            .iter()
            .filter(|cookie| {
                cookie
                    .to_str()
                    .ok()
                    .and_then(|value| value.split(';').next())
                    .and_then(|value| value.split_once('='))
                    .is_none_or(|(name, _)| {
                        name.trim() != SESSION && !name.trim().starts_with(STATE_PREFIX)
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        result.remove(http::header::SET_COOKIE);
        for cookie in cookies {
            result.append(http::header::SET_COOKIE, cookie);
        }
        protect(&mut result);
        result
    }
    pub(crate) async fn authorize<R: AsyncRead + Unpin + ?Sized>(
        &self,
        method: &Method,
        uri: &Uri,
        authority: &str,
        headers: &mut HeaderMap,
        reader: &mut R,
    ) -> Result<Option<Response>> {
        if uri.path() == CALLBACK {
            let mut response = Response::new(400);
            if headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|length| length > 4096)
            {
                return Ok(Some(response));
            }
            if method != Method::POST
                || uri.query().is_some()
                || !self.matches(authority)
                || !headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
                    .is_some_and(callback_content_type)
            {
                return Ok(Some(response));
            }
            let mut body = Vec::new();
            reader.take(4097).read_to_end(&mut body).await?;
            if body.len() > 4096 {
                return Ok(Some(response));
            }
            if body.contains(&b';') || !valid_form_escapes(&body) {
                return Ok(Some(response));
            }
            let pairs = url::form_urlencoded::parse(&body).collect::<Vec<_>>();
            if pairs.len() != 2
                || pairs.iter().filter(|(name, _)| name == "state").count() != 1
                || pairs.iter().filter(|(name, _)| name == "assertion").count() != 1
            {
                return Ok(Some(response));
            }
            let state = pairs
                .iter()
                .find(|(name, _)| name == "state")
                .unwrap()
                .1
                .as_ref();
            let assertion = pairs
                .iter()
                .find(|(name, _)| name == "assertion")
                .unwrap()
                .1
                .as_ref();
            let Ok(return_path) = self.consume_state(headers, state) else {
                return Ok(Some(response));
            };
            response.headers.append(http::header::SET_COOKIE,HeaderValue::from_str(&format!("{STATE_PREFIX}{state}=; Path={CALLBACK}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax"))?);
            response.status = 403;
            response.body = Bytes::from_static(b"Forbidden\n");
            let Ok(claims) = self.verifier.verify_broker(assertion).await else {
                return Ok(Some(response));
            };
            let Ok(expiry) = self.validate_assertion(&claims, state) else {
                return Ok(Some(response));
            };
            let cookie = self.issue_session(expiry)?;
            response.status = 303;
            response.body = Bytes::new();
            response.headers.remove(http::header::CONTENT_TYPE);
            response.headers.remove("x-content-type-options");
            response
                .headers
                .append(http::header::SET_COOKIE, HeaderValue::from_str(&cookie)?);
            response
                .headers
                .insert(http::header::LOCATION, HeaderValue::from_str(&return_path)?);
            return Ok(Some(response));
        }
        if self.valid_session(headers) {
            strip_cookies(headers);
            return Ok(None);
        }
        if method != Method::GET && method != Method::HEAD {
            return Ok(Some(Response::new(401)));
        }
        let mut response = Response::new(400);
        if !self.matches(authority) {
            return Ok(Some(response));
        }
        let path = uri.path_and_query().map_or("/", |path| path.as_str());
        let Ok(return_path) = return_path(path) else {
            return Ok(Some(response));
        };
        let state = random::<32>()?;
        let state = URL_SAFE_NO_PAD.encode(state);
        let payload = State {
            state: state.clone(),
            hostname: self.hostname.clone(),
            return_path,
            exp: now() + 600,
        };
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
        let value = format!(
            "{encoded}.{}",
            URL_SAFE_NO_PAD.encode(mac(&self.state_key, encoded.as_bytes())?)
        );
        response.status = 302;
        response.body = Bytes::new();
        response.headers.remove(http::header::CONTENT_TYPE);
        response.headers.remove("x-content-type-options");
        let mut location = url::Url::parse("https://login.trycloudflare.com/authorize")?;
        location
            .query_pairs_mut()
            .append_pair("hostname", &self.hostname)
            .append_pair("state", &state);
        response.headers.insert(
            http::header::LOCATION,
            HeaderValue::from_str(location.as_str())?,
        );
        response.headers.append(http::header::SET_COOKIE,HeaderValue::from_str(&format!("{STATE_PREFIX}{state}={value}; Path={CALLBACK}; Expires={}; Max-Age=600; Secure; HttpOnly; SameSite=None",httpdate::fmt_http_date(std::time::UNIX_EPOCH+std::time::Duration::from_secs(payload.exp))))?);
        Ok(Some(response))
    }
    fn matches(&self, authority: &str) -> bool {
        authority.eq_ignore_ascii_case(&self.hostname)
            || authority
                .strip_suffix(":443")
                .is_some_and(|host| host.eq_ignore_ascii_case(&self.hostname))
    }
    fn consume_state(&self, headers: &HeaderMap, state: &str) -> Result<String> {
        canonical(state, 32)?;
        let cookies = cookies(headers);
        let name = format!("{STATE_PREFIX}{state}");
        let matches = cookies
            .iter()
            .filter(|(key, _)| key == &name)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            bail!("state cookie missing or duplicate");
        }
        let (encoded, signature) = matches[0]
            .1
            .split_once('.')
            .context("invalid state cookie")?;
        if matches[0].1.len() > 4096 {
            bail!("state cookie exceeds maximum size");
        }
        let signature = canonical(signature, 32)?;
        if !boring::memcmp::eq(&signature, &mac(&self.state_key, encoded.as_bytes())?) {
            bail!("invalid state cookie signature");
        }
        let payload: State = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?)?;
        if payload.hostname != self.hostname
            || !boring::memcmp::eq(payload.state.as_bytes(), state.as_bytes())
            || payload.exp <= now()
        {
            bail!("invalid state binding or expiry");
        }
        return_path(&payload.return_path)
    }
    fn validate_assertion(&self, claims: &serde_json::Value, state: &str) -> Result<u64> {
        let text = |name| {
            claims
                .get(name)
                .and_then(serde_json::Value::as_str)
                .context("missing broker assertion claim")
        };
        let number = |name| {
            claims
                .get(name)
                .and_then(serde_json::Value::as_u64)
                .context("missing broker assertion time")
        };
        let iat = number("iat")?;
        let exp = number("exp")?;
        let identity = number("identity_exp")?;
        if text("type")? != "quick_tunnel_auth"
            || text("callback_host")? != self.hostname
            || !boring::memcmp::eq(text("state")?.as_bytes(), state.as_bytes())
            || canonical(text("state")?, 32).is_err()
            || exp <= now()
            || iat > exp
            || exp - iat > 120
            || iat > now() + 30
            || identity < exp
            || identity <= now()
        {
            bail!("broker assertion binding or time rejected");
        }
        let email = text("email")?.trim().to_ascii_lowercase();
        validate_email(&email)?;
        let (_, domain) = email.split_once('@').unwrap();
        if !self
            .recipients
            .iter()
            .any(|recipient| recipient == &email || recipient.strip_prefix("*@") == Some(domain))
        {
            bail!("broker identity does not match recipient policy");
        }
        Ok(identity)
    }
    fn issue_session(&self, identity_exp: u64) -> Result<String> {
        let expiry = identity_exp.min(now() + 14400);
        if expiry <= now() {
            bail!("identity expired");
        }
        let payload = serde_json::to_vec(&Session {
            nonce: URL_SAFE_NO_PAD.encode(random::<16>()?),
            exp: expiry,
        })?;
        let value = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(mac(&self.session_key, &payload)?)
        );
        Ok(format!(
            "{SESSION}={value}; Path=/; Expires={}; Secure; HttpOnly; SameSite=Lax",
            httpdate::fmt_http_date(std::time::UNIX_EPOCH + std::time::Duration::from_secs(expiry))
        ))
    }
    fn valid_session(&self, headers: &HeaderMap) -> bool {
        let cookies = cookies(headers);
        let sessions = cookies
            .iter()
            .filter(|(name, _)| name == SESSION)
            .collect::<Vec<_>>();
        if sessions.len() != 1 {
            return false;
        }
        let Some((payload, signature)) = sessions[0].1.split_once('.') else {
            return false;
        };
        let Ok(payload) = URL_SAFE_NO_PAD.decode(payload) else {
            return false;
        };
        let Ok(signature) = canonical(signature, 32) else {
            return false;
        };
        let Ok(expected) = mac(&self.session_key, &payload) else {
            return false;
        };
        if !boring::memcmp::eq(&signature, &expected) {
            return false;
        }
        serde_json::from_slice::<Session>(&payload)
            .is_ok_and(|session| session.exp > now() && canonical(&session.nonce, 16).is_ok())
    }
}
impl Response {
    fn new(status: u16) -> Self {
        let mut headers = HeaderMap::new();
        protect(&mut headers);
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        Self {
            status,
            headers,
            body: Bytes::from(format!(
                "{}\n",
                http::StatusCode::from_u16(status)
                    .unwrap()
                    .canonical_reason()
                    .unwrap()
            )),
        }
    }
}
pub(crate) fn protect(headers: &mut HeaderMap) {
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
}
fn cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|value| value.trim().split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}
fn strip_cookies(headers: &mut HeaderMap) {
    let remaining = cookies(headers)
        .into_iter()
        .filter(|(name, _)| name != SESSION && !name.starts_with(STATE_PREFIX))
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    headers.remove(http::header::COOKIE);
    if let Ok(value) = HeaderValue::from_str(&remaining)
        && !remaining.is_empty()
    {
        headers.insert(http::header::COOKIE, value);
    }
}
fn return_path(raw: &str) -> Result<String> {
    let path = raw.split('?').next().unwrap_or(raw);
    let decoded = decode_path(path)?;
    if !raw.starts_with('/')
        || decoded.starts_with("//")
        || decoded.contains('\\')
        || raw.contains('#')
        || decoded == CALLBACK
    {
        bail!("invalid Quick Tunnel return path");
    }
    let uri: Uri = raw.parse().context("invalid Quick Tunnel return path")?;
    if uri.scheme().is_some() || uri.authority().is_some() {
        bail!("invalid Quick Tunnel return path");
    }
    Ok(raw.into())
}
fn decode_path(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                bail!("invalid path escape");
            }
            let high = (bytes[i + 1] as char)
                .to_digit(16)
                .context("invalid path escape")?;
            let low = (bytes[i + 2] as char)
                .to_digit(16)
                .context("invalid path escape")?;
            out.push((high * 16 + low) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}
fn mac(key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    Ok(boring::hash::hmac_sha256(key, payload)?.to_vec())
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    boring::rand::rand_bytes(&mut bytes)?;
    Ok(bytes)
}
fn canonical(value: &str, size: usize) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(value)?;
    if bytes.len() != size || URL_SAFE_NO_PAD.encode(&bytes) != value {
        bail!("invalid canonical authentication value");
    }
    Ok(bytes)
}
fn now() -> u64 {
    jsonwebtoken::get_current_timestamp()
}
fn valid_form_escapes(body: &[u8]) -> bool {
    let mut index = 0;
    while index < body.len() {
        if body[index] == b'%' {
            if index + 2 >= body.len()
                || !body[index + 1].is_ascii_hexdigit()
                || !body[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn callback_content_type(value: &str) -> bool {
    const BASE: &str = "application/x-www-form-urlencoded";
    let (base, mut rest) = value
        .split_once(';')
        .map_or((value, ""), |(base, _)| (base, &value[base.len()..]));
    let Ok(media_type) = base.trim().parse::<mime::Mime>() else {
        return false;
    };
    if media_type.essence_str() != BASE {
        return false;
    }
    // Go accepts parameter whitespace/quoted escapes and equal duplicates that Mime rejects.
    let mut parameters = std::collections::BTreeMap::new();
    loop {
        rest = rest.trim_start();
        if rest.is_empty() || rest.trim() == ";" {
            return true;
        }
        let Some(parameter) = rest.strip_prefix(';') else {
            return false;
        };
        let parameter = parameter.trim_start();
        let Some((name, value)) = parameter.split_once('=') else {
            return false;
        };
        let name = name.trim_end().to_ascii_lowercase();
        let Ok(parsed_name) = format!("{BASE}; {name}=x").parse::<mime::Mime>() else {
            return false;
        };
        if parsed_name.params().count() != 1
            || !parsed_name
                .params()
                .any(|(parsed, _)| parsed == name.as_str())
        {
            return false;
        }
        let value = value.trim_start();
        let decoded;
        if let Some(quoted) = value.strip_prefix('"') {
            let bytes = quoted.as_bytes();
            let mut index = 0;
            let mut result = Vec::new();
            loop {
                let Some(&byte) = bytes.get(index) else {
                    return false;
                };
                index += 1;
                match byte {
                    b'"' => break,
                    b'\r' | b'\n' => return false,
                    b'\\'
                        if bytes
                            .get(index)
                            .is_some_and(|byte| b"()<>@,;:\\\"/[]?=".contains(byte)) =>
                    {
                        result.push(bytes[index]);
                        index += 1;
                    }
                    _ => result.push(byte),
                }
            }
            decoded = result;
            rest = &quoted[index..];
        } else {
            let end = value
                .bytes()
                .position(|byte| {
                    byte <= b' ' || byte >= 127 || b"()<>@,;:\\\"/[]?=".contains(&byte)
                })
                .unwrap_or(value.len());
            if end == 0 {
                return false;
            }
            decoded = value.as_bytes()[..end].to_vec();
            rest = &value[end..];
        }
        if parameters
            .insert(name, decoded.clone())
            .is_some_and(|previous| previous != decoded)
        {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
        pkey::PKey,
    };
    use http_body_util::Full;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    const CONTENT_TYPES: &[(&str, bool)] = &[
        ("application/x-www-form-urlencoded", true),
        ("APPLICATION/X-WWW-FORM-URLENCODED", true),
        (" application/x-www-form-urlencoded \t", true),
        ("application/x-www-form-urlencoded; charset=UTF-8", true),
        ("application/x-www-form-urlencoded ; charset = UTF-8", true),
        (
            "application/x-www-form-urlencoded;\tcharset=\"UTF-8\"",
            true,
        ),
        ("application/x-www-form-urlencoded; charset=\"\"", true),
        ("application/x-www-form-urlencoded; note=\"a;b=c\"", true),
        ("application/x-www-form-urlencoded; note=\"a\\\"b\"", true),
        ("application/x-www-form-urlencoded; note=\"a\\\\b\"", true),
        ("application/x-www-form-urlencoded; note=\"a\\qb\"", true),
        (
            "application/x-www-form-urlencoded; note=\"caf\u{e9}\"",
            true,
        ),
        (
            "application/x-www-form-urlencoded; charset=UTF-8; CHARSET=UTF-8",
            true,
        ),
        ("application/x-www-form-urlencoded; x*=UTF-8''a%20b", true),
        ("application/x-www-form-urlencoded; x*0=a; x*1=b", true),
        ("application/x-www-form-urlencoded; x=a;", true),
        ("application/x-www-form-urlencoded;", true),
        ("application/x-www-form-urlencoded; \t", true),
        ("", false),
        ("application/json", false),
        ("application/x-www-form-urlencoded+json", false),
        ("application /x-www-form-urlencoded", false),
        ("application/x-www-form-urlencoded; charset", false),
        ("application/x-www-form-urlencoded; charset=", false),
        ("application/x-www-form-urlencoded; =UTF-8", false),
        ("application/x-www-form-urlencoded; charset=\"UTF-8", false),
        (
            "application/x-www-form-urlencoded; charset=\"UTF-8\"oops",
            false,
        ),
        (
            "application/x-www-form-urlencoded; charset=UTF-8 extra",
            false,
        ),
        (
            "application/x-www-form-urlencoded; charset=UTF-8; charset=utf-8",
            false,
        ),
        (
            "application/x-www-form-urlencoded; x=\"a\\\"b\"; x=a",
            false,
        ),
        ("application/x-www-form-urlencoded;;", false),
        ("application/x-www-form-urlencoded; x=a; ;", false),
    ];

    struct BodyProbe<'a> {
        polls: usize,
        remaining: &'a [u8],
    }
    impl AsyncRead for BodyProbe<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.polls += 1;
            let size = buffer.remaining().min(self.remaining.len());
            buffer.put_slice(&self.remaining[..size]);
            self.remaining = &self.remaining[size..];
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn callback_length_and_mime_guards_run_before_body_read() {
        let auth = Authorizer::new(
            "synthetic.trycloudflare.com",
            vec!["visitor@example.invalid".into()],
        )
        .unwrap();
        let uri = CALLBACK.parse().unwrap();
        for &(content_type, valid) in CONTENT_TYPES {
            assert_eq!(
                callback_content_type(content_type),
                valid,
                "{content_type:?}"
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_bytes(content_type.as_bytes()).unwrap(),
            );
            let mut reader = BodyProbe {
                polls: 0,
                remaining: b"invalid form",
            };
            let response = auth
                .authorize(
                    &Method::POST,
                    &uri,
                    "synthetic.trycloudflare.com",
                    &mut headers,
                    &mut reader,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status, 400);
            assert_eq!(reader.polls > 0, valid, "{content_type:?}");
        }
        for (declared, body, should_read, remaining) in [
            (Some("4097"), vec![], false, 0),
            (Some("4096"), vec![b'a'; 4096], true, 0),
            (Some("1"), vec![b'a'; 100], true, 0),
            (None, vec![b'a'; 4098], true, 1),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            if let Some(declared) = declared {
                headers.insert(
                    http::header::CONTENT_LENGTH,
                    HeaderValue::from_static(declared),
                );
            }
            let mut reader = BodyProbe {
                polls: 0,
                remaining: &body,
            };
            let response = auth
                .authorize(
                    &Method::POST,
                    &uri,
                    "synthetic.trycloudflare.com",
                    &mut headers,
                    &mut reader,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status, 400);
            assert_eq!(reader.polls > 0, should_read);
            assert_eq!(reader.remaining.len(), remaining);
        }
    }

    #[test]
    #[ignore = "requires the pinned Go source oracle"]
    fn go_callback_mime_source_contract() {
        let oracle = std::env::var_os("CLOUDFLARED_GO_ORACLE").expect("pinned Go oracle");
        let values = CONTENT_TYPES
            .iter()
            .map(|(value, _)| *value)
            .collect::<Vec<_>>();
        let output = std::process::Command::new(oracle)
            .arg("quick-mime")
            .arg(serde_json::to_string(&values).unwrap())
            .output()
            .unwrap();
        assert!(output.status.success());
        let source: Vec<bool> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(source.len(), CONTENT_TYPES.len());
        for (&(value, expected), source) in CONTENT_TYPES.iter().zip(source) {
            assert_eq!(callback_content_type(value), source, "{value:?}");
            assert_eq!(expected, source, "{value:?}");
        }
    }

    #[tokio::test]
    async fn signed_callback_session_recipient_binding_and_cookie_isolation() {
        let key =
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
        let mut context = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut context)
            .unwrap();
        let jwks=serde_json::to_vec(&serde_json::json!({"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":"synthetic","x":URL_SAFE_NO_PAD.encode(&point[1..33]),"y":URL_SAFE_NO_PAD.encode(&point[33..65])}]})).unwrap();
        let pem = PKey::from_ec_key(key)
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        let signing = EncodingKey::from_ec_pem(&pem).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let jwks = jwks.clone();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(socket),
                            hyper::service::service_fn(
                                move |_: http::Request<hyper::body::Incoming>| {
                                    let jwks = jwks.clone();
                                    async move {
                                        Ok::<_, std::io::Error>(http::Response::new(Full::new(
                                            Bytes::from(jwks),
                                        )))
                                    }
                                },
                            ),
                        )
                        .await;
                });
            }
        });
        let mut auth = Authorizer::new(
            "synthetic.trycloudflare.com",
            vec!["*@example.invalid".into()],
        )
        .unwrap();
        auth.verifier = Arc::new(
            crate::access::jwt::JwtVerifier::test_endpoint(
                &format!("http://{address}/"),
                "https://login.trycloudflare.com",
                vec!["cloudflared-quick-tunnel".into()],
                Algorithm::ES256,
                std::time::Duration::from_secs(60),
            )
            .unwrap(),
        );
        let mut headers = HeaderMap::new();
        let response = auth
            .authorize(
                &Method::GET,
                &"/protected?x=1".parse().unwrap(),
                "synthetic.trycloudflare.com",
                &mut headers,
                &mut tokio::io::empty(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers[http::header::CACHE_CONTROL],
            "private, no-store"
        );
        let location =
            url::Url::parse(response.headers[http::header::LOCATION].to_str().unwrap()).unwrap();
        let state = location
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let cookie = response.headers[http::header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let now = now();
        let claims = serde_json::json!({"iss":"https://login.trycloudflare.com","aud":"cloudflared-quick-tunnel","iat":now,"exp":now+60,"type":"quick_tunnel_auth","identity_exp":now+3600,"email":"Visitor@Example.invalid","callback_host":"synthetic.trycloudflare.com","state":state});
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("synthetic".into());
        let token = jsonwebtoken::encode(&header, &claims, &signing).unwrap();
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &state)
            .append_pair("assertion", &token)
            .finish();
        let mut callback_headers = HeaderMap::new();
        callback_headers.insert(
            http::header::COOKIE,
            HeaderValue::from_str(&cookie).unwrap(),
        );
        callback_headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let response = auth
            .authorize(
                &Method::POST,
                &CALLBACK.parse().unwrap(),
                "synthetic.trycloudflare.com:443",
                &mut callback_headers,
                &mut body.as_bytes(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 303);
        assert_eq!(response.headers[http::header::LOCATION], "/protected?x=1");
        let session = response
            .headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .find_map(|value| value.to_str().unwrap().strip_prefix(SESSION))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let mut authenticated = HeaderMap::new();
        authenticated.insert(
            http::header::COOKIE,
            HeaderValue::from_str(&format!("unrelated=value; {SESSION}{session}; {cookie}"))
                .unwrap(),
        );
        assert!(
            auth.authorize(
                &Method::POST,
                &"/origin".parse().unwrap(),
                "synthetic.trycloudflare.com",
                &mut authenticated,
                &mut tokio::io::empty()
            )
            .await
            .unwrap()
            .is_none()
        );
        assert_eq!(authenticated[http::header::COOKIE], "unrelated=value");
        let restarted = Authorizer::new(
            "synthetic.trycloudflare.com",
            vec!["*@example.invalid".into()],
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            HeaderValue::from_str(&format!("{SESSION}{session}")).unwrap(),
        );
        assert_eq!(
            restarted
                .authorize(
                    &Method::POST,
                    &"/origin".parse().unwrap(),
                    "synthetic.trycloudflare.com",
                    &mut headers,
                    &mut tokio::io::empty()
                )
                .await
                .unwrap()
                .unwrap()
                .status,
            401
        );
        let mut rejected = claims.clone();
        rejected["email"] = serde_json::json!("visitor@sub.example.invalid");
        assert!(auth.validate_assertion(&rejected, &state).is_err());
        rejected = claims.clone();
        rejected["state"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0; 32]));
        assert!(auth.validate_assertion(&rejected, &state).is_err());
        for unsafe_path in [
            "//evil.invalid",
            "/%2F%2Fevil.invalid",
            "/%5Cevil.invalid",
            CALLBACK,
            "/path#fragment",
        ] {
            assert!(return_path(unsafe_path).is_err());
        }
        let mut origin = HeaderMap::new();
        origin.append(
            http::header::SET_COOKIE,
            HeaderValue::from_str(&format!("{SESSION}=forged; Path=/")).unwrap(),
        );
        origin.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("unrelated=value"),
        );
        assert_eq!(
            auth.response_headers(&origin)
                .get_all(http::header::SET_COOKIE)
                .iter()
                .count(),
            1
        );
        server.abort();
    }
}
