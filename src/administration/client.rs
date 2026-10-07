use super::credentials::AccountCredentials;
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde_json::{Value, json};
use std::time::Duration;
use url::Url;
use uuid::Uuid;

#[cfg(test)]
mod pagination_tests;

pub struct AccountClient {
    credentials: AccountCredentials,
    base: Url,
    client: Client<hyper_boring::HttpsConnector<HttpConnector>, Full<Bytes>>,
}

pub(crate) fn verified_tls_connector() -> Result<boring::ssl::SslConnectorBuilder> {
    let mut ssl = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
    ssl.set_cert_store_builder(boring::x509::store::X509StoreBuilder::new()?);
    ssl.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))?;
    Ok(ssl)
}
pub(crate) fn verified_connector() -> Result<hyper_boring::HttpsConnector<HttpConnector>> {
    let ssl = verified_tls_connector()?;
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(15)));
    let mut connector = hyper_boring::HttpsConnector::with_connector(http, ssl)?;
    connector.set_callback(|config, _| {
        config.set_use_server_name_indication(false);
        Ok(())
    });
    connector.set_ssl_callback(|ssl, uri| {
        crate::crypto::set_tls_name(ssl, uri.host().unwrap_or(""))
            .map_err(|_| boring::error::ErrorStack::get())?;
        crate::crypto::configure_platform_trust(ssl)
    });
    Ok(connector)
}

impl AccountClient {
    pub fn new(credentials: AccountCredentials, endpoint: &str) -> Result<Self> {
        if credentials.account_id.is_empty() {
            bail!("origin certificate has no account ID; run cloudflared login");
        }
        for component in [&credentials.account_id, &credentials.zone_id] {
            if component
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && b != b'-' && b != b'_')
            {
                bail!("invalid account or zone identifier");
            }
        }
        let endpoint = if credentials.endpoint == "fed" {
            "https://api.fed.cloudflare.com/client/v4"
        } else {
            endpoint
        };
        let base = Url::parse(&format!("{}/", endpoint.trim_end_matches('/')))
            .context("invalid API URL")?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
        {
            bail!("invalid API URL");
        }
        let connector = verified_connector()?;
        Ok(Self {
            credentials,
            base,
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }

    pub fn account(&self) -> &str {
        &self.credentials.account_id
    }
    pub fn endpoint(&self) -> &str {
        &self.credentials.endpoint
    }
    fn path(&self, suffix: &str) -> String {
        format!("accounts/{}/{suffix}", self.credentials.account_id)
    }

    pub(super) async fn request(
        &self,
        method: http::Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
        envelope: bool,
    ) -> Result<Value> {
        let mut url = self.base.join(path)?;
        if !query.is_empty() {
            let query = query
                .iter()
                .map(|(key, value)| (*key, value.as_str()))
                .collect::<std::collections::BTreeMap<_, _>>();
            url.query_pairs_mut().extend_pairs(query);
        }
        let mut request = http::Request::builder()
            .method(method)
            .uri(url.as_str())
            .header(
                http::header::AUTHORIZATION,
                format!("Bearer {}", self.credentials.api_token),
            )
            .header(
                http::header::USER_AGENT,
                format!("cloudflared/{}", crate::config::UPSTREAM_VERSION),
            )
            .header(http::header::ACCEPT, "application/json;version=1");
        let bytes = if let Some(body) = &body {
            request = request.header(http::header::CONTENT_TYPE, "application/json");
            serde_json::to_vec(body)?
        } else {
            Vec::new()
        };
        let mut request = request.body(Full::new(Bytes::from(bytes)))?;
        let method = request.method().clone();
        let gzip = crate::http_body::prepare_gzip(&method, request.headers_mut());
        let response = tokio::time::timeout(Duration::from_secs(15), async {
            let response = self.client.request(request).await?;
            let response = crate::http_body::response(response, gzip);
            let status = response.status();
            let body = response.into_body().collect().await?.to_bytes();
            Ok::<_, anyhow::Error>((status, body))
        })
        .await
        .context("account API request timed out")??;
        let (status, bytes) = response;
        let value = serde_json::from_slice::<Value>(&bytes).ok();
        if let Some(errors) = value
            .as_ref()
            .and_then(|v| v.get("errors"))
            .and_then(Value::as_array)
            .filter(|e| !e.is_empty())
        {
            let message = errors
                .iter()
                .map(|e| {
                    format!(
                        "code: {}, reason: {}",
                        e["code"],
                        e["message"].as_str().unwrap_or("API error")
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            bail!(
                "{}",
                message.replace(&self.credentials.api_token, "[redacted]")
            );
        }
        if status == http::StatusCode::CONFLICT {
            bail!("tunnel with name already exists");
        }
        if status != http::StatusCode::OK {
            bail!(
                "{}",
                match status.as_u16() {
                    400 => "incorrect request parameters".to_owned(),
                    401 | 403 => "unauthorized".to_owned(),
                    404 => "not found".to_owned(),
                    _ => format!("API call failed with status {status}"),
                }
            );
        }
        if !envelope {
            return Ok(Value::Null);
        }
        let value = value.context("failed to decode API response")?;
        if value["success"] != true {
            bail!("API call failed");
        }
        Ok(value)
    }

    pub async fn tunnels(&self, mut query: Vec<(&str, String)>) -> Result<Vec<Value>> {
        self.paged(&self.path("cfd_tunnel"), &mut query).await
    }

    async fn paged(&self, path: &str, query: &mut Vec<(&str, String)>) -> Result<Vec<Value>> {
        let mut all = Vec::new();
        for page in 1u32.. {
            query.retain(|(key, _)| *key != "page");
            query.push(("page", page.to_string()));
            let value = self
                .request(http::Method::GET, path, query, None, true)
                .await?;
            if !value["result_info"].is_null() && !value["result_info"].is_object() {
                bail!("invalid API pagination metadata");
            }
            let super::models::Pagination {
                count,
                page: _,
                per_page,
                total_count,
            } = serde_json::from_value::<Option<super::models::Pagination>>(
                value["result_info"].clone(),
            )
            .context("invalid API pagination metadata")?
            .unwrap_or_default();
            let result = value.get("result").context("missing API list result")?;
            if !result.is_null() {
                let rows = result.as_array().context("unexpected API list response")?;
                all.extend(rows.iter().cloned());
            }
            if count < per_page || all.len() as i64 >= total_count {
                return Ok(all);
            }
        }
        unreachable!()
    }
    pub async fn resolve_tunnel(&self, name: &str) -> Result<Uuid> {
        if let Ok(id) = name.parse() {
            return Ok(id);
        }
        self.tunnels(vec![
            ("name", name.to_owned()),
            ("is_deleted", "false".into()),
        ])
        .await?
        .first()
        .and_then(|v| v["id"].as_str())
        .context("name is not an active tunnel")?
        .parse()
        .context("invalid tunnel ID in API response")
    }
    pub(super) async fn resolve_tunnels(&self, inputs: &[String]) -> Result<Vec<Uuid>> {
        let mut ids = Vec::new();
        let mut names = Vec::new();
        for input in inputs {
            match input.parse::<Uuid>() {
                Ok(id) => ids.push(id),
                Err(_) => names.push(input),
            }
        }
        for name in names {
            let tunnels = self
                .tunnels(vec![("name", name.clone()), ("is_deleted", "false".into())])
                .await?;
            if tunnels.len() != 1 {
                bail!(
                    "there should only be 1 non-deleted Tunnel named {}",
                    name.replace(&self.credentials.api_token, "[redacted]")
                );
            }
            ids.push(
                tunnels[0]["id"]
                    .as_str()
                    .context("API returned no tunnel ID")?
                    .parse()
                    .context("invalid tunnel ID in API response")?,
            );
        }
        Ok(ids)
    }
    pub async fn create(&self, name: &str, secret: &[u8]) -> Result<Value> {
        use base64::Engine;
        if name.is_empty() || Uuid::parse_str(name).is_ok() {
            bail!("tunnel name required; UUIDs cannot be tunnel names");
        }
        let v=self.request(http::Method::POST,&self.path("cfd_tunnel"),&[],Some(json!({"name":name,"tunnel_secret":base64::engine::general_purpose::STANDARD.encode(secret)})),true).await?;
        Ok(v["result"].clone())
    }
    pub async fn tunnel(&self, id: Uuid) -> Result<Value> {
        Ok(self
            .request(
                http::Method::GET,
                &self.path(&format!("cfd_tunnel/{id}")),
                &[],
                None,
                true,
            )
            .await?["result"]
            .clone())
    }
    pub async fn delete(&self, id: Uuid, force: bool) -> Result<()> {
        let query = if force {
            vec![("cascade", "true".into())]
        } else {
            vec![]
        };
        self.request(
            http::Method::DELETE,
            &self.path(&format!("cfd_tunnel/{id}")),
            &query,
            None,
            false,
        )
        .await?;
        Ok(())
    }
    pub async fn token(&self, id: Uuid) -> Result<String> {
        self.request(
            http::Method::GET,
            &self.path(&format!("cfd_tunnel/{id}/token")),
            &[],
            None,
            true,
        )
        .await?["result"]
            .as_str()
            .map(str::to_owned)
            .context("unexpected tunnel token response")
    }
    pub async fn management_token(&self, id: Uuid, resource: &str) -> Result<String> {
        if !matches!(resource, "logs" | "admin" | "host_details") {
            bail!("resource must be one of: logs, admin, host_details");
        }
        self.request(
            http::Method::POST,
            &self.path(&format!("cfd_tunnel/{id}/management/{resource}")),
            &[],
            None,
            true,
        )
        .await?["result"]
            .as_str()
            .map(str::to_owned)
            .context("unexpected management token response")
    }
    pub async fn connections(&self, id: Uuid) -> Result<Value> {
        Ok(self
            .request(
                http::Method::GET,
                &self.path(&format!("cfd_tunnel/{id}/connections")),
                &[],
                None,
                true,
            )
            .await?["result"]
            .clone())
    }
    pub async fn cleanup(&self, id: Uuid, connector: Option<Uuid>) -> Result<()> {
        let query = connector
            .map(|id| vec![("client_id", id.to_string())])
            .unwrap_or_default();
        self.request(
            http::Method::DELETE,
            &self.path(&format!("cfd_tunnel/{id}/connections")),
            &query,
            None,
            false,
        )
        .await?;
        Ok(())
    }
    pub async fn hostname_route(&self, id: Uuid, body: Value) -> Result<Value> {
        Ok(self
            .request(
                http::Method::PUT,
                &format!("zones/{}/tunnels/{id}/routes", self.credentials.zone_id),
                &[],
                Some(body),
                true,
            )
            .await?["result"]
            .clone())
    }
    pub async fn routes(
        &self,
        method: http::Method,
        suffix: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value> {
        if method == http::Method::GET && suffix.is_empty() {
            return Ok(Value::Array(
                self.paged(&self.path("teamnet/routes"), &mut query.to_vec())
                    .await?,
            ));
        }
        Ok(self
            .request(
                method,
                &self.path(&format!("teamnet/routes{suffix}")),
                query,
                body,
                true,
            )
            .await?["result"]
            .clone())
    }
    pub async fn vnets(
        &self,
        method: http::Method,
        suffix: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value> {
        Ok(self
            .request(
                method,
                &self.path(&format!("teamnet/virtual_networks{suffix}")),
                query,
                body,
                true,
            )
            .await?["result"]
            .clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };

    #[tokio::test]
    async fn loopback_api_auth_pagination_routes_and_error_redaction() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let log = log.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: http::Request<Incoming>| {
                        let log = log.clone();
                        async move {
                            assert_eq!(
                                request.headers()[http::header::AUTHORIZATION],
                                "Bearer synthetic-token"
                            );
                            assert_eq!(
                                request.headers()[http::header::ACCEPT],
                                "application/json;version=1"
                            );
                            let method = request.method().clone();
                            let uri = request.uri().to_string();
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            let body = if body.is_empty() {
                                Value::Null
                            } else {
                                serde_json::from_slice(&body).unwrap()
                            };
                            log.lock()
                                .unwrap()
                                .push((method.clone(), uri.clone(), body));
                            let result = if uri.contains("page=1") {
                                json!({"success":true,"result":[{"name":"one"},{"name":"two"}],"result_info":{"count":2,"per_page":2,"total_count":3}})
                            } else if uri.contains("page=2") {
                                json!({"success":true,"result":[{"name":"three"}],"result_info":{"count":1,"per_page":2,"total_count":3}})
                            } else if uri.ends_with("/token") {
                                json!({"success":true,"result":"synthetic-tunnel-token"})
                            } else if uri.ends_with("/failure") {
                                json!({"success":false,"errors":[{"code":1000,"message":"synthetic-token denied"}]})
                            } else {
                                json!({"success":true,"result":{"id":"00000000-0000-0000-0000-000000000001","name":"fixture"}})
                            };
                            let status = if uri.ends_with("/failure") { 500 } else { 200 };
                            Ok::<_, Infallible>(
                                http::Response::builder()
                                    .status(status)
                                    .header(http::header::CONTENT_TYPE, "application/json")
                                    .body(Full::new(Bytes::from(
                                        serde_json::to_vec(&result).unwrap(),
                                    )))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        let client = AccountClient::new(
            AccountCredentials {
                account_id: "test-account".into(),
                zone_id: "test-zone".into(),
                api_token: "synthetic-token".into(),
                endpoint: String::new(),
            },
            &format!("http://{address}/client/v4"),
        )
        .unwrap();
        assert_eq!(
            client
                .tunnels(vec![("is_deleted", "false".into())])
                .await
                .unwrap()
                .len(),
            3
        );
        let created = client.create("fixture", &[7; 32]).await.unwrap();
        let id = created["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(client.token(id).await.unwrap(), "synthetic-tunnel-token");
        client
            .hostname_route(
                id,
                json!({"type":"dns","user_hostname":"fixture.test","overwrite_existing":false}),
            )
            .await
            .unwrap();
        client
            .routes(
                http::Method::POST,
                "",
                &[],
                Some(json!({"network":"192.0.2.0/24","tunnel_id":id,"comment":"fixture"})),
            )
            .await
            .unwrap();
        client
            .vnets(
                http::Method::PATCH,
                &format!("/{id}"),
                &[],
                Some(json!({"name":"fixture-network"})),
            )
            .await
            .unwrap();
        client.delete(id, true).await.unwrap();
        let error = client
            .request(http::Method::GET, "failure", &[], None, true)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("1000"));
        assert!(!error.contains("synthetic-token"));
        let log = seen.lock().unwrap();
        assert!(
            log.iter()
                .any(|(method, path, body)| method == http::Method::POST
                    && path == "/client/v4/accounts/test-account/cfd_tunnel"
                    && body["tunnel_secret"] == "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=")
        );
        assert!(
            log.iter()
                .any(|(method, path, _)| method == http::Method::DELETE
                    && path.ends_with("?cascade=true"))
        );
        assert!(
            log.iter()
                .any(|(method, path, _)| method == http::Method::PUT
                    && path.starts_with("/client/v4/zones/test-zone/tunnels/"))
        );
        assert!(
            log.iter()
                .any(|(_, path, _)| path == "/client/v4/accounts/test-account/teamnet/routes")
        );
        server.abort();
    }
}
