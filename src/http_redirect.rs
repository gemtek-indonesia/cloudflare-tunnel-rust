use crate::{access::ApplicationUrl, http_body::ResponseBody};
use anyhow::{Result, bail};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, header};
use http_body_util::BodyExt;
use hyper::body::Body;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use std::future::Future;
use tokio::io::AsyncReadExt;
use tokio_util::io::StreamReader;

pub(crate) async fn follow<B, F, Fut>(
    mut request: Request<B>,
    mut send: F,
) -> Result<Response<ResponseBody>>
where
    B: Clone + Default,
    F: FnMut(Request<B>) -> Fut,
    Fut: Future<Output = Result<Response<ResponseBody>>>,
{
    let initial = ApplicationUrl::remote(&request.uri().to_string())
        .map_err(|_| anyhow::anyhow!("invalid HTTP redirect base URL"))?;
    let original_headers = request.headers().clone();
    let original_body = request.body().clone();
    let mut current = initial.clone();
    let mut include_body = true;
    let mut strip_sensitive = false;
    let mut requests = 0;
    basic_auth(&current, request.headers_mut())?;
    *request.uri_mut() = initial
        .request_uri()
        .map_err(|_| anyhow::anyhow!("invalid HTTP redirect base request URI"))?;
    loop {
        let method = request.method().clone();
        let host = request.headers().get(header::HOST).cloned();
        let response = send(request)
            .await
            .map_err(|_| anyhow::anyhow!("HTTP request failed"))?;
        requests += 1;
        let drop_body = match response.status().as_u16() {
            301..=303 => true,
            307 | 308 => false,
            _ => return Ok(response),
        };
        let Some(location) = response
            .headers()
            .get(header::LOCATION)
            .filter(|value| !value.as_bytes().is_empty())
        else {
            return Ok(response);
        };
        let location = std::str::from_utf8(location.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid HTTP redirect Location"))?;
        let next = current
            .join(location)
            .map_err(|_| anyhow::anyhow!("invalid HTTP redirect Location"))?;
        let relative = oxiri::IriRef::parse_unchecked(location).scheme().is_none();
        include_body &= !drop_body;
        if initial.host() != next.host() && !copy_sensitive(&initial, &next) {
            strip_sensitive = true;
        }
        let mut headers = original_headers.clone();
        headers.remove(header::HOST);
        if relative
            && let Some(host) = host.filter(|host| host.as_bytes() != current.host().as_bytes())
        {
            headers.insert(header::HOST, host);
        }
        if strip_sensitive {
            for name in [
                header::AUTHORIZATION,
                header::WWW_AUTHENTICATE,
                header::COOKIE,
                "cookie2".parse().expect("static header"),
                header::PROXY_AUTHORIZATION,
                header::PROXY_AUTHENTICATE,
            ] {
                headers.remove(name);
            }
        }
        if !include_body {
            for name in [
                header::CONTENT_ENCODING,
                header::CONTENT_LANGUAGE,
                header::CONTENT_LOCATION,
                header::CONTENT_TYPE,
            ] {
                headers.remove(name);
            }
            headers.remove(header::CONTENT_LENGTH);
            headers.remove(header::TRANSFER_ENCODING);
        }
        if !(current.scheme() == "https" && next.scheme() == "http")
            && headers
                .get(header::REFERER)
                .is_none_or(|value| value.as_bytes().is_empty())
        {
            headers.insert(
                header::REFERER,
                http::HeaderValue::from_str(&current.without_userinfo())
                    .map_err(|_| anyhow::anyhow!("invalid HTTP redirect Referer"))?,
            );
        }
        let mut next_request = Request::new(if include_body {
            original_body.clone()
        } else {
            B::default()
        });
        *next_request.method_mut() = if drop_body && method != Method::GET && method != Method::HEAD
        {
            Method::GET
        } else {
            method
        };
        *next_request.uri_mut() = next
            .request_uri()
            .map_err(|_| anyhow::anyhow!("invalid HTTP redirect request URI"))?;
        *next_request.headers_mut() = headers;
        basic_auth(&next, next_request.headers_mut())?;
        discard(response).await;
        if requests >= 10 {
            bail!("stopped after 10 redirects");
        }
        current = next;
        request = next_request;
    }
}

fn basic_auth(url: &ApplicationUrl, headers: &mut HeaderMap) -> Result<()> {
    if url.has_userinfo()
        && headers
            .get(header::AUTHORIZATION)
            .is_some_and(|value| value.as_bytes().is_empty())
    {
        headers.remove(header::AUTHORIZATION);
    }
    url.basic_auth(headers)
        .map_err(|_| anyhow::anyhow!("invalid HTTP redirect authorization"))
}

fn copy_sensitive(initial: &ApplicationUrl, next: &ApplicationUrl) -> bool {
    let initial = initial.hostname();
    let next = next.hostname();
    next == initial
        || (!next.contains([':', '%'])
            && next
                .strip_suffix(initial)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

async fn discard(response: Response<ResponseBody>) {
    let length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok());
    if length.is_none_or(|length| length <= 2048) {
        let stream = response.into_body().into_data_stream();
        let mut reader = StreamReader::new(stream).take(2048);
        let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
    }
}

pub(crate) async fn direct<B>(
    client: &Client<hyper_boring::HttpsConnector<HttpConnector>, B>,
    request: Request<B>,
) -> Result<Response<ResponseBody>>
where
    B: Body<Data = Bytes> + Clone + Default + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    follow(request, |mut request| async move {
        let method = request.method().clone();
        let gzip = crate::http_body::prepare_gzip(&method, request.headers_mut());
        let response = client.request(request).await?;
        Ok(crate::http_body::response(response, gzip))
    })
    .await
}

#[cfg(test)]
mod tests;
