pub mod jwt;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};

pub(crate) type HttpClient = Client<hyper_boring::HttpsConnector<HttpConnector>, Full<Bytes>>;

pub(crate) fn http_client() -> Result<HttpClient> {
    Ok(Client::builder(TokioExecutor::new()).build(crate::administration::verified_connector()?))
}

pub(crate) async fn bounded_body(
    response: &mut http::Response<hyper::body::Incoming>,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        if let Ok(data) = frame.context("HTTP response body failed")?.into_data() {
            if body
                .len()
                .checked_add(data.len())
                .is_none_or(|length| length > limit)
            {
                bail!("HTTP response exceeds maximum size");
            }
            body.extend_from_slice(&data);
        }
    }
    Ok(body)
}
