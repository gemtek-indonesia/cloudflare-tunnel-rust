use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};

pub const REQUEST_HEADERS: &str = "cf-cloudflared-request-headers";
pub const RESPONSE_HEADERS: &str = "cf-cloudflared-response-headers";
pub const RESPONSE_META: &str = "cf-cloudflared-response-meta";
pub const MAX_SERIALIZED_HEADERS: usize = 1024 * 1024;
pub type Header = (Vec<u8>, Vec<u8>);

/// Preserve duplicate values and HTTP/1 header bytes without HTTP/2 validation.
pub fn serialize(headers: &[Header]) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}:{}",
                STANDARD_NO_PAD.encode(name),
                STANDARD_NO_PAD.encode(value)
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

pub fn deserialize(encoded: &str) -> Result<Vec<Header>, &'static str> {
    if encoded.len() > MAX_SERIALIZED_HEADERS {
        return Err("serialized headers exceed limit");
    }
    encoded
        .split(';')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (name, value) = pair
                .split_once(':')
                .ok_or("invalid serialized header pair")?;
            Ok((
                STANDARD_NO_PAD
                    .decode(name)
                    .map_err(|_| "invalid header name base64")?,
                STANDARD_NO_PAD
                    .decode(value)
                    .map_err(|_| "invalid header value base64")?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_binary_headers_roundtrip() {
        let headers = vec![
            (b"Set-Cookie".to_vec(), b"a=1".to_vec()),
            (b"Set-Cookie".to_vec(), vec![0xff, b';', b':']),
        ];
        assert_eq!(deserialize(&serialize(&headers)).unwrap(), headers);
        assert!(deserialize("YWJj:def:ghi").is_err());
        assert!(deserialize("YWJj").is_err());
    }
}
