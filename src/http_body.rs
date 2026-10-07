use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use http::{HeaderMap, Method, Response, header};
use http_body_util::{BodyExt, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Frame, Incoming};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio_util::io::{ReaderStream, StreamReader};

pub type ResponseBody = UnsyncBoxBody<Bytes, io::Error>;

/// Go requests gzip only when the first encoding/range value is empty and the method is not HEAD.
pub fn prepare_gzip(method: &Method, headers: &mut HeaderMap) -> bool {
    let first_empty = |name| {
        headers
            .get(name)
            .is_none_or(|value| value.as_bytes().is_empty())
    };
    if method != Method::HEAD && first_empty(header::ACCEPT_ENCODING) && first_empty(header::RANGE)
    {
        // Preserve explicitly empty and duplicate values; Go's extra header is appended separately.
        headers.append(
            header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
        true
    } else {
        false
    }
}

/// Decoding stays lazy and streaming; caller limits count decoded bytes.
pub fn response(response: Response<Incoming>, requested_gzip: bool) -> Response<ResponseBody> {
    let decode = requested_gzip
        && response
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"));
    let (mut parts, incoming) = response.into_parts();
    let body = if decode {
        parts.headers.remove(header::CONTENT_ENCODING);
        parts.headers.remove(header::CONTENT_LENGTH);
        let trailers = Arc::new(Mutex::new(None));
        let captured = trailers.clone();
        let source = incoming
            .map_frame(move |frame| {
                if let Some(value) = frame.trailers_ref() {
                    *captured.lock().expect("body trailers mutex") = Some(value.clone());
                }
                frame
            })
            .into_data_stream()
            .map_err(io::Error::other);
        let reader = StreamReader::new(source);
        let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(reader);
        decoder.multiple_members(true);
        let valid = Arc::new(AtomicBool::new(true));
        let observed = valid.clone();
        let stream = ReaderStream::new(decoder).map(move |result| {
            if result.is_err() {
                observed.store(false, Ordering::Relaxed);
            }
            result.map(Frame::data)
        });
        let tail = futures::stream::once(async move {
            if valid.load(Ordering::Relaxed) {
                trailers
                    .lock()
                    .expect("body trailers mutex")
                    .take()
                    .map(|headers| Ok(Frame::trailers(headers)))
            } else {
                None
            }
        })
        .filter_map(std::future::ready);
        StreamBody::new(stream.chain(tail)).boxed_unsync()
    } else {
        incoming.map_err(io::Error::other).boxed_unsync()
    };
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests;
