use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use serde::Serialize;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Response/request body used throughout the server.
pub type Body = http_body_util::combinators::BoxBody<Bytes, BoxError>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed()
}

pub fn empty() -> Body {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

pub fn incoming(body: Incoming) -> Body {
    body.map_err(|e| Box::new(e) as BoxError).boxed()
}

pub fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(full(body))
        .expect("valid response")
}

pub fn text_response(status: StatusCode, text: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(full(text))
        .expect("valid response")
}

/// Lowercased request host without port, from `Host` (HTTP/1.1) or the URI
/// authority (HTTP/2).
pub fn request_host<B>(req: &Request<B>) -> Option<String> {
    let raw = req
        .uri()
        .authority()
        .map(|a| a.host().to_string())
        .or_else(|| req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).map(|s| s.to_string()))?;
    Some(strip_port(&raw).to_ascii_lowercase())
}

pub fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map(|i| &host[..=i]).unwrap_or(host);
    }
    match host.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

pub fn header_str(value: Option<&HeaderValue>) -> Option<&str> {
    value.and_then(|v| v.to_str().ok())
}
