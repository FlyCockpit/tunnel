//! The embedded single-page app (see `build.rs`) and the CLI install scripts.

use http::{HeaderMap, HeaderValue, Method, Response, StatusCode, header};

use crate::state::AppState;
use crate::util::{Body, full};

pub struct Asset {
    pub path: &'static str,
    pub mime: &'static str,
    pub raw: &'static [u8],
    pub br: Option<&'static [u8]>,
    pub gz: Option<&'static [u8]>,
}

include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));

/// Shown at every page when the server was built without the `ui` feature.
const NOT_BUILT: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Tunnel</title></head>\
<body><main><h1>Tunnel</h1><p>This server was built without the web UI (cargo feature <code>ui</code>).</p>\
<p>The API works as usual: see <code>/v1/openapi.json</code>.</p></main></body></html>";

fn find(path: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|a| a.path == path)
}

fn accepts(headers: &HeaderMap, coding: &str) -> bool {
    headers.get_all(header::ACCEPT_ENCODING).iter().filter_map(|v| v.to_str().ok()).any(|v| {
        v.split(',').any(|part| {
            let mut it = part.trim().split(';');
            let name = it.next().unwrap_or("").trim();
            let q_zero = it.any(|p| p.trim().replace(' ', "") == "q=0");
            name.eq_ignore_ascii_case(coding) && !q_zero
        })
    })
}

/// `GET`/`HEAD` of a UI path. Hashed files under `/assets/` are immutable;
/// any other path is the app shell (`index.html`, never cached), which
/// routes on the client.
pub fn serve(path: &str, method: &Method, headers: &HeaderMap) -> Response<Body> {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .body(full(""))
            .expect("valid response");
    }
    let (asset, immutable) = match find(path) {
        Some(a) if path != "/index.html" => (Some(a), path.starts_with("/assets/")),
        // A missing hashed file is a 404, not the app shell (a stale page
        // must not get HTML for its script).
        None if path.starts_with("/assets/") => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CACHE_CONTROL, "no-store")
                .body(full("not found"))
                .expect("valid response");
        }
        _ => (find("/index.html"), false),
    };
    let Some(asset) = asset else {
        return Response::builder()
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .body(full(NOT_BUILT))
            .expect("valid response");
    };
    let (body, encoding) = match (asset.br, asset.gz) {
        (Some(br), _) if accepts(headers, "br") => (br, Some("br")),
        (_, Some(gz)) if accepts(headers, "gzip") => (gz, Some("gzip")),
        _ => (asset.raw, None),
    };
    let mut resp = Response::builder()
        .header(header::CONTENT_TYPE, asset.mime)
        .header(header::VARY, "accept-encoding")
        .header(header::CACHE_CONTROL, if immutable { "public, max-age=31536000, immutable" } else { "no-store" })
        .body(full(if *method == Method::HEAD { &[][..] } else { body }))
        .expect("valid response");
    if let Some(e) = encoding {
        resp.headers_mut().insert(header::CONTENT_ENCODING, HeaderValue::from_static(e));
    }
    resp
}

/// `/install.sh` and `/install.ps1` (see `install.rs`).
pub fn install_script(state: &AppState, path: &str, method: &Method) -> Response<Body> {
    crate::install::response(state, path, method)
}
