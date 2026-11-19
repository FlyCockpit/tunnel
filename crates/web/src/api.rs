//! Same-origin JSON calls to `/ui/api/*`. Every request carries
//! `X-Tunnel-CSRF`: the session's token once signed in, else `1` (the server
//! needs the header on every request; a custom header cannot be sent
//! cross-origin without a preflight it never grants).

use std::cell::RefCell;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestCredentials, RequestInit, Response};

thread_local! {
    static CSRF: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub fn set_csrf(token: Option<String>) {
    CSRF.with(|c| *c.borrow_mut() = token);
}

#[derive(Clone, Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn network(e: impl std::fmt::Debug) -> ApiError {
    ApiError { status: 0, code: "network".into(), message: format!("could not reach the server ({e:?})") }
}

pub async fn call<T: DeserializeOwned>(method: &str, path: &str, body: Option<&impl Serialize>) -> Result<T, ApiError> {
    let init = RequestInit::new();
    init.set_method(method);
    init.set_credentials(RequestCredentials::SameOrigin);
    if let Some(body) = body {
        let text = serde_json::to_string(body).map_err(network)?;
        init.set_body(&wasm_bindgen::JsValue::from_str(&text));
    }
    let req = Request::new_with_str_and_init(path, &init).map_err(network)?;
    let headers = req.headers();
    let csrf = CSRF.with(|c| c.borrow().clone()).unwrap_or_else(|| "1".into());
    headers.set("X-Tunnel-CSRF", &csrf).map_err(network)?;
    if body.is_some() {
        headers.set("Content-Type", "application/json").map_err(network)?;
    }
    let window = web_sys::window().expect("window");
    let resp: Response = JsFuture::from(window.fetch_with_request(&req)).await.map_err(network)?.unchecked_into();
    let status = resp.status();
    let text = match resp.text() {
        Ok(p) => JsFuture::from(p).await.ok().and_then(|v| v.as_string()).unwrap_or_default(),
        Err(_) => String::new(),
    };
    if !(200..300).contains(&status) {
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        return Err(ApiError {
            status,
            code: v["error"]["code"].as_str().unwrap_or("error").to_string(),
            message: v["error"]["message"].as_str().map(str::to_string).unwrap_or_else(|| format!("HTTP {status}")),
        });
    }
    let text = if text.trim().is_empty() { "null".to_string() } else { text };
    serde_json::from_str(&text).map_err(|e| ApiError { status, code: "decode".into(), message: e.to_string() })
}

pub async fn get<T: DeserializeOwned>(path: &str) -> Result<T, ApiError> {
    call::<T>("GET", path, None::<&()>).await
}

pub async fn post<T: DeserializeOwned>(path: &str, body: &impl Serialize) -> Result<T, ApiError> {
    call::<T>("POST", path, Some(body)).await
}

pub async fn patch<T: DeserializeOwned>(path: &str, body: &impl Serialize) -> Result<T, ApiError> {
    call::<T>("PATCH", path, Some(body)).await
}

pub async fn delete(path: &str) -> Result<(), ApiError> {
    call::<Value>("DELETE", path, None::<&()>).await.map(|_| ())
}
