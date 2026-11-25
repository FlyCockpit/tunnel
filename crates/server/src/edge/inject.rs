//! Inline ICE-server injection into navigation HTML.
//!
//! A small streaming injector instead of a full HTML rewriter: the only job is
//! to place one `<script>` as early as possible in `<head>`, and everything
//! after the insertion point passes through untouched.

use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::{Bytes, BytesMut};
use http_body::{Body as HttpBody, Frame};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tunnel_protocol::IceConfig;

use crate::util::{Body, BoxError};

/// How much of the document is buffered while looking for `<head>`.
const SCAN_LIMIT: usize = 16 * 1024;

const SCRIPT_TEMPLATE: &str = r#"(function(){"use strict";
var w=window;
if(w.__tunnelIce)return;
var C=__TUNNEL_CONFIG__,H=__TUNNEL_HOST__;
var S={servers:C.iceServers,expiresAt:C.expires_at,ttl:C.ttl_s};
Object.defineProperty(w,"__tunnelIce",{value:S});
var N=w.RTCPeerConnection;
if(typeof N!=="function")return;
function hostOf(u){u=String(u).replace(/^[a-z]+:(\/\/)?/i,"");if(u.charAt(0)==="[")return u.slice(0,u.indexOf("]")+1).toLowerCase();return u.split(/[:?\/]/)[0].toLowerCase();}
function ours(s){if(!s)return false;var u=s.urls!=null?s.urls:s.url;u=Array.isArray(u)?u:[u];for(var i=0;i!==u.length;i++){if(u[i]!=null&&hostOf(u[i])===H)return true;}return false;}
function merge(c){var o=Object.assign({},c);var l=o.iceServers;l=l==null?[]:Array.isArray(l)?l:[l];o.iceServers=l.filter(function(s){return !ours(s);}).concat(S.servers);return o;}
var P=class RTCPeerConnection extends N{constructor(c,...r){super(merge(c),...r);}setConfiguration(c){return super.setConfiguration(merge(c));}};
Object.defineProperty(P,"name",{value:"RTCPeerConnection"});
w.RTCPeerConnection=P;
if(w.webkitRTCPeerConnection)w.webkitRTCPeerConnection=P;
var F=w.fetch,T=0;
function later(ms){clearTimeout(T);T=setTimeout(refresh,Math.min(Math.max(ms,1000),2147483647));}
function plan(){later((S.expiresAt-S.ttl/4)*1000-Date.now());}
function refresh(){if(typeof F!=="function")return;F.call(w,"/__tunnel/ice",{credentials:"same-origin",cache:"no-store"}).then(function(r){if(!r.ok)throw new Error("ice "+r.status);return r.json();}).then(function(c){if(!c||!Array.isArray(c.iceServers))throw new Error("ice");S.servers=c.iceServers;S.expiresAt=c.expires_at;S.ttl=c.ttl_s||S.ttl;plan();}).catch(function(){later(60000);});}
plan();
})();"#;

/// The inline script body (without the `<script>` tags). The CSP hash covers
/// exactly this text.
pub fn script(ice: &IceConfig, turn_host: &str) -> String {
    SCRIPT_TEMPLATE.replacen("__TUNNEL_HOST__", &js_json(&turn_host.to_ascii_lowercase()), 1).replacen(
        "__TUNNEL_CONFIG__",
        &js_json(ice),
        1,
    )
}

pub fn tag(script: &str) -> Bytes {
    Bytes::from(format!("<script>{script}</script>"))
}

/// Base64 SHA-256 of the exact script text, for a CSP `'sha256-…'` source.
pub fn csp_hash(script: &str) -> String {
    STANDARD.encode(Sha256::digest(script.as_bytes()))
}

/// JSON that is safe inside an HTML `<script>` element: `<`, `>`, `&` only
/// ever occur inside JSON strings, where `\u00XX` escapes are equivalent.
fn js_json<T: Serialize + ?Sized>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "null".to_string())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// Body wrapper that inserts `tag` once, early in an HTML document.
pub struct Injector {
    inner: Body,
    /// `Some` until inserted (or until we give up on an empty body).
    tag: Option<Bytes>,
    buf: BytesMut,
    trailers: Option<Frame<Bytes>>,
    inner_done: bool,
}

impl Injector {
    pub fn new(inner: Body, tag: Bytes) -> Self {
        Self { inner, tag: Some(tag), buf: BytesMut::new(), trailers: None, inner_done: false }
    }

    fn emit_with_tag(&mut self, at: usize) -> Bytes {
        let tag = self.tag.take().unwrap_or_default();
        let buf = std::mem::take(&mut self.buf);
        let mut out = BytesMut::with_capacity(buf.len() + tag.len());
        out.extend_from_slice(&buf[..at]);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&buf[at..]);
        out.freeze()
    }

    /// The origin finished (EOF or trailers) before an insertion point was found.
    fn finish(&mut self) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.buf.is_empty() {
            // Empty body: nothing to inject into.
            self.tag = None;
            return Poll::Ready(self.trailers.take().map(Ok));
        }
        let at = match scan(&self.buf) {
            Scan::Found(at) => at,
            Scan::NeedMore { html_end } => fallback(&self.buf, html_end),
        };
        Poll::Ready(Some(Ok(Frame::data(self.emit_with_tag(at)))))
    }
}

impl HttpBody for Injector {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if this.tag.is_none() {
            if let Some(t) = this.trailers.take() {
                return Poll::Ready(Some(Ok(t)));
            }
            if this.inner_done {
                return Poll::Ready(None);
            }
            return Pin::new(&mut this.inner).poll_frame(cx);
        }
        loop {
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    this.inner_done = true;
                    return this.finish();
                }
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        this.buf.extend_from_slice(&data);
                        let at = match scan(&this.buf) {
                            Scan::Found(at) => at,
                            Scan::NeedMore { html_end } if this.buf.len() >= SCAN_LIMIT => {
                                fallback(&this.buf, html_end)
                            }
                            Scan::NeedMore { .. } => continue,
                        };
                        return Poll::Ready(Some(Ok(Frame::data(this.emit_with_tag(at)))));
                    }
                    Err(trailers) => {
                        this.trailers = Some(trailers);
                        return this.finish();
                    }
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.tag.is_none() && self.trailers.is_none() && (self.inner_done || self.inner.is_end_stream())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Scan {
    /// Insert at this byte offset.
    Found(usize),
    /// No decision yet; `html_end` is the offset just past `<html …>` if seen.
    NeedMore { html_end: Option<usize> },
}

#[derive(PartialEq, Eq)]
enum Tri {
    Yes,
    No,
    Partial,
}

/// Find the insertion point: after an early charset declaration in `<head>`
/// unless an enforcing meta CSP precedes it; otherwise right after `<head …>`;
/// or, if `<body`/`<script`
/// comes first, after `<html …>` (if seen) else before that tag.
fn scan(buf: &[u8]) -> Scan {
    let mut html_end = None;
    let mut i = 0;
    while let Some(off) = buf[i..].iter().position(|&b| b == b'<') {
        let lt = i + off;
        let rest = &buf[lt..];
        if rest.starts_with(b"<!--") {
            match find(&rest[4..], b"-->") {
                Some(end) => {
                    i = lt + 4 + end + 3;
                    continue;
                }
                None => return Scan::NeedMore { html_end },
            }
        }
        if rest.len() < 2 {
            return Scan::NeedMore { html_end };
        }
        if rest[1] == b'!' || rest[1] == b'?' {
            match tag_end(rest) {
                Some(end) => {
                    i = lt + end;
                    continue;
                }
                None => return Scan::NeedMore { html_end },
            }
        }

        let head = is_tag(rest, b"head");
        let html = is_tag(rest, b"html");
        let early = [is_tag(rest, b"body"), is_tag(rest, b"script")];
        if head == Tri::Yes {
            return match tag_end(rest) {
                Some(end) => head_insertion(buf, lt + end),
                None => Scan::NeedMore { html_end },
            };
        }
        if html == Tri::Yes {
            match tag_end(rest) {
                Some(end) => {
                    html_end = Some(lt + end);
                    i = lt + end;
                    continue;
                }
                None => return Scan::NeedMore { html_end },
            }
        }
        if early.contains(&Tri::Yes) {
            return Scan::Found(html_end.unwrap_or(lt));
        }
        if head == Tri::Partial || html == Tri::Partial || early.contains(&Tri::Partial) {
            return Scan::NeedMore { html_end };
        }
        i = lt + 1;
    }
    Scan::NeedMore { html_end }
}

/// Keep charset metadata within the HTML encoding prescan's first 1024 bytes.
/// Buffer only that small window, stay before enforcing meta CSP, and never
/// scan into script/style text.
fn head_insertion(buf: &[u8], head_end: usize) -> Scan {
    let window = &buf[..buf.len().min(1024)];
    let mut i = head_end;
    while i < window.len() {
        let Some(off) = window[i..].iter().position(|&b| b == b'<') else { break };
        let lt = i + off;
        let rest = &window[lt..];
        if rest.starts_with(b"<!--") {
            let Some(end) = find(&rest[4..], b"-->") else { break };
            i = lt + 4 + end + 3;
            continue;
        }
        if rest.starts_with(b"</")
            || [b"script".as_slice(), b"style", b"body"].iter().any(|name| is_tag(rest, name) == Tri::Yes)
        {
            return Scan::Found(head_end);
        }
        let Some(end) = tag_end(rest) else { break };
        if is_tag(rest, b"meta") == Tri::Yes {
            let attrs = &rest[5..end - 1];
            if has_attribute(attrs, b"http-equiv", Some(b"content-security-policy")) {
                return Scan::Found(lt);
            }
            if has_attribute(attrs, b"charset", None) {
                return Scan::Found(lt + end);
            }
        }
        if is_tag(rest, b"title") == Tri::Yes {
            // A title is raw text; apparent tags inside it are not metadata.
            let Some(close) = window[lt + end..].windows(7).position(|w| w.eq_ignore_ascii_case(b"</title")) else {
                break;
            };
            let close = lt + end + close;
            let Some(end) = tag_end(&window[close..]) else { break };
            i = close + end;
        } else {
            i = lt + end;
        }
    }
    if buf.len() >= 1024 {
        Scan::Found(head_end)
    } else {
        // EOF uses this fallback too, preserving the normal head insertion.
        Scan::NeedMore { html_end: Some(head_end) }
    }
}

/// Match attribute names and optional values outside other quoted values, so
/// e.g. `content="charset=..."` is not mistaken for a charset attribute.
fn has_attribute(mut attrs: &[u8], expected_name: &[u8], expected_value: Option<&[u8]>) -> bool {
    while !attrs.is_empty() {
        attrs = attrs.trim_ascii_start();
        let end = attrs.iter().position(|b| b.is_ascii_whitespace() || matches!(b, b'=' | b'/')).unwrap_or(attrs.len());
        let (name, rest) = attrs.split_at(end);
        attrs = rest.trim_ascii_start();
        let mut attr_value = &b""[..];
        if let Some(value) = attrs.strip_prefix(b"=") {
            attrs = value.trim_ascii_start();
            if let Some(&quote @ (b'\'' | b'"')) = attrs.first() {
                attrs = &attrs[1..];
                let Some(end) = attrs.iter().position(|&b| b == quote) else { return false };
                attr_value = &attrs[..end];
                attrs = &attrs[end + 1..];
            } else {
                let end = attrs.iter().position(u8::is_ascii_whitespace).unwrap_or(attrs.len());
                attr_value = &attrs[..end];
                attrs = &attrs[end..];
            }
        } else if end == 0 && !attrs.is_empty() {
            attrs = &attrs[1..];
        }
        if name.eq_ignore_ascii_case(expected_name)
            && expected_value.is_none_or(|value| attr_value.eq_ignore_ascii_case(value))
        {
            return true;
        }
    }
    false
}

/// Does `rest` (starting at `<`) open element `name`? ASCII case-insensitive,
/// and the name must end at `>`, `/`, or whitespace (so `<header>` is not `<head>`).
fn is_tag(rest: &[u8], name: &[u8]) -> Tri {
    let n = name.len() + 1;
    let avail = rest.len().min(n);
    if !rest[1..avail].eq_ignore_ascii_case(&name[..avail - 1]) {
        return Tri::No;
    }
    if rest.len() <= n {
        return Tri::Partial;
    }
    match rest[n] {
        b'>' | b'/' | b' ' | b'\t' | b'\n' | b'\r' | 0x0c => Tri::Yes,
        _ => Tri::No,
    }
}

/// Offset just past the `>` closing the tag that starts `rest`, skipping
/// quoted attribute values.
fn tag_end(rest: &[u8]) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (j, &b) in rest.iter().enumerate().skip(1) {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(j + 1),
            None => {}
        }
    }
    None
}

/// No `<head>` decision within the scan window: after `<html …>` if seen,
/// else after a leading BOM, whitespace, and `<!doctype …>`.
fn fallback(buf: &[u8], html_end: Option<usize>) -> usize {
    if let Some(end) = html_end {
        return end;
    }
    let mut i = 0;
    if buf.starts_with(&[0xEF, 0xBB, 0xBF]) {
        i = 3;
    }
    while i < buf.len() && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    let rest = &buf[i..];
    if rest.len() >= 9
        && rest[..9].eq_ignore_ascii_case(b"<!doctype")
        && let Some(end) = tag_end(rest)
    {
        return i + end;
    }
    i
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, StreamBody};
    use tunnel_protocol::IceServer;

    fn insert(doc: &str) -> String {
        let at = match scan(doc.as_bytes()) {
            Scan::Found(at) => at,
            Scan::NeedMore { html_end } => fallback(doc.as_bytes(), html_end),
        };
        format!("{}X{}", &doc[..at], &doc[at..])
    }

    #[test]
    fn after_head() {
        assert_eq!(insert("<!doctype html><html><HEAD lang=x><title>"), "<!doctype html><html><HEAD lang=x>X<title>");
        assert_eq!(insert("<html><header></header><head>"), "<html><header></header><head>X");
        assert_eq!(insert("<!-- <head> --><head>"), "<!-- <head> --><head>X");
        assert_eq!(insert("<head data-x=\">\">a"), "<head data-x=\">\">Xa");
    }

    #[test]
    fn after_early_charset() {
        for prefix in
            ["", "<!-- metadata -->", "<meta name=viewport content='width=device-width'>", "<title>App</title>"]
        {
            let doc = format!("<html><head>{prefix}<META data-x='charset=fake' CHARSET = \"utf-8\"><title>App</title>");
            assert_eq!(insert(&doc), doc.replace("utf-8\">", "utf-8\">X"));
        }
        for doc in [
            "<head><!-- <meta charset=utf-8> --></head>",
            "<head><meta content='charset=utf-8'></head>",
            "<head><title><meta charset=utf-8></title></head>",
            "<head><script>var x='<meta charset=utf-8>';</script></head>",
        ] {
            assert!(insert(doc).starts_with("<head>X"));
        }
    }

    #[tokio::test]
    async fn split_meta_csp_precedes_charset() {
        let chunks: Vec<Result<Frame<Bytes>, BoxError>> = [
            "<head><meta http-eq",
            "uiv='Content-Security-Policy' content=\"script-src 'self'\">",
            "<meta charset=utf-8></head>",
        ]
        .into_iter()
        .map(|c| Ok(Frame::data(Bytes::from(c))))
        .collect();
        let inner: Body = StreamBody::new(futures_util::stream::iter(chunks)).boxed();
        let out = Injector::new(inner, Bytes::from_static(b"<script></script>")).collect().await.unwrap().to_bytes();
        assert_eq!(&out[..], b"<head><script></script><meta http-equiv='Content-Security-Policy' content=\"script-src 'self'\"><meta charset=utf-8></head>");
    }

    #[test]
    fn before_meta_csp_that_precedes_charset() {
        for csp in [
            "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self'\">",
            "<META content=\"script-src 'self'\" HTTP-EQUIV = 'CONTENT-SECURITY-POLICY'>",
            "<meta http-equiv=content-security-policy content=\"script-src 'self'\">",
        ] {
            let prefix = "<head><meta name=viewport content=x>";
            assert_eq!(
                insert(&format!("{prefix}{csp}<meta charset=utf-8>")),
                format!("{prefix}X{csp}<meta charset=utf-8>")
            );
        }
    }

    #[test]
    fn after_charset_when_meta_csp_follows_or_is_report_only() {
        let csp = "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self'\">";
        assert_eq!(insert(&format!("<head><meta charset=utf-8>{csp}")), format!("<head><meta charset=utf-8>X{csp}"));
        for meta in [
            "<meta http-equiv=Content-Security-Policy-Report-Only content=\"script-src 'self'\">",
            "<meta content='http-equiv=content-security-policy'>",
        ] {
            assert_eq!(
                insert(&format!("<head>{meta}<meta charset=utf-8>")),
                format!("<head>{meta}<meta charset=utf-8>X")
            );
        }
    }

    #[tokio::test]
    async fn split_charset_stays_in_prescan_window() {
        let chunks: Vec<Result<Frame<Bytes>, BoxError>> = [
            "<html><head>",
            "<meta name=viewport content=x><me",
            "ta char",
            "set='utf-8'>",
            "<title>App</title></head>",
        ]
        .into_iter()
        .map(|c| Ok(Frame::data(Bytes::from(c))))
        .collect();
        let inner: Body = StreamBody::new(futures_util::stream::iter(chunks)).boxed();
        let tag = format!("<script>{}</script>", "x".repeat(2048));
        let out = Injector::new(inner, Bytes::from(tag.clone())).collect().await.unwrap().to_bytes();
        let out = std::str::from_utf8(&out).unwrap();
        let charset_end = out.find("utf-8'>").unwrap() + "utf-8'>".len();
        assert!(charset_end <= 1024);
        assert_eq!(&out[charset_end..charset_end + tag.len()], tag);
        assert_eq!(out.matches("<script>").count(), 1);
    }

    #[test]
    fn charset_scan_is_bounded() {
        let doc = format!("<head>{}<meta charset=utf-8>", " ".repeat(1024));
        assert!(insert(&doc).starts_with("<head>X"));
    }

    #[test]
    fn body_or_script_first() {
        assert_eq!(insert("<html lang=en><body>"), "<html lang=en>X<body>");
        assert_eq!(insert("<!doctype html><script>"), "<!doctype html>X<script>");
    }

    #[test]
    fn fallback_positions() {
        assert_eq!(insert("\u{feff}  <!DOCTYPE html>hello"), "\u{feff}  <!DOCTYPE html>Xhello");
        assert_eq!(insert("hello"), "Xhello");
        assert_eq!(scan(b"<he"), Scan::NeedMore { html_end: None });
    }

    #[test]
    fn script_is_inert_html() {
        let ice = IceConfig {
            ice_servers: vec![IceServer {
                urls: vec!["stun:t.example.com:3478".into()],
                username: Some("</script>".into()),
                credential: None,
            }],
            expires_at: 1,
            ttl_s: 1,
        };
        let s = script(&ice, "t.example.com");
        assert!(!s.to_ascii_lowercase().contains("</script"));
        assert!(s.contains("\"t.example.com\""));
        assert_eq!(csp_hash("a").len(), 44);
    }

    #[tokio::test]
    async fn streams_split_head() {
        let chunks: Vec<Result<Frame<Bytes>, BoxError>> =
            ["<html><he", "ad>rest", " more"].into_iter().map(|c| Ok(Frame::data(Bytes::from(c)))).collect();
        let inner: Body = StreamBody::new(futures_util::stream::iter(chunks)).boxed();
        let out = Injector::new(inner, Bytes::from_static(b"<script></script>")).collect().await.unwrap().to_bytes();
        assert_eq!(&out[..], b"<html><head><script></script>rest more");
    }

    #[tokio::test]
    async fn empty_body_stays_empty() {
        let out = Injector::new(crate::util::empty(), Bytes::from_static(b"X")).collect().await.unwrap().to_bytes();
        assert!(out.is_empty());
    }
}
