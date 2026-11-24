//! The daemon's local `GET /ice` endpoint for sandbox peers.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use super::Daemon;

const MAX_REQUEST_HEAD: usize = 8 * 1024;
/// Concurrent `/ice` connections; any local user can open them.
const MAX_HTTP_CONNS: usize = 32;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Constant-time comparison of the presented bearer token.
fn token_matches(head: &str, expected: &str) -> bool {
    let presented = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("authorization") {
            return None;
        }
        let value = value.trim();
        let (scheme, token) = value.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then(|| token.trim().to_string())
    });
    let Some(presented) = presented else {
        return false;
    };
    let (a, b) = (presented.as_bytes(), expected.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
/// Bind `127.0.0.1:<port>` for [`serve_http`]. A taken port only disables
/// the endpoint (`None`); the ICE file still works.
pub async fn bind_http(port: u16) -> Option<TcpListener> {
    match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
        Ok(l) => {
            info!(port, "ICE HTTP endpoint listening");
            Some(l)
        }
        Err(e) => {
            warn!(port, error = %e, "ICE HTTP endpoint disabled");
            None
        }
    }
}

/// Serve the current ICE config at `http://127.0.0.1:<port>/ice` to callers
/// presenting `Authorization: Bearer $TUNNEL_ICE_TOKEN` (loopback is shared
/// with every local user, so concurrent connections are capped).
pub async fn serve_http(daemon: Arc<Daemon>, listener: TcpListener, port: u16) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_HTTP_CONNS));
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                // Full: drop the connection rather than queue it.
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    debug!("ICE HTTP endpoint busy; connection dropped");
                    continue;
                };
                let daemon = daemon.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(HTTP_TIMEOUT, answer(&daemon, sock, port)).await {
                        Ok(Err(e)) => debug!(error = %e, "ICE HTTP request failed"),
                        Err(_) => debug!("ICE HTTP request timed out"),
                        Ok(Ok(())) => {}
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "ICE HTTP accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn answer(daemon: &Daemon, mut sock: TcpStream, port: u16) -> std::io::Result<()> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < MAX_REQUEST_HEAD {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&head);
    let mut request_line = head.lines().next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default();
    let path = request_line.next().unwrap_or_default().split('?').next().unwrap_or_default();

    let (status, body) = if !host_allowed(&head, port) {
        // DNS rebinding guard: a web page must not read credentials via a
        // hostname it controls that resolves to 127.0.0.1.
        ("403 Forbidden", r#"{"error":"forbidden"}"#.to_string())
    } else if method == "GET" && path == "/ice" && !token_matches(&head, &daemon.ice_token) {
        (
            "401 Unauthorized",
            r#"{"error":"send Authorization: Bearer $TUNNEL_ICE_TOKEN (from `tunnel ice --format env`)"}"#.to_string(),
        )
    } else if method == "GET" && path == "/ice" {
        match daemon.current_ice() {
            Some(ice) => ("200 OK", serde_json::to_string(&ice).unwrap_or_default()),
            None => ("503 Service Unavailable", r#"{"error":"no ICE config yet"}"#.to_string()),
        }
    } else {
        ("404 Not Found", r#"{"error":"not found"}"#.to_string())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(response.as_bytes()).await?;
    sock.shutdown().await
}

fn host_allowed(head: &str, port: u16) -> bool {
    let host = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim().eq_ignore_ascii_case("host").then(|| value.trim().to_ascii_lowercase())
    });
    match host {
        // HTTP/1.0 clients may omit Host; only a browser can be rebound.
        None => true,
        Some(h) => {
            let with_port = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
            h == "127.0.0.1" || h == "localhost" || with_port.contains(&h)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_is_required() {
        let t = "tnice_0123456789abcdef0123456789abcdef";
        assert!(token_matches(&format!("GET /ice HTTP/1.1\r\nAuthorization: Bearer {t}\r\n\r\n"), t));
        assert!(token_matches(&format!("GET /ice HTTP/1.1\r\nauthorization: bearer  {t}\r\n\r\n"), t));
        assert!(!token_matches("GET /ice HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", t));
        assert!(!token_matches("GET /ice HTTP/1.1\r\nAuthorization: Bearer tnice_wrong\r\n\r\n", t));
    }

    #[test]
    fn host_check_rejects_rebinding() {
        assert!(host_allowed("GET /ice HTTP/1.1\r\nHost: 127.0.0.1:47801\r\n\r\n", 47801));
        assert!(!host_allowed("GET /ice HTTP/1.1\r\nHost: evil.example:47801\r\n\r\n", 47801));
    }
}
