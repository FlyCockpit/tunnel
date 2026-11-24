//! ICE config helpers: the `/ice` token, refresh timing and the `ice` command's variables.

use std::time::{SystemTime, UNIX_EPOCH};

use tunnel_protocol::{IceConfig, IceServer};

/// Kept in the 0700 state directory so the token survives daemon restarts
/// (agents keep a `TUNNEL_ICE_TOKEN` they were given).
const TOKEN_FILE: &str = "ice-token";
const TOKEN_PREFIX: &str = "tnice_";

/// The `/ice` bearer token: read from `<state dir>/ice-token`, or created (0600).
pub fn load_or_create_token(state_dir: &std::path::Path) -> anyhow::Result<String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = state_dir.join(TOKEN_FILE);
    if let Ok(t) = std::fs::read_to_string(&path) {
        let t = t.trim();
        if t.starts_with(TOKEN_PREFIX) && t.len() > 32 {
            return Ok(t.to_string());
        }
    }
    let bytes: [u8; 32] = rand::random();
    let token = format!("{TOKEN_PREFIX}{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let tmp = state_dir.join(format!("{TOKEN_FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(token.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    Ok(token)
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// True when less than 25% of the credential's TTL remains (or it expired).
pub fn needs_refresh(ice: &IceConfig) -> bool {
    let remaining = ice.expires_at.saturating_sub(unix_now());
    remaining == 0 || remaining.saturating_mul(4) < ice.ttl_s
}

/// Variables for `ice --format env` and `ice --exec`.
pub fn env_vars(ice: &IceConfig, ice_file: &str) -> Vec<(&'static str, String)> {
    let turn: Vec<&IceServer> =
        ice.ice_servers.iter().filter(|s| s.username.is_some() && s.credential.is_some()).collect();
    let urls: Vec<&str> = turn
        .iter()
        .flat_map(|s| s.urls.iter())
        .map(String::as_str)
        .filter(|u| u.starts_with("turn:") || u.starts_with("turns:"))
        .collect();
    let mut vars = vec![("TURN_URLS", urls.join(","))];
    if let Some(server) = turn.first() {
        vars.push(("TURN_USERNAME", server.username.clone().unwrap_or_default()));
        vars.push(("TURN_CREDENTIAL", server.credential.clone().unwrap_or_default()));
    }
    vars.push(("ICE_SERVERS_JSON", serde_json::to_string(&ice.ice_servers).unwrap_or_else(|_| "[]".to_string())));
    vars.push(("ICE_EXPIRES_AT", ice.expires_at.to_string()));
    vars.push(("TUNNEL_ICE_FILE", ice_file.to_string()));
    vars
}

/// POSIX single-quoting: safe inside `eval "$(...)"`.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

pub fn format_env(vars: &[(&'static str, String)]) -> String {
    vars.iter().map(|(k, v)| format!("export {k}={}\n", shell_quote(v))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn env_vars_pick_turn_urls() {
        let ice = IceConfig {
            ice_servers: vec![
                IceServer { urls: vec!["stun:turn.example.com:3478".into()], username: None, credential: None },
                IceServer {
                    urls: vec![
                        "turn:turn.example.com:3478?transport=udp".into(),
                        "turns:turn.example.com:443?transport=tcp".into(),
                    ],
                    username: Some("1:ab:sbx".into()),
                    credential: Some("c".into()),
                },
            ],
            expires_at: 1,
            ttl_s: 86400,
        };
        let vars = env_vars(&ice, "/run/tunnel/ice.json");
        let get = |k: &str| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("TURN_URLS").as_deref(),
            Some("turn:turn.example.com:3478?transport=udp,turns:turn.example.com:443?transport=tcp")
        );
        assert_eq!(get("TURN_USERNAME").as_deref(), Some("1:ab:sbx"));
        assert_eq!(get("ICE_EXPIRES_AT").as_deref(), Some("1"));
    }

    #[test]
    fn token_persists() {
        let dir = std::env::temp_dir().join(format!("cp-ice-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = load_or_create_token(&dir).unwrap();
        assert_eq!(load_or_create_token(&dir).unwrap(), a);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
