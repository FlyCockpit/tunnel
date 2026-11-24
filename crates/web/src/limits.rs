//! The Users page's limits editor, without the UI: how a limit's setting is
//! shown in the form and what a filled-in form sends (`PATCH /ui/api/users/{id}`).

use serde_json::{Map, Value, json};

use crate::ui::{gb_text, parse_gb};

/// A limit's number as the form shows it: the amount and, for lifetimes,
/// its unit (`s`, `m`, `h`, `d`; the largest that is exact).
pub fn form_value(key: &str, n: Option<u64>) -> (String, String) {
    match (key, n) {
        ("traffic_bytes", Some(b)) => (gb_text(b), String::new()),
        ("tunnel_ttl_s", Some(s)) => {
            let (size, unit) = [(86_400, "d"), (3600, "h"), (60, "m"), (1, "s")]
                .into_iter()
                .find(|(size, _)| s % size == 0)
                .unwrap_or((1, "s"));
            ((s / size).to_string(), unit.to_string())
        }
        ("tunnel_ttl_s", None) => (String::new(), "d".into()),
        (_, n) => (n.map(|n| n.to_string()).unwrap_or_default(), String::new()),
    }
}

/// The setting a field asks for: `"default"`, `"unlimited"` or the number
/// (lifetimes in seconds, traffic in bytes), or what is wrong with it.
pub fn wanted(key: &str, label: &str, mode: &str, typed: &str, unit: &str) -> Result<Value, String> {
    let typed = typed.trim();
    match mode {
        "default" => return Ok(json!("default")),
        "unlimited" => return Ok(json!("unlimited")),
        _ => {}
    }
    let n = match key {
        "traffic_bytes" => parse_gb(typed),
        "tunnel_ttl_s" => typed.parse::<u64>().ok().filter(|n| *n > 0).and_then(|n| {
            n.checked_mul(match unit {
                "s" => 1,
                "m" => 60,
                "h" => 3600,
                _ => 86_400,
            })
        }),
        _ => typed.parse::<u64>().ok(),
    };
    n.map(|n| json!(n)).ok_or_else(|| match key {
        "traffic_bytes" => format!("{label}: enter GB, e.g. 50 or 0.5."),
        "tunnel_ttl_s" => format!("{label}: enter a whole number of seconds, minutes, hours or days."),
        _ => format!("{label}: enter a whole number (0 or more)."),
    })
}

/// Whether `wanted` differs from the setting the form was opened with.
pub fn changed(initial: &Value, wanted: &Value) -> bool {
    initial != wanted
}

/// The request body for the changed limits.
pub fn patch_body(changed: Map<String, Value>) -> Value {
    json!({ "limits": changed })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the form sends back for a setting nobody touched.
    fn untouched(key: &str, setting: Value) -> Value {
        let mode = if setting.is_u64() { "number" } else { setting.as_str().unwrap() };
        let (typed, unit) = form_value(key, setting.as_u64());
        wanted(key, "x", mode, &typed, &unit).unwrap()
    }

    #[test]
    fn an_untouched_form_sends_nothing() {
        for (key, setting) in [
            ("tunnels", json!(0)),
            ("tunnels", json!(3)),
            ("machines", json!("unlimited")),
            ("tunnel_ttl_s", json!(90)),
            ("tunnel_ttl_s", json!(3600)),
            ("tunnel_ttl_s", json!(7 * 86_400)),
            ("tunnel_ttl_s", json!(5400)),
            ("tunnel_ttl_s", json!("default")),
            ("traffic_bytes", json!(1_500_000)),
            ("traffic_bytes", json!(5_000_000_000u64)),
        ] {
            assert!(!changed(&setting, &untouched(key, setting.clone())), "{key} {setting}");
        }
        assert_eq!(form_value("tunnel_ttl_s", Some(90)), ("90".into(), "s".into()));
        assert_eq!(form_value("tunnel_ttl_s", Some(5400)), ("90".into(), "m".into()));
    }

    #[test]
    fn typed_values_become_settings() {
        assert_eq!(wanted("tunnel_ttl_s", "x", "number", "8", "h"), Ok(json!(28_800)));
        assert_eq!(wanted("tunnel_ttl_s", "x", "number", "2", "d"), Ok(json!(172_800)));
        assert_eq!(wanted("traffic_bytes", "x", "number", "0.5", ""), Ok(json!(500_000_000)));
        assert_eq!(wanted("machines", "x", "number", " 0 ", ""), Ok(json!(0)));
        assert_eq!(wanted("tunnels", "x", "unlimited", "abc", ""), Ok(json!("unlimited")));
        assert_eq!(wanted("tunnels", "x", "default", "", ""), Ok(json!("default")));
        for (key, typed) in [("tunnels", "abc"), ("tunnels", "-1"), ("tunnel_ttl_s", "0"), ("traffic_bytes", "0")] {
            assert!(wanted(key, "Field", "number", typed, "h").unwrap_err().starts_with("Field: "), "{key} {typed}");
        }
        assert!(changed(&json!(3), &json!(4)) && changed(&json!("default"), &json!(10)));
    }

    #[test]
    fn the_body_wraps_the_changes_in_limits() {
        let mut m = Map::new();
        m.insert("tunnels".into(), json!(3));
        assert_eq!(patch_body(m), json!({ "limits": { "tunnels": 3 } }));
    }
}
