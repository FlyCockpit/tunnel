//! A session's device as people say it ("Chrome on Linux"), from the raw
//! user-agent string the server stored. The raw string stays available in
//! the Sessions table (hover and "Browser details"); this is only its name.

/// `Chrome on Linux`, `Safari on iPhone`, `Firefox`, `curl on Linux`, or
/// `Unknown device` when there is no user agent.
pub fn device_name(user_agent: Option<&str>) -> String {
    let ua = user_agent.map(str::trim).unwrap_or_default();
    if ua.is_empty() {
        return "Unknown device".into();
    }
    match (browser(ua), system(ua)) {
        (Some(b), Some(s)) => format!("{b} on {s}"),
        (Some(b), None) => b.to_string(),
        (None, Some(s)) => format!("A browser on {s}"),
        (None, None) => "Unknown browser".into(),
    }
}

/// The browser, most specific first: Edge, Opera and Samsung Internet also
/// say "Chrome" and "Safari"; Chrome also says "Safari".
fn browser(ua: &str) -> Option<&'static str> {
    const BROWSERS: [(&str, &str); 11] = [
        ("Edg", "Edge"),
        ("OPR/", "Opera"),
        ("SamsungBrowser/", "Samsung Internet"),
        ("Vivaldi/", "Vivaldi"),
        ("Firefox/", "Firefox"),
        ("FxiOS/", "Firefox"),
        ("Chromium/", "Chromium"),
        ("CriOS/", "Chrome"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
        ("curl/", "curl"),
    ];
    BROWSERS.iter().find(|(token, _)| ua.contains(token)).map(|(_, name)| *name)
}

/// The operating system or device, most specific first (Android says
/// "Linux", iPhones say "like Mac OS X").
fn system(ua: &str) -> Option<&'static str> {
    const SYSTEMS: [(&str, &str); 8] = [
        ("iPhone", "iPhone"),
        ("iPad", "iPad"),
        ("Android", "Android"),
        ("CrOS", "ChromeOS"),
        ("Windows", "Windows"),
        ("Macintosh", "macOS"),
        ("Mac OS X", "macOS"),
        ("Linux", "Linux"),
    ];
    SYSTEMS.iter().find(|(token, _)| ua.contains(token)).map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::device_name;

    #[test]
    fn common_browsers_get_their_everyday_names() {
        for (ua, want) in [
            (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Chrome on Linux",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
                "Safari on macOS",
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
                "Safari on iPhone",
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
                "Chrome on iPhone",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
                "Edge on Windows",
            ),
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0", "Firefox on Windows"),
            (
                "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
                "Samsung Internet on Android",
            ),
            (
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
                "Chrome on Android",
            ),
            (
                "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Chrome on ChromeOS",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/115.0.0.0",
                "Opera on Windows",
            ),
            ("curl/8.5.0", "curl"),
        ] {
            assert_eq!(device_name(Some(ua)), want, "{ua}");
        }
    }

    #[test]
    fn missing_or_unknown_agents_still_read_as_words() {
        assert_eq!(device_name(None), "Unknown device");
        assert_eq!(device_name(Some("  ")), "Unknown device");
        assert_eq!(device_name(Some("SomeBot/1.0")), "Unknown browser");
        assert_eq!(device_name(Some("Mozilla/5.0 (X11; Linux x86_64) Gecko")), "A browser on Linux");
    }
}
