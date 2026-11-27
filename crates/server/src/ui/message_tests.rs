//! Keep display wording at its source so user-provided values are never recased.

use std::path::Path;

// Split call arguments while leaving nested calls and quoted commas intact.
fn arguments(source: &str) -> Vec<&str> {
    let (mut depth, mut quoted, mut escaped, mut start) = (0usize, false, false, 0);
    let mut args = Vec::new();
    for (i, c) in source.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '(' | '[' | '{' => depth += 1,
            ')' if depth == 0 => {
                args.push(source[start..i].trim());
                break;
            }
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                args.push(source[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    args
}

fn check_messages(source: &str, constructors: &[(&str, usize)], file: &Path) {
    for (constructor, argument) in constructors {
        for (offset, rest) in source.match_indices(constructor) {
            let rest = source[offset + rest.len()..].trim_start();
            let Some(rest) = rest.strip_prefix('(') else { continue };
            let args = arguments(rest);
            let Some(message) = args.get(*argument) else { continue };
            let message = message
                .strip_prefix("format!")
                .map_or(*message, |s| s.trim_start().strip_prefix('(').unwrap().trim_start());
            if let Some(literal) = message.strip_prefix('"') {
                let line = source[..offset].lines().count();
                assert!(
                    literal.chars().next().is_some_and(char::is_uppercase),
                    "{}:{line}: message must start with a capitalized word: {message}",
                    file.display()
                );
            }
        }
    }
}

fn scan_ui(dir: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            scan_ui(&path);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let name = path.file_name().unwrap().to_str().unwrap();
            if name == "tests.rs" || name.ends_with("_tests.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let source = source.split("#[cfg(test)]").next().unwrap();
            check_messages(source, &[("ApiError::new", 2), ("ApiError::validation", 0), ("forbidden", 1)], &path);
        }
    }
}

#[test]
fn ui_and_shared_error_literals_start_with_capitalized_words() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    scan_ui(&root.join("ui"));
    for name in ["api/mod.rs", "clients.rs", "limits.rs", "config/smtp.rs", "db/mod.rs"] {
        let path = root.join(name);
        let source = std::fs::read_to_string(&path).unwrap();
        let source = source.split("#[cfg(test)]").next().unwrap();
        check_messages(source, &[("ApiError::new", 2), ("ApiError::validation", 0)], &path);
        match name {
            "api/mod.rs" => check_messages(source, &[("Self::new", 2)], &path),
            "clients.rs" => check_messages(source, &[("Err", 0)], &path),
            "config/smtp.rs" => {
                let address = source.split("pub fn parse_address").nth(1).unwrap();
                check_messages(address, &[("Err", 0)], &path);
            }
            "limits.rs" => {
                check_messages(source, &[("Err", 0), ("serde::de::Error::custom", 0)], &path);
                for function in ["machine_limit_message", "tunnel_limit_message", "ttl_limit_message"] {
                    let body = source.split(&format!("pub fn {function}")).nth(1).unwrap();
                    let body = body.split("\n///").next().unwrap();
                    // The TTL suffix is a sentence continuation, not a new message.
                    let body = body.rsplit("format!").next().unwrap();
                    check_messages(&format!("format!{body}"), &[("format!", 0)], &path);
                }
            }
            "db/mod.rs" => {
                let password = source.split("pub struct PasswordRequired").next().unwrap();
                let error = password.rsplit("#[error").next().unwrap();
                check_messages(&format!("error{error}"), &[("error", 0)], &path);
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn source_scan_rejects_lowercase_and_value_leading_literals() {
    for source in [
        "ApiError::new(StatusCode::CONFLICT, \"code\", \"lowercase\")",
        "ApiError::validation(format!(\"{name} is taken\"))",
        "forbidden(\"code\",\n \"lowercase\")",
    ] {
        assert!(
            std::panic::catch_unwind(|| {
                check_messages(
                    source,
                    &[("ApiError::new", 2), ("ApiError::validation", 0), ("forbidden", 1)],
                    Path::new("example.rs"),
                );
            })
            .is_err()
        );
    }
}

#[tokio::test]
async fn validation_responses_preserve_values_and_start_with_words() {
    use super::*;

    let state = state_with(|config| {
        config.smtp = Some(crate::config::smtp::SmtpConfig {
            host: "127.0.0.1".into(),
            port: 1025,
            user: None,
            pass: None,
            from: "Tunnel <tunnel@example.com>".into(),
        });
    });
    let mut owner = owner(&state).await;
    let name = owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "eNrOlL" }))).await;
    assert_eq!(name.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(name.body["error"]["message"], "The name `enroll` is reserved; pick another name");
    for (address, expected) in [
        ("bad ADDRESS", "The address \"bad ADDRESS\" is not an email address"),
        (
            "Bob@bücher.example",
            "The address \"Bob@bücher.example\" must use ASCII characters (write international domains in their xn-- form)",
        ),
    ] {
        let response = owner
            .call(
                &state,
                "POST",
                "/ui/api/account/email",
                Some(json!({ "email": address, "password": "olivia-password" })),
            )
            .await;
        assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response.body["error"]["message"], expected);
    }
    let missing = owner.call(&state, "GET", "/ui/api/unknown", None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.body["error"]["message"], "No route found");
}
