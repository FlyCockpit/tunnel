//! `GET /install.sh` and `GET /install.ps1` on the UI host: install the
//! `tunnel` client of this server's own version, then sign the machine in
//! through the browser (`tunnel login https://<ui host>`).
//!
//! Modelled on ws-model-proxy's installer: the release archive is installed
//! only if its SHA-256 matches the release's `sha256.sum` (fail closed: no
//! checksum file, no entry, no hashing tool or a mismatch stops the install).
//! The release workflow also attests build provenance, which
//! `gh attestation verify <file> --repo FlyCockpit/tunnel` checks.
//! Piping a script into a shell trusts this server's operator; the "Get the
//! CLI" page says so and shows the manual path.

use http::{Method, Response, StatusCode, header};

use crate::state::AppState;
use crate::util::{Body, full};

pub const REPOSITORY: &str = "https://github.com/FlyCockpit/tunnel";
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn release_url() -> String {
    format!("{REPOSITORY}/releases/download/v{VERSION}")
}

// Values are embedded in single quotes; refuse anything that could leave them.
fn shell_quoted(value: &str) -> String {
    assert!(
        value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~%+@:/=-".contains(&b)),
        "install.sh: refusing to embed {value:?}"
    );
    format!("'{value}'")
}

/// The POSIX installer. Everything runs from `main` on the last line, so a
/// download cut short runs nothing.
pub fn install_sh(ui_origin: &str) -> String {
    let template = r#"#!/bin/sh
# Tunnel client (tunnel) installer for __ORIGIN__
# Installs the checksummed tunnel __VERSION__ release binary for this machine into
# ~/.local/bin (or $TUNNEL_INSTALL_DIR), then signs this machine in through the browser.
# Set TUNNEL_NO_LOGIN=1 to skip the sign-in.
set -eu

TUNNEL_VERSION=__Q_VERSION__
TUNNEL_RELEASE_URL=__Q_RELEASE__
TUNNEL_REPOSITORY=__Q_REPO__
TUNNEL_ORIGIN=__Q_ORIGIN__

say() { printf 'tunnel: %s\n' "$*"; }
die() { printf 'tunnel: %s\n' "$*" >&2; exit 1; }

bin_dir() {
  if [ -n "${TUNNEL_INSTALL_DIR:-}" ]; then
    printf '%s' "$TUNNEL_INSTALL_DIR"
  else
    [ -n "${HOME:-}" ] || die "set HOME (or TUNNEL_INSTALL_DIR), then run this again."
    printf '%s/.local/bin' "$HOME"
  fi
}

# The release target for this machine, or nothing when no release binary runs here.
detect_target() {
  arch=$(uname -m)
  case "$arch" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) return 0 ;;
  esac
  case "$(uname -s)" in
    # Static musl builds run on any Linux libc.
    Linux) printf '%s-unknown-linux-musl' "$arch" ;;
    Darwin)
      # A Rosetta shell reports x86_64 on Apple silicon: install the native build.
      if [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
        arch=aarch64
      fi
      printf '%s-apple-darwin' "$arch"
      ;;
  esac
}

# curl only: wget cannot refuse a redirect away from https for a single download.
fetch() {
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1"
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$1"
  else
    return 1
  fi
}

install_release() {
  target=$1
  archive="tunnel-$target.tar.xz"
  command -v curl >/dev/null 2>&1 || die "curl is needed to download tunnel."
  dir=$(bin_dir)
  mkdir -p "$dir"
  # Staged beside the install directory, not in /tmp: the binary is test-run before it is
  # installed (a noexec /tmp would refuse that), and the final rename stays on one filesystem.
  tmp=$(mktemp -d "$dir/.tunnel-install.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  say "downloading tunnel $TUNNEL_VERSION for $target from $TUNNEL_RELEASE_URL..."
  fetch "$TUNNEL_RELEASE_URL/sha256.sum" "$tmp/sha256.sum" ||
    die "could not download $TUNNEL_RELEASE_URL/sha256.sum (is tunnel $TUNNEL_VERSION released?). Build it instead: cargo install --git $TUNNEL_REPOSITORY --tag v$TUNNEL_VERSION --locked tunnel-client"
  expected=$(awk -v f="$archive" '{ sub(/\r$/, "") } $2 == f || $2 == "*" f { print tolower($1); exit }' "$tmp/sha256.sum")
  case "$expected" in
    "" | *[!0-9a-f]*) die "sha256.sum has no checksum for $archive; not installing it." ;;
  esac
  [ ${#expected} -eq 64 ] || die "sha256.sum has no checksum for $archive; not installing it."
  fetch "$TUNNEL_RELEASE_URL/$archive" "$tmp/$archive" ||
    die "could not download $TUNNEL_RELEASE_URL/$archive."
  actual=$(sha256_of "$tmp/$archive" | awk '{ print tolower($1) }')
  [ -n "$actual" ] ||
    die "no SHA-256 tool (sha256sum, shasum or openssl) found; not installing an unverified binary."
  [ "$actual" = "$expected" ] ||
    die "checksum mismatch for $archive (expected $expected, got $actual); not installing it."
  say "checksum verified ($expected)."
  (cd "$tmp" && tar -xJf "$archive") ||
    die "could not unpack $archive (tar needs xz: install xz-utils)."
  binary="$tmp/tunnel-$target/tunnel"
  [ -f "$binary" ] && [ ! -L "$binary" ] || die "$archive does not contain tunnel-$target/tunnel."
  "$binary" --version >/dev/null 2>&1 ||
    die "the downloaded tunnel does not run on this machine; build it: cargo install --git $TUNNEL_REPOSITORY --tag v$TUNNEL_VERSION --locked tunnel-client"
  [ ! -d "$dir/tunnel" ] || die "$dir/tunnel is a directory; remove it, then run this again."
  # Rename over the old binary: a running daemon keeps its old file.
  chmod 755 "$binary" && mv -f "$binary" "$dir/tunnel" || die "could not install into $dir."
  installed="$dir/tunnel"
}

install_source() {
  command -v cargo >/dev/null 2>&1 ||
    die "no release binary fits this machine and cargo is not installed. Install Rust from https://rustup.rs, then run this again."
  say "building tunnel $TUNNEL_VERSION from $TUNNEL_REPOSITORY with cargo; this takes a few minutes..."
  cargo install --git "$TUNNEL_REPOSITORY" --tag "v$TUNNEL_VERSION" --locked --force tunnel-client
  installed="${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}/bin/tunnel"
}

main() {
  installed=""
  target=$(detect_target)
  if [ -n "$target" ]; then
    install_release "$target"
  else
    say "no tunnel release binary fits this machine ($(uname -s) $(uname -m)); building from source instead."
    install_source
  fi
  dir=${installed%/tunnel}
  say "installed $installed."
  case ":$PATH:" in
    *":$dir:"*) ;;
    *) say "$dir is not on your PATH: run \"$dir/tunnel\", or add it to PATH." ;;
  esac
  if [ -n "${TUNNEL_NO_LOGIN:-}" ]; then
    say "next: $installed login $TUNNEL_ORIGIN"
    return 0
  fi
  say "signing this machine in: approve it in your browser."
  "$installed" login "$TUNNEL_ORIGIN"
}

main "$@"
"#;
    template
        .replace("__Q_VERSION__", &shell_quoted(VERSION))
        .replace("__Q_RELEASE__", &shell_quoted(&release_url()))
        .replace("__Q_REPO__", &shell_quoted(REPOSITORY))
        .replace("__Q_ORIGIN__", &shell_quoted(ui_origin))
        .replace("__ORIGIN__", ui_origin)
        .replace("__VERSION__", VERSION)
}

/// `tunnel` has no Windows build (it needs Unix sockets and signals); the
/// PowerShell one-liner says so instead of failing obscurely. It throws
/// rather than `exit`, which would close the window it runs in.
pub fn install_ps1(ui_origin: &str) -> String {
    format!(
        "# Tunnel client installer for {ui_origin}\n\
         & {{\n\
         throw 'tunnel: there is no Windows build of tunnel. In WSL, run: curl -fsSL {ui_origin}/install.sh | sh'\n\
         }}\n"
    )
}

pub fn response(state: &AppState, path: &str, method: &Method) -> Response<Body> {
    let Some(ui) = state.config.ui_host.as_deref() else {
        return Response::builder().status(StatusCode::NOT_FOUND).body(full("not found")).expect("valid response");
    };
    if !matches!(*method, Method::GET | Method::HEAD) {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .body(full(""))
            .expect("valid response");
    }
    let origin = format!("https://{ui}");
    let body = if path == "/install.ps1" { install_ps1(&origin) } else { install_sh(&origin) };
    Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(full(if *method == Method::HEAD { String::new() } else { body }))
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_pins_version_release_and_origin() {
        let s = install_sh("https://ui.example.com");
        assert!(s.starts_with("#!/bin/sh\n"));
        assert!(s.contains(&format!("TUNNEL_VERSION='{VERSION}'")));
        assert!(s.contains(&format!("TUNNEL_RELEASE_URL='{REPOSITORY}/releases/download/v{VERSION}'")));
        assert!(s.contains("TUNNEL_ORIGIN='https://ui.example.com'"));
        assert!(s.contains("checksum mismatch"));
        assert!(s.trim_end().ends_with("main \"$@\""));
        assert!(!s.contains("__"), "every placeholder is filled");
    }

    #[test]
    #[should_panic(expected = "refusing to embed")]
    fn refuses_quotes() {
        install_sh("https://ui.example.com'; rm -rf ~; '");
    }
}
