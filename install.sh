#!/bin/sh
# Tunnel server installer: download `tunnel-server`, install it to
# /usr/local/bin only if its SHA-256 matches the release's `sha256.sum`
# (fail closed), then run the setup wizard. All configuration logic lives in
# `tunnel-server setup`. The release also carries signed build provenance:
# `gh attestation verify tunnel-server-<target> --repo FlyCockpit/tunnel`.
#
#   curl -fsSL https://github.com/FlyCockpit/tunnel/releases/latest/download/install.sh | sudo sh
#   curl -fsSL https://github.com/FlyCockpit/tunnel/releases/latest/download/install.sh | sudo sh -s -- --staging
set -eu

# Override DOWNLOAD_BASE to install from a specific release or an HTTPS mirror.
DOWNLOAD_BASE="${DOWNLOAD_BASE:-https://github.com/FlyCockpit/tunnel/releases/latest/download}"

BIN=tunnel-server
INSTALL_DIR=/usr/local/bin

die() {
    echo "install.sh: $*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || die "only Linux is supported"
[ "$(id -u)" = 0 ] || die "must run as root (curl -fsSL ... | sudo sh)"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

case "$(uname -m)" in
    x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac
asset="$BIN-$target"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

fetch() {
    curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$1" "$DOWNLOAD_BASE/$1" ||
        die "download failed: $DOWNLOAD_BASE/$1"
}

echo "Downloading $asset from $DOWNLOAD_BASE"
fetch sha256.sum
fetch "$asset"

# Lines are "<hash>  <name>" (or "<hash> *<name>" in binary mode).
expected=$(awk -v f="$asset" '{ sub(/\r$/, "") } $2 == f || $2 == "*" f { print tolower($1); exit }' "$tmp/sha256.sum")
case "$expected" in
    "" | *[!0-9a-f]*) die "$asset is not listed in sha256.sum; not installing it" ;;
esac
[ ${#expected} -eq 64 ] || die "$asset is not listed in sha256.sum; not installing it"
actual=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"

# Copy then rename, so a running service's binary is replaced atomically.
mkdir -p "$INSTALL_DIR"
cp "$tmp/$asset" "$INSTALL_DIR/.$BIN.new"
chmod 0755 "$INSTALL_DIR/.$BIN.new"
mv -f "$INSTALL_DIR/.$BIN.new" "$INSTALL_DIR/$BIN"
echo "Installed $INSTALL_DIR/$BIN ($("$INSTALL_DIR/$BIN" --version 2>/dev/null || echo unknown version))"

# exec skips the EXIT trap.
rm -rf "$tmp"
trap - EXIT INT TERM

(exec </dev/tty) 2>/dev/null || die "no terminal available; run '$INSTALL_DIR/$BIN setup' from an interactive shell"
exec "$INSTALL_DIR/$BIN" setup "$@" </dev/tty
