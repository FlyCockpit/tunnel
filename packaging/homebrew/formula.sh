#!/bin/sh
# Print the Homebrew formula for the tunnel client of release <version>,
# pinning each archive's SHA-256 from that release's sha256.sum:
#   packaging/homebrew/formula.sh 1.0.0 sha256.sum > tunnel.rb
# The release workflow attaches the result to the GitHub release; publishing
# it to a tap (FlyCockpit/homebrew-tap) is a separate, manual step.
set -eu
version=$1
sums=$2
sum() {
  awk -v f="tunnel-$1.tar.xz" '$2 == f || $2 == "*" f { print $1; found = 1; exit } END { exit !found }' "$sums" ||
    { echo "formula.sh: no checksum for tunnel-$1.tar.xz" >&2; exit 1; }
}
base="https://github.com/FlyCockpit/tunnel/releases/download/v$version"
# Looked up first, so a missing entry stops the script (set -e).
mac_arm=$(sum aarch64-apple-darwin)
mac_intel=$(sum x86_64-apple-darwin)
linux_arm=$(sum aarch64-unknown-linux-musl)
linux_intel=$(sum x86_64-unknown-linux-musl)
cat <<RUBY
class Tunnel < Formula
  desc "Share local ports at preview URLs over one outbound connection"
  homepage "https://github.com/FlyCockpit/tunnel"
  version "$version"
  license "MIT"

  on_macos do
    on_arm do
      url "$base/tunnel-aarch64-apple-darwin.tar.xz"
      sha256 "$mac_arm"
    end
    on_intel do
      url "$base/tunnel-x86_64-apple-darwin.tar.xz"
      sha256 "$mac_intel"
    end
  end

  on_linux do
    on_arm do
      url "$base/tunnel-aarch64-unknown-linux-musl.tar.xz"
      sha256 "$linux_arm"
    end
    on_intel do
      url "$base/tunnel-x86_64-unknown-linux-musl.tar.xz"
      sha256 "$linux_intel"
    end
  end

  def install
    bin.install "tunnel"
  end

  def caveats
    <<~EOS
      Sign this machine in to your server (you approve it in the browser):
        tunnel login https://<your tunnel server>
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tunnel --version")
  end
end
RUBY
