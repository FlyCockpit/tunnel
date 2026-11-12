# Changelog

All notable changes to Tunnel are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 - Unreleased

### Added

- First public release of Tunnel, licensed under MIT.
- A single server binary with TLS termination, DNS-01 certificate issuance and
  Cloudflare, Hetzner, DigitalOcean and Route53 support.
- Link-only, password and public tunnel access, with zone-host sign-in and
  single-use or reusable access links.
- One outbound WSS connection carrying multiple local ports with Yamux,
  supporting HTTP, WebSockets and SSE.
- A built-in STUN/TURN relay and automatic browser ICE configuration.
- Root and rootless setup, sandboxed systemd service, backup and restore,
  health checks and Prometheus metrics.
- A REST management API with OpenAPI and scoped per-machine client logins,
  sharing commands and access links.
- GitHub Release binaries for Linux and macOS clients, static Linux servers,
  signed SHA-256 checksums, installer and third-party license notices.
