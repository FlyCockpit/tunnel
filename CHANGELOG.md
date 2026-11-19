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
- Service credentials (`tnsvc_`) for platforms that manage tunnels on behalf of
  others, each with its own live-tunnel quota; tunnel-token rotation; a
  `label` filter on the tunnel list; public previews limited to the admin
  unless `limits.allow_public_for_clients` is set.
- Client: `TUNNEL_TARGET_HOST` / `--target` to forward exposed ports to an IP
  address instead of loopback, `--state-dir` / `TUNNEL_STATE_DIR` with a
  documented foreground `tunnel daemon` for supervisors, the forwarding target
  in `status --json`, and a non-dumpable daemon on Linux.
- Revoking an access link, a gate session expiring, an access change and
  closing the tunnel now also end proxied HTTP responses that are already
  streaming (SSE, long downloads) and uploads, not only WebSockets and new
  requests; `tunnel_access_cuts_total` counts them.
- Accounts and a web UI on its own `ui_host`: an owner created with
  `tunnel-server admin link` (also the recovery path), admins and members
  invited with single-use expiring links, per-member quotas (live tunnels,
  machines, tunnel lifetime), public previews only for admins or members an
  admin allows, disabling users, TOTP two-factor sign-in with recovery codes,
  an audit log, and strict CSRF, `Origin` and `Sec-Fetch-Site` checks on the
  cookie-authenticated `/ui/api/*` (the bearer API is unchanged).
- Browser-approved machine login (`tunnel login https://<ui_host>`, RFC 8628
  device flow); login codes for machines without a browser stay.
- `GET /v1/server` (origins, preview host template, the caller's limits) and
  `GET /v1/tunnels/{id}/access-links`.
- A server-served client installer, `/install.sh`, that installs this server's
  version from the GitHub release only if it matches the release's
  `sha256.sum`, then signs the machine in through the browser.
- Machine clients now belong to an account. A database from an earlier
  prerelease build is refused until upgraded once:
  `ALTER TABLE clients ADD COLUMN user_id TEXT REFERENCES users(id)` (with the
  service stopped), start the server, create the owner with `admin link`, then
  `UPDATE clients SET user_id = (SELECT id FROM users WHERE role = 'owner')`.
- The web UI (`crates/web`, Leptos rendered in the browser, about 270 kB
  gzip) embedded in release servers (`--features ui`); an agent skill printed
  by `tunnel help agent` (`docs/agent/SKILL.md`).
- Agent conveniences in the client: `--json` on `share`, `link` and `links`;
  `tunnel unshare [PORT…]` (deletes the shared tunnel, or stops sharing some
  ports); `share --for[=DURATION]` (foreground, unshares when the time is up
  or on a signal); `tunnel links` and `tunnel unlink <ID>`; `link --label`.
- `tunnel-server user invite [--role member|admin] [--hours N]` and
  `user delete <name>` for managing accounts from the server's shell.
- Traffic counters per tunnel and per user and month (request/response bodies
  and WebSocket messages, kept in memory and flushed about once a minute),
  shown in the web UI and the API (`bytes_in`/`bytes_out`, `traffic_limited`,
  `GET /v1/server` `limits.traffic`), and optional monthly per-user caps set
  by admins (`limits.member_monthly_traffic_gb` for new members): at the cap
  the user's tunnels answer 503 "Traffic limit reached" and in-flight requests
  and WebSockets are cut, until the cap is raised, the month is reset or a new
  month starts. A database from an earlier prerelease build is refused until
  upgraded once, with the service stopped:
  `ALTER TABLE tunnels ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0;`
  `ALTER TABLE tunnels ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0;`
  `ALTER TABLE users ADD COLUMN traffic_cap INTEGER;` (the `traffic` table is
  created on start). WebSocket traffic is now counted while it flows (it was
  counted only when a WebSocket closed cleanly).
- The sign-in page explains how to claim an owner account that has no
  password yet; loading the Users page no longer disables the invite button.
- Renaming machines: in the web UI (own machines; admins also members', the
  owner anyone's; audited), `tunnel-server client rename`, and
  `PATCH /v1/clients/{name}` for the admin token. New machine and service names
  made only of dots, or `enroll`, are refused (they collide with URL paths).
- GitHub Release binaries for Linux and macOS: static Linux servers and client
  archives (`tunnel-<target>.tar.xz`), `sha256.sum` checked fail closed by both
  installers, signed build provenance (GitHub artifact attestations, keyless),
  a Homebrew formula pinning each archive's checksum, and third-party license
  notices.