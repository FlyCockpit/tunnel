# Changelog

All notable changes to Tunnel are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 - Unreleased

### Added

- Row-bound AES-256-GCM wrapping of every account and tunnel Argon2id password
  hash, using an HKDF-SHA256 key derived from `ui_secret`. A database-only leak
  no longer permits offline password guessing without the config secret.
  Setup now generates `ui_secret` even without the UI, and `serve` requires it.
  Startup converts legacy hashes atomically and refuses unknown keys or damaged
  seals; restore checks backup keys without modifying the backup.
- Two-factor recovery codes are stored sealed too: the code's SHA-256 inside
  row-bound AES-256-GCM under a separate HKDF-SHA256 key from `ui_secret`, so a
  database-only leak no longer allows offline guessing of the 50-bit codes.
  Startup converts existing codes without needing them, and `secret check`
  reports recovery-code counts.
- `tunnel-server secret rotate`: retain the old key as `ui_secret_previous`,
  generate a new server secret, and restart to re-seal passwords, recovery codes
  and TOTP secrets in one transaction. Existing sessions remain valid; open UI pages need a reload.
  Back up the config with the database; losing the secret requires password
  resets and two-factor re-enrollment.
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
  sharing commands and access links; `GET /v1/server` (origins, preview host
  template, the caller's limits) and `GET /v1/tunnels/{id}/access-links`.
- Service credentials (`tnsvc_`) for platforms that manage tunnels on behalf of
  others, each with its own live-tunnel quota; tunnel-token rotation; a
  `label` filter on the tunnel list; public previews limited to the admin
  unless `limits.allow_public_for_clients` is set.
- Revoking an access link, a gate session expiring, an access change and
  closing the tunnel end the visitor's in-flight requests as well: streaming
  responses (SSE, long downloads), uploads and WebSockets;
  `tunnel_access_cuts_total` counts them.
- Accounts and a web UI on its own `ui_host`: an owner created with
  `tunnel-server admin link` (also the recovery path), admins and members
  invited with single-use expiring links, per-user limits set by admins (for
  members) and the owner (for admins) in the Users page — live tunnels,
  machines, tunnel lifetime and monthly traffic, each Server default, a number
  or Unlimited (an unlimited lifetime allows tunnels that never expire),
  audited, shown on the Account page and in `GET /v1/server` — public previews only for admins or members an
  admin allows, disabling users, TOTP two-factor sign-in with recovery codes,
  an audit log, and strict CSRF, `Origin` and `Sec-Fetch-Site` checks on the
  cookie-authenticated `/ui/api/*`. Every machine client belongs to an account.
  The sign-in page explains how to claim an owner account that has no
  password yet.
- The web UI (`crates/web`, Leptos rendered in the browser, about 270 kB
  gzip) embedded in release servers (`--features ui`).
- Machine login approved in the browser (`tunnel login https://<ui_host>`,
  RFC 8628 device flow), or with a login code for machines without a browser.
- Renaming machines: in the web UI (own machines; admins also members', the
  owner anyone's; audited), `tunnel-server client rename`, and
  `PATCH /v1/clients/{name}` for the admin token. New machine and service names
  made only of dots, or `enroll`, are refused (they collide with URL paths).
- Tunnel display names: `tunnel share --name`, `name` on the tunnel API, and
  Rename in the web UI (audited). A label only: URLs and links never change.
  Shown first in the dashboard and in `tunnel status`.
- Open on your own tunnel in the web UI goes to the preview signed in, without
  its password or link prompt, through a single-use owner link bound to that
  port (a minute at most, audited; a browser's repeated request from the same
  address within seconds still lands). Others' tunnels get Visit (their normal
  sign-in).
- The web UI works on phones and tablets: a two-row header, tables that
  become one card per row, and 44 px touch targets.
- One user menu in the web UI's header, as in the other FlyCockpit apps: who
  is signed in, Account, the admin pages (Users, Server), the theme (Light,
  Dark, System) and Sign out, usable from the keyboard and with a screen
  reader. Signed out, a theme button opens the theme choices.
- Every dead end in the web UI and on the preview gate says what to do next:
  errors read as sentences, a wrong password points to the reset, a
  signed-out machine approval says why it asks for a sign-in, an unusable
  invite or access link says so and whom to ask, and the preview sign-in
  form names the preview it opens. Two-factor setup can be left with
  Not now, and deleting a tunnel, revoking a link or an invite and removing
  a machine ask first. On Machines, a new machine's name clears once its
  code is made, a taken name is flagged at the field, and removing that
  machine hides its code.
- A reload of the web UI paints its own header, nav and footer at once (from
  a non-secret "last signed in as" hint), with only the content as a
  placeholder; the Users page's limits editor has one row per limit with the
  unit inline and errors next to the field; Account → Sessions names devices
  ("Chrome on Linux") with the raw user agent under Browser details.
- `tunnel-server user invite [--role member|admin] [--hours N]` and
  `user delete <name>` for managing accounts from the server's shell.
- Sign-in reset links for someone locked out: Reset sign-in in the Users page
  (admins for members, the owner for admins; a fresh code with two-factor
  sign-in on) or `tunnel-server user reset <name> [--hours N]`. Single-use,
  an hour by default; opening one sets a new password, turns two-factor
  sign-in off and ends the account's sessions. Void after any sign-in or role
  change of the account, or once its maker may no longer reset it; audited.
- Optional email (`[smtp]`, lettre over rustls): `setup` offers it (flags
  `--smtp-*`, password from `$SMTP_PASS`), `tunnel-server mail setup | test |
  off` changes it later; failures name the step. With it: mailed invites
  (confirming the address), a confirmed address per account (changes confirmed
  by mail, the old address told), "Forgot password?" (same answer for every
  input, rate limited, keeps two-factor sign-in and asks for its code), sign-in
  resets mailed by admins (sharing the one-mail-per-two-minutes account limit
  with "Forgot password?"), and security notices. Without it nothing changes.
- Traffic counters per tunnel and per user and month (request/response bodies
  and WebSocket messages, counted while they flow, kept in memory and flushed
  about once a minute), shown in the web UI and the API (`bytes_in`/`bytes_out`,
  `traffic_limited`, `GET /v1/server` `limits.traffic`), and optional monthly
  per-user caps set by admins (`limits.member_monthly_traffic_gb` for new
  members): at the cap the user's tunnels answer 503 "Traffic limit reached"
  and in-flight requests and WebSockets are cut, until the cap is raised, the
  month is reset or a new month starts.
- Client: `TUNNEL_TARGET_HOST` / `--target` to forward exposed ports to an IP
  address instead of loopback, `--state-dir` / `TUNNEL_STATE_DIR` with a
  documented foreground `tunnel daemon` for supervisors, the forwarding target
  in `status --json`, and a non-dumpable daemon on Linux.
- Agent conveniences in the client: `--json` on `share`, `link` and `links`;
  `tunnel unshare [PORT…]` (deletes the shared tunnel, or stops sharing some
  ports); `share --for[=DURATION]` (foreground, unshares when the time is up
  or on a signal); `tunnel links` and `tunnel unlink <ID>`; `link --label`;
  an agent skill printed by `tunnel help agent` (`docs/agent/SKILL.md`).
- A server-served client installer, `/install.sh`, that installs this server's
  version from the GitHub release only if it matches the release's
  `sha256.sum`, then signs the machine in through the browser.
- GitHub Release binaries for Linux and macOS: static Linux servers and client
  archives (`tunnel-<target>.tar.xz`), `sha256.sum` checked fail closed by both
  installers, signed build provenance (GitHub artifact attestations, keyless),
  a Homebrew formula pinning each archive's checksum, and third-party license
  notices.
