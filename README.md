<p align="center">
  <img src=".github/assets/logo.png" alt="" width="160" height="160">
</p>

<h1 align="center">Tunnel</h1>

<p align="center">A self-hosted preview tunnel that exposes ports from machines with no public IP over one outbound WSS connection, behind an access gate.</p>

<p align="center">
  <a href="LICENSE"><img src="https://shieldcn.dev/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://github.com/FlyCockpit/tunnel/releases"><img src="https://shieldcn.dev/github/FlyCockpit/tunnel/release.svg" alt="GitHub release"></a>
  <a href="https://www.rust-lang.org/tools/install"><img src="https://shieldcn.dev/badge/Rust-1.89%2B-orange.svg?logo=rust" alt="Rust 1.89+"></a>
  <a href="https://github.com/FlyCockpit"><img src="https://shieldcn.dev/badge/part%20of-FlyCockpit-0ea5e9.svg" alt="Part of FlyCockpit"></a>
</p>

> **Status: pre-release.** The first release, 1.0.0, is pending. The installer will work once that release is published and its minisign public-key placeholder is replaced (see [Installation](#installation)).

A sandbox or development machine with no public IP and only outbound 443 runs `tunnel`, which keeps one WSS connection to a VPS running `tunnel-server`. Visitors open `https://{port}-{id}.previews.example.com`, pass a cookie gate minted from a click-time access link, and reach the local port over HTTP/1.1, HTTP/2, WebSockets, SSE, and WebRTC (built-in STUN/TURN relay). It is for people who build apps in sandboxes or on laptops and need to share a running preview.

## Features

- **One binary server.** `tunnel-server` terminates its own TLS and issues Let's Encrypt certificates over DNS-01 (Cloudflare, Hetzner, DigitalOcean, Route53).
- **Access gate.** Each tunnel is link-only, password-protected or public, with a cookie gate on the zone host. Access links work in every mode.
- **One outbound connection.** `tunnel` multiplexes every exposed port with Yamux over a single WSS connection.
- **WebRTC.** A built-in STUN/TURN relay (no coturn), with ICE configuration injected into preview pages.
- **Operations.** An interactive or non-interactive setup wizard (rootless supported), a systemd unit, backup and restore, `/healthz`, and Prometheus metrics.
- **Management API.** A REST API with an OpenAPI document at `/v1/openapi.json`, plus per-machine client logins (`login`, `share`, `link`).

## How it works

```text
tunnel ──one WSS (Yamux)──▶ tunnel-server ◀── visitor (HTTPS)
  (sandbox)                 SNI peek → TLS → hyper → gate → proxy over a Yamux stream
```

The server peeks at each TLS ClientHello on port 443: TURN-over-TLS goes to the relay, everything else is terminated and served by hyper. Requests for a preview host pass the access gate and are forwarded over a Yamux stream on the sandbox's connection. The axum management API and a SQLite store run in the same binary.

## Quick start

```sh
# On the server: the wizard sets up DNS, the certificate and the service,
# and prints the admin token once
cargo build --release -p tunnel-server
./target/release/tunnel-server setup
# Create a one-time login code for a laptop
./target/release/tunnel-server client add laptop

# On the laptop: paste the login code, then share a port
cargo build --release -p tunnel-client
./target/release/tunnel login
./target/release/tunnel share 3000
```

Running server setup without `sudo` selects rootless mode; use `sudo` for a system install.

## Installation

### Build from source

Requires Rust 1.89+. The C toolchain is needed for `ring` and the bundled SQLite.

```sh
cargo build --release -p tunnel-server
# Bake the default tunnel server into the sandbox client (TUNNEL_SERVER overrides it at runtime):
TUNNEL_DEFAULT_SERVER=wss://tunnel.example.com cargo build --release -p tunnel-client
cargo test --workspace
```

Static Linux binaries (what `install.sh` downloads, and what sandboxes run):

```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl -p tunnel-server
cargo build --release --target x86_64-unknown-linux-musl -p tunnel-client
# aarch64 from x86_64 needs a cross C toolchain, e.g. `cargo zigbuild` or `cross`:
cargo zigbuild --release --target aarch64-unknown-linux-musl -p tunnel-server
```

`tunnel` is supported on Linux and macOS (non-Unix targets fail with `compile_error!`).

### Release artifacts and installer

GitHub Releases are the distribution channel. The release workflow builds:

- `tunnel-server-<target>` and `tunnel-<target>` for
  `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (static Linux binaries).
- `tunnel-<target>` for `aarch64-apple-darwin` and `x86_64-apple-darwin`.
- `install.sh`, `THIRD_PARTY_LICENSES.html`, `SHA256SUMS` covering every asset,
  and its minisign signature, `SHA256SUMS.minisig`.

The workflow checks the release tag against the workspace version and uses the
version's changelog entry as release notes. The Linux server installer checks the
minisign signature and SHA-256 before installation. Before the first release,
replace its `MINISIGN_PUBKEY` placeholder. Until then it refuses installation
unless `TUNNEL_ALLOW_UNSIGNED=1` is explicitly set (SHA-256 is still checked).

### Server setup

On the server (Debian 12+, Ubuntu 22.04+, Fedora 40+, RHEL/Alma/Rocky 9+), once a release and its installer are published:

On a minimal Debian/Ubuntu VPS, install the prerequisites first. ACME uses the
system CA store, so `ca-certificates` is required even with a static binary:

```sh
# Already root (many VPS images have no sudo):
apt-get update
apt-get install -y ca-certificates curl
# Otherwise:
sudo apt-get update
sudo apt-get install -y ca-certificates curl
```

```sh
# Already root:
curl -fsSL https://github.com/FlyCockpit/tunnel/releases/latest/download/install.sh | sh
# Otherwise:
curl -fsSL https://github.com/FlyCockpit/tunnel/releases/latest/download/install.sh | sudo sh
```

Until the installer's minisign key placeholder is replaced, explicitly opt in to
checksum-only verification. Put the environment assignment after `sudo`, which
otherwise resets it:

```sh
# Already root:
curl -fsSL https://github.com/FlyCockpit/tunnel/releases/latest/download/install.sh | TUNNEL_ALLOW_UNSIGNED=1 sh
# Otherwise:
curl -fsSL https://github.com/FlyCockpit/tunnel/releases/latest/download/install.sh | sudo TUNNEL_ALLOW_UNSIGNED=1 sh
```

Append `-s -- --staging` to `sh` to test against Let's Encrypt staging.
Open inbound TCP 80 and 443 in any cloud provider firewall as well as the host firewall.
For Cloudflare, give the API token **Zone → DNS → Edit** AND **Zone → Zone → Read**
for the selected zone. The plain "Edit zone DNS" template lacks Zone Read,
which setup needs for `GET /zones`.

The installer verifies the binary, installs it to `/usr/local/bin`, and
execs `tunnel-server setup </dev/tty`. The wizard asks for domains,
ACME email, DNS provider (Cloudflare, Hetzner, DigitalOcean, Route53) and
token, and whether to enable WebRTC; then creates the service user and
directories, writes `/etc/tunnel-server/config.toml`, creates and verifies
DNS records, issues the certificate (DNS-01), configures the
firewall, installs the systemd unit, self-tests, and prints the admin token
once. For root installs, `config.toml` is owned by `root:tunnel-server` with
mode 0640, and the data directory must be the default `/var/lib/tunnel`
(setup and `restore` refuse to change ownership of any other path as root). The systemd unit uses `NoNewPrivileges`, `ProtectSystem=strict` and
restricted writable paths. Re-running `setup` changes nothing unless an answer changed.
Setup will not take over another program's names: it refuses an existing `tunnel-server`
account that isn't a no-login account with home `/var/lib/tunnel`, and an existing
`tunnel-server.service` whose `ExecStart` isn't `tunnel-server`. Rootless setup leaves
alone any `/etc/tunnel-server` that doesn't hold a Tunnel config.

#### Rootless install

To get the binary without root, download the server asset and verification files
directly. You need `curl`, `sha256sum`, and `minisign` available to your user.
Choose `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl` for your server:

```sh
target=x86_64-unknown-linux-musl
release=https://github.com/FlyCockpit/tunnel/releases/latest/download
curl -fSLO "$release/tunnel-server-$target"
curl -fSLO "$release/SHA256SUMS"
curl -fSLO "$release/SHA256SUMS.minisig"
minisign -Vm SHA256SUMS -P '<key>'
sha256sum -c --ignore-missing SHA256SUMS
chmod +x "tunnel-server-$target"
./tunnel-server-$target setup
```

Replace `<key>` with the published project minisign public key. Signature
verification requires that key to be published; the placeholder is not a key.
Setup copies itself to `~/.local/bin/tunnel-server`.

Run setup as a normal user (no root after one preflight command).
Its preflight prints one `sudo sh -c '…'` line (unprivileged
ports from 80, lingering, and moving an existing root install); after that,
setup, upgrades, and restarts need no root. The user unit is written under
`$XDG_CONFIG_HOME/systemd/user` (default `~/.config/systemd/user`), so
`XDG_CONFIG_HOME` must be the same for setup and the user's systemd manager.
Non-interactive:

```sh
tunnel-server setup --yes --host tunnel.example.com --email you@example.com \
  --dns-token-file ~/cf-token --frame-ancestors '*'
```

One hostname covers everything: the API and sandbox tunnel use it, previews are
`*.<host>`, TURN is `turn.<host>`, and two DNS records (`<host>`, `*.<host>`) suffice.

## Configuration

The server configuration lives in `/etc/tunnel-server/config.toml` (rootless installs: `$XDG_CONFIG_HOME/tunnel-server/config.toml`, default `~/.config/tunnel-server/config.toml`; the data directory is `$XDG_DATA_HOME/tunnel`, default `~/.local/share/tunnel`). It holds the host, the DNS provider token, `frame_ancestors`, the `[webrtc]` section and limits. The admin token is stored hashed. The server needs TCP 443 and 80, and with WebRTC also UDP/TCP 3478 and UDP 49160–49999 by default.

Every HTTPS response carries `Strict-Transport-Security: max-age=31536000`
(without `includeSubDomains`, so other subdomains of the domain you use are
unaffected).

The client reads `TUNNEL_TOKEN`, `TUNNEL_SERVER`, `TUNNEL_ICE_FILE` and `TUNNEL_ICE_PORT`; see the [client README](crates/client/README.md#environment).

### WebRTC

`setup --webrtc true` turns on the built-in STUN/TURN relay (no coturn,
works rootless). It listens on UDP and TCP 3478 and takes TURN over TLS on 443
(SNI `turn.<host>`, covered by the wildcard certificate and DNS record). Relays
use UDP ports at the public IPv4 in `webrtc.relay_min_port` through
`webrtc.relay_max_port` (inclusive; default 49160–49999). Setup opens the
configured STUN/TURN port (default UDP/TCP 3478) and UDP relay range in active
ufw/firewalld for a system install; rootless setup prints the required rules.
Open those ports in any cloud firewall too. Relays never reach non-public
addresses or the server's own other ports; relay-to-relay traffic stays in
process. The total is capped at 1,200 relays and by the configured port range
(840 ports by default), with 3 Mbit/s per relay in both directions combined
and at most 1,000 TCP/TLS connections. Credentials are the per-tunnel ones the edge injects and
`tunnel ice` prints (TURN REST, `webrtc.static_auth_secret`). Per-tunnel
and per-source-IP relay quotas are each 240 (IPv6 sources share a /64 quota).
Reaching a relay quota returns TURN error 486 (Allocation Quota Reached).
Deleting a tunnel immediately invalidates its credentials and closes its existing relays. TCP/TLS
TURN connections are closed if they do not authenticate promptly.

## Usage

### Administration

Admin commands: `tunnel-server status`, `token rotate`, `backup <path>`, `restore <path>`,
`cert renew [--force]`, `client add <name> | list | delete <name>`, and
`service add <name> --max-tunnels <n> | list | set <name> --max-tunnels <n> | rotate <name> | delete <name>`
(root only for a root install).

Health check: `GET https://<host>/healthz` returns JSON (`status`, `database`,
`certificate_days_left`): 200 when healthy, 503 when the database does not answer
or the certificate is missing or has fewer than 7 full days left. It is open by default
and omits the version. `tunnel-server health-token set` restricts it to
callers presenting the printed health token (`Authorization: Bearer …` or
`?token=…`, for uptime monitors); these authenticated responses also include
`version`. The admin token is not accepted. Other callers receive 404.
`health-token clear` reopens it.

Backups: `backup <path>` writes a consistent copy of the database (0600; it holds
token hashes). `restore <path>` checks the copy's integrity, stops the service,
keeps the current database as `tunnel.db.before-restore-<time>`, swaps the
copy in, and starts the service again. The config file (`config.toml`) and the
`certs/` directory are not in the database; back them up separately. `restore`
accepts only databases written by Tunnel 1.0.0 or later.

### Tunnels and access

`POST /v1/tunnels` and `PATCH /v1/tunnels/{id}` take
`access: {mode: "link" | "password" | "public", username, password}`. The creator
(admin, client or service token) chooses the mode and can change it; a tunnel token
cannot change access settings. Only the admin token may make a tunnel public
unless `limits.allow_public_for_clients = true`; client and service tokens
otherwise get HTTP 403 `public_not_allowed` when creating a public tunnel or
switching one to public (link and password mode stay available).

- **Link** (default): visitors need an access link to establish a gate session.
- **Password**: visitors sign in with the configured username and password;
  access links also work. An expired or consumed link shows the login page.
- **Public**: anyone with the preview URL can visit without a gate session.

Mint links with `POST /v1/tunnels/{id}/access-links` (or `tunnel link`).
The response's `url` points to
`https://<zone>/__access/{port}-{id}/{token}`. Links can be single-use or reusable until
expiry. Redeeming one grants a cookie session for every port of that tunnel;
revoking the link revokes the sessions derived from it. Mint single-use links
when a visitor clicks to open a preview so link scanners cannot consume them early.

Revocation and expiry also end what is already running. When a link is revoked,
the access mode or password changes, or the tunnel is deleted, gets a new token
or disconnects, every request and WebSocket still in progress on that tunnel
stops relaying at once, in either direction, and is rechecked (normally within
milliseconds; a recheck that cannot reach the database within 10 seconds counts
as lost). When a gate session expires, only the requests admitted with it are
rechecked, at that moment. The one exception is the CORS preflight a protected
tunnel lets through without a session (an `OPTIONS` stripped of cookies and
body): it holds no access to lose and is not watched.

A request admitted with a gate session keeps going if any session it presented
is still valid; one admitted while the tunnel was public keeps going only while
the tunnel stays public. The ones that lost their access end within moments,
whether or not the visitor is still reading: a response still streaming (SSE, a
long download, a chunked body) is aborted mid-body, so the visitor sees a broken
transfer rather than a complete one (an HTTP/1.0 client reading a response
without a length can tell only from the connection closing early); an upload is
cut and the origin connection closed, even if the origin stopped reading it; a
request still waiting for the origin gets a 401; a WebSocket is closed. A cut
exchange still counts against the tunnel's stream limit until the visitor's
connection lets go of it, as any slow visitor does. `tunnel_access_cuts_total`
on the metrics endpoint counts these cuts. A tunnel that reaches its own expiry
is ended the same way by the expiry sweep, within 15 seconds. Bytes already
handed to the connection before the revocation may still reach a slow reader
before it sees the failure; nothing the origin sends later does.

Sign-in lives only on the zone host: `/__access/...` for links and `/__login`
for passwords. These routes are absent on preview hosts, keeping preview service
workers away from access tokens and passwords. The gate cookie is Secure,
HttpOnly and Partitioned with SameSite=None. A session established in an iframe
belongs to that parent site's partition; a direct visit needs its own link.

`frame_ancestors` defaults to an empty list: previews may be framed only by their
own origin. List allowed HTTPS sites to permit other parents. Allowing any site
requires an explicit `setup --frame-ancestors '*'`.

Because every preview shares one site, the gate checks `Origin` on WebSocket
upgrades and state-changing requests that carry a gate session. It allows only
the tunnel's own preview hosts, sites listed in `frame_ancestors` (`*` does not
count), and requests without an `Origin` (non-browser clients). Top-level form
submissions from unrelated sites (for example an OAuth `form_post` callback) are
also allowed. Everything else, including other previews, gets a 403.

`POST /v1/tunnels/{id}/token` replaces the tunnel token and returns the new one
once. The old token can no longer connect, and a connection made with it is
closed with `replaced` (the client exits with code 4). Use it when the tunnel
moves to another host. Expired tunnels return 409.

Tunnel, client and service list endpoints accept `limit` (default 100, range 1–500) and
`cursor` for pagination. `GET /v1/tunnels` also takes `label` (exact match), and
rejects unknown query parameters. Pass the response's `next_cursor` as the next request's
`cursor`; `next_cursor` is omitted on the last page. Invalid parameters return 422.

### Logged-in machines

`tunnel-server client add laptop` prints a one-time (15 min) login code:

```sh
tunnel login                # on the laptop; paste tnenr_…@tunnel.example.com
tunnel share 3000           # prints a one-time link
tunnel share 5173 --public  # same tunnel, now public
tunnel link --reusable      # another link
tunnel stop                 # deletes the tunnel
```

The login code is single-use and expires after 15 minutes. Enrollment exchanges
it for a long-lived `tncli_` client token saved locally; it lasts until the client
is deleted. A client token can manage only the tunnels it created and their
access links. It may own at most `limits.max_tunnels_per_client` tunnels
(default 20 live tunnels); creation beyond this quota returns HTTP 429 with
`error.code: "tunnel_quota"`. Admin tokens are exempt. `client list` shows enrolled machines; `client delete <name>`
revokes the token, cancels pending codes and stops its tunnels. `logout` only
forgets the local login.

### Service credentials

A service (for example a sandbox platform that creates one tunnel per sandbox)
gets an API-only `tnsvc_` token from the admin:

```sh
tunnel-server service add wssp --max-tunnels 200 --token-file ./wssp.token  # or omit --token-file to print it once
```

The admin API offers the same: `POST /v1/services {name, max_tunnels}` returns
the token once; `GET /v1/services`, `PATCH /v1/services/{name} {max_tunnels}`,
`POST /v1/services/{name}/token` (rotate) and `DELETE /v1/services/{name}`.

A service token works like a client token on `/v1/tunnels` and
`/v1/access-links`: it sees, changes and deletes only the tunnels it created and
their links, and cannot manage clients or services. It may own at most its
own `max_tunnels` live tunnels (HTTP 429 `tunnel_quota` beyond that); lowering
the quota keeps existing tunnels. Hand each host only its tunnel's `tntun_` token,
and rotate that token when the tunnel moves. Deleting a service revokes its token
and stops its tunnels.

### Sandbox client

Inside a sandbox, `tunnel expose <port>` uses a tunnel token passed in `TUNNEL_TOKEN`. The [client README](crates/client/README.md) covers its commands, state, ICE helpers and exit codes.

## Development

```sh
cargo build --workspace
cargo test --workspace
```

### Workspace layout

```text
Cargo.toml                 workspace, shared dependency versions, release profile
install.sh                 curl | sh installer: download, verify, exec `setup`
crates/protocol/           wire messages, constants, mux (rust-yamux driver), WebSocket↔bytes bridge
crates/server/             tunnel-server (VPS)
  src/main.rs              CLI: serve | setup | token rotate | health-token | status | backup | restore | cert renew | client
  src/commands.rs          non-interactive subcommands; `serve` wires everything together
  src/listener.rs          :443 (SNI peek → TURN over TLS, else TLS + hyper auto) and :80 redirect
  src/turn_relay.rs        built-in STUN/TURN relay (UDP/TCP 3478, TLS via 443), peer filter, limits
  src/edge.rs proxy.rs     visitor edge: lifecycle, gate, reserved paths, forwarding, WebSockets
  src/gate.rs gatehost.rs  gate cookie; sign-in (links, password) on the zone host
  src/headers.rs           hop-by-hop, Origin/Location/Set-Cookie/CSP/iframe rewrites
  src/inject.rs            streaming ICE <script> injection + CSP hash
  src/pages.rs ratelimit.rs
  src/api.rs               management API (axum, utoipa OpenAPI)
  src/control.rs           sandbox control plane (/v1/connect → Yamux)
  src/registry.rs state.rs live connections, shared state and caches
  src/db.rs purge.rs       SQLite and the hourly purge
  src/tls.rs sni.rs acme.rs dns/   certificate store, ClientHello peek, DNS-01 issuance, DNS providers
  src/ice.rs metrics.rs    TURN REST credentials, Prometheus text on 127.0.0.1:9464
  src/setup/               interactive wizard (prompts, firewall, systemd)
crates/client/             tunnel-client (sandbox); see crates/client/README.md
```

## Documentation

- [`tunnel` client](crates/client/README.md): commands, logged-in machines, environment and exit codes

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
development checks, contribution licensing and sign-off requirements.

## Security

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/FlyCockpit/tunnel/security/advisories/new).
See [SECURITY.md](SECURITY.md) for supported versions and scope.

## License

MIT. Copyright (c) 2026 FlyCockpit LLC. See [LICENSE](LICENSE).

Release binaries ship with `THIRD_PARTY_LICENSES.html` for dependency notices.
