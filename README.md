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

> **Status: pre-release.** The first release, 1.0.0, is pending. The installers work once that release is published (see [Installation](#installation)).

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

- `tunnel-server-<target>` for `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl` (static Linux binaries, web UI embedded).
- `tunnel-<target>.tar.xz` (holding `tunnel-<target>/tunnel`) for those two
  and for `aarch64-apple-darwin` and `x86_64-apple-darwin`.
- `install.sh` (server), `tunnel.rb` (Homebrew formula pinning each client
  archive's SHA-256), third-party notices (`THIRD_PARTY_LICENSES.html`, and
  `THIRD_PARTY_LICENSES_WEB_UI*` for the embedded web UI and its font), and
  `sha256.sum` covering every asset.

The workflow checks the release tag against the workspace version, uses the
version's changelog entry as release notes, and signs SLSA build provenance
for every binary, archive and `sha256.sum` with GitHub artifact attestations
(keyless; no signing key or repository secret). Verify a download with:

```sh
sha256sum --ignore-missing -c sha256.sum
gh attestation verify tunnel-server-x86_64-unknown-linux-musl --repo FlyCockpit/tunnel
```

Both installers refuse to install anything that does not match `sha256.sum`
(no file, no entry, no hashing tool or a mismatch stops them). The server's
installer is `install.sh` in the release; the client's is served by every
server with the web UI at `https://<ui_host>/install.sh` (it installs that
server's version into `~/.local/bin`, then runs `tunnel login https://<ui_host>`).
Homebrew users can install the client from the release's formula once it is
in a tap (`brew install flycockpit/tap/tunnel`).

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
directly. You need `curl` and `sha256sum` available to your user.
Choose `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl` for your server:

```sh
target=x86_64-unknown-linux-musl
release=https://github.com/FlyCockpit/tunnel/releases/latest/download
curl -fSLO "$release/tunnel-server-$target"
curl -fSLO "$release/sha256.sum"
sha256sum -c --ignore-missing sha256.sum
gh attestation verify "tunnel-server-$target" --repo FlyCockpit/tunnel   # optional, needs the GitHub CLI
chmod +x "tunnel-server-$target"
./tunnel-server-$target setup
```

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

The web UI gets its own name (see [Hosts and domains](#web-ui-accounts-and-hosts)):
by default `<first label>-ui.<rest>` (e.g. `tunnel-ui.example.com`), since
names under the preview zone are previews; `--ui-host none` turns it off.
Setup asks whether other people will use the server (`--multi-user`); if so,
the preview zone must be on a separate registrable domain, possibly at
another DNS provider, and setup then needs that zone's settings too:

```sh
tunnel-server setup --yes --host tunnel.example.com --email you@example.com \
  --dns-token-file ~/cf-token --multi-user true \
  --preview-zone previews.example-previews.com \
  --preview-dns-provider hetzner --preview-dns-zone example-previews.com \
  --preview-dns-token-file ~/hetzner-token
```

The config keeps the extra zone under `[[extra_dns]]`; each name uses the most
specific zone holding it, for records and for DNS-01 certificate challenges.
For a DNS provider setup does not support, create the records it prints
yourself (`--skip-dns`; setup still verifies them) and bring your own
certificate (`--own-certificate true`): put `fullchain.pem` and `privkey.pem`
covering every listed name into the data directory's `certs/`; the server
reloads replacements within a minute, never issues or renews one itself, and
warns in its log when the certificate needs replacing. A first setup with the
web UI ends by printing the one-time link that creates the owner account.

## Configuration

The server configuration lives in `/etc/tunnel-server/config.toml` (rootless installs: `$XDG_CONFIG_HOME/tunnel-server/config.toml`, default `~/.config/tunnel-server/config.toml`; the data directory is `$XDG_DATA_HOME/tunnel`, default `~/.local/share/tunnel`). It holds the host, the DNS provider token, `frame_ancestors`, the `[webrtc]` section and limits. The admin token is stored hashed. The server needs TCP 443 and 80, and with WebRTC also UDP/TCP 3478 and UDP 49160–49999 by default.

Every HTTPS response carries `Strict-Transport-Security: max-age=31536000`
(without `includeSubDomains`, so other subdomains of the domain you use are
unaffected).

The client reads `TUNNEL_TOKEN`, `TUNNEL_SERVER`, `TUNNEL_ICE_FILE` and `TUNNEL_ICE_PORT`; see the [client README](crates/client/README.md#environment).

### Web UI, accounts and hosts

The web UI lives on its own host, `ui_host`, and is off until that is set
(together with `ui_secret`, at least 32 random characters, e.g.
`openssl rand -base64 33`; it seals TOTP secrets and derives CSRF tokens, so
keep it with the config's other secrets). The UI host serves the app, its JSON
API under `/ui/api/*`, the client installer (`/install.sh`) and the bearer API
under `/v1/*`; `api_host` serves the bearer API under `/v1/*` too.

**Hosts and domains.** `ui_host` and `preview_zone` are independent:

| Layout | Example | Use |
|---|---|---|
| Separate registrable domain (recommended) | UI `tunnel.example.com`, previews `*.example-previews.com` | required when people other than you use the server |
| Preview zone under a separate domain | UI `tunnel.example.com`, previews `*.p.example-previews.com` | same, when the preview domain also hosts other things |
| Same domain | UI `tunnel.example.com`, previews `*.previews.example.com` | single-user only; the UI's status page warns |

The UI must never be the preview zone or a name under it (the server refuses
that config): previews run code anyone with a machine wrote, and a page on the
preview apex or a preview host would be same-origin or a parent of every
preview. The preview zone's apex serves only the sign-in pages
(`/__access/…`, `/__login`) and nothing else. Even with the UI on a
separate name, previews on the same registrable domain are *same-site* with
it: the UI defends against that (below), but a preview can still evict the
UI's cookie by flooding the cookie jar (sign-out only), password managers may
offer UI passwords on preview pages, and look-alike pages live on your own
domain. A separate preview domain removes all three. Operators of public
multi-tenant servers should also get the preview zone onto the
[Public Suffix List](https://publicsuffix.org/) (as `github.io` is), which
makes browsers treat each preview host as its own site, isolating previews
from each other too.

**Defenses on the UI.** The session cookie is `__Host-tunnel-ui` (host-only,
`Secure`, `HttpOnly`, `SameSite=Strict`); the edge never forwards it to an
origin. Every `/ui/api/*` request must carry `X-Tunnel-CSRF` (a custom header
forces a CORS preflight, which the server never grants; writes need the
session's token), an `Origin` of exactly `https://<ui_host>` (required except
on GET), and `Sec-Fetch-Site: same-origin` when the browser sends it. Pages
use a strict CSP (`script-src 'self' 'wasm-unsafe-eval'`, no inline script,
`frame-ancestors 'none'`). The bearer API ignores cookies and `Origin`, and
access-link redemption on the preview zone stays a cross-site top-level GET.

**Accounts.** `tunnel-server admin link` prints a one-time link (15 minutes)
to create the owner account; run on a server that has an owner, it resets the
owner's password and turns two-factor sign-in off (the recovery path; the
page can also remove all of the owner's machines). Machines added before
anyone signed up (`client add` or `POST /v1/clients` without a user) belong to
an owner account without a password, which the setup link later claims.
Accounts are owner, admin or member. Admins invite people with single-use,
expiring links (`https://<ui_host>/invite#…`, 7 days by default; the token
stays in the fragment, out of logs), manage members, and see every tunnel;
only the owner invites or changes admins. Members see and manage only their
own machines, tunnels and links, within their quotas (defaults
`limits.member_max_tunnels` 10 live tunnels across their machines,
`member_max_clients` 5 machines, `member_max_tunnel_ttl_s` 7 days). Members
cannot create public previews unless an admin allows it for them
(`can_public`) or `limits.allow_public_for_clients` is on; access links and
password mode always work. Disabling a user ends their sessions, removes their
machines and closes their tunnels. Sign-in is username and password
(Argon2id) with optional TOTP and ten single-use recovery codes; changing the
password or the second factor ends the user's other sessions, and a sign-in
that was being checked while that happened does not get a session. Sign-in is
limited per address (`limits.login_rate_per_min`, default 10) and per username
(three times that, so one address cannot lock anyone out) before any password
is hashed; five wrong codes in a row lock the second factor for 15 minutes,
doubling up to a day. Users with two-factor sign-in confirm approving or
adding a machine with a code when their last check is older than ten minutes. The UI keeps an audit log (90 days).
`tunnel-server user list` lists accounts; from the server's shell,
`user invite [--role member|admin] [--hours N]` prints an invite link (as the
owner would make one) and `user delete <name>` removes an account other than
the owner, with its sessions and machines. There is no open sign-up, no email
and no SSO.

**Traffic.** The server counts what each tunnel relays (request and response
bodies and WebSocket messages, both directions; headers are not counted) per
tunnel and, for tunnels of a user's machines, per user and calendar month
(UTC). Counters live in memory and are written to the database about once a
minute (nothing is written while idle; a restart may lose the last minute,
in the user's favour). Admins can give a member a monthly cap (the owner can
also cap admins; nobody caps the owner) in the Users page, and new members
get `limits.member_monthly_traffic_gb` if it is set (default: no cap). Once a
user reaches their cap, their tunnels answer **503 "Traffic limit reached"**
(no caching) and what they were relaying is cut at once (downloads, uploads,
WebSockets); their machines can still sign in and create tunnels, and the
API's tunnel views and `GET /v1/server` say `traffic_limited`. Raising or
removing the cap, "Reset month" (audited) or the next month lifts it. Members
see their month on the Account page; tunnel lists show each tunnel's traffic.
Service and admin-token tunnels are counted per tunnel and never capped. On a
public tunnel anyone with the URL spends its owner's traffic. Monthly figures
are kept for a year.

**Machines.** `tunnel login https://<ui_host>` on a machine prints a code and
opens the approval page (RFC 8628 device flow); the user signs in, types the
code (it never appears in a link, so nobody can send you a link that approves
their machine), checks the machine's name and address, and approves. The new
client belongs to them. Users with two-factor sign-in confirm with a code when
their last check is older than ten minutes. Machines without a browser still
use one-time login codes (`tunnel-server client add <name> [--user <name>]`,
or "Add a headless machine" in the UI). Machines can be renamed in the UI (your
own; admins also members', the owner anyone's), with
`tunnel-server client rename <name> <new-name>`, or `PATCH /v1/clients/{name}`
with the admin token; the login, token and tunnels stay as they are, and the
UI's audit log records the change. New names (machines and services) are 1–64
letters, digits, `.`, `_` or `-`; not only dots, and not `enroll`.

**Services** (`tnsvc_`, below) are not accounts: platforms such as a sandbox
service keep their own quota, and member limits never apply to them.

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
`cert renew [--force]`, `admin link`, `user list | invite [--role member|admin] [--hours N] | delete <name>`,
`client add <name> [--user <name>] | list | rename <name> <new-name> | delete <name>`, and
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

#### Databases from prerelease builds

A database written by a prerelease 1.0.0 build from before user accounts or
traffic counters is refused at startup, with a message naming the missing
column. Upgrade it once with `sqlite3` on the database file (`tunnel.db` in
the data directory):

1. Stop the service and copy the database first (`tunnel-server backup` refuses
   it too): `sqlite3 tunnel.db ".backup tunnel.db.pre-upgrade"`.
2. Add each missing column to the tables that exist (a table that does not
   exist yet, such as `users` in a database from before accounts, is created
   on start with all its columns, as is the `traffic` table):
   `ALTER TABLE tunnels ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0;`
   `ALTER TABLE tunnels ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0;`
   `ALTER TABLE users ADD COLUMN traffic_cap INTEGER;`
   `ALTER TABLE clients ADD COLUMN user_id TEXT REFERENCES users(id);`
3. Start the service.
4. If you added `clients.user_id`, the existing machines have no account yet
   and cannot connect until they belong to one. Create the owner if
   `tunnel-server user list` shows none: with the web UI on, run
   `tunnel-server admin link`, open the link and finish the owner's sign-up;
   without the web UI, `tunnel-server client add <name>` (for a new machine)
   creates the owner. Then give the existing machines to the owner:
   `UPDATE clients SET user_id = (SELECT id FROM users WHERE role = 'owner') WHERE user_id IS NULL;`.

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

With the web UI on, `tunnel login https://<ui_host>` signs a machine in after
you approve it in the browser (see above). Without a browser,
`tunnel-server client add laptop` prints a one-time (15 min) login code:

```sh
tunnel login                # on the laptop; paste tnenr_…@tunnel.example.com
tunnel share 3000           # prints a one-time link
tunnel share 5173 --public  # same tunnel, now public
tunnel link --reusable      # another link
tunnel links                # list the links; `tunnel unlink <id>` revokes one
tunnel unshare              # deletes the tunnel
```

The login code is single-use and expires after 15 minutes. Enrollment exchanges
it for a long-lived `tncli_` client token saved locally; it lasts until the client
is deleted. A client token can manage only the tunnels it created and their
access links. It may own at most `limits.max_tunnels_per_client` tunnels
(default 20 live tunnels), and a member's machines together at most the
member's own quota; creation beyond this returns HTTP 429 with
`error.code: "tunnel_quota"`. Admin tokens are exempt. `GET /v1/server` tells
any caller where things live (API, control, gate and UI origins, the preview
host template) and its own limits, including whether it may create public
previews. `GET /v1/tunnels/{id}/access-links` lists a tunnel's links (the URLs
themselves are never stored). `client list` shows enrolled machines; `client delete <name>`
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

The web UI (`crates/web`, Leptos rendered in the browser) is not a workspace
member and builds for `wasm32-unknown-unknown` only. A plain server build
serves a "UI not built" page; to embed the UI:

```sh
rustup target add wasm32-unknown-unknown
# wasm-bindgen must match the version in crates/web/Cargo.lock; wasm-opt (binaryen) is optional.
WASM_BINDGEN=/path/to/wasm-bindgen WASM_OPT=/path/to/wasm-opt crates/web/build.sh
cargo build --release -p tunnel-server --features ui
```

CI pins and checksums both tools (`.github/workflows/web.yml`) and fails a
build whose first load exceeds 400 kB gzip. The UI's design tokens are copied
from the FlyCockpit template (`crates/web/UPSTREAM` records the commit); its
edge lines (the paddings every container shares) are in
[crates/web/README.md](crates/web/README.md#edge-lines).

### Workspace layout

```text
Cargo.toml                 workspace, shared dependency versions, release profile
install.sh                 curl | sh installer: download, verify, exec `setup`
crates/protocol/           wire messages, constants, mux (rust-yamux driver), WebSocket↔bytes bridge
crates/server/             tunnel-server (VPS)
  src/main.rs              CLI: serve | setup | token rotate | health-token | status | backup | restore | cert renew | admin | user | client | service
  src/ui/                  web UI host: /ui/api/* (accounts, sessions, TOTP, invites, admin), embedded assets
  src/device.rs install.rs browser-approved machine login (RFC 8628); the client's /install.sh
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
crates/web/                web UI (Leptos CSR, wasm32); build.sh writes dist/ for the server's `ui` feature
docs/agent/SKILL.md        how AI agents share apps with tunnel (`tunnel help agent`)
packaging/homebrew/        formula generator used by the release workflow
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
