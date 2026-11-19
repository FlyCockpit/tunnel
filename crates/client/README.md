# Tunnel client

The `tunnel` command exposes local ports (HTTP, WebSockets, SSE)
through the Tunnel server over one outbound WSS connection, and keeps TURN
credentials fresh for server-side WebRTC peers. Unix only (Linux, macOS).

## Build

```sh
cargo build --release -p tunnel-client
```

The binary is `target/release/tunnel`.

## Commands

```sh
TUNNEL_TOKEN=tntun_… tunnel expose 3000                  # starts the daemon if needed, adds the port
tunnel expose 8080 5173                                  # adds ports to the running daemon
tunnel expose 3000 --target 10.20.0.2                    # dial 10.20.0.2:3000 instead of loopback (IP literals only)
tunnel unexpose 8080
tunnel status                                            # human-readable
tunnel status --json                                     # for scripts and automation
tunnel ice --format json|env|file [--fresh]              # current ICE config
tunnel ice --exec -- npm run dev                         # run a command with TURN_*/ICE_* set
tunnel stop                                              # stop the daemon and forget its ports
```

The first command starts one background daemon; later commands talk to it over
a Unix socket. If the daemon dies (crash, OOM kill), the next command restarts
it from the persisted state with the same token and ports.

`expose` with a `TUNNEL_TOKEN` different from the daemon's switches the
daemon to the new tunnel (ports from the old tunnel are dropped).

`status --json`:

```json
{
  "state": "connected",
  "tunnel_id": "ab12cd3efg",
  "host_template": "{port}-ab12cd3efg.previews.example.com",
  "ports": [{ "port": 3000, "host": "3000-ab12cd3efg.previews.example.com", "connected": true }],
  "last_error": null,
  "ice_file": "/run/tunnel/ice.json"
}
```

`state` is one of `connecting`, `connected`, `revoked` (tunnel deleted or
expired, or token rejected), `replaced` (another client connected with the same
token), `stopped` (no daemon and no tunnel).

## Logged-in machines

Outside a sandbox, a machine can create its own tunnels instead of receiving a
tunnel token:

```sh
tunnel login https://tunnel.example.com                  # approve this machine in the browser (--name, --no-browser)
tunnel login                                             # or paste the code from `tunnel-server client add <name>`
tunnel share 3000 [5173 …]                               # link-only; prints a one-time link per port
tunnel share 3000 --public                               # anyone with the URL (if the server allows it)
TUNNEL_SHARE_PASSWORD=… tunnel share 3000 --password [--username bob]
tunnel share 3000 --link                                 # back to links only
tunnel share 3000 --for=30m                              # foreground: unshares after 30 min or on Ctrl-C (bare --for: 1h)
tunnel link [--port 3000] [--reusable] [--ttl 1h] [--label bob]
tunnel links                                             # the shared tunnel's links (ids, use, expiry; no URLs)
tunnel unlink <ID>                                       # revoke one link and the visits it allowed
tunnel unshare [PORT …]                                  # delete the shared tunnel (or stop sharing just those ports)
tunnel stop                                              # stops the daemon; also deletes the shared tunnel
tunnel logout
```

`share`, `link` and `links` take `--json` for scripts and agents. `share --json`
and `link --json` print one line (errors and notes go to stderr):

```json
{"tunnel":"ab12cd3efg","mode":"link","expires_at":1795400000,
 "links":[{"port":3000,"url":"https://…","connected":true,"id":"lk…","expires_at":1795370000,"single_use":true}]}
```

`"traffic_limited": true` is added when the account has reached its monthly
traffic cap (visitors then see "Traffic limit reached"; `share` also warns on
stderr). `link --json` always describes the one new access link. For `share --json`
in `public` and `password` mode each entry has the preview URL instead of a
link (no `id`), and `password` adds `"username"`. With `share --for --json`
that line is the only output on stdout; the process then waits and exits
after unsharing (exit 0, or 3/4 if the tunnel was revoked or replaced
meanwhile). `--for` always makes a new tunnel whose lifetime is the `--for`
duration, so it also ends if the process is killed. `unshare` with nothing
shared prints `nothing shared` and exits 0; it leaves a daemon alone that
serves another tunnel (one from `expose`).

Browser login prints a code and the approval page (`https://<ui host>/device`);
sign in there, type the code, check the machine name and address, and approve.
It works from SSH sessions too (the page opens on any device). The machine
then belongs to the approving account.

The login (server and client token) is saved in
`$XDG_CONFIG_HOME/tunnel/login.json` (default
`~/.config/tunnel/login.json`, 0600). `share` reuses the tunnel
it made while the daemon still serves it, so one link covers every shared
port. Access links work in link, password and public modes, and sign-in takes
place on the zone host, separate from preview content. A gate session covers
every port of its tunnel. Each client token may own at most
`limits.max_tunnels_per_client` live tunnels (default 20). Creating another
returns HTTP 429 with `error.code: "tunnel_quota"`; admin tokens are exempt.
Deleting the client revokes
its token and deletes its tunnels. `logout` only removes the local login.
`expose` also uses the logged-in server when `TUNNEL_SERVER` is unset.

New shares live for 8 hours by default (`share --ttl 30m|8h|2d` overrides this).
Reusing a share keeps its existing expiry and preserves its access mode unless
an access flag is given. Password mode defaults to username `preview`. `share` prints links
valid for up to 10 minutes; `link` uses the same default (`--ttl` overrides it), and
selects the first shared port unless `--port` is given. Link lifetimes are capped
at the tunnel's remaining lifetime with a small margin.

## Environment

| Variable | Meaning |
|---|---|
| `TUNNEL_TOKEN` | Tunnel token (`tntun_…`). Pass by environment, never argv. The client refuses values without the `tntun_` prefix. |
| `TUNNEL_SERVER` | Tunnel server, e.g. `wss://tunnel.example.com` (`https://` and bare hosts are accepted). `expose` falls back to the logged-in server, then the daemon's saved server (when reusing its tunnel), then `TUNNEL_DEFAULT_SERVER` baked in at build time. |
| `TUNNEL_TARGET_HOST` | IPv4 or IPv6 literal the daemon dials for exposed ports instead of loopback (e.g. a VM's address when the client runs on its host). Hostnames are refused. Saved with the tunnel; `--target` on `expose`/`share` sets it too. Only exposed ports are ever dialled. |
| `TUNNEL_STATE_DIR` | State directory, used as is (absolute path); same as the global `--state-dir`. One daemon and one tunnel per directory. |
| `TUNNEL_ICE_FILE` | ICE file the daemon keeps fresh. Default `/run/tunnel/ice.json` if writable, else `<state dir>/ice.json`. |
| `TUNNEL_ICE_PORT` | Port of `http://127.0.0.1:<port>/ice` (default `47801`). Requests need `Authorization: Bearer $TUNNEL_ICE_TOKEN`. |
| `TUNNEL_SHARE_PASSWORD` | Password for `share --password`; otherwise prompted without echo. |
| `RUST_LOG` | Log filter (daemon default `info`, commands `warn`). |

State lives in `--state-dir` / `$TUNNEL_STATE_DIR` if given, else
`$XDG_RUNTIME_DIR/tunnel/` (else `/tmp/tunnel-<uid>/`), mode 0700: `daemon.sock`, `state.json` (0600,
holds the token), `daemon.log`, `daemon.lock`, `share.json`, `ice-token`, and
`ice.json` (unless `TUNNEL_ICE_FILE` or the writable `/run/tunnel/` default
places the ICE file elsewhere).

`ice --format env` prints `export K='v'` lines for `TURN_URLS`
(comma-separated `turn:`/`turns:` URLs), `TURN_USERNAME`, `TURN_CREDENTIAL`,
`ICE_SERVERS_JSON` (JSON array), `ICE_EXPIRES_AT` (unix seconds),
and `TUNNEL_ICE_FILE`. It also prints `TUNNEL_ICE_URL` and `TUNNEL_ICE_TOKEN`
only when the daemon bound its local `/ice` endpoint. The default
`127.0.0.1:47801` port is shared by all users; `TUNNEL_ICE_PORT` overrides it.
If the port is taken, use `TUNNEL_ICE_FILE`. The bearer token lives in
`<state dir>/ice-token` and survives daemon restarts.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Error (message on stderr) |
| 3 | Revoked: the tunnel was deleted or expired, or the token was rejected. Create a new tunnel. |
| 4 | Replaced: another client connected with this token. The daemon stopped instead of fighting it. |

`ice --exec` replaces the client process and returns the executed command's exit
status. Invalid command-line arguments exit with code 2 (Clap).

The daemon exits with the same terminal codes. A revoked daemon is never restarted until
a different token is supplied; a replaced one can be restarted by an explicit
`expose` or `share`, or by supplying a different token. These codes are stable.

## Supervised daemon

A supervisor (for example a systemd unit started by a sandbox host) can run the
daemon in the foreground instead of letting commands start it:

```sh
# environment (from a 0600 file, never argv): TUNNEL_TOKEN, TUNNEL_SERVER, TUNNEL_TARGET_HOST
tunnel --state-dir /run/user/1000/host/tunnels/sbx-1 daemon      # logs to stderr; exit 3 = gone, 4 = replaced
tunnel --state-dir /run/user/1000/host/tunnels/sbx-1 expose 3000 5173
tunnel --state-dir /run/user/1000/host/tunnels/sbx-1 status --json   # includes tunnel_id, target and features
```

- One daemon per state directory; a second one exits 0 at once. The directory is
  created (0700) if missing; its parent must exist.
- The daemon saves the token in `state.json` in that directory, so put it on
  tmpfs (`/run/user/<uid>/…`) if the token must not reach persistent disk.
  A daemon refuses to start on an unreadable or malformed `state.json`
  (`tunnel stop` removes it) instead of falling back to defaults.
- Ports can also be sent over `<state dir>/daemon.sock` as the `expose` command does
  (newline-delimited JSON `{"type":"expose","ports":[3000]}`).
- `status --json` lists the daemon's `features`; `"target"` means it honours
  `--target` / `TUNNEL_TARGET_HOST` (a command refuses `--target` with a
  running daemon that does not list it). IPv4-mapped IPv6 targets are
  treated as the IPv4 address.
- On Linux the daemon marks itself non-dumpable, so other processes of the same
  user cannot read its memory or environment through `/proc` or ptrace.
- Suggested supervision: restart on failure, but not on exit 3 (and treat 4 as
  "another client holds the tunnel").

## Using it from scripts / automation

An automation service can create a tunnel and run the client on another machine.
Keep the admin token in that service and pass only the tunnel token to the client:

1. `POST /v1/tunnels` with the admin token (or reuse the machine's live tunnel).
2. Run in the sandbox: `TUNNEL_TOKEN=tntun_… tunnel expose <port>`.
3. Poll `GET /v1/tunnels/{id}` (or `tunnel status --json`) until the port is connected.
4. Export into the application shell with `tunnel ice --format env`.
   `TUNNEL_ICE_FILE` is always supplied; `TUNNEL_ICE_URL` and `TUNNEL_ICE_TOKEN`
   are supplied only if the daemon bound its local `/ice` port (default
   `127.0.0.1:47801`, shared by all users; override with `TUNNEL_ICE_PORT`).
   Otherwise, use the file. If needed, your script can set
   `TUNNEL_HOST_TEMPLATE` from the API's `host_template` and
   `TUNNEL_ICE_SERVERS` from `ice --format json`; the client does not export these two variables.
5. On "stop preview": `DELETE /v1/tunnels/{id}`; the daemon exits and `status --json` reports `revoked`.

Server-side WebRTC peers (SFU, aiortc, Pion, voice agents) can use TURN over TLS on
443. Restart the dev server with the credential in its environment:

```sh
tunnel ice --exec -- npm run dev
# or
eval "$(tunnel ice --format env)"; npm run dev
```

(`eval "$(…)" npm run dev` on one line does not work: `eval` joins its
arguments into one string.) Values loaded at process start expire with the
credential TTL (24h by default, configured by `webrtc.sandbox_ttl_s`); long-running peers should re-read `$TUNNEL_ICE_FILE`.
When the local `/ice` port bound successfully, they can instead
`GET $TUNNEL_ICE_URL` with `Authorization: Bearer $TUNNEL_ICE_TOKEN`.
If another user or process holds the port, those two variables are omitted;
use the file or choose another port with `TUNNEL_ICE_PORT`. Browser code needs nothing: the edge injects
ICE config into preview pages when WebRTC and the tunnel's `inject_ice` setting
are enabled (`inject_ice` defaults to true).

**Never write TURN credentials, ICE config, or preview hostnames into source
files or committed `.env` files.** They expire, and the preview host is not a
deployment URL. Read them from the environment or the ICE file at runtime.
