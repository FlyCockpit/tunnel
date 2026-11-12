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
tunnel login                                             # paste the code from `tunnel-server client add <name>`
tunnel share 3000 [5173 …]                               # link-only; prints a one-time link per port
tunnel share 3000 --public                               # anyone with the URL
TUNNEL_SHARE_PASSWORD=… tunnel share 3000 --password [--username bob]
tunnel share 3000 --link                                 # back to links only
tunnel link [--port 3000] [--reusable] [--ttl 1h]
tunnel stop                                              # also deletes the shared tunnel
tunnel logout
```

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
| `TUNNEL_ICE_FILE` | ICE file the daemon keeps fresh. Default `/run/tunnel/ice.json` if writable, else `<state dir>/ice.json`. |
| `TUNNEL_ICE_PORT` | Port of `http://127.0.0.1:<port>/ice` (default `47801`). Requests need `Authorization: Bearer $TUNNEL_ICE_TOKEN`. |
| `TUNNEL_SHARE_PASSWORD` | Password for `share --password`; otherwise prompted without echo. |
| `RUST_LOG` | Log filter (daemon default `info`, commands `warn`). |

State lives in `$XDG_RUNTIME_DIR/tunnel/` (else
`/tmp/tunnel-<uid>/`, mode 0700): `daemon.sock`, `state.json` (0600,
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
`expose` or `share`, or by supplying a different token.

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
