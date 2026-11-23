---
name: tunnel
description: Share a local web app (dev server, preview) with a specific person through the user's Tunnel server, using the `tunnel` CLI. Use when the user asks to show, share or send a running local app, port or preview to someone, or to stop sharing it.
---

# Sharing a local app with `tunnel`

`tunnel` exposes ports of this machine at `https://<port>-<id>.<preview zone>`
on the user's own Tunnel server. Visitors need an **access link** unless the
user asked for something else.

## Before you start

- `tunnel status --json` shows whether this machine is sharing, its ports and
  (when it can read the tunnel) its `mode` (`link`, `password` or `public`)
  and, in password mode, the `username` and each port's `login_url`. Run it
  **before** you share. A machine has one tunnel daemon: if `state` is not
  `stopped`, a tunnel is already running and it is not yours. `share` may add
  your ports to it, and a new share (including `--for`) would take the daemon
  over and cut that tunnel off. Ask the human before sharing then.
- If a command says "not logged in", ask the user to run
  `tunnel login https://<their server>` and approve the machine in their
  browser. Do not try to log in yourself, and never ask for their password.
- Make sure the app is listening on the port first (e.g. `curl -sI http://127.0.0.1:3000`).

## Share

```sh
tunnel share 3000 --json                # link-only tunnel (8 h); one single-use link per port
tunnel share 3000 5173 --ttl 1h --json  # several ports, shorter lifetime
```

`--json` prints one line you can parse:

```json
{"tunnel":"ab12cd3efg","mode":"link","expires_at":1795400000,
 "links":[{"port":3000,"url":"https://…","connected":true,"id":"lk…","expires_at":1795370000,"single_use":true}]}
```

- Give the `url` **only to the user**, and say it works once, within 10
  minutes. For another person, make another link (one link per person).
- `"connected": false` means the port is not reachable yet: check that the
  app is running, then `tunnel status --json`.
- `"traffic_limited": true` means the user's account has used its monthly
  traffic: visitors will see "Traffic limit reached". Tell the user; only a
  server admin can raise the limit.
- Never use `--public` unless the user explicitly asked for a public URL.
  Members' public previews are refused unless an admin allowed them; do not
  look for workarounds.
- `--password` (with `TUNNEL_SHARE_PASSWORD` set) is for when the user asks
  for a shared password instead of links. See Password mode below.

### Password mode

```sh
TUNNEL_SHARE_PASSWORD=… tunnel share 3000 --password --for=8h --json
```

```json
{"tunnel":"ab12cd3efg","mode":"password","expires_at":1795400000,"username":"preview",
 "links":[{"port":3000,"url":"https://3000-ab12cd3efg.<zone>/","connected":true,
           "login_url":"https://<zone>/__login?to=3000-ab12cd3efg&next=%2F"}]}
```

- Give the human the **`login_url`** (plus the username and password): it
  opens the sign-in form, which then goes to the preview.
- The gate redirects to the sign-in form only for page loads: requests with
  `Sec-Fetch-Dest: document` (or `iframe`/`frame`), or, without that header,
  `Accept: text/html`. Everything else (curl, `fetch`, you) gets **401**, in
  password mode too; its body names the `login_url` (JSON with
  `Accept: application/json`). A 401 from `curl` therefore does not mean the
  share is broken. Never send the password over HTTP Basic: there is none.

### For a fixed time, or "leave this up"

When the share should end by itself (a demo, a review session), or the human
says to leave it up, run it with `--for` in the background:

```sh
tunnel share 3000 --for=30m --json   # prints the JSON line, waits, then unshares (bare --for: 1h)
tunnel share 3000 --for=8h --json    # "leave this up": ends by itself after 8 h
```

It always makes a **new** tunnel, deletes it when the time is up, on Ctrl-C
or SIGTERM, and its lifetime is the `--for` duration, so it also ends if the
process is killed. Stop it with SIGTERM to end early. It refuses only while an
earlier `tunnel share` from this machine is still up; a tunnel started any
other way (e.g. `tunnel expose`) it would take over, because it uses the
machine's one daemon. So check `tunnel status --json` first (see Before you
start).

`--ttl` and `--for` are exclusive. Pick `--for` for anything you start;
`--ttl` (default 8h) is for a share the daemon keeps up in the background,
after your process ends, until someone runs `tunnel unshare`, and it reuses
the machine's current shared tunnel if there is one.

## More links

```sh
tunnel link --json                          # a new single-use link, valid 10 minutes
tunnel link --label bob --json              # note who got it (shown by `tunnel links` and the web UI)
tunnel link --port 5173 --ttl 1h --json     # for one port, valid longer
tunnel link --reusable --json               # works more than once until it expires: only if asked
tunnel links --json                         # the links so far: id, label, used_at, expires_at (no URLs)
tunnel unlink <ID>                          # revoke one link and end the visits it allowed
```

A link that was already opened shows "access required" to the next visitor:
make a new one. If a link went to the wrong person, `tunnel unlink` it.

## Stop

```sh
tunnel unshare            # deletes the tunnel and stops its daemon (says "nothing shared" if there is none)
tunnel unshare 5173       # stop sharing one port; the tunnel goes once no port is left
```

**Never unshare a tunnel you did not create in this session.** Someone may be
using it (the human, or a person they sent it to). Before `tunnel unshare`,
check `tunnel status --json`: if the tunnel is not the one your own `share`
printed, or it was already there before you shared, ask the human instead.
A share you started with `--for` ends by itself; stop it with SIGTERM.

Unshare your own share when the user is done or when the task ends; do not
leave tunnels running "just in case". The user can also see and delete
tunnels and links in the server's web UI.

## Rules

- Links are credentials: do not paste them into logs, commits, issues or
  chats other than the one with the user.
- Do not share ports the user did not ask for (databases, admin panels).
- Do not change the server's settings or try other servers.
- Errors go to stderr as `tunnel: …` with a non-zero exit code; exit 3 means
  the tunnel was deleted or expired, 4 that another client took it over.
