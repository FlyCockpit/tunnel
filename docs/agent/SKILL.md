---
name: tunnel
description: Share a local web app (dev server, preview) with a specific person through the user's Tunnel server, using the `tunnel` CLI. Use when the user asks to show, share or send a running local app, port or preview to someone, or to stop sharing it.
---

# Sharing a local app with `tunnel`

`tunnel` exposes ports of this machine at `https://<port>-<id>.<preview zone>`
on the user's own Tunnel server. Visitors need an **access link** unless the
user asked for something else.

## Before you start

- `tunnel status --json` shows whether this machine is sharing and its ports.
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
- Never use `--public` unless the user explicitly asked for a public URL.
  Members' public previews are refused unless an admin allowed them; do not
  look for workarounds.
- `--password` (with `TUNNEL_SHARE_PASSWORD` set) is for when the user asks
  for a shared password instead of links.

### For a fixed time

When the share should end by itself (a demo, a review session), run it in
the foreground:

```sh
tunnel share 3000 --for=30m --json   # prints the JSON line, waits, then unshares (bare --for: 1h)
```

It makes a new tunnel, deletes it when the time is up, on Ctrl-C or SIGTERM,
and its lifetime is the `--for` duration, so it also ends if the process is
killed. Run it in the background (or a separate terminal) if you need the
shell meanwhile, and stop it with SIGTERM to end early.

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

Unshare when the user is done or when the task ends; do not leave tunnels
running "just in case". The user can also see and delete tunnels and links in
the server's web UI.

## Rules

- Links are credentials: do not paste them into logs, commits, issues or
  chats other than the one with the user.
- Do not share ports the user did not ask for (databases, admin panels).
- Do not change the server's settings or try other servers.
- Errors go to stderr as `tunnel: …` with a non-zero exit code; exit 3 means
  the tunnel was deleted or expired, 4 that another client took it over.
