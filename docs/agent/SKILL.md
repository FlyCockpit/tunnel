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
tunnel share 3000                 # link-only tunnel (8 h); prints one single-use link per port
tunnel share 3000 5173 --ttl 1h   # several ports, shorter lifetime
```

- Give the printed link **only to the user**, and say it works once. For
  another person, make another link (one link per person).
- Never use `--public` unless the user explicitly asked for a public URL.
  Members' public previews are refused unless an admin allowed them; do not
  look for workarounds.
- `--password` (with `TUNNEL_SHARE_PASSWORD` set) is for when the user asks
  for a shared password instead of links.

## More links

```sh
tunnel link                        # a new single-use link, valid 10 minutes
tunnel link --port 5173 --ttl 1h   # for one port, valid longer
tunnel link --reusable             # works more than once until it expires: only if asked
```

A link that was already opened shows "access required" to the next visitor:
make a new one.

## Stop

```sh
tunnel stop                        # stops the daemon and deletes the tunnel
```

Stop sharing when the user is done or when the task ends; do not leave
tunnels running "just in case". The user can also see and delete tunnels and
links in the server's web UI.

## Rules

- Links are credentials: do not paste them into logs, commits, issues or
  chats other than the one with the user.
- Do not share ports the user did not ask for (databases, admin panels).
- Do not change the server's settings or try other servers.
