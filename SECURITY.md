# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** through GitHub private
vulnerability reporting:

<https://github.com/FlyCockpit/tunnel/security/advisories/new>

Do not open public issues, discussions or pull requests for security problems.
We aim to acknowledge reports within 72 hours. Include the affected version,
reproduction steps, impact and a minimal demonstration with synthetic data.
Never include live tokens, passwords, access links or DNS provider credentials.

## Supported versions

| Version | Security fixes |
|---|---|
| 1.0.x | Latest patch release only |
| Earlier versions | Unsupported |

The first 1.0.0 release is pending. Until it is published, reports against `main`
are welcome. Upgrade to the latest supported patch release when fixes ship.

## Scope

- The access gate, zone-host sign-in, password authentication, access links,
  cookies, iframe policy and isolation between preview origins and tunnels.
- Admin, tunnel, client, enrollment, health and local ICE tokens: issuance,
  storage, authorization, revocation and accidental disclosure.
- The management API, WSS control plane and HTTP/WebSocket proxy, including
  request handling, untrusted preview applications and resource exhaustion.
- The built-in STUN/TURN relay: authentication, tunnel deletion, quotas and
  prevention of relay access to local, private or otherwise forbidden peers.
- DNS-01 setup, certificate handling, backups, restore and service permissions.
- The release workflow and installers: checksums (`sha256.sum`, checked fail
  closed by both installers), build provenance attestations, asset integrity
  and installation boundaries.
- The web UI and its accounts: sign-in, two-factor codes, sessions, CSRF and
  same-site defenses, invites, roles and per-user isolation, and the
  browser-approved machine login.

An owner deliberately making a tunnel public grants visitors access to that
application. An application can still have its own vulnerabilities; report a
Tunnel issue if it bypasses the gate or crosses a tunnel/token boundary.
Local state and backups contain sensitive material and require filesystem access
controls. Use a dedicated preview domain and restrict `frame_ancestors` to the
sites that should embed previews.
