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

Account and tunnel password hashes use Argon2id, wrapped with AES-256-GCM under
an HKDF-SHA256 key derived from the server's `ui_secret` and bound to the row id
and password purpose. A database-only leak does not permit offline password
guessing without `config.toml`'s `ui_secret`; it still exposes usernames, email
addresses, metadata and hashes of high-entropy random tokens. A database and
config leak permits offline Argon2id guessing, as before. The same server secret
also seals TOTP secrets and derives CSRF tokens; setup always generates it and
`serve` requires it, including when the web UI is disabled.

Back up `config.toml` together with the database. Losing `ui_secret` means every
account and tunnel password must be reset and two-factor sign-in re-enrolled.
Restore refuses a backup sealed with another secret unless that secret is
available as `ui_secret_previous`; legacy raw password hashes are converted at
startup. A wrong key or damaged password seal refuses startup before listening
and rolls back the entire conversion.

Backups taken before the password-sealing upgrade and pre-upgrade database
copies kept by `restore` as `tunnel.db.before-restore-*` still contain unwrapped
password hashes. Delete these copies once they are no longer needed.

Run `tunnel-server secret rotate` to save the old secret as `ui_secret_previous`,
generate a new secret, and try to restart the service. Restart re-seals passwords
and TOTP secrets in one transaction. Sessions remain valid; reload web UI pages
for new CSRF tokens. Apply the pending rotation by restarting before rotating
again. Retain `ui_secret_previous` while you need backups from before the
rotation; a later rotation replaces it, so retain matching config backups too.
