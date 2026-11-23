# Contributing to Tunnel

Thanks for your interest in improving Tunnel. The first public release,
1.0.0, is pending; please open an issue to discuss larger changes before starting.

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Do not open public issues or pull requests for security problems. Report them
privately as described in [SECURITY.md](SECURITY.md).

## Licensing and the Developer Certificate of Origin

Tunnel is licensed under `MIT` (see [LICENSE](./LICENSE)). Contributions are accepted under the same license: by submitting a contribution you agree that it is licensed to the project and its users under `MIT` (inbound = outbound). There is no separate contributor license agreement.

Every commit must be signed off to certify the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) 1.1, reproduced below. Sign off by adding a `Signed-off-by` trailer with your real name and an email address you can be reached at:

```text
Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` adds the trailer for you, using your `user.name` and `user.email`.

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Development setup

Install Rust 1.89 or later (edition 2024), a C toolchain for ring and bundled
SQLite, and [cargo-deny](https://github.com/EmbarkStudios/cargo-deny).
The [README](README.md#installation) covers building and server setup.

The workspace contains `tunnel-protocol` in `crates/protocol`,
`tunnel-server` in `crates/server`, and `tunnel-client` in
`crates/client`. The server's setup and service management target Linux;
the client supports Linux and macOS.

## Repository rules

- Keep each change focused. Unrelated refactors, formatting and dependency updates
  belong in separate pull requests; discuss new dependencies first.
- Preserve the access gate and token boundaries. Admin tokens stay with management
  services; clients receive tunnel or client tokens with narrower permissions.
- Never include secrets, private hostnames, access links or personal data in code,
  fixtures, issues or logs. Use example domains and synthetic credentials.
- Update user documentation when behavior or configuration changes. Keep binary
  names, environment variables and protocol identifiers compatible.

## Checks

Before opening a pull request, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.89 check --workspace --all-targets --locked
cargo deny check
(cd crates/web && cargo deny check)
```

CI checks formatting, Clippy, the minimum supported Rust version, tests on Linux
and macOS, and dependency licenses, bans and sources. Advisory checks run weekly
and on manual dispatch. Both cover the root workspace and the web UI in
`crates/web`, which is its own workspace with its own `deny.toml`. Tests should
use local fixtures and fake providers; do not require production credentials or
infrastructure.

## Pull requests

- Describe the problem, resulting behavior and checks you ran in the template.
- Make sure every commit is signed off under the DCO above.
- Add meaningful tests for behavior changes and update the relevant docs.
- Follow the [security policy](SECURITY.md) for sensitive changes or reports.
