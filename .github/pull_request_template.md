## Summary

<!-- What does this change do, and why? Link related issues (for example "Closes #123"). -->

## Checks run

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo +1.89 check --workspace --all-targets --locked`
- [ ] `cargo deny check`
- [ ] Other (describe):

## Checklist

- [ ] Every commit is signed off under the [Developer Certificate of Origin](https://github.com/FlyCockpit/tunnel/blob/main/CONTRIBUTING.md#licensing-and-the-developer-certificate-of-origin).
- [ ] Behavior changes have meaningful tests and relevant documentation updates.
- [ ] Changes preserve tunnel isolation and token permissions, or describe the intended change.
- [ ] No secrets, private hostnames, access links or personal data in code, tests, fixtures or logs.
