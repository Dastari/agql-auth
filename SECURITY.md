# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/Dastari/agql-auth/security/advisories/new).
Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Include the affected version or commit, the API or flow involved, and a
reproduction or failing test when you have one. You will receive an
acknowledgement, and fixes are prepared privately and published with the
advisory after a release.

## Supported versions

`agql-auth` is distributed as Git release tags (see
[docs/release-process.md](docs/release-process.md)). Security fixes land in the
next release; consumers should move to the latest `v*` tag. Older tags are not
patched.

## Dependency advisories

CI runs `cargo audit` against the committed `Cargo.lock`. Advisories that
cannot be resolved by an upgrade are listed with their disposition in
[docs/dependency-advisories.md](docs/dependency-advisories.md).
