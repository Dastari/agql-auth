# Release process

## Release identities

`agql-auth` is a Git-distributed library (`publish = false`). New releases use
immutable annotated `v<version>` tags, beginning with `v0.19.0`. Historical
`agql-auth/v0.7.0` remains untouched. A Git tag alone is not a published release.
The attached `v<version>.json` records `commit`, `version`, `tag`, and `cargoLock`
(the SHA-256 of the committed lockfile). Both it and `SHA256SUMS` are attested.

Consumers pin the release tag, for example `tag = "v0.19.1"`, as the Git
reference for this library, and record the commit from that release's attached
manifest in their own reviewed pin record. A published release tag is annotated
and is never moved, so the tag and the recorded commit remain one identity; a
consumer lockfile that resolves the tag to a different commit is the detection
point. `scripts/release.py notes` renders this release body from the same
checked release identity, and the publication workflow attaches it.

## Version policy

Source, build script, or Cargo manifest changes since the last reachable `v*`
release tag require an increased SemVer and a new top changelog entry. Breaking
pre-1.0 contracts require a minor bump. CI checks release state and version
policy; release validation additionally runs cargo-semver-checks 0.46.0 against
the latest reachable version tag. Workflow, scripts, lockfile and documentation
maintenance alone do not require a version bump. Review dependency compatibility
when changing the lockfile even though it does not set the library version.

## Prepare the release commit

1. Branch from current `main`; update source, version, changelog and migration
   instructions together when contracts change.
2. Commit `Cargo.lock` for reproducible checks. Validation uses Rust 1.90.0 and
   `--locked`. Keep dependencies compatible with that validation toolchain.
3. Run `scripts/check-release-state.sh`,
   `scripts/check-package-release-policy.sh`,
   `python3 -m unittest discover -s scripts -p 'test_*.py'`, and
   `cargo fmt --all -- --check`.
4. For both defaults and `--no-default-features`, run
   `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`,
   and `RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps`.
   There are currently no Cargo features; adding one requires extending the
   explicit validation matrix. Never substitute `--all-features`.
5. Run `cargo semver-checks --baseline-rev "$(python3 scripts/release.py baseline)"
   --default-features` with pinned cargo-semver-checks 0.46.0.
6. Review the diff, open a PR, and merge after CI succeeds. Do not tag locally.
   On Gema's shared host, launch every compiling Cargo command, including
   installation, rustdoc and SemVer checks, through
   `/home/toby/projects/gema-2026/scripts/run-cargo-bounded.sh`, with an explicit
   disk-backed `CARGO_TARGET_DIR=/home/toby/.gema/cargo-target/agql-auth`.

The first release stays 0.19.0 if the preparation only changes release machinery,
lockfile and documentation. Its commit is the merged workflow commit, not the
older 1d2e9fe2 source commit. Consumers must resolve the actual release tag.

## Preview the release bill of materials

From a clean committed checkout, run:

```bash
python3 scripts/release.py manifest --output /tmp/agql-auth-release.json
```

The manifest is deterministic for that commit and requires a tracked lockfile.
Preview the release body the same way:

```bash
python3 scripts/release.py notes --output /tmp/agql-auth-release.md
```

## Publish through GitHub Actions

Before the first dispatch, a repository administrator must create the `release`
environment, require Toby (`Dastari`) as a human reviewer, restrict deployment
to `main`, and enable GitHub immutable releases. Merely naming an environment in
YAML does not create reviewer protection. The guard also checks that the designated
human reviewer is configured, failing closed otherwise. The repository owner verifies these
settings; an unprotected environment is not an approved publication route.

Toby dispatches `release.yml` as `Dastari`, from `main`, supplying `version`
(without `v`), `target_ref` (the full current `main` SHA), and `prerelease`.
The protected entry job requires human approval before validation. The workflow
checks current `main` and an unused tag, runs CI and SemVer lanes, rechecks
current `main`, generates and attests assets, pushes an annotated tag, assembles
a draft release with every asset, then publishes it. No library binary is built
and no crates.io publication occurs.

Download both assets from the resulting release. Run `sha256sum -c SHA256SUMS`
and `gh attestation verify <asset> --repo Dastari/agql-auth` for each asset.
Compare the peeled tag SHA to the manifest `commit` and the selected merged SHA.
Consumer repositories record the tag, commit and manifest digest after review.

## Failure and rollback

Before tagging, fix the branch and rerun validation. Never move, delete or reuse
a published version tag. If publication fails after tagging, retain the tag and
recover the exact attested assets from the workflow artifact into the draft for
that tag; do not regenerate them from a different commit. If `main` advances
during validation, the publication job fails and a new dispatch must validate
the new commit. Correct a defective published source through a new version.
