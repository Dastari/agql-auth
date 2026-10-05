# Password-login rejection review

## Reviewed identities

| Source | Package version | Exact source commit | Result before this patch |
| --- | --- | --- | --- |
| Published Git source release `v0.19.1` | 0.19.1 | `96bafbf21adbc7ad963729e1e981feaba5debe90` | Disabled branch bypasses work and failure recording |
| Requested exact commit | 0.19.1 | `3d4bf073217da53cac04a5f295fc37c29b507e80` | Same gap |
| Remote `main`, fetched for this review on 2026-10-05 | 0.19.1 | `3d4bf073217da53cac04a5f295fc37c29b507e80` | Same gap; newer main does not close it |
| This PR | 0.19.2 candidate | Record the PR head SHA from GitHub | Fix and executable contracts; release pending owner action |

`agql-auth` has `publish = false`: 0.19.1 is a published Git source release,
not a crates.io publication. Its downloaded `v0.19.1.json` manifest agrees with
the peeled tag and records lockfile SHA-256
`98b1dad854c5eabd87527b6b300030facda6c842de50dd14e6742b781a4296ac`.
`SHA256SUMS` verifies the manifest. The requested commit and reviewed main have
no changes to `src`, `Cargo.toml`, or `Cargo.lock` relative to that tag.
Both downloaded assets also pass `gh attestation verify --repo Dastari/agql-auth`
using GitHub CLI 2.102.0 (one verified result each).

The executable example below was also copied into detached worktrees at both
baseline commits. Unknown and enabled/wrong-password cases locked on attempt
three. Disabled/correct-password attempts failed the attempt-three lockout
assertion on both baselines (exit 101), reproducing the gap. The patched example
passes (exit 0).

## Behavior and compatibility

After the existing admission check, an unknown or disabled account performs one
verification against the fixed dummy Argon2 hash. An enabled account verifies
its stored hash. Every admitted rejection records the available principal and
client keys through `record_rate_limit_attempt`. Disabled attempts record even
with a correct password or corrupt stored hash, return `UserDisabled`, and exit
before conditional clear, session construction, signing, refresh generation,
or persistence.

The existing engine still owns password work, key construction, windows,
backoff, lockout, expiry, saturating arithmetic, retry-after calculations, CAS
retries, and conditional clear. This patch changes none of those algorithms
or store traits. There are no production SQL adapters, consumer schemas,
downstream edits, routes, host-specific policy, normalization changes, Cargo
dependency additions, overrides, or dependency exceptions. The lockfile changes
only this crate's version.

| Condition | Rust error | GraphQL code |
| --- | --- | --- |
| Admitted unknown or enabled/wrong password | `InvalidCredentials` | `INVALID_CREDENTIALS` |
| Admitted disabled, any password | `UserDisabled` | `USER_DISABLED` |
| Active backoff | `AuthThrottled` | `RATE_LIMITED` + `retryAfterSeconds` |
| Active lockout | `AuthLocked` | `RATE_LIMITED` + `retryAfterSeconds` |
| Failure to persist a rejection | `Store` | `AUTH_SERVICE_UNAVAILABLE` |

The threshold-activating rejection retains its credential error; the next
attempt is blocked before user lookup/password verification and is not counted
again. Disabled failures can now block another principal sharing a client
bucket. Only an admitted enabled/correct-password login clears its observed
revisions, and it finishes that clear before token issuance. A concurrent
newer failure survives stale clear. Credential admission remains check-then-
verify; an already admitted burst can cross the threshold, and each failure is
recorded. Per-key CAS does not provide a transaction across both buckets.

The deliberately distinct `USER_DISABLED` public error is preserved. This is
work comparability, not a promise of account indistinguishability or a timing
bound. Dummy PHC parameters equal newly generated default hashes; custom
host-stored hash parameters can have different costs. Existing tokens, refresh
rotation, auth payloads, GraphQL transport, configuration, and store contracts
remain compatible. There is no data migration.

## Executable example

```bash
cargo +1.90.0 run --locked --example password-login-rejection
```

Expected public results for each unknown, enabled/wrong, and disabled/correct
case: two credential rejections followed by `RATE_LIMITED` with a 300-second
lockout. The example uses identical credential policies, a fixed clock, distinct
clients to isolate cases, and a refresh store that fails on any access.

The reusable contract includes the same-client and same-principal cases:

```bash
cargo +1.90.0 test --locked password_login -- --skip consumer_conformance
```

It covers persisted counters for unknown, enabled/wrong, disabled/wrong,
disabled/correct and disabled/corrupt-hash cases; exact injected-clock backoff,
lockout, window and expiry boundaries; independently effective principal and
client controls; saturation; stale CAS/clear; and successful clear before
issuance. Eight writers across two services are forced to observe absence for
one principal before attempting CAS. The contract requires seven or more
conflicts and all eight committed increments in both buckets.

Assertions count completed Argon2 verifier calls, compare PHC algorithm,
version and work parameters, and count entry to token generation. Disabled
attempts must produce an error, zero issuance entries, zero refresh records,
and zero rotations. No elapsed-time threshold is used. Test probes are compiled
only under `cfg(test)` and retain hashes, never submitted passwords.

## SQLite and PostgreSQL consumer-store examples

`src/tests/consumer_store.rs` implements the public `AuthRateLimitStore` trait
and transports operations to `testdata/consumer_rate_limit_store.py` using
JSON. Each operation opens a real database connection. The Python fixture uses
stdlib SQLite or `psql`; no Cargo dependency is added. Snapshots and revisions
are stored together with a unique flow/bucket/value-hash key. First insert uses
`ON CONFLICT DO NOTHING`; updates/deletes require the observed revision.
Replacement-key mismatch is rejected. All policy transitions remain in Rust.

These are executable test consumers, not evidence for any downstream adapter.
The shared contract runs against memory, SQLite and PostgreSQL. Fixture SQL is
isolated to randomly named test tables and databases and prescribes no host
schema. Production adapters should use their driver's bind parameters; this
fixture validates generated identifiers and escapes every SQL literal. Use an
isolated database and discard it if a test fails before cleanup.

SQLite needs Python 3 with SQLite >= 3.35 (`RETURNING` support):

```bash
cargo +1.90.0 test --locked sqlite_password_login_consumer_conformance -- --ignored
```

PostgreSQL additionally needs `psql` and a dedicated local test database. For
example, start a disposable PostgreSQL 17 container (credentials below are
only for this local test fixture):

```bash
docker run --rm -d --name agql-auth-conformance \
  -e POSTGRES_USER=agql_test -e POSTGRES_PASSWORD=agql_test \
  -e POSTGRES_DB=agql_conformance -p 127.0.0.1:54329:5432 postgres:17
# Wait for this command to succeed before running the contracts:
docker exec agql-auth-conformance pg_isready -U agql_test -d agql_conformance
export AGQL_AUTH_TEST_POSTGRES_URL='postgresql://agql_test:agql_test@127.0.0.1:54329/agql_conformance'
cargo +1.90.0 test --locked password_login_consumer_conformance -- --ignored
docker stop agql-auth-conformance
```

Both SQL tests are explicitly enabled in CI's `consumer-conformance` job,
including reusable release validation. The normal suite marks them ignored
because it does not require external tools/databases. They run all six shared
contracts: rejection matrix, success, concurrent failures, clear ordering,
store CAS/expiry/saturation, and independent buckets.

## Validation and release handoff

The PR was validated with Rust 1.90.0, Argon2 0.5.3, async-graphql 7.2.1,
SQLite 3.46.1, and PostgreSQL 17.5 (psql 18.4). Commands:

```bash
scripts/check-release-state.sh
scripts/check-package-release-policy.sh
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo +1.90.0 fmt --all -- --check
# Repeat this lane with --no-default-features on each Cargo command:
cargo +1.90.0 clippy --locked --all-targets -- -D warnings
cargo +1.90.0 test --locked
RUSTDOCFLAGS='-D warnings' cargo +1.90.0 doc --locked --no-deps
# With cargo-semver-checks 0.46.0 on PATH:
cargo +1.90.0 semver-checks --baseline-rev v0.19.1 --default-features
```

See the PR for final command results, exact head SHA, and hosted CI status.
Local results: 187 tests passed in each normal feature lane (the two SQL tests
are explicitly ignored there); both SQL consumer tests passed when enabled;
both Clippy and rustdoc lanes passed with warnings denied; formatting and both
release gates passed; nine release-script tests passed; cargo-semver-checks
0.46.0 passed 196 compatibility checks against `v0.19.1` (49 not applicable).
The release-script suite intentionally emits a missing-lockfile error while
testing that rejection; the suite itself exits successfully.

Merge, tag, and publication remain with the owner. 0.19.2 is a candidate until
the protected release workflow publishes its immutable tag and attested
manifest. A merge/squash can change the reviewed PR SHA; validate and record
the actual release identity rather than assuming it equals the PR head.
Digibase will exact-pin that reviewed release, use the same source identity
across direct/transitive dependencies, and run its own downstream contracts.
