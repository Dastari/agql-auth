# Atomic Abuse Protection

`agql-auth` applies per-principal and per-client counters, exponential backoff,
and temporary lockout to authentication and request-initiation flows. The host
owns persistence; the crate owns the deterministic state transition.

## Atomic Store Contract

`AuthRateLimitStore` uses `AuthRateLimitSnapshot`, which contains the ordinary
`AuthRateLimitState` plus an opaque UUID revision. The service performs:

1. read the current versioned snapshot;
2. centrally calculate the next window/backoff/lockout state;
3. attempt a conditional insert or update using the observed revision;
4. on conflict, reread, recalculate, and retry.

There is no unconditional save API or multi-instance fallback. With `N`
successful concurrent records for one key, every operation has one CAS
linearization point and the committed attempt count includes all `N` unless a
configured window reset occurs between their injected timestamps.

`expected_revision = None` means insert only if absent. A supplied revision
means update only if the current row has that exact revision. The replacement
revision must be persisted atomically and is freshly generated for every
attempt. Conditional clear uses the same comparison and must leave newer state
untouched.

The trait uses only concrete parameters and remains object-safe behind
`Arc<dyn AuthRateLimitStore>`.

## Request Admission

Password-reset and login-code request helpers atomically decide admission and
record the attempt for each key. Admission is based on the state before the
transition, preserving the existing rule that the request which first activates
backoff is allowed. A concurrent request cannot also claim the same pre-state:
its CAS conflicts, it rereads the committed backoff, and it returns `false`.

Principal and client buckets are separate keys. Atomicity is guaranteed per
key, not as one transaction across both buckets. If one key admits and records
before a second key denies, the first key remains recorded; this is a safe
over-count rather than an abuse-state bypass.

Credential checks remain check-then-verify operations because password, code,
and factor verification cannot be held inside a storage transaction. A burst
may begin before another failure activates lockout, but every resulting failure
is recorded through CAS and none is lost.

Password login applies the same configured credential controls to unknown,
disabled, and enabled/wrong-password attempts. Unknown and disabled accounts
perform one verification against the fixed dummy Argon2 hash; enabled accounts
use their stored hash. Disabled correct-password attempts are failures too.
An admitted disabled attempt returns `UserDisabled`, never clears attempts,
and never enters access/refresh issuance. Already active controls reject before
password work; persistence errors propagate through the safe public error map.
The threshold-activating failure returns its credential error, and the next
attempt receives throttling/lockout. There is no constant-time guarantee across
host-chosen stored hash parameters and no change to the deliberately distinct
public `USER_DISABLED` error.

## Record Versus Clear

Before credential verification, the service remembers the observed revision
for each key. Success clears only those exact revisions. If another failure
commits a newer revision while verification is in flight, clear conflicts and
leaves the newer failure intact. If clear linearizes first, a later failure sees
absence and creates a fresh revision, so the failure remains recorded.

Expired state is treated as inactive. The next attempt atomically replaces it
with a reset window using its current revision. Stores may delete expired rows
in background maintenance, but deletion must not turn a conditional update or
clear into an unconditional mutation.

## SQLite And PostgreSQL

SQLite adapters can implement CAS with a write transaction and a unique key on
the complete flow/bucket/value-hash tuple. Test absence for first insert, or
update with both key and expected revision in the predicate. Only report success
when one row was inserted or changed.

PostgreSQL adapters may use a row lock, conditional update, or upsert with a
revision predicate. First-insert unique conflicts and update revision conflicts
both return `Ok(false)` so the service retries with current state.

Neither backend needs crate-owned SQL, schema names, an ORM, a distributed
cache, or a network rate-limit service.

## Clock And Arithmetic

`new_with_rate_limit_store_and_clock` injects the clock used for rate-limit
windows, backoff, lockout, expiry, and retry-after results. Compatibility
constructors use `SystemClock`.

Attempt increment uses saturating arithmetic with an explicit `u32::MAX` cap.
Every timestamp addition is checked. Unsafe timestamp arithmetic returns a safe
configuration error rather than wrapping or panicking.

## Adapter Conformance Checklist

Downstream adapters should run the same store against these cases:

- barrier-start first inserts for one key;
- barrier-start increments of an existing key;
- exact window and expiry reset boundaries under `FixedClock`;
- backoff and lockout thresholds;
- `u32::MAX` attempt state and maximum timestamps;
- stale compare-exchange conflict without mutation;
- stale conditional clear leaving a newer revision intact;
- clear followed by insert using a fresh revision;
- two `AuthService` instances sharing the adapter;
- safe public errors that contain no normalized principal, client address, or
  opaque `value_hash`.

The in-memory implementation and crate test suite exercise this contract.
Test-only consumer adapters also execute the password-login contract against
SQLite and PostgreSQL in CI. See [commands and review evidence](password-login-review.md).
These isolated fixtures prescribe no production schema or downstream policy;
consumer adapters should repeat the contract against their own isolated store.

## Bounded process-local storage

The default `MemoryAuthRateLimitStore` stores at most 16,384 live records. Every
operation reclaims expired records under the CAS mutex, using an expiry index
that retains one deadline per key. New distinct keys at capacity return
`AuthServiceUnavailable`; existing active counters and lockouts remain intact.
Never treat this error as admission or evict an active record to accept a new
principal. Multi-process hosts still need durable shared storage and bounded
request/work admission.

```rust
use std::{num::NonZeroUsize, sync::Arc};
use agql_auth::{MemoryAuthRateLimitStore, SystemClock};

let store = MemoryAuthRateLimitStore::with_capacity_and_clock(
    NonZeroUsize::new(32_768).unwrap(),
    Arc::new(SystemClock),
);
```

Use the same trusted clock in the store and `AuthService` when injecting one.
Expired replacements are rejected. `purge_expired()` can reclaim state during
idle periods; no background task is spawned. See [the migration guide](../MIGRATION.md#0200-to-0201-bounded-process-local-abuse-state).
