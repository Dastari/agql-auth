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

Password-reset and login-code request helpers first evaluate every key and
return `false` without recording anything when any key is in backoff or
lockout. Only then do they record the request against each key. A throttled
client therefore cannot add or advance state for the principals it names, so
one address cannot silently suppress another user's reset or login-code mail
or fill the store with principal entries. Admission is based on the state
before the transition, preserving the rule that the request which first
activates backoff is allowed. A concurrent request cannot also claim the same
pre-state: its CAS conflicts, it rereads the committed backoff, and it returns
`false`. If a key denies during recording (a concurrent request won the race)
or cannot be recorded, keys already recorded by that call are refunded.

Request helpers count the submitted principal as given (trimmed and ASCII
lowercased); they never look the account up, so they reveal nothing about it.

## Credential Reservation

Password login, login-code verification and both rate-limited TOTP variants
count an attempt before verifying anything:

1. every principal and client key is evaluated; active backoff or lockout
   returns `AuthThrottled` or `AuthLocked` without recording;
2. each key is then incremented by CAS exactly as a failure would be, and
   every CAS rechecks backoff and lockout against the state it replaces;
3. only then does the service verify the password, code or TOTP step.

A failure needs no further write: it was already counted. Because the count
is committed before verification, a burst of concurrent attempts cannot all
observe a state below the lockout threshold. At most
`max_attempts_before_lockout` attempts per window are verified for one
principal, and the same bound applies per client. Until an attempt resolves it
counts toward thresholds, so concurrent attempts on the same bucket can see a
transient backoff that the attempt's success later removes.

A store that cannot record the attempt (an error, or a full
`MemoryAuthRateLimitStore`) fails the request with `AuthServiceUnavailable`
before verification. No outcome then depends on the secret, so a full or
failing store is never an uncounted guessing oracle. If one key was recorded
before another failed, that record is refunded where possible.

Password login resolves the account before building keys. A known account is
counted against its stable local user ID, so every spelling or alias the user
store accepts shares one budget; an unknown principal is counted against its
normalized input. Unknown accounts, and stored hashes that Argon2 cannot
verify with real work (unparsable, another algorithm, invalid parameters),
perform one verification against the fixed dummy Argon2 hash and return
`InvalidCredentials`. Disabled accounts verify their stored hash: a wrong
password returns `InvalidCredentials` and the correct one `UserDisabled`, so
the disabled state is only revealed with proof of the password. Both stay
counted, never clear attempts and never enter access/refresh issuance.
Already active controls reject before password work; persistence errors
propagate through the safe public error map. The threshold-activating failure
returns its credential error, and the next attempt receives
throttling/lockout. There is no constant-time guarantee across host-chosen
stored hash parameters.

## Settle Versus Refund

A success settles its reservation. The principal bucket is cleared if its
revision is still the one the reservation wrote; otherwise only this attempt
is refunded and newer failures survive. The client bucket is shared by every
principal behind one address, so a success refunds only its own attempt.
Failures other principals recorded from that address stay counted: logging in
to one's own account does not reset an address used to spray other accounts,
and successful logins never accumulate state for a shared address.

A refund restores the exact state the reservation replaced when nothing was
recorded since. Otherwise it removes one attempt from the current window and
drops backoff or lockout only when the remaining count is below that
threshold. A refund for a window that has since ended changes nothing.

Attempts that verified nothing are refunded: a saturated password work pool,
an expired login challenge, or invalid host-supplied TOTP options. These
outcomes do not depend on the submitted secret. Password-reset token
consumption verifies a signed token, which cannot be guessed; it keeps
check-then-record counting and clears only the principal bucket on success.

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
- refund CAS restoring a replaced state and conditional delete of a fresh record;
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
principal. Credential flows reserve before verification, so at capacity they
fail closed for every outcome rather than verifying uncounted.

Request-initiation flows (password-reset and login-code requests, with a
six-hour default TTL) may hold at most half of the capacity, rounded down.
Request spam therefore cannot take the entries credential verification needs.
While either share is full, new principals in that share receive
`AuthServiceUnavailable`, which is a denial of service, not a bypass.
Multi-process hosts still need durable shared storage and bounded
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

## Async password work admission

Async password login and challenge hashing/verification leave runtime threads using
one process-wide pool of two workers and 32 queued jobs. Admission uses a nonblocking
bounded queue; saturation and worker faults fail closed as `AuthServiceUnavailable`.
The attempt was reserved before work was queued and is refunded, because no
secret was checked and the outcome is the same for every password. No store lock is held during CPU work.
Cancellation does not free actual running/queued capacity early. Atomic challenge
attempts already reserved remain charged even when the executor cannot admit work.

Hosts separately bound incoming requests, password/code sizes and accepted Argon2
costs. These controls must cover explicit synchronous hash/verify helpers too; those
helpers remain blocking by design. This pool does not add a password-size or Argon2
parameter compatibility cutoff and never logs sensitive inputs.
