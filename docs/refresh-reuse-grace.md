# Refresh reuse grace

Refresh tokens rotate on every use, and reusing a revoked token normally counts as
theft and revokes the whole session family. That also catches an honest client: the
server can commit a rotation and the response can be lost, through a reload, a dropped
connection or a suspended tab. The client still holds the old token, so its next
request looks like theft and the person is signed out. A client-side lock cannot fix
a response lost after commit.

`AuthService::with_refresh_reuse_grace` accepts that reuse for a short window. It is
off by default. Without it, behavior, errors and store calls are unchanged.

```rust
let auth = AuthService::new(config, users, refresh_tokens)?
    .with_refresh_reuse_grace(time::Duration::seconds(10))?
    .with_refresh_reuse_grace_observer(audit);
```

The window must be positive, at most `MAX_REFRESH_REUSE_GRACE` (30 seconds) and shorter
than `refresh_token_ttl`. Anything else returns `AuthError::InvalidConfiguration`.

The setting applies to every `refresh` and `step_up_session` call on that service. A
host that wants some credentials to stay strict uses a separate service for them.

## Behavior

A presented revoked token qualifies when all of these hold:

- It records a replacement (`replaced_by_token_id`). Only rotation sets this.
- Its `revoked_at` is less than the window from now. Exactly the window is too late.
- It has not expired.
- Its family has exactly one unrevoked, unexpired token, for the same user and session.

The call then issues a new token and replaces the family's newest token with it through
`RefreshTokenStore::rotate_refresh_token`. The newest token is revoked as an ordinary
rotation and is eligible itself, for its own window. The family has one live token after
every step. This is a successor, not a branch.

Anything else is replay, as it is without the option: the family is revoked and the call
returns `RefreshTokenReplayDetected`. Sign-out, administrative revocation and earlier
replay leave a family with no live token, so they end the grace even inside the window.

Losing the rotation race follows the same rule. When `rotate_refresh_token` returns
`false`, the token is read again. If it qualifies, the call succeeds as above, and both
callers of a concurrent double refresh get a token.

A window is measured from the presented token's own `revoked_at`, which a reuse never
writes, so a chain of reuses cannot keep an old token usable. A reuse only ever writes
the family's newest token. With the option on, `logout(token, false)` on an
already-revoked token does nothing, so it cannot move `revoked_at` either.

The window is symmetric, so a small clock difference between instances does not turn a
race into a sign-out. A `revoked_at` further ahead of the local clock than the window
is refused. Skew can extend a token's use by as much as the skew, and only skew smaller
than the window has this effect. Keep instances synchronized. Tests can inject a clock
with `with_refresh_rotation_clock`.

## No widening

A grace reuse runs the same steps as rotation, with the same errors:

- A disabled or missing user is refused, and nothing is revoked.
- Roles, scopes and authorization roles must be in the presented token, in the family's
  newest token and, for roles and scopes, in current authority. Authorization roles
  also go through the host's provider. A grant the newest token has already lost cannot
  come back through an older token.
- `Legacy` grants are refused, and `Host` grants need a `RefreshGrantAuthority`. The
  authority's `previous` argument is the newest token, which is the one being replaced.
- Assurance comes from the presented token, never from the newest. A step-up on the
  newest token does not pass to someone presenting an older one. The cost falls on
  the honest client: if a plain refresh of an older token replaces a stepped-up token,
  that client steps up again.
- A step-up that presents a superseded token follows the same rule and applies the
  step-up the host just verified.

## Observing it

The crate has no audit log. `with_refresh_reuse_grace_observer` installs a
`RefreshReuseGraceObserver`, which is called once after each accepted reuse with a
`RefreshReuseGraceEvent`. Ordinary rotation and refused reuse do not call it. The event
holds the family, session, user and record IDs, times, IP address and user agent, and
never a token or a hash.

The call comes after the commit, and it cannot refuse the reuse. A crash or a cancelled
request between the commit and the call loses the event, so treat it as an audit signal
and not as a durable record.

In the store, a grace reuse looks like a rotation. `RefreshTokenRevocationReason` has no
new value, because adding one would break exhaustive matches.

## What the store must do

Override `RefreshTokenStore::find_live_refresh_tokens_in_family`. Its default returns
`Ok(None)`, meaning not supported, and then reuse stays replay even when a window is
set. So a store that has not adopted this, and a wrapper that does not forward the
method, stay strict. The service does not report this at startup, so test it.

No new column is needed. The check uses `revoked_at` and `replaced_by_token_id`.

The read must:

- Return every unrevoked token in the family, including any past its expiry, and an
  empty list when there are none.
- Read committed state in one consistent snapshot. One plain `SELECT` does this.
- **Not lock what it reads.** At PostgreSQL `READ COMMITTED`, a
  `SELECT ... WHERE revoked_at IS NULL FOR UPDATE` that waits on a concurrent rotation
  re-checks the old row, finds it revoked and does not see the replacement, because that
  row was committed after the statement's snapshot. It returns nothing, which reads as a
  revoked family, and the honest caller is signed out.

```sql
SELECT * FROM refresh_tokens
WHERE session_family_id = ? AND revoked_at IS NULL;
```

Overriding it also commits the store to these rules:

1. **`rotate_refresh_token` stays a compare-and-swap.** This is the existing contract:
   revoke the current token and insert the replacement in one transaction, and return
   `Ok(false)`, changing nothing, when the current token is already revoked. There is no
   new write operation.
2. **`replaced_by_token_id` is set only by rotation.** The record has no reason field,
   so this is how a rotation is recognized.
3. **A revoked token's `revoked_at` and `replaced_by_token_id` do not change while its
   family is live.** A window is measured from them. `revoke_refresh_token` must check
   this in the same statement, `UPDATE ... WHERE id = ? AND revoked_at IS NULL`, because
   its caller may have read the token before a concurrent rotation. Without the check,
   a sign-out racing a rotation overwrites the rotation and ends that token's grace early.
   Changing them during family revocation is harmless, because no live token remains.
4. **Family revocation cannot miss a replacement.** At PostgreSQL `READ COMMITTED`, a
   single `UPDATE ... WHERE session_family_id = ? AND revoked_at IS NULL` can block on
   the newest row while a rotation commits. It then skips that row and never sees the
   replacement, which stays live after sign-out. Ordinary rotation has the same hazard,
   and the grace makes rotations more common. Serialize the two per family:

```sql
-- In both revoke_refresh_token_family and rotate_refresh_token. The lock is its own
-- statement, so the statements after it read what the previous holder committed.
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended(?, 0)); -- the session family ID
UPDATE refresh_tokens SET revoked_at = ?, ...
WHERE session_family_id = ? AND revoked_at IS NULL;
COMMIT;
```

`SERIALIZABLE` with retries also works. So does SQLite with `BEGIN IMMEDIATE`, which
serializes writers.

### Why one live token holds under concurrency

Every change to the live token is one `rotate_refresh_token` commit, which moves it from
one record to the next atomically. A reader sees the old state or the new one, never
both and never neither.

Two reuses that race both read the newest token `B` and both try to replace it. The
first commits. The second waits on `B`'s row, re-checks `revoked_at IS NULL` after the
commit, matches nothing and returns `false` without inserting. The service then reads
the new newest token, rebuilds the replacement against it and tries again. The same
applies to a reuse racing an ordinary rotation of `B`, and to reuses of different old
tokens, because every writer contends on the newest row. Each failed attempt means
another caller succeeded.

After 32 failed attempts the call returns `AuthError::Store` and revokes nothing, because
contention is not evidence of theft. The client can retry while the window lasts.

`testdata/consumer_refresh_token_store.py` is an executable example on both backends, and
`refresh_reuse_grace_consumer_conformance` runs these races against it.

## The cost

Someone holding a stolen, just-rotated token can use it inside the window without
tripping detection. They then hold the live token.

That lasts until the real client's next refresh. By then the real client's token was
revoked more than the window ago, so that refresh is replay and revokes the family,
including the thief's token. How long this takes depends on when the client next
refreshes, which is usually about one access-token lifetime.

Rotating does not help the thief. It writes only the thief's own newest token, so it
cannot renew the window of the token the real client holds. If the real client returns
inside the window it gets the live token, and the thief is the one caught next.

Both sides can avoid detection only if each refreshes inside the other's window, every
time, for as long as it lasts. If a real client never refreshes again, the thief keeps
the session until something else ends it. That is also true without this option, for a
thief who rotates a stolen live token first.

So the option gives up detection of a theft only for a reuse inside the window.

**Use a window of a few seconds, not the 30-second maximum.** The window only has to
cover a response lost after commit and the client's next attempt, which on a working
connection follow within a second or two. Every extra second is time in which a reuse of
a stolen token goes unnoticed, and widens the overlap that alternating refreshes need to
stay hidden. Raise it only for clients that measurably retry later.

Each accepted reuse inserts a token record, as a rotation does. Reuses are limited only
by the window, so hosts that bound a family's history should allow for that.
