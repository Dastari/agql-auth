# Storage Traits

`agql-auth` is database agnostic. The host application implements storage traits
against its own database and transaction model.

The traits are async and should be implemented with the same consistency
guarantees you would use for session state in production.

## Required For Password Sessions

`UserStore` loads users by login principal and by local user ID.

The returned `StoredUser` includes:

- local user ID
- principal
- password hash
- local roles
- local scopes
- disabled flag

`RefreshTokenStore` stores hashed refresh tokens and tracks rotation,
revocation, replay, and session families. Store only `StoredRefreshToken`'s
`token_hash`, never the raw refresh token.

Important refresh-token behavior:

- `insert_refresh_token` stores the newly issued token record.
- `find_refresh_token_by_hash` must return revoked records too, so replay can
  be detected.
- `revoke_refresh_token` is used during logout and expiry.
- `revoke_refresh_token_family` is used for sign-out and after replay detection.
- `touch_refresh_token` records use metadata outside refresh rotation.
- `rotate_refresh_token` atomically revokes the current token and inserts the
  replacement during refresh.

Since `0.8`, the record's existing `session` value may contain
`SessionContext.assurance`, and `refreshable_metadata` contains only tenant,
organization, actor, and correlation values. Persist both unchanged in the
replacement row. Missing values from pre-0.8 rows deserialize as `None`; never
backfill `auth_time` with refresh or migration time. See
[session assurance](session-assurance.md) and [MIGRATION.md](../MIGRATION.md).

`rotate_refresh_token` is required in `0.6.0`. It must return `Ok(true)` only
when the current token exists, is not revoked, is marked used/revoked for
rotation, and the replacement token is inserted in the same transaction. Return
`Ok(false)` if the current token is missing or already revoked. If the
replacement cannot be inserted, return `Err(...)` and leave the current token
unmodified.

### Concurrency rules

A session family has at most one unrevoked token, and only rotation moves it to a
new record. Every `RefreshTokenStore` must keep that true under concurrency, with or
without the reuse grace:

1. **Rotation is a compare-and-swap decided by the update.** Update the current row
   first and insert the replacement only when exactly one row changed. Do not decide
   from an earlier `SELECT`: a read without a lock can see a token that a concurrent
   family revocation is revoking, and the port then inserts a live replacement after
   sign-out.
2. **Single revocation leaves a revoked row unchanged**, checked in the same
   statement. Sign-out reads the token before it revokes it. If a rotation commits in
   between, overwriting `revoked_at` and `replaced_by_token_id` hides the rotation
   from the service, and the replacement outlives the sign-out.
3. **Family revocation cannot miss a replacement.** At `READ COMMITTED` (PostgreSQL's
   default, SQL Server with or without RCSI, MySQL when configured), a single
   `UPDATE ... WHERE session_family_id = ? AND revoked_at IS NULL` can block on the
   current row while a rotation commits, then skip it and never see the replacement,
   which was committed after the statement's snapshot. Serialize family revocation
   and rotation per family.

Canonical rotation, update first and row-count checked:

```sql
BEGIN;
-- Per-family lock here, as its own statement (see the backend notes).

UPDATE refresh_tokens
SET revoked_at = :now,
    replaced_by_token_id = :replacement_id,
    last_used_at = :now,
    ip_address = :ip_address,
    user_agent = :user_agent
WHERE id = :current_id
  AND revoked_at IS NULL;

-- affected rows != 1: ROLLBACK; return Ok(false)

INSERT INTO refresh_tokens (...) VALUES (...);
-- insert fails: ROLLBACK; return Err(...)

COMMIT; -- return Ok(true)
```

Family revocation takes the same lock:

```sql
BEGIN;
-- The same per-family lock.
UPDATE refresh_tokens
SET revoked_at = :now, revocation_reason = :reason
WHERE session_family_id = :family_id
  AND revoked_at IS NULL;
COMMIT;
```

Single revocation is one statement:
`UPDATE refresh_tokens SET ... WHERE id = :id AND revoked_at IS NULL`.

Backend notes:

- **PostgreSQL.** Take `SELECT pg_advisory_xact_lock(hashtextextended(:family_id::text, 0))`
  as the first statement of both transactions. It must be its own statement, so that
  the statements after it read what the previous holder committed. `SERIALIZABLE`
  with retry on serialization failure also works.
- **SQLite.** Open both transactions with `BEGIN IMMEDIATE`, which serializes
  writers. SQLite has no `SELECT ... FOR UPDATE`, so the update-first shape is the
  natural one; read the row count from `changes()` or the driver.
- **SQL Server.** `FOR UPDATE` exists only for cursors. Use the update-first shape
  with `@@ROWCOUNT`, and serialize per family with
  `sp_getapplock @Resource = <family id>, @LockMode = 'Exclusive', @LockOwner = 'Transaction'`
  at the start of both transactions, or run both at `SERIALIZABLE`.
- **MySQL (InnoDB).** Under `READ COMMITTED` gap locks are off, so take a per-family
  lock in both transactions, for example `SELECT ... FOR UPDATE` on a per-family or
  per-user row that both always lock first. Check `ROW_COUNT()` after the update.

Add a unique index over unrevoked rows, so a broken rotation or an accidental branch
fails instead of leaving two live tokens:

```sql
-- PostgreSQL and SQLite; SQL Server accepts the same filtered index.
CREATE UNIQUE INDEX refresh_tokens_one_live_per_family
ON refresh_tokens (session_family_id)
WHERE revoked_at IS NULL;

-- MySQL has no partial index: index a generated column that is NULL once revoked.
ALTER TABLE refresh_tokens
  ADD COLUMN live_family_id BINARY(16)
    AS (IF(revoked_at IS NULL, session_family_id, NULL)) STORED,
  ADD UNIQUE INDEX refresh_tokens_one_live_per_family (live_family_id);
```

The index needs the update-first order: the current row must be revoked before the
replacement row is inserted in the same transaction.

Use a unique index on the refresh-token hash and indexes on session-family IDs
to make revocation efficient.

`testdata/consumer_refresh_token_store.py` implements these rules on SQLite and
PostgreSQL. The ignored `*_refresh_reuse_grace_consumer_conformance` tests run the
crate's rotation, sign-out and family-revocation races against it, including a
rotation that starts while a family revocation is uncommitted and the reverse. Run
the same races against your adapter.

`find_live_refresh_tokens_in_family` is optional. Its default reports no support.
It is only needed for the opt-in [refresh reuse grace](refresh-reuse-grace.md), which
relies on the concurrency rules above and adds the requirements listed there.

## Abuse Protection

`AuthRateLimitStore` persists counters for rate limiting, exponential backoff,
and temporary lockout. `AuthService::new` uses `MemoryAuthRateLimitStore`, which
is useful for tests and single-process development. Production deployments with
multiple app instances should implement `AuthRateLimitStore` and construct the
service with `AuthService::new_with_rate_limit_store`.

The store receives opaque keys:

- `flow`, such as `password_login`, `login_code_verification`,
  `totp_verification`, `password_reset_token_consumption`,
  `password_reset_request`, or `login_code_request`
- `bucket`, either `principal` or `client`
- `value_hash`, a SHA-256 hash of the normalized principal/user/client value

The store persists `AuthRateLimitSnapshot`: the state plus a fresh UUID
revision. `compare_exchange_auth_rate_limit_state` must conditionally insert
when no revision was observed or update only the exact observed revision.
`clear_auth_rate_limit_state` is also conditional. This lets the service keep
all policy calculations centralized while preventing lost increments and stale
success/expiry cleanup from erasing newer failures.

Durable backends need a revision column or equivalent document field. SQLite
can use a write transaction or conditional insert/update; PostgreSQL can use a
row lock, conditional update, or revision-guarded upsert. An unconditional
upsert after `find_auth_rate_limit_state` does not satisfy the contract.

`AuthConfig.rate_limits.credential` controls password login, login-code
verification, TOTP verification, and password-reset token consumption.
`AuthConfig.rate_limits.request` controls password-reset and login-code request
initiation. Each `AuthRateLimitPolicy` exposes:

- `enabled`
- `window`
- `backoff_after_attempts`
- `max_attempts_before_lockout`
- `base_backoff`
- `max_backoff`
- `lockout_duration`
- `state_ttl`

Throttled credential checks return `AuthError::AuthThrottled`; lockouts return
`AuthError::AuthLocked`. Both map to GraphQL extension codes and include
`retryAfterSeconds`.

See [atomic abuse protection](abuse-protection.md) for CAS semantics, clock
injection, clear ordering, migration, and adapter conformance cases.

## API Tokens

`ApiTokenStore` persists long-lived opaque API/service tokens. It is independent
of `UserStore` and `RefreshTokenStore`.

The store must support:

- inserting a `StoredApiToken`
- finding a token by hash
- touching last-used metadata
- revoking a token

Optional trait methods support revoking all tokens for a principal or all
tokens bound to a generic resource.

Store only `StoredApiToken.token_hash`, never the raw token returned in
`IssuedApiToken`. Use a unique index on `token_hash`; revoked records should
still be returned by `find_api_token_by_hash` so the service can distinguish a
revoked token from an unknown token.

## Password Reset

`PasswordResetTokenStore` makes password-reset tokens one-time use.

The service issues a signed reset token. The store records the token ID and
marks it consumed:

```rust
let issued = auth
    .issue_password_reset_token_with_store(&reset_store, user_id, ttl)
    .await?;

let verified = auth
    .consume_password_reset_token(&reset_store, &issued.token)
    .await?;
```

`consume_password_reset_token` must be atomic. If two requests try to consume
the same token ID, exactly one should return `true`.

## Login Challenges

`LoginChallengeStore` persists one-time numeric challenges for email-code,
SMS-code, or similar flows.

The store must support:

- inserting a unique immutable challenge and password-hashed code
- reading the challenge by ID
- atomically reserving an attempt before password verification
- conditionally consuming the unexpired challenge exactly once

`reserve_login_challenge_attempt` must check presence, consumption, expiry and
`attempts < max_attempts` in the same atomic update that increments `attempts`.
Return the post-increment snapshot, or the corresponding `AuthError` for a
terminal record. Committed reservations are never refunded after cancellation,
store response loss, incorrect code, or subsequent failure. Release transaction
locks before returning; password work runs outside the store transaction.

SQLite/PostgreSQL-style admission shape (bind every value):

```sql
UPDATE login_challenges
SET attempts = attempts + 1
WHERE id = ? AND consumed_at IS NULL AND expires_at > ?
  AND attempts < max_attempts
RETURNING *;
```

Adapt parameters and types to the backend. SQL Server uses `OUTPUT inserted.*`
instead of `RETURNING`; a lock/transaction implementation is also acceptable.
Zero affected rows must deny, never trigger an unconditional retry/update.
Reads used to classify a denial must not grant admission. Both SQLite's write
serialization and PostgreSQL/SQL Server concurrent conditional-update behavior
must be verified by each host adapter against its disposable database fixture.

Consumption must atomically require `consumed_at IS NULL`, `expires_at > now`,
and `attempts > 0`, then set `consumed_at`. A correctly verified final admitted
attempt remains eligible when the counter equals the cap. All other record
fields are immutable; duplicate insert and ID reuse are forbidden. Service and
store clocks must use the same trusted time basis. The service rechecks expiry
after asynchronous completion too. See [the migration guide](../MIGRATION.md)
for the coordinated old-worker shutdown and outstanding-challenge invalidation.

## OIDC State

`OAuthStateStore` is required for OIDC and plain OAuth 2.0 authorization-code
flows.

`create_authorization_request` stores an `OAuthLoginState` containing the hashed
state, nonce, PKCE verifier, redirect URI, requested scopes, expiry, an
optional versioned `authorization_policy`, and the `response_mode` the
callback must arrive in. The typed-options API binds that policy to the exact
state; legacy/default requests store `None`. The raw state is returned only to
the browser redirect flow. `OAuth2Provider` states carry an empty nonce;
`OidcProvider` refuses such a state and `OAuth2Provider` refuses a state with a
nonce. Give every provider its own `provider_name`: an OIDC provider and an
OAuth 2.0 provider must never share one. The nonce check is defense in depth,
not a supported way to share a state namespace.

`consume_oauth_state` must consume state exactly once. A replayed callback with
the same state must not be accepted.

The method must atomically find an unconsumed state by `(provider_name,
state_hash)`, set `consumed_at`, and return the pre-consumption snapshot with
`consumed_at == None`. Returning the post-update record will make the callback
look replayed.

SQL-style shape:

```sql
UPDATE oauth_states
SET consumed_at = ?
WHERE provider_name = ?
  AND state_hash = ?
  AND consumed_at IS NULL
RETURNING provider_name, state_hash, nonce, code_verifier, redirect_uri,
          scopes, authorization_policy, response_mode, created_at, expires_at,
          NULL AS consumed_at;
```

Recommended database constraints:

- unique key on `(provider_name, state_hash)`
- nullable `consumed_at`
- nullable JSON/typed `authorization_policy`; missing legacy values mean no
  request, never satisfied step-up
- `response_mode` (`query` or `form_post`); a missing legacy value means
  `query`. A store that drops it makes `form_post` callbacks fail closed
- `nonce` may be empty (plain OAuth 2.0 states)
- compare expiry before accepting the callback
- update `consumed_at` in the same statement that verifies it is currently null

## TOTP Replay

`TotpReplayStore` is optional but recommended for production MFA. Stateless
TOTP verification can accept the same valid code more than once within the skew
window. `consume_totp_step` should atomically insert or mark
`(principal_id, factor_id, step)` and return `true` only for the first consume.

## External Identities

`ExternalIdentityStore` links validated provider identities to local users.

For Microsoft Entra work/school accounts, `agql-auth` prefers `tid + oid` as
the stable external subject. For generic OIDC it falls back to `iss + sub`.

The store should treat `(provider_name, external_subject)` as unique. Do not use
email, UPN, display name, or preferred username as authorization identifiers;
those fields can change and are not stable identity keys.

## Optional Provider Tokens

`OAuthTokenStore` is optional and is not required for login.

Use it only when the host explicitly wants to retain provider access or refresh
tokens. Provider refresh tokens should be encrypted by the host before
persistence. Microsoft access tokens should be treated as opaque unless the host
is separately validating them for a resource-server use case.

## Current authority for sensitive operations

See [principal lifecycle](principal-lifecycle.md#current-authority-for-sensitive-operations)
for immediate fail-closed status/current-grant checks and the
[0.20 migration](../MIGRATION.md#0192-to-0200-current-authority-and-sensitive-operations)
for refresh provenance, stored role ceilings, and mandatory host/OIDC authority.

The default memory abuse store has a finite capacity and reclaims expired rows;
see [bounded process-local storage](abuse-protection.md#bounded-process-local-storage)
for safe capacity failures, clock injection and idle cleanup. Durable stores must
retain atomic CAS/clear behavior while performing their own TTL lifecycle.
