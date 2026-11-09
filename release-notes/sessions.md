# Release notes: sessions stream (0.27.0)

Refresh sessions, the GraphQL refresh-cookie helper and the password worker pool.

## AUTH-2: sign-out with an already-rotated refresh token left its successor live

`logout(token, false)` with a token that rotation had already superseded did nothing
to the live successor. With reuse grace it returned early; without, it re-revoked the
already-revoked record, which the store's guard turns into a no-op. A victim signing
out with a stolen-and-rotated token left the thief's session alive, and reuse
detection never fired. Now a superseded token (`revoked_at` and
`replaced_by_token_id` set) is a reuse signal: `logout(token, false)` revokes the
whole family with `ReplayDetected`, with or without grace and inside the grace window
too. When the presented token is live, the service revokes it, reads it again, and
revokes the family if a rotation committed in between. That closes the sign-out vs
refresh race. A token revoked for another reason changes nothing. Family revocation,
`logout(token, true)`, is now the documented default for sign-out. The contradiction
in `docs/refresh-reuse-grace.md` is fixed.

### Changelog

Security
- `AuthService::logout(token, false)` with a refresh token that rotation has
  superseded now revokes the whole session family as `ReplayDetected`, with or without
  refresh reuse grace. Before, it left the successor live and raised no reuse signal.
- A rotation that commits while `logout(token, false)` runs no longer leaves its
  replacement live. The service reads the token again and revokes the family.

Fixed
- `docs/refresh-reuse-grace.md` no longer says both that sign-out leaves no live
  token and that `logout(token, false)` on a superseded token does nothing.
- `logout(token, false)` on a token revoked without a replacement no longer calls
  `revoke_refresh_token` again.

Fixed (behaviour)
- `docs/getting-started.md` recommends `logout(token, true)` for sign-out.

### Migration

- No API change. Hosts that relied on `logout(token, false)` leaving the rest of a
  rotated family alone now see the family revoked. Audit trails record
  `ReplayDetected` for a sign-out that presented a superseded token, and `Logout` for
  one that raced a rotation.
- Stores must leave an already revoked record unchanged in `revoke_refresh_token`
  (`UPDATE ... WHERE id = ? AND revoked_at IS NULL`). This was previously stated only
  for grace adopters; see AUTHX-3. If a store overwrites `replaced_by_token_id`, the
  service cannot see a racing rotation, and that race behaves as before.

## AUTHX-3: refresh-family revocation could miss a concurrently committed replacement

At `READ COMMITTED` (PostgreSQL's default, SQL Server, MySQL when configured) a single
`UPDATE ... WHERE session_family_id = ? AND revoked_at IS NULL` blocks on the row a
concurrent rotation is revoking, then skips it and never sees the replacement that
rotation inserts. The per-family serialization requirement was documented only for
reuse-grace adopters, and the recommended rotation SQL (`SELECT ... FOR UPDATE`, then
INSERT and UPDATE) does not port: it is a syntax error on SQLite and cursor-only on
SQL Server. A port that drops the lock and ignores the update's row count leaves a
live replacement after sign-out. The requirements are now in the base
`RefreshTokenStore` docs and `docs/storage-traits.md`. The update-first,
row-count-checked shape is canonical, with notes for PostgreSQL (advisory lock), SQLite
(`BEGIN IMMEDIATE`), SQL Server (`sp_getapplock` or `SERIALIZABLE`) and MySQL
(per-family lock row). Both docs recommend a unique index on `session_family_id` over
unrevoked rows, with a generated-column variant for MySQL. The consumer fixture
now has that index and can hold a family revocation open. New conformance races run
on the memory store and on the fixture's SQLite and PostgreSQL backends. No library
code needed to change: the reference stores were already correct.

### Changelog

Security
- `RefreshTokenStore` now requires every store, not only reuse-grace adopters, to
  serialize `rotate_refresh_token` with `revoke_refresh_token_family` per family, to
  decide rotation from the row count of an update-first compare-and-swap, and to leave
  already revoked records unchanged in `revoke_refresh_token`.

Fixed
- `docs/storage-traits.md` replaces the non-portable `SELECT ... FOR UPDATE` rotation
  sample with the update-first, row-count-checked shape and per-backend notes.

Added
- Docs recommend a unique index on `(session_family_id) WHERE revoked_at IS NULL`.
- Conformance races: a rotation started while a family revocation is uncommitted, a
  rotation racing a family revocation, and two rotations of one token. They run in the
  existing `*_refresh_reuse_grace_consumer_conformance` CI tests and in-crate on the
  memory store.

### Migration

- Store implementors: check `rotate_refresh_token`, `revoke_refresh_token` and
  `revoke_refresh_token_family` against the concurrency rules in
  `docs/storage-traits.md#concurrency-rules`. A PostgreSQL store at `READ COMMITTED`
  without a per-family lock (or `SERIALIZABLE`) can leave a token live after sign-out.
- Optional: add the partial unique index. It needs the update-first order in rotation:
  revoke the current row before inserting the replacement.

## #33 (AUTH-21): absolute session lifetime and revoke-by-user

Refresh rotation could extend a session indefinitely. Disabling a user or changing a
password did not end their refresh families, and there was no user-wide store
operation. `AuthConfig::max_session_lifetime` (default 90 days, `None` to disable)
now bounds a session family from its first issuance. The deadline is persisted in the
new `StoredRefreshToken::session_expires_at`, set at login or host issuance and copied
unchanged to every replacement, including grace reuses (the earlier of the presented
and newest token's deadline). Each replacement expires at the earlier of
`refresh_token_ttl` from rotation and the deadline. No existing field holds the
original authentication time: `created_at` is per record, and
`SessionAssurance::authenticated_at` is optional and moves on step-up. So the deadline
lives in a new optional field. Its default fails safe: a record without it, whether a
pre-0.27 row or a store that drops the field, is never extended past its own
`expires_at` while a maximum lifetime is configured. Such sessions get shorter, never
longer. `RefreshTokenStore::revoke_refresh_tokens_for_user` is a new required method,
and `AuthService::revoke_user_sessions` calls it. It is required because a default
would either silently do nothing or fail at password-reset time. Implementors already
have to touch their row mapping for the new field anyway.

### Changelog

Security
- Refresh rotation never extends a session family past
  `AuthConfig::max_session_lifetime` from its first issuance. Default: 90 days.
- New `AuthService::revoke_user_sessions(user_id, reason) -> AuthResult<u64>` revokes
  every refresh token of a user, in every family. Call it when disabling a user, after
  a password change or reset, and for "sign out everywhere".

Added
- `AuthConfig::max_session_lifetime: Option<Duration>` and
  `DEFAULT_MAX_SESSION_LIFETIME`.
- `StoredRefreshToken::session_expires_at: Option<OffsetDateTime>`
  (`#[serde(default)]`, omitted from JSON when `None`).
- `RefreshTokenStore::revoke_refresh_tokens_for_user` (required).
- Consumer fixture `revoke_user` operation and conformance races for user revocation
  against concurrent rotation.

Breaking
- `RefreshTokenStore` has a new required method, `revoke_refresh_tokens_for_user`.
- `StoredRefreshToken` has a new public field. Struct literals must set it.
- `AuthConfig` has a new public field. Struct literals that list every field must set it.
- With the default 90-day lifetime, sessions end at most 90 days after login however
  often they refresh. Records without `session_expires_at` stop sliding while a
  lifetime is configured.

### Migration

- Store implementors:
  - Persist `session_expires_at` in a nullable timestamp column, or keep it in a
    serialized record, and map it in both directions. Do not backfill it from
    migration time. Leaving it `None` for existing rows is correct: those sessions end
    at their current `expires_at`.
  - Implement `revoke_refresh_tokens_for_user(user_id, revoked_at, reason) -> u64`.
    Revoke only unrevoked rows of that user and return how many. Index `user_id`. It
    must not miss a replacement that a concurrent rotation commits. Either serialize
    it with rotation through a per-user lock that rotation also takes, or, at
    `READ COMMITTED`, repeat the UPDATE in the same transaction until a fresh SELECT
    finds no unrevoked token of the user. SQLite's `BEGIN IMMEDIATE` needs neither.
    See `docs/storage-traits.md`.
- Config: to keep sliding sessions without an absolute limit, set
  `config.max_session_lifetime = None`. In that case records without a deadline slide
  as before, and records that have one keep it.
- Struct literals: add `session_expires_at: None` to `StoredRefreshToken { .. }` and
  `max_session_lifetime` to a full `AuthConfig { .. }` literal, or build it from
  `AuthConfig::new(..)` with `..`.
- Hosts: call `auth.revoke_user_sessions(&user_id, RefreshTokenRevocationReason::AdminRevoked)`
  when disabling a user and after a password change. Issued access tokens remain
  valid until their `exp`.
- Password-reset completion, for the `single-use` stream or the integrator: this
  stream did not edit `src/service/password_reset.rs`. After the reset token is
  consumed successfully (`consume_password_reset_token*` returning the user), call
  `self.revoke_user_sessions(&user_id, RefreshTokenRevocationReason::AdminRevoked).await?`.
  Inside the service, `self.refresh_store.revoke_refresh_tokens_for_user(&user_id, now, RefreshTokenRevocationReason::AdminRevoked)`
  is equivalent. Otherwise document that the host must call it when it stores the new
  password hash.

## AUTH-3: refresh-cookie helper left the raw token in some responses

`graphql_refresh_cookie_directive` blanked `session.refreshToken` only in an
error-free response of exactly the expected shape. An aliased `session` or
`refreshToken`, an omitted `refreshTokenExpiresAt`, or a partial error (any entry in
`response.errors`) left the raw token in the JSON body. A first top-level entry
without a session also ended the scan early. Now, whenever an issuing field is
selected and `sanitize_response` is on (the default), sanitizing runs on every
response, errors included, before any directive is decided. In the issuing entries,
at any depth, every value under the refresh-token field name and every string shaped
like a token the crate issues (64 URL-safe base64 characters) is blanked. Every copy
of a token found at the canonical path is blanked anywhere in the body. A body that
cannot be inspected is replaced with `null`. `Set` is returned for the first complete
`session.refreshToken` + `session.refreshTokenExpiresAt` pair, also on partial errors,
since the session was issued. `Clear` still needs an error-free response. The docs
also describe the out-of-band alternative: keep the token out of the schema and set
the cookie with `Context::insert_http_header`.

### Changelog

Security
- `graphql_refresh_cookie_directive` no longer leaves a raw refresh token in the
  response body for aliased fields, nested selections, an omitted
  `refreshTokenExpiresAt` or partial errors.

Fixed
- Scanning without response keys no longer stops at the first entry without a session.

Fixed (behaviour)
- `Set` is returned when an issuing entry holds a complete session even if other
  fields failed. Without an expiry no `Set` is returned and the token is still
  removed.

### Migration

- No API change. Hosts must run the helper on error responses too. Clients must
  select `refreshToken` and `refreshTokenExpiresAt` under their schema names in the
  session object, or no cookie is set and the token is removed.
- Within issuing entries, a non-token string of exactly 64 URL-safe base64 characters
  is also blanked.

## #39 (AUTHX-4) and #38 first bullet: password work pool, length cap, Argon2 parameters, rehash signal

The pool was process-wide with 2 workers and 32 queue slots and no configuration
hook. A `thread::Builder::spawn` failure on first use was cached in a `OnceLock`, so
every later `AuthService::new` failed until restart. `PasswordWorkPool` and
`PasswordWorkPoolConfig` are now public. The default pool stays process-wide: one
budget bounds Argon2's CPU and memory however many services a process builds. It is
sized from available parallelism, clamped to 1..=8 workers, with 16 queued jobs per
worker. `PasswordWorkPool::new` accepts 1..=256 workers and 1..=65536 queued jobs.
`AuthService::with_password_work_pool` installs a pool, so hosts can share one
budget or isolate services explicitly. Workers start on first use. A spawn failure
fails only that call (when no worker runs) and is retried on the next one. A partial
spawn runs with the workers it has. The guarantee that admitted work stays charged
after the caller cancels is kept, and its tests are unchanged.

`AuthConfig::password_hashing` sets the Argon2id parameters (defaults 19456 KiB, 2
iterations, 1 lane, the previous `Argon2::default()`) and `max_password_bytes`
(default 1024, at most 4096). An over-long password is never hashed. `hash_password`
and the async hasher return the new `AuthError::PasswordTooLong`. `verify_password` and
async verification return `InvalidCredentials` before queueing, which is the
hashing/verification layer. So login counts it as an ordinary credential failure
through its existing path, with the same fast result for every account (no
enumeration oracle). Unknown and disabled users verify a dummy hash under the
configured parameters, computed once at construction when they differ from the
defaults, so their cost matches a current user's. `password_hash_needs_rehash(hash)`
reports a stored hash that is not Argon2id v19 with the configured m/t/p, or cannot
be parsed. The docs now state that the login route needs edge throttling.

### Changelog

Security
- Password work no longer caches a thread-spawn failure. Workers start on first use
  and a failed spawn is retried on the next call.
- Passwords longer than `PasswordHashingConfig::max_password_bytes` (default 1024
  bytes) are never hashed. Verification treats them as a wrong password without Argon2
  work.
- The dummy verification for unknown and disabled users uses the configured Argon2
  parameters.

Added
- `PasswordWorkPool` (`new`, `shared`), `PasswordWorkPoolConfig` (`Default` from
  available parallelism), `MAX_PASSWORD_WORKERS`, `MAX_QUEUED_PASSWORD_JOBS`,
  `DEFAULT_MAX_PASSWORD_WORKERS`, `DEFAULT_QUEUED_PASSWORD_JOBS_PER_WORKER`.
- `AuthService::with_password_work_pool`.
- `AuthConfig::password_hashing: PasswordHashingConfig` (`max_password_bytes`,
  `memory_kib`, `iterations`, `parallelism`), `DEFAULT_MAX_PASSWORD_BYTES`,
  `MAX_PASSWORD_BYTES_LIMIT`.
- `AuthService::password_hash_needs_rehash`.
- `AuthError::PasswordTooLong`, public code `PASSWORD_TOO_LONG`, message
  "password is too long".

Fixed (behaviour)
- The default pool is sized from available parallelism (up to 8 workers, 16 queued
  jobs per worker) instead of 2 workers and 32 queued jobs.

Breaking
- New `AuthError` variant `PasswordTooLong`. Exhaustive matches must handle it.
- `AuthConfig` has a new public field, `password_hashing`.
- Hashing a password over 1024 bytes now fails, and verifying one fails as
  `InvalidCredentials`.

### Migration

- Exhaustive `match` on `AuthError`: add `PasswordTooLong`. Show it to the user as a
  validation error (code `PASSWORD_TOO_LONG`).
- Full `AuthConfig { .. }` literals: add `password_hashing: PasswordHashingConfig::default()`.
- A user whose existing password is longer than the cap can no longer log in with it.
  Raise `max_password_bytes` (up to 4096) before upgrading if you allowed longer
  passwords, or reset those users.
- To size the pool, build one with
  `PasswordWorkPool::new(PasswordWorkPoolConfig { workers, queued_jobs })?` and pass
  it to `with_password_work_pool` on each service that should share it.
- To raise Argon2 costs, set `config.password_hashing`. After each successful login,
  if `auth.password_hash_needs_rehash(&stored.password_hash)`, store
  `auth.hash_password(password)?`.
- Throttle the password-login route at the edge, per client and globally.

## Interactions for the integrator

- `login` is unchanged (owned by `abuse-controls`). The length cap and the dummy-hash
  parameter substitution live in `verify_password_async_before`, `hash_password*` and
  `verify_password`. `login` still passes `DUMMY_PASSWORD_HASH`, which the verifier maps
  to the configured-parameter dummy. An over-long password reaches login's existing
  `Err(InvalidCredentials)` branches, so whatever counting `abuse-controls` adopts for
  wrong passwords applies.
- Shared files touched: `src/service.rs` (logout, `prepare_rotation`,
  `issue_auth_payload`, `issue_tokens_only` gains a `session_expires_at` parameter,
  new `session_deadline`, `revoke_user_sessions`, password helpers, constructor),
  `src/stores.rs` (`RefreshTokenStore` docs and new method), `src/models.rs` (one
  field), `src/config.rs` (two fields, `PasswordHashingConfig`), `src/errors.rs` (one
  variant), `src/lib.rs` (exports), `src/tests.rs` (memory store method, module list).
- Any `RefreshTokenStore` implementation added on another branch needs
  `revoke_refresh_tokens_for_user`, and any `StoredRefreshToken { .. }` literal needs
  `session_expires_at`.
