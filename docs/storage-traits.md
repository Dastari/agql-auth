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
- `revoke_refresh_token_family` is used after replay detection.
- `touch_refresh_token` records use metadata outside refresh rotation.
- `rotate_refresh_token` atomically revokes the current token and inserts the
  replacement during refresh.

`rotate_refresh_token` is required in `0.6.0`. It must return `Ok(true)` only
when the current token exists, is not revoked, is marked used/revoked for
rotation, and the replacement token is inserted in the same transaction. Return
`Ok(false)` if the current token is missing or already revoked. If the
replacement cannot be inserted, return `Err(...)` and leave the current token
unmodified.

SQL-style shape:

```sql
BEGIN;

SELECT id, revoked_at
FROM refresh_tokens
WHERE id = ?
FOR UPDATE;

-- if missing or revoked: ROLLBACK; return false

INSERT INTO refresh_tokens (...) VALUES (...);

UPDATE refresh_tokens
SET revoked_at = ?,
    replaced_by_token_id = ?,
    last_used_at = ?,
    ip_address = ?,
    user_agent = ?
WHERE id = ?
  AND revoked_at IS NULL;

COMMIT;
```

Use a unique index on the refresh-token hash and indexes on session-family IDs
to make revocation efficient.

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

- inserting the challenge and password-hashed code
- reading the challenge by ID
- incrementing failed attempts
- consuming the challenge exactly once

The consume operation should be atomic to reject replayed codes.

## OIDC State

`OAuthStateStore` is required for OIDC authorization-code flows.

`create_authorization_request` stores an `OAuthLoginState` containing the hashed
state, nonce, PKCE verifier, redirect URI, requested scopes, and expiry. The
raw state is returned only to the browser redirect flow.

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
          scopes, created_at, expires_at, NULL AS consumed_at;
```

Recommended database constraints:

- unique key on `(provider_name, state_hash)`
- nullable `consumed_at`
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
