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
- `revoke_refresh_token` is used during logout, expiry, and rotation.
- `revoke_refresh_token_family` is used after replay detection.
- `touch_refresh_token` records use metadata before rotation.

Use a unique index on the refresh-token hash and indexes on session-family IDs
to make revocation efficient.

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

Recommended database constraints:

- unique key on `(provider_name, state_hash)`
- nullable `consumed_at`
- compare expiry before accepting the callback
- update `consumed_at` in the same statement that verifies it is currently null

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
