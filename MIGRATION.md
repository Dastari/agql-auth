# Migration Guide

## 0.26.0 to 0.27.0: security hardening

This is a security release and a breaking pre-1.0 minor. Every host must act:
store traits gain required methods and columns, several defaults are stricter, some
public error codes change, and OAuth/OIDC callbacks need a browser-binding cookie.
Access tokens minted by a 0.26 issuer still pass the new validation defaults. There
is no SDL change. Sections below are grouped by who has to act; start with the
checklist.

### Upgrade checklist

Do these in order. Steps 1 to 4 can be done before any 0.27 node runs.

1. **Migrate storage first.** Every new column is nullable, so 0.26 nodes keep
   working against the migrated schema.
   - Refresh tokens: add nullable `session_expires_at`, index `user_id`, and
     implement `revoke_refresh_tokens_for_user`. Optionally add the unique index on
     live family rows (see [Store implementors](#store-implementors)).
   - Password reset: persist `user_id`, add `invalidated_at`, implement
     `invalidate_password_reset_tokens_for_user`.
   - OAuth state: add nullable `browser_binding_hash` and return it from
     `consume_oauth_state`.
   - Optional: a purpose-token replay table if you will call `consume_purpose_token`.
2. **Fix compile errors.** Struct literals, exhaustive matches, removed methods,
   `Drop` types and unit-struct guards; see [API changes](#api-changes).
3. **Check data that the new rules reject.** Before upgrading, find and plan for:
   - TOTP factors with secrets shorter than 16 bytes (they must be re-enrolled);
   - passwords longer than 1024 bytes (raise `max_password_bytes`, up to 4096, or
     reset those users);
   - scope grants that relied on a raw prefix wildcard (`orders*`, `tenant.1*`);
   - issuers using `AccessTokenScopeClaimFormat::LegacyArray`, clients sending raw
     tokens without `Bearer `, and any pre-0.6 issuer still running;
   - persisted `session_bound_delegation` principal references (they stop resolving);
   - API tokens issued `with_audience(..)` (their services must declare it);
   - delegating users or OIDC-provisioned users missing from the `UserStore`.
4. **Check configuration against the new bounds** in a staging start-up;
   `AuthService::new`, provider construction and `create_login_challenge` report
   violations as `InvalidConfiguration`. See
   [Configuration and defaults](#configuration-and-defaults).
5. **Upgrade resource servers and validators before issuers.**
   - 0.26 code cannot deserialize session context carrying `AuthMethod::OAuth2`, so
     every validator and service that reads sessions must run 0.27 before any
     issuer uses `OAuth2Provider::login_with_callback`.
   - Validators can take the stricter defaults at once if clients send `Bearer`,
     no issuer uses `LegacyArray` and no pre-0.6 issuer runs; otherwise apply the
     opt-ins in [Opting back into legacy behaviour](#opting-back-into-legacy-behaviour)
     first and remove them later.
   - Ship the golden scope vectors version `2.0` (`testdata/scope_match_golden.json`)
     to every router or service that implements them in the same deployment step,
     so issuers and resource servers agree on wildcard semantics.
   - Resource servers using `require_cnf` must pass presented certificate or key
     material before upgrading, or every such request fails.
6. **Upgrade issuers (`AuthService` and provider nodes).** While 0.26 and 0.27 nodes
   both serve traffic:
   - OAuth/OIDC flows started on a 0.26 node, or before the cookie step is
     deployed, fail on a 0.27 callback with `INVALID_OAUTH_STATE` and must be
     restarted. States live at most `state_ttl`; deploy the cookie step together
     with the upgrade, or drain in-flight logins.
   - Refresh sessions rotated by a 0.26 node carry no `session_expires_at`; with a
     lifetime configured they end at their own `expires_at` instead of sliding.
   - Password-login counters for known accounts move to a new key, so the old and
     new nodes count separately until the old keys expire (1 hour by default).
   - Purpose tokens minted by 0.26 nodes have no `jti`: they validate but cannot be
     consumed. Switch callers to `consume_purpose_token` only after every issuer
     runs 0.27 and the longest purpose-token TTL has passed.
7. **Update host flows.** Set the browser-binding cookie, call
   `revoke_user_sessions` when disabling a user or changing a password, sign out with
   `logout(token, true)`, declare API-token audiences, add `.allow_delegated()` to
   guards that must admit delegated tokens, use `verify_login_challenge_for` in
   second-factor and step-up flows, run `graphql_refresh_cookie_directive` on error
   responses too, and rehash on login when `password_hash_needs_rehash` says so.
8. **After the fleet is on 0.27**, remove the legacy opt-ins you needed for the
   rollout, and run the new refresh-store conformance races against your adapter.

### Store implementors

**`RefreshTokenStore`**

- New required method `revoke_refresh_tokens_for_user(user_id, revoked_at, reason)
  -> AuthResult<u64>`. Revoke only unrevoked rows of that user and return the count.
  It must not miss a replacement a concurrent rotation commits: serialize it with
  rotation through a per-user lock that rotation also takes, or at `READ COMMITTED`
  repeat the update until a fresh read finds no unrevoked row. SQLite's
  `BEGIN IMMEDIATE` needs neither. There is no default, so a wrapper store must
  forward it.

  A PostgreSQL sketch with `sqlx` (`store_err` and `reason_to_db` are host helpers):

  ```rust
  async fn revoke_refresh_tokens_for_user(
      &self,
      user_id: &str,
      revoked_at: OffsetDateTime,
      reason: RefreshTokenRevocationReason,
  ) -> AuthResult<u64> {
      let mut tx = self.pool.begin().await.map_err(store_err)?;
      let mut revoked = 0;
      loop {
          // At READ COMMITTED each statement sees rows committed before it
          // started, so a replacement the previous UPDATE skipped is found here.
          revoked += sqlx::query(
              "UPDATE refresh_tokens SET revoked_at = $1, revocation_reason = $2
               WHERE user_id = $3 AND revoked_at IS NULL",
          )
          .bind(revoked_at)
          .bind(reason_to_db(&reason))
          .bind(user_id)
          .execute(&mut *tx)
          .await
          .map_err(store_err)?
          .rows_affected();
          let live: Option<i32> = sqlx::query_scalar(
              "SELECT 1 FROM refresh_tokens
               WHERE user_id = $1 AND revoked_at IS NULL LIMIT 1",
          )
          .bind(user_id)
          .fetch_optional(&mut *tx)
          .await
          .map_err(store_err)?;
          if live.is_none() {
              break;
          }
      }
      tx.commit().await.map_err(store_err)?;
      Ok(revoked)
  }
  ```

- New field `StoredRefreshToken::session_expires_at: Option<OffsetDateTime>`.
  Persist it in a nullable column (or the serialized record) and map it both ways;
  rotation copies it unchanged to every replacement. Do not backfill it: `None` on
  existing rows is correct and those sessions end at their current `expires_at`.
  Serialized records omit it when `None` and read without it.
- The concurrency rules that 0.26 stated for reuse-grace adopters now apply to every
  store: serialize `rotate_refresh_token` with `revoke_refresh_token_family` per
  family, decide rotation from the row count of an update-first compare-and-swap,
  and leave an already revoked record unchanged in `revoke_refresh_token`
  (`UPDATE ... WHERE id = ? AND revoked_at IS NULL`). The non-portable
  `SELECT ... FOR UPDATE` sample is replaced; see
  [concurrency rules](docs/storage-traits.md#concurrency-rules) for PostgreSQL,
  SQLite, SQL Server and MySQL. A PostgreSQL store at `READ COMMITTED` without a
  per-family lock (or `SERIALIZABLE`) can leave a token live after sign-out.
- Recommended: a unique index on live family rows. It requires the update-first
  order (revoke the current row before inserting its replacement):

  ```sql
  CREATE UNIQUE INDEX refresh_tokens_one_live_per_family
  ON refresh_tokens (session_family_id)
  WHERE revoked_at IS NULL;
  ```

  MySQL has no partial index; use the generated-column variant in
  [storage traits](docs/storage-traits.md#concurrency-rules).

**`PasswordResetTokenStore`**

- New required method `invalidate_password_reset_tokens_for_user(user_id,
  keep_token_id, invalidated_at) -> AuthResult<u64>`. The service calls it after
  issuing a token (keeping the new one) and after consuming one (keeping none). It
  must invalidate every other unconsumed token of that user or return `Err`; never
  return `Ok` without invalidating.
- Persist the `user_id` passed to `insert_password_reset_token`, add an
  `invalidated_at` column, and make `consume_password_reset_token` return `false` for
  invalidated rows.

  ```sql
  UPDATE password_reset_tokens SET invalidated_at = ?
  WHERE user_id = ? AND (? IS NULL OR id <> ?)
    AND consumed_at IS NULL AND invalidated_at IS NULL;
  ```

**`OAuthStateStore`**

- Persist the new nullable `OAuthLoginState::browser_binding_hash` (64 hex
  characters) unchanged and add it to the `RETURNING` list of `consume_oauth_state`.
  It is `NULL` only for providers configured with
  `OAuthBrowserBinding::NotRequiredHostBindsState`. A store that drops it makes every
  bound callback fail closed with `INVALID_OAUTH_STATE`. Serialized records omit it
  when `None`.

**`PurposeTokenReplayStore` (new, optional)**

- Needed only for `AuthService::consume_purpose_token`. `consume_purpose_token(
  token_id, expires_at)` must insert the id atomically (unique key) and return
  `Ok(true)` only for the first call, `Ok(false)` afterwards, and `Err` when the
  outcome is unknown. Keep rows at least until `expires_at`.

**`ApiTokenStore`**

- The default `revoke_api_tokens_for_principal` and `revoke_api_tokens_for_resource`
  now return `InvalidConfiguration` instead of `Ok(0)`. Stores still compile; if you
  rely on bulk revocation, override both. Existing overrides are unaffected.
- Persist the audience and resource binding exactly; authentication now compares
  them. A `touch_api_token` error no longer fails authentication.

**`AuthRateLimitStore`**

- No trait, key, state or schema change. Adapters now see more writes: a CAS on each
  key before verification, refund CASes that restore an older state or lower
  `attempts`, and `clear_auth_rate_limit_state(key, Some(rev))` on a record created
  moments earlier. Adapters that pass the conformance list need no change; run the
  new refund case in [atomic abuse protection](docs/abuse-protection.md).

**`TotpReplayStore` and `ExternalIdentityStore`**

- Signatures are unchanged, but the docs now state requirements as "must":
  `consume_totp_step` inserts `(principal_id, factor_id, step)` atomically against a
  unique constraint and returns `true` only for the inserting call (`NULL` factor IDs
  do not collide; store a sentinel). `link_external_identity` enforces
  `(provider_name, external_subject)` uniqueness with a constraint, returns `Err` on
  a concurrent duplicate and never re-points a link. Check your adapters.

### Configuration and defaults

| Setting | 0.27 behaviour |
|---|---|
| `AuthConfig::max_session_lifetime` | New, `Some(90 days)`. Bounds a session family from first issuance. |
| `AuthConfig::password_hashing` | New. Argon2id 19456 KiB, 2 iterations, 1 lane (as before); `max_password_bytes` 1024, at most 4096. |
| `AuthConfig::previous_verification_keys` | New, empty. RS256 only, at most 8, no empty, duplicate or current `kid`. |
| `access_token_ttl` | Must not exceed `max_access_token_ttl`. |
| `AccessTokenScopeClaimFormat::LegacyArray` | `AuthService::new` refuses it unless `legacy_scope_claims` is `Accept`. |
| `PurposePolicy::default()` | `RequireAccessToken`, which now also requires `typ = "access"`. |
| `BearerParseMode::default()` | `RequireBearer` for `AccessTokenValidator`. |
| `LegacyScopeClaims::default()` | `Reject`, for the enum, `AuthConfig` and the validator. |
| `KeyRefreshPolicy` | `UseStale` with new `max_stale` (1 hour); keys fail after `cache_ttl + max_stale` without a successful refresh. |
| Static JWKS | Unique `kid` per key in multi-key documents, no `oct` keys, `alg` must match the key type; non-RS256 keys need `allowed_algorithms`. |
| `LoginChallengeOptions` | `code_length` 6 to 12, `max_attempts` 1 to 10. |
| `TotpOptions` | `period_seconds` 15 to 300, `allowed_skew` at most 2; `generate_totp_secret` 20 to 64 bytes. |
| `MemoryAuthRateLimitStore` | Request-initiation flows may hold at most `capacity / 2` entries; capacity 1 rejects every request flow. |
| Password work pool | Process-wide, sized from available parallelism (1 to 8 workers, 16 queued jobs each). |
| `OidcProviderConfig::browser_binding`, `OAuth2ProviderConfig::browser_binding` | `OAuthBrowserBinding::Required`. |
| `discovery_url`, `redirect_uri` | `https://` (loopback `http://` allowed); `redirect_uri` absolute, without `#`. |
| `OidcProviderConfig::issuer` | Optional; required when the discovery URL does not end in `/.well-known/openid-configuration`, compared exactly. |
| `state_ttl` | At most `MAX_OAUTH_STATE_TTL_SECONDS` (3600). |
| `allowed_id_token_algs` | One key family (`RS*`/`PS*`, `ES256`/`ES384` or `EdDSA`); no `HS*`. |
| `private_key_jwt` | `iss == sub == client_id`, lifetime at most 600 seconds; `aud` defaults to the issuer (generic OIDC, or `OAuth2ProviderConfig::issuer` when set). Entra keeps the token endpoint. |
| `OAuth2ProviderConfig::issuer` | Needed if the provider returns RFC 9207 `iss`; a callback `iss` without a configured issuer is refused. |

**Clocks.** The service's session clock now drives issuance, refresh, logout, user
revocation, reset stamps and service-side validation of access, purpose and
password-reset tokens. Set it with `with_session_clock`, or with `with_clock`, which
also sets the login-challenge clock. `with_refresh_rotation_clock` remains as the
former name and now covers all of this: a host that injected a rotation clock (for
example a fixed clock in tests) now also issues and validates with it. The rate-limit
clock is not changed by `with_clock`: it must match the rate-limit store's own clock,
so choose both together with `new_with_rate_limit_store_and_clock` (and
`MemoryAuthRateLimitStore::with_capacity_and_clock`). `ApiTokenService::with_clock`
sets issuance, expiry, touch and revocation time for API tokens. `OidcProvider` checks
ID-token `exp`/`nbf` against its own injected clock with `clock_skew`.

```rust
let clock: Arc<dyn Clock> = Arc::new(SystemClock);
let auth = AuthService::new_with_rate_limit_store_and_clock(
    config, users, sessions, rate_limits, clock.clone(),
)?
.with_clock(clock.clone());
let api_tokens = ApiTokenService::new(api_store).with_clock(clock);
```

### API changes

- `CombinedAuth` and `ApiTokenService` are no longer `UnwindSafe`/`RefUnwindSafe`
  (they now hold `Arc<dyn …>` hooks and clocks, like `AuthService` already did).
  Wrap them in `AssertUnwindSafe` if you pass them across `catch_unwind`.

**Signatures**

- `issue_password_reset_token(&store, user_id).await` (one-hour TTL) is async and
  takes the store. `issue_password_reset_token_with_ttl(user_id, ttl)` is removed;
  use `issue_password_reset_token_with_store(&store, user_id, ttl).await`.
  Validation-only resets are no longer possible; `authenticate_password_reset_token`
  remains a repeatable pre-check only.
- `ApiTokenService::with_expected_audience` and `with_expected_resource` return
  `AuthResult<Self>`.

**Removed or narrowed**

- `OidcAuthorizationRequest::code_verifier` and
  `OAuth2AuthorizationRequest::code_verifier` are removed. The verifier lives only in
  the stored `OAuthLoginState`; never send it to the browser.
- `OidcProvider::exchange_code`, `OAuth2Provider::exchange_code` and
  `OAuth2Provider::fetch_profile` are crate-private. Use `handle_callback` or
  `login_with_callback`. Do not resolve identity from a client-supplied access
  token: it carries no audience proof.

**Struct literals**

| Type | Add |
|---|---|
| `AuthConfig` | `max_session_lifetime`, `password_hashing: PasswordHashingConfig::default()`, `previous_verification_keys: Vec::new()` (or build with `AuthConfig::new(..)` and `..`) |
| `StoredRefreshToken` | `session_expires_at: None` (or the issuance deadline) |
| `KeyRefreshPolicy` | `max_stale` (or `..KeyRefreshPolicy::default()`) |
| `IssuedPurposeToken`, `VerifiedPurposeToken` | `token_id` |
| `PrincipalReference` | `grant_ceiling: None` (a ceiling for delegations; prefer `AuthPrincipal::reference()`) |
| `RecentMfaPolicy` | `required_amr: vec![]`, `required_context: None` (or `..RecentMfaPolicy::new(age)`) |
| `OidcProviderConfig` | `issuer`, `browser_binding` (prefer `OidcProviderConfig::new`) |
| `OidcCallbackInput` | `iss: None`, `browser_binding` (prefer `code_and_state(..)` with `with_browser_binding`/`with_issuer`) |
| `OAuthLoginState` | `browser_binding_hash` |
| `OidcAuthorizationRequest` | `browser_binding`; remove `code_verifier` |

`OAuth2ProviderConfig` and `ClientJwtClaims` are `non_exhaustive` and get the new
fields with defaults.

**Enum variants** (exhaustive matches need arms)

- `AuthError::PasswordTooLong` (`PASSWORD_TOO_LONG`, show as a validation error) and
  `AuthError::PurposeTokenReplayed` (`PURPOSE_TOKEN_REPLAYED`).
- `ClaimRequirementError::ConfirmationMismatch` and `ConfirmationNotPresented`.
- `AuthMethod::OAuth2`.

**Guards.** `RequireAuth` and `RequirePrincipal` are no longer unit structs; write
`RequireAuth::new()` instead of `RequireAuth`.

**`Drop` types.** `OidcProviderConfig`, `OAuth2ProviderConfig`,
`MicrosoftEntraConfig`, `OidcTokenResponse` and `OAuth2TokenResponse` zeroize secrets
on drop, so fields cannot be moved out and `..config` struct update from them is not
allowed. Clone the field or use `std::mem::take(&mut response.access_token)`.

**`Display` and `Debug`.** `AuthError`'s `Display` (`to_string()`, `{err}`, a plain
`?` into `async_graphql::Error`) is now `public_message()`. Log with
`err.diagnostic()` or `{err:?}`, which keep the old text byte for byte, and use
`.extend()` in resolvers to send `extensions.code`. Tests that asserted `Display`
strings should assert `public_code()`. `StoredUser`, `StoredLoginChallenge`,
`StoredRefreshToken`, `StoredApiToken`, `IssuedLoginChallenge` and
`GraphqlRefreshCookieDirective` print `[redacted]` for secret fields; update any
`Debug` snapshot. Serialization is unchanged.

### Behaviour changes

**Public error codes**

| Case | 0.26 | 0.27 |
|---|---|---|
| Password login, disabled account, wrong password | `USER_DISABLED` | `INVALID_CREDENTIALS` |
| Password login, unparsable or non-Argon2 stored hash | `AUTH_SERVICE_UNAVAILABLE` | `INVALID_CREDENTIALS` (after dummy work) |
| Login with a password over `max_password_bytes` | hashed | `INVALID_CREDENTIALS`, counted |
| `hash_password` over `max_password_bytes` | hashed | `PASSWORD_TOO_LONG` |
| Rate-limit store error or full in-memory store during a credential attempt | verified uncounted | `AUTH_SERVICE_UNAVAILABLE` before any secret is checked |
| Out-of-range TOTP options (before the rate-limit check) or challenge options | accepted | `INVALID_CONFIGURATION` |
| TOTP secret shorter than 16 bytes | accepted | `INVALID_TOTP_SECRET` |
| `step_up_session` with no methods | accepted | `INVALID_CONFIGURATION` |
| Accepted MFA that records no method | could satisfy empty allowlists | `ASSURANCE_METHOD_NOT_ALLOWED` |
| Empty `allowed_amr`/`required_amr` entry | | `FORBIDDEN` (`ASSURANCE_POLICY_ERROR`) |
| Raw token without `Bearer ` at `AccessTokenValidator` | accepted | `INVALID_BEARER_TOKEN` |
| Raw token in an `Authorization` value at `AuthService`, `ApiTokenService`, `CombinedAuth` or the `authorization` connection-init key | accepted | `INVALID_BEARER_TOKEN` (`access_token`/`accessToken` init keys still take the bare token) |
| Older sibling reset token after a newer one is issued or one is consumed | consumable | `PASSWORD_RESET_TOKEN_REPLAYED` |
| Purpose token consumed twice via `consume_purpose_token` | | `PURPOSE_TOKEN_REPLAYED` |
| API token for another audience or resource, or audience-bound token at a service without `with_expected_audience` | accepted | `INVALID_API_TOKEN` |
| Default API-token bulk revocation | `Ok(0)` | `INVALID_CONFIGURATION` |
| Delegation reference persisted before 0.27 | resolved to the parent | `FORBIDDEN` |
| Session-bound delegation, parent missing / disabled | issued | `FORBIDDEN` / `USER_DISABLED` |
| OIDC or OAuth 2.0 login, local user disabled / missing | session issued | `USER_DISABLED` / `FORBIDDEN` |
| Callback without, or with a wrong, browser binding | accepted | `INVALID_OAUTH_STATE` (state stays consumed) |
| Callback `iss` mismatch | accepted | `UNAUTHENTICATED` |
| Insecure discovery endpoint or issuer mismatch; negative `expires_in` | accepted | `AUTH_SERVICE_UNAVAILABLE` |

Accounts with corrupt or non-Argon2 hashes are no longer signalled by login; find them
with data checks. Concurrent in-flight attempts on one bucket count toward thresholds
until they resolve, so three or more simultaneous attempts can see a transient
`RATE_LIMITED` that a success then removes.

**Sessions and sign-out**

- Sessions end at most 90 days after login however often they refresh. Each
  replacement expires at the earlier of `refresh_token_ttl` from rotation and the
  recorded deadline. Records without a deadline stop sliding while a lifetime is
  configured.
- `logout(token, false)` with a superseded token revokes the whole family as
  `ReplayDetected`, with or without reuse grace. If a rotation commits during the
  call, the family is revoked as `Logout`. A token revoked for another reason changes
  nothing. Use `logout(token, true)` for sign-out.
- Consuming a password-reset token (`consume_password_reset_token*`) now invalidates
  the user's other reset tokens and calls `revoke_user_sessions(user_id,
  RefreshTokenRevocationReason::AdminRevoked)`. If either step fails, the token stays
  consumed and the error is returned; the user needs a fresh reset. Hosts that
  already revoked sessions after a reset may keep doing so (it revokes nothing more).
- Call `revoke_user_sessions` yourself when disabling a user, after a password
  change and for "sign out everywhere". Issued access tokens stay valid until `exp`.
- `graphql_refresh_cookie_directive` sanitizes every response, including error
  responses, whenever an issuing field is selected and `sanitize_response` is on. Run
  it on error responses too. Clients must select `refreshToken` and
  `refreshTokenExpiresAt` under their schema names, or no cookie is set and the token
  is removed. `Set` is returned for partial errors when the session was issued;
  `Clear` still needs an error-free response. Any 64-character URL-safe base64 string
  in an issuing entry is blanked.

**Credentials and abuse controls**

- Success no longer clears the client bucket; it refunds only its own attempt.
- Known-account password-login counters use a key derived from the user ID; old
  raw-principal counters are ignored and expire by TTL. Client and unknown-principal
  counters carry over. Request flows keep the submitted principal.
- Password-pool saturation refunds the reserved attempt.
- Unknown and disabled users verify a dummy hash under the configured parameters.
  After a successful login, `if auth.password_hash_needs_rehash(&stored.password_hash)`,
  store `auth.hash_password(password)?`. Throttle the login route at the edge.

**Delegation and principals**

- `ResolvedPrincipal::principal()` and `into_principal()` for a delegation return a
  delegated view: grants intersected with the reference's `grant_ceiling`, expiry the
  earlier of token and parent, parent assurance kept only for the same `auth_time`,
  custom claims dropped, and the delegation grant kind (so it cannot manage the
  session or delegate further). Re-create persisted delegation references from the
  delegated principal with `AuthPrincipal::reference()`.
- `prepare_session_bound_access_token_only` and `issue_session_bound_access_token_only`
  require the parent in the
  `UserStore` (`find_user_by_id`) and enabled, as the fixed-audience facade did.
- OIDC provisioners must return a `user_id` that exists in the `AuthService`
  `UserStore`. `OAuth2Provider` hosts should move to `login_with_callback` with an
  `OAuth2UserProvisioner`; hosts keeping `handle_callback` must load the user and
  refuse `disabled` before calling `issue_verified_user_session*`.

**Guards, scopes and claims**

- Every user and principal guard refuses tokens where
  `AccessTokenMetadata::is_delegated()` is true (session-bound delegations and any
  `actor` claim) unless it calls `.allow_delegated()`. API-token principals are
  unaffected.
- `RequireAllRoles`, `RequireAllScopes`, `RequireAllPrincipalScopes` and the
  `has_all_scopes` helpers deny an empty list; build them only from non-empty lists.
- `HierarchicalScopeMatch` treats a trailing wildcard as a whole final segment with
  literally equal prefix segments; a wildcard inside a segment is literal. Rewrite
  `orders*` as `orders.*` and `tenant.1*` as `tenant.1.*`. Hosts with a verified
  role-scope catalogue should build their matcher with
  `catalogue.hierarchical_scope_match(options)` to enforce `exact_only`.
- `require_cnf` (and `tenant_jti_and_cnf()`) needs presented material. Use
  `authenticate_bearer_with_confirmation` or `inject_http_auth_with_confirmation`,
  and `validate_with_confirmation` instead of `validate`.
- `jti` and `nbf` are reserved purpose-token custom-claim names.

**Keys and validation**

- Service-side validation selects the key by header `kid`, including the previous
  verification keys; previous keys never sign. See
  [key rotation](docs/key-rotation.md) for publish, switch, wait and remove.
- A one-key JWKS whose key has a `kid` requires it on tokens; multi-key documents no
  longer need `key_id`. A resolved key verifies only tokens whose header `alg` equals
  its algorithm. `RotatingJwksKeySet` users must refresh periodically
  (`needs_refresh()`). A custom `key_resolver` returning HMAC keys needs
  `accept_hs256(true)`.

**API tokens**

```rust
let api_tokens = ApiTokenService::new(Arc::new(api_token_store))
    .with_expected_audience("graphql-api")?
    // Optional, for a service that serves exactly one resource:
    .with_expected_resource("project", project_id)?
    // Optional: be told when last-used updates fail.
    .with_touch_observer(Arc::new(TouchAlerts));
```

A service with no declared audience refuses audience-bound tokens. A service with no
declared resource still accepts resource-bound tokens and carries the binding on the
principal for the host to enforce. `issue_token` refuses a blank audience and a
half-set resource binding.

**OIDC and OAuth 2.0 browser binding**

At the start route, store `request.browser_binding` in a cookie; at the callback, pass
it back and clear the cookie:

```rust
let request = provider.create_authorization_request(&state_store).await?;
if let Some(binding) = &request.browser_binding {
    let max_age = (request.expires_at - OffsetDateTime::now_utc()).whole_seconds();
    response.headers_mut().append(
        SET_COOKIE,
        format!(
            "__Host-oidc_binding={binding}; Path=/; Secure; HttpOnly; \
             SameSite=Lax; Max-Age={max_age}"
        )
        .parse()?,
    );
}
// redirect to request.authorization_url

// Callback (query mode):
let mut input = OidcCallbackInput::code_and_state(code, state);
if let Some(iss) = query.iss {
    input = input.with_issuer(iss);
}
if let Some(binding) = cookies.get("__Host-oidc_binding") {
    input = input.with_browser_binding(binding);
}
let outcome = provider.handle_callback(&state_store, input).await?;
// clear the cookie: same name, Max-Age=0
```

For `form_post`, use `SameSite=None; Secure; HttpOnly`, or hand off to a same-site
`GET` route before reading the cookie. Use one redirect URI per provider. See
[OIDC form_post and signed client credentials](docs/oidc-form-post-and-client-credentials.md).

**Other provider changes**

- `private_key_jwt`: build claims as `ClientJwtClaims::new(client_id, client_id)`
  with a lifetime of at most ten minutes. Generic-OIDC providers that accept only the
  token endpoint as audience need `.with_audience(token_endpoint)`.
- Profile and ID-token `email`, `name`, `preferred_username` and `picture` values over
  320, 512 or 2048 bytes are treated as absent; an over-long OAuth 2.0 email also
  clears `email_verified`.
- Entra ID tokens must match the signing key's JWKS `issuer` with `{tenantid}`
  replaced by `tid`. `MicrosoftEntraConfig` sets the expected issuer itself.
- `OidcHttpClient` implementations must not follow redirects (any 3xx is `Err`).
- Wire formats: `OAuthLoginState` JSON gains optional `browser_binding_hash`;
  `OidcAuthorizationRequest` drops `code_verifier` and gains optional
  `browser_binding`; `OidcCallbackInput` gains optional `iss` and `browser_binding`;
  session context may carry `"auth_method": "OAuth2"`.

**Login challenges and assurance**

- Second-factor and step-up flows should call `verify_login_challenge_for(store,
  challenge_id, code, &LoginChallengeExpectation::for_principal(principal), metadata)`
  with the principal (and optionally `with_channel`) the challenge was created for.
  A mismatch fails as `INVALID_LOGIN_CHALLENGE` before an attempt is spent. The
  unbound methods remain correct for passwordless login, where the challenge fixes
  the principal.
- `RecentMfaPolicy` normalizes `allowed_amr` and `required_amr` like session methods,
  so `"TOTP"` now matches. `required_amr` is all-of; `required_context` matches
  `SessionAssurance.context` exactly.

### Opting back into legacy behaviour

| Legacy behaviour | Opt-in | Notes |
|---|---|---|
| Raw tokens without `Bearer ` | `.bearer_parse_mode(BearerParseMode::BearerOrRaw)` on the validator; on `AuthService`/`ApiTokenService` call `authenticate_access_token` / `authenticate_token` with the bare token | `CombinedAuth` has no opt-out. WebSocket clients can send the bare token in `access_token`/`accessToken` instead of `authorization`. |
| Pre-0.14 `scopes` array | `.legacy_scope_claims(LegacyScopeClaims::Accept)` on validators and `.with_legacy_scope_claims(LegacyScopeClaims::Accept)` on the issuing `AuthConfig` | Prefer switching the issuer to `Standard` and waiting the maximum access-token TTL. |
| Tokens without `typ`/`purpose` (pre-0.6 issuers) | `.purpose_policy(PurposePolicy::AccessTokenOrLegacy)` on validators | The service's own validation stays strict. |
| Sliding sessions without an absolute limit | `config.max_session_lifetime = None` | Records with a recorded deadline keep it. |
| Passwords longer than 1024 bytes | `config.password_hashing.max_password_bytes` up to `MAX_PASSWORD_BYTES_LIMIT` (4096) | No unbounded option. |
| Unbound OAuth state | `config.browser_binding = OAuthBrowserBinding::NotRequiredHostBindsState` | Only if the host already ties `state` to the browser; a bound state still needs its value. |
| Delegated or actor tokens on default guards | `.allow_delegated()` on that guard | Per resolver. |
| Fail at `cache_ttl` when refresh fails | `stale_policy: StaleKeyPolicy::Reject` | The unbounded stale window has no opt-in; size `max_stale` instead. |
| Old pool size (2 workers, 32 jobs) | `with_password_work_pool(PasswordWorkPool::new(PasswordWorkPoolConfig { workers: 2, queued_jobs: 32 })?)` | Share one pool across services to keep one budget. |
| Generic-OIDC `private_key_jwt` `aud` = token endpoint | `.with_audience(token_endpoint)` on `ClientJwtClaims` | |
| Rotation-only clock | none | Inject a clock suitable for issuance and validation, or leave the default. |

The rest has no opt-out: credential counting and refunds, `USER_DISABLED` only after
the correct password, `AuthError` `Display`, empty-list denial, segment wildcards,
`require_cnf` possession checks, JWKS parsing, delegation narrowing and parent checks,
reset-token `typ` and sibling invalidation, API-token audience checks, external-login
account checks, discovery and `iss` checks, and the challenge, TOTP and OAuth bounds.

## 0.25.0 to 0.26.0: optional refresh reuse grace

No action is required. The new API is additive, with no data, SDL or wire migration,
and hosts that do not opt in see no behavior change. `RefreshTokenStore` gains one
method with a default, so existing implementations compile unchanged and stay strict.

To adopt it, override `RefreshTokenStore::find_live_refresh_tokens_in_family`, meet the
store rules in [Refresh reuse grace](docs/refresh-reuse-grace.md#what-the-store-must-do),
and call `with_refresh_reuse_grace` on the service. A wrapper store must forward the new
method, otherwise the window stays off. The window cost is described in the same guide.

## 0.24.0 to 0.25.0: restricted fixed-audience delegation

No action is required. The new `FixedAudienceDelegation` API is additive, with no
data, SDL or wire migration, and hosts that do not use it see no behavior change.

To adopt it, replace `Arc::new(auth)` at startup with
`auth.into_shared_with_fixed_audience_delegation(audience)?`, give issuance callers
the returned facade, and pin the receiver's validator to that audience. The owner
must sign with RS256, every delegating user must be in its `UserStore`, and purpose
tokens can no longer use the reserved audience on that owner. See
[Restricted fixed-audience delegation](docs/access-token-only.md#restricted-fixed-audience-delegation).

## 0.23.0 to 0.24.0: explicit async-graphql features

This is a breaking transitive build-feature change, requiring a pre-1.0 minor
bump. Auth now uses `async-graphql = { version = "7", default-features = false }`
with no named features. Auth APIs and behavior are unchanged, including UUID/time
domain values, guard decisions, context injection, errors/redaction, request/response
helpers, tokens, refresh rotation, crypto, MFA/OIDC, storage and concurrency.
There is no data, SDL or wire migration.

Hosts that relied on incidental feature unification must request their own
capabilities on the same resolved async-graphql package. For example:

```toml
[dependencies]
# Keep your reviewed agql-auth Git selector; update it to the reviewed 0.24.0 commit.
async-graphql = { version = "7", default-features = false, features = ["graphiql", "playground", "dynamic-schema", "tempfile"] }
```

Select only what the host uses. `tempfile` keeps file-backed multipart upload
content (`UploadValue::content`); without it async-graphql uses bytes-backed
content. Add `email-validator` explicitly if the host uses its email validator.
A host may also choose async-graphql defaults explicitly; this restores its full
default contribution and its dependencies. Extra features remain additive and
do not require an Auth feature. Review the host's complete resolved dependency
graph and third-party notices; a minimal Auth edge cannot remove features
enabled by other consumers. No dependency versions or license grants change.

See [GraphQL feature selection](docs/graphql-features.md) for executable minimal
and additive consumer checks.

## 0.22.1 to 0.23.0: OAuth 2.0 providers, form_post and client credentials

New behavior is opt-in. Existing `OidcProvider` flows keep `response_mode=query`,
`client_secret_post`, the same token request parameters and the same public
error codes. Breaking changes:

1. **`OidcProviderConfig` struct literals.** New public fields
   `response_mode`, `token_endpoint_auth_method` and `client_jwt`. Code that
   builds the struct with a literal must add them; code using
   `OidcProviderConfig::new` or `MicrosoftEntraConfig` is unaffected.
   Serialized configurations without the new fields deserialize to the
   defaults. `client_jwt` is never serialized: give a deserialized configuration
   its signer again before `OidcProvider::new`, which fails closed when
   `private_key_jwt` or `client_secret_basic` lacks a credential.
2. **`OAuthLoginState` struct literals and persistence.** New public field
   `response_mode` (`OAuthResponseMode`). Add it to struct literals
   (`OAuthResponseMode::Query` keeps earlier behavior). JSON-serialized records
   omit it for `query` and old records read as `query`. Column-mapped stores
   must add a `response_mode` column (`query`/`form_post`, default `query`),
   write it on insert and return it from `consume_oauth_state`. A store that
   drops it makes `form_post` callbacks fail closed. `OAuth2Provider` states
   store an empty `nonce`; allow an empty value in that column.
3. **`ValidatedOidcClaims` struct literals.** New public field
   `email_verified: Option<bool>` (serde default `None`). Test doubles that
   construct the struct must add it. Hosts that read `raw["email_verified"]`
   may switch to the typed field.
4. **`AuthError` variants.** `OAuthProviderError`, `OAuthCallback(String)`,
   `OAuthTokenExchange(String)`, `OAuthUserInfo(String)` and
   `OAuthMissingSubject` are new. Exhaustive matches need arms or a wildcard.
   They are produced only by `OAuth2Provider`; `OidcProvider` errors are
   unchanged.
5. **`client_secret` is no longer serialized.** `OidcProviderConfig`,
   `MicrosoftEntraConfig` and the new `OAuth2ProviderConfig` skip
   `client_secret` when serializing, so a serialize/deserialize round trip
   yields `client_secret: None`. Deserializing a document that contains
   `client_secret` still works. Hosts that persisted configurations by
   serializing them must store the secret separately (encrypted) and set it
   after loading. A missing secret makes `client_secret_basic` fail at
   construction and `client_secret_post` send no secret, which the provider
   rejects.
6. **Empty-nonce states.** `OidcProvider` now returns `InvalidOAuthState` for a
   consumed state whose nonce is empty. Stores that round-trip the nonce are
   unaffected; a store that loses the nonce previously failed at ID-token
   validation and now fails earlier.

Non-breaking additions and changes:

- `OidcHttpClient` gains `supports_request_headers`, `get_json_with_headers`
  and `post_form_json_with_headers` with defaults. Defaults delegate when only
  `Accept` is supplied and otherwise fail closed. Implement all three (sending
  every header, never logging them) to use `client_secret_basic` or
  `OAuth2Provider`.
- `OidcProviderConfig` and `MicrosoftEntraConfig` `Debug` output redacts
  `client_secret`.
- Never give an `OidcProvider` and an `OAuth2Provider` the same
  `provider_name`; they share the state and identity namespace.
- `ClientJwtClaims::issued_at_skew` (default 30 s, serde default for older
  documents) backdates `iat`; `exp = iat + lifetime`. The OIDC token request now lists client credentials after
  `code_verifier`; parameter order has no protocol meaning.
- For `form_post`, add a POST callback route that parses the form body into
  `OidcCallbackInput` and calls `handle_callback_in_mode(..,
  OAuthResponseMode::FormPost)`. Read the cross-site POST and SameSite guidance
  in [OIDC form_post and signed client credentials](docs/oidc-form-post-and-client-credentials.md).

No token or stored-session migration is required.

## 0.22.0 to 0.22.1: bounded embedded catalogue signatures

The signed catalogue structural limit is now 2 MiB, exported as
`MAX_ROLE_SCOPE_CATALOGUE_SIGNATURE_BYTES`. Compact JWS carries the complete
catalogue in its payload, so the former 64 KiB limit rejected otherwise legal
host catalogues. The limit remains finite and inclusive. Host transport must
enforce its own finite whole-envelope bound before JSON deserialization; a
signature limit does not bound the repeated clear-text catalogue or HTTP body.
Catalogue counts, references and values, signature verification, exact claims,
issuer, audience and lifetime checks are unchanged. No token or stored-record
migration is required.

## 0.21.3 to 0.22.0: explicit current-session authority

Ordinary-session resolvers may opt into `ResolvedPrincipal::from_current_session`
when authoritative session reconstruction lacks the original access-token jti or
correlation and has a different expiry. Pass the exact original requested
reference separately from the current session principal; never stamp access-token
metadata onto current session state. This constructor requires explicit
`UserSession` grant kinds, matching identity/session/family/tenant/bindings, a
nonempty bounded current security version and both live deadlines. An accepted
version, when present, must match; an absent accepted version is not invented.

`ResolvedPrincipal::new` retains its existing sensitive-operation exact-credential
behavior. Neither path authenticates credentials or proves store reads happened.
Implement authoritative `TokenStatusChecker` for the original token and current
session resolver; errors deny. No wire, stored-record or schema migration is
required. See [the lifecycle contract](docs/principal-lifecycle.md#ordinary-current-session-proof).

## 0.21.2 to 0.21.3: validator clock observation

The additive `AccessTokenValidator::current_time()` returns `time::OffsetDateTime`
from the exact retained validation clock on each call. Transport adapters using
an injected clock should observe this method when comparing/scheduling credential
expiry, rather than silently substituting system time. Handle unsupported target
clock conversions by denying authentication; never fall back to another clock.
This accessor does not authenticate or revalidate account/session status. Existing
constructors, stateless validation and token/store formats are unchanged; no data
migration is required.

## 0.21.1 to 0.21.2: primitive and complete-flow documentation

Documentation-only update; no runtime, public API, token or stored-record
migration is required. The patch version satisfies the source-path release rule
for call-site Rustdoc edits. Audit applications using the low-level helpers
against the [complete secure flows](docs/secure-primitive-flows.md): host-verified
issuance does not verify credentials/current user state, stateless TOTP can
replay, reset validation does not consume, and optional bulk revocation defaults
to `Ok(0)` without revoking anything. Existing primitives and defaults remain
available; choose and implement the complete host workflow deliberately.

## 0.21.0 to 0.21.1: bounded async password work

No public signature, stored record or token migration is required. Async password
login and challenge issuance/verification now await a runtime-neutral worker pool
shared by all service instances in the process: two running jobs and at most 32
queued jobs. Queue saturation, worker initialization/disconnection and execution
failure return `AuthServiceUnavailable`; they do not become bad credentials or
increment credential-failure counters. Handle that operational error as temporary
unavailability. Pool initialization failure makes service construction fail closed.

Cancellation does not remove or refund queued/running CPU work. A login-challenge
reservation committed before executor saturation/cancellation remains charged, as
required by the atomic store contract; obtain another challenge if exhausted.
Unknown/disabled logins still perform fixed dummy verification when admitted.
After successful verification and counter-clear awaits, login re-reads the exact
user ID before creating a session. Deleted/disabled users and changed password
hashes deny; session roles/scopes come from this current record. Queued challenge
verification checks expiry again inside its worker before starting Argon2.
This is a decision-time authoritative read, not atomic fencing with later store
writes; hosts needing atomic revocation/issuance consistency must supply that
transaction or session-version boundary.
The explicit `hash_password`/`verify_password` methods remain synchronous and block
their caller; keep them outside async runtime workers when called directly.

Host request admission, password/code size limits and accepted stored Argon2 cost
parameters remain host policy. This release introduces no arbitrary password-size
or cost cutoff. A bounded job count does not bound the size of one hostile request
or the memory/CPU cost of one accepted hash. No password or hash is logged by the
executor, and no application/store lock is held during password work.

## 0.20.3 to 0.21.0: atomic login-challenge admission

This is a breaking pre-1.0 release. Replace
`LoginChallengeStore::increment_login_challenge_attempts` with the required
`reserve_login_challenge_attempt`. It must atomically check that the challenge
is present, unconsumed, unexpired, and below its cap, increment `attempts`, and
return the resulting snapshot. A read/check/write sequence without locking or
a conditional atomic update is insufficient. No default implementation is
provided. Release the storage lock before returning to password verification.

Rename `StoredLoginChallenge.failed_attempts` to `attempts` in Rust, serialized
records, and storage mappings. The count now includes every admitted guess,
including a correct code and cancelled/interrupted work. `max_attempts` limits
all admitted work, so retries after cancellation can exhaust the challenge.
Never refund an admission, even when its response is lost.

Quiesce old challenge-verification workers, invalidate outstanding challenges,
and deploy the new store/service together. Issue fresh challenges afterward.
Do not run old increment-after-failure verifiers concurrently with new atomic
reservation verifiers; they can bypass each other's caps. There is no implicit
serde alias for the old counter. This does not change access/refresh tokens or
other authentication store contracts.

Challenge IDs and their principal, code hash, timestamps, maximum and channel
are immutable. Reject duplicate insertion and never reuse an ID. Consumption
must atomically require an unconsumed, unexpired record with an admitted attempt.
The final correctly verified reservation can consume when `attempts == max_attempts`.
Exactly one concurrent consumer may succeed; do not recreate missing rows.

`with_login_challenge_clock` sets a trusted issuance/verification clock; stores
must use the same time basis. Its default is system UTC and it is separate from
the existing rate-limit clock. The service checks expiry after password work,
after consumption, and before returning `VerifiedLoginChallenge`. A challenge
consumed just before expiry can remain consumed while verification fails closed;
the caller must obtain a new challenge. See [storage contracts](docs/storage-traits.md#login-challenges).

## 0.20.2 to 0.20.3: time and configuration invariants

Issuer and audience must contain non-whitespace characters. Ordinary access,
custom-grant maximum, and refresh lifetimes must be positive and produce a
representable timestamp. JWT expiry (access, purpose, reset) must fall in a later whole second than
issuance because NumericDate has second precision. Positive fractional TTLs
remain supported when their resulting expiry crosses that boundary. Invalid
configuration or expiry arithmetic returns `InvalidConfiguration`; issuance no
longer panics or deliberately creates expired credentials from negative TTLs.
Use a test-owned signed fixture or validator clock to test expiration.

`max_access_token_ttl` continues to cap access-only/delegated grants; ordinary
refreshable sessions still use the separate `access_token_ttl`. Configure both
according to your application policy. No new universal lifetime cap is imposed.

Access-token `exp`, `iat`, and optional `nbf` must fit `time::OffsetDateTime`.
Previously accepted out-of-range timestamps now return `InvalidAccessToken`,
never a principal whose expiry disappears from metadata. Normal timestamps and
configured leeway retain their semantics. No token/store format changes.

Invalid or overflowing `ReauthorizationPolicy` durations, and non-finite
lifetime fractions, schedule a check immediately. Periodic scheduling still
does not satisfy the immediate checks required for sensitive operations.

## 0.20.1 to 0.20.2: combined bearer validation

No API, persisted-data, or configuration migration is required. `CombinedAuth`
now passes the original header to `AccessTokenAuth::authenticate_bearer`, whose
contract accepts the bearer input according to the validator's configured policy.
Custom implementations must parse the optional Bearer scheme as documented;
they must not rely on the combined injector stripping it. Do not weaken
`BearerParseMode::RequireBearer` to work around the former rejection of valid
headers. Raw JWTs remain rejected when that policy is enabled.

## 0.20.0 to 0.20.1: bounded process-local abuse state

`MemoryAuthRateLimitStore::default()` now holds at most 16,384 live records and
reclaims records at `expires_at <= clock.now()` on every operation. Active
counters/lockouts are never evicted to make room. At capacity, a new distinct key
returns `AuthServiceUnavailable` (safe public code `AUTH_SERVICE_UNAVAILABLE`);
existing keys can still update or clear. Hosts must deny admission on store
errors and must not silently switch to a fresh/unbounded store. Principal/client
buckets remain separate; a safe over-count can persist if one admits before
another fails. Global work/request admission is still a host responsibility.

Use `MemoryAuthRateLimitStore::with_capacity_and_clock` with a nonzero capacity
and the same trusted clock/time basis as the service when customizing either.
The default service and store both use system UTC. An already-expired replacement
is rejected; do not pair a fixed/historical service clock with a system-clock
store. `purge_expired()` permits explicit cleanup during idle periods; ordinary
operations already purge lazily. Clones share state and limits. There is no
background thread, active eviction, or distributed persistence.

No AuthRateLimitStore method or serialized snapshot migration is required.
Durable stores may already delete expired records. Compare conflicts and stale
clears still preserve live versions; expiry reclamation can independently remove
expired records. A bounded expiry index avoids accumulating stale deadlines
when the same counter is updated repeatedly.

## 0.19.2 to 0.20.0: current authority and sensitive operations

Persist the new `StoredRefreshToken.grant_source`, `roles`, and
`authorization_roles` fields in every store insert/read/rotation transaction.
Serialized records missing provenance
load as `RefreshGrantSource::Legacy` and cannot refresh. Reauthenticate those
sessions; do not infer provenance from `auth_method` or bulk-label historical
host/OIDC grants as password grants. Rust struct literals need all three fields.

Password login records `StoredUser` provenance. Each rotation intersects prior
roles/scopes with the current enabled user's roles/scopes. Typed authorization
roles are intersected with the current `AdditionalTokenRolesProvider` result.
Both ceilings narrow monotonically. Removal survives
later rotations even if the user's authority is restored; new permissions need
new authentication. Roles no longer expand during refresh.

All host issuance APIs, including OIDC callbacks and host-verified password
flows, record `Host` provenance. Install `with_refresh_grant_authority` with a
`RefreshGrantAuthority` that reads current durable provider/custom grants,
checks revocation and tenant membership, and returns `CurrentRefreshGrant`.
Without it, refresh returns `Forbidden`; issuance itself remains available.
The returned roles/scopes are intersected with the prior grant, so an external
scope need not exist on StoredUser and an intentionally downscoped grant cannot
widen. Disabled/deleted local users always fail before the host hook.

Access-token signature validation still proves a signed snapshot. Sensitive
operations must call `revalidate_sensitive_principal` at evaluation time using
an authoritative `TokenStatusChecker` and `CurrentPrincipalResolver`. Neither
periodic WebSocket checks nor `AlwaysActiveTokenStatus` meets immediate
revocation requirements. Check account/token/session/family revocation for
user sessions and the opaque token's current record for API principals; reject
unsupported principal kinds or unavailable stores. The resolver must preserve
the exact accepted credential reference (including token ID), reject disabled
or deleted accounts, and supply current authority. This helper narrows roles,
scopes and typed authorization roles while preserving accepted assurance and
all token metadata. Supply `now` from the trusted evaluation clock immediately
before calling; never reuse an old timestamp or cache a successful result.
Existing durable-job resolvers may return a refreshed credential; this sensitive
operation helper instead requires exact accepted credential identity, with the
explicit delegation-parent exception described in the lifecycle guide.
Hosts still enforce audience, purpose, sender confirmation,
resource, operation and tenant bindings using the original accepted principal.
Do not project away these restrictions before policy evaluation.

The refresh decision reads authority before atomic refresh-store rotation. A
completed permission removal visible to that read is reflected in new tokens;
concurrent changes after the read require host transaction/version fencing.
Immediate revalidation observes authority at evaluation, without promising to
undo writes after a later revocation. Do not cache its result across sensitive
operations or subscription events.

## 0.19.1 to 0.19.2: disabled password-login abuse protection

No API, token, store, schema, or configuration migration is required. Disabled
password-login attempts now do one dummy Argon2 verification and record a
credential failure in both available principal/client buckets. This includes
correct passwords and invalid stored hashes. The dummy hash uses the engine's
default Argon2 work parameters, also used for unknown principals; hosts with
custom stored hash parameters should not interpret this as constant-time
equivalence to every enabled-account verification.

Admitted attempts still return `UserDisabled` (`USER_DISABLED` in GraphQL).
Repeated attempts can now activate `AuthThrottled` or `AuthLocked`, including
for other principals sharing the client bucket. Active controls reject before
password work. Failure to persist counters returns the existing safe
`AUTH_SERVICE_UNAVAILABLE` error. A disabled attempt never clears failures or
issues access/refresh authority. Only an admitted enabled correct-password
login conditionally clears the revisions observed before verification, then
issues a session.

Merge and publish through the owner-controlled release process. Consumers
select the reviewed immutable release tag and record its manifest commit,
keeping direct and transitive dependencies on one Cargo source identity;
no dependency exception is required. See
[review and executable evidence](docs/password-login-review.md).

## 0.19.0 to 0.19.1: license declaration

The package now declares MIT licensing and includes `LICENSE`. No source API,
configuration, token, database, role, or stored-scope migration is needed.
Select the same published release tag in direct and transitive consumers to
retain one Cargo source/type universe.

## 0.18.0 to 0.19.0: opt-in super-scopes for exact-only requirements

Existing consumers need no configuration change. The compatibility default
keeps configured super-scopes from satisfying exact-only requirements, while
direct exact grants remain accepted and wildcard-derived matches remain
rejected.

A host that wants its configured super-scopes to apply to exact-only
requirements can enable the policy explicitly:

```rust
let matcher = HierarchicalScopeMatch::new(
    HierarchicalScopeOptions::default()
        .with_super_scopes(["root.admin", "operations.breakglass"])
        .with_allow_super_scopes_for_exact_only(true)
        .with_exact_only_scopes(["payments.credentials.release"]),
)?;
```

Only exact membership in `super_scopes` receives blanket authority. Wildcards,
hierarchical wildcard matches, related strings, and unrelated grants do not
satisfy an exact-only requirement. Disable the option to restore the previous
behavior. No token, database, role, or stored-scope migration is implied.

## 0.17.1 to 0.18.0: typed authorization roles and resilient catalogue policy

Existing issuers and validators need no configuration change. The new
`authorization_roles` claim defaults to an empty set and remains separate from
application `roles`.

An issuer adopting compact grants implements `AdditionalTokenRolesProvider`
and installs it with `AuthService::with_additional_token_roles_provider`. The
provider is called for login and every refreshable-session rotation. It is not
called for sessionless or session-bound delegated tokens. Resource servers
expand `AuthUser::token_claims.authorization_roles`, not application roles.

`StaticRoleScopeExpansion` now rejects unknown identifiers. Remote caches
should request an immediate refresh on that error, preserve their last
signature-verified snapshot when refresh fails, and fail the affected request
if the identifier remains unknown. Use
`RoleScopeCatalogueValidationOptions::default().with_*` to configure the
issuer's maximum signed lifetime and clock leeway independently of local
refresh frequency.

No database migration is implied. Membership storage, catalogue transport,
retry policy, and stale-while-revalidate bounds remain host-owned.

## 0.17.0 to 0.17.1: compact default session context

No API, database, or authorization migration is required. Newly serialized
`SessionContext` documents omit `mfa` when it is the default unsatisfied empty
state and omit `active_scope` when it is absent. Both fields already deserialize
with defaults, so typed consumers remain compatible. Consumers that compare raw
JWT JSON should accept the missing default-valued fields before updating the
issuer. Non-default MFA, assurance, and active-scope evidence remains explicit.

## 0.16.0 to 0.17.0: opt-in role-to-scope expansion

The release adds a provider-neutral expansion contract without changing token
issuance or validation defaults. Existing consumers need no changes.

Hosts adopting compact role grants should publish a bounded
`RoleScopeCatalogue`, verify its signature and binding outside `agql-auth`, and
construct `StaticRoleScopeExpansion` only from that verified snapshot. Union
the returned scopes with direct token scopes through `effective_scopes` before
authorization. A remote cache should implement `RoleScopeExpansionProvider`
and return `RoleScopeExpansionError::Unavailable` when it has no current,
verified snapshot. Unknown roles now fail explicitly so a consumer can refresh
and deny safely.

Roll out resource-server expansion before issuers stop placing expanded scopes
in tokens. Roll back by restoring expanded scope issuance while leaving the
additive provider contract unused. Membership persistence, catalogue URLs,
signing keys, and cache timing remain host-owned.

## 0.15.0 to 0.16.0: exact-only hierarchical requirements

`HierarchicalScopeOptions` adds `exact_only_scopes` and
`exact_only_scope_patterns`. Constructor and default users retain empty
compatibility defaults. The options type is now non-exhaustive: start from
`HierarchicalScopeOptions::default()` and use its `with_*` methods so future
fields do not break consumer construction. `HierarchicalScopeMatch::new` and
`ScopeMatcher::hierarchical` now return a validation `Result`.

To prevent blanket or wildcard grants from satisfying selected sensitive
requirements, provide the host-owned set:

```rust
let matcher = HierarchicalScopeMatch::new(
    HierarchicalScopeOptions::default()
        .with_super_scopes(["platform.admin"])
        .with_exact_only_scopes(["payments.credentials.release"]),
)?;
```

For a required scope in the set, matching stops at exact, case-sensitive grant
equality. All other requirements keep the configured hierarchical behavior.
The crate supplies no names or defaults, and no JWT, database, role, or stored
scope migration is required. Roll back by removing the configured values after
confirming that doing so is acceptable to the host's authorization policy.

Use `exact_only_scope_patterns` when the sensitive requirement contains a
resource identifier that cannot be enumerated. Pattern selection follows the
same configured wildcard grammar but never turns the pattern into a grant. A
bare-wildcard pattern is rejected. Other wildcard-bearing patterns produce a
validation warning that hosts should surface because each can select a whole
requirement subtree.

## 0.14.0 to 0.15.0: existing-session-bound delegation

Existing sessionless calls to `issue_access_token_only` remain valid and keep
their synthetic `sid` semantics. Newly issued sessionless tokens include the
closed `grant_kind = sessionless` claim. Normal refreshable access tokens use
`grant_kind = user_session`. Consumers that deserialize JWTs into exhaustive
wire structs must add the optional `grant_kind`, `session_version`, and
`operation` fields before upgrading issuers.

The session-bound contract is opt-in and requires no schema migration. To
adopt it:

1. Implement `VerifiedActiveUserSessionResolver` against the authoritative
   active-session store. Its read must reject revoked/expired records and load
   the exact subject, session/family/tenant, current session/security version,
   roles, scopes, assurance, and absolute/idle expiry without updating idle
   expiry or interactive last-active time.
2. Install the resolver during trusted startup with
   `with_active_user_session_resolver`.
3. Call `prepare_session_bound_access_token_only` with the initially resolved
   principal and a mandatory `SessionBoundDelegationBinding`, apply TTL or
   optional confirmation/custom claims to the returned opaque request, then
   call `issue_session_bound_access_token_only`. Preparation reads and stamps
   the authoritative version; issuance reads it again.
4. At every protected request, validate normal signature/issuer/audience plus
   the exact actor, resource, correlation, confirmation (when configured),
   operation binding, session version, and current session status. Reject
   delegated credentials from login/session-management endpoints with
   `authenticate_session_management_bearer` or
   `require_session_management_eligible`.

The issuer rechecks after initial resolution, but it cannot make application
store verification and JWT signing one transaction. The signed session version
is therefore mandatory: a revocation/version change after signing is rejected
by the next current-session assurance check.

`AuthConfig` adds `max_session_bound_delegation_ttl`; constructors default it
to 15 minutes. Exhaustive literals must initialize it to a positive value no
greater than `max_access_token_ttl`. `AccessTokenMetadata`,
`ClaimRequirements`, and `PrincipalReference` also have additive public fields.
No refresh-token, session-family, or delegated-session row is created, so no
database migration or backfill is required.

## 0.13.0 to 0.14.0: standard access-token `scope`

Version 0.14 changes newly issued access JWTs from the project-specific
`scopes` string array to the standard OAuth space-delimited `scope` string.
The in-process authorization model does not change: successfully validated
values still become `AuthUser::scopes: Vec<String>`, and guards and scope
matchers operate as before.

### Wire and source compatibility

Before 0.14, an access-token payload contained:

```json
{
  "scopes": ["users.read", "users.write"]
}
```

The 0.14 default is:

```json
{
  "scope": "users.read users.write"
}
```

An empty scope set omits `scope`. Purpose tokens are a separate token type and
continue using their purpose-specific `scopes` array. Opaque API/service
tokens, refresh tokens, stored sessions, and provider tokens are unchanged.

`AuthConfig` now has public `access_token_scope_claim_format` and
`legacy_scope_claims` fields. Constructor and builder users are
source-compatible. Exhaustive `AuthConfig` struct literals must add both
fields, normally as `AccessTokenScopeClaimFormat::Standard` and
`LegacyScopeClaims::Accept` during migration.

### Safe rolling deployment

Do not switch the issuer until every JWT consumer can read `scope`. A safe
order is:

1. Upgrade issuers and validators to 0.14 while temporarily keeping legacy
   issuance:

   ```rust
   use agql_auth::{
       AccessTokenScopeClaimFormat, AuthConfig, LegacyScopeClaims,
   };

   let config = AuthConfig::with_rs256_pem(private_pem, public_pem, key_id)
       .with_access_token_scope_claim_format(
           AccessTokenScopeClaimFormat::LegacyArray,
       )
       .with_legacy_scope_claims(LegacyScopeClaims::Accept);
   ```

2. Upgrade every router, resource server, worker, and other JWT consumer to
   accept the standard `scope` string. A 0.14 `AccessTokenValidator` accepts
   both representations by default.
3. Change issuers to `AccessTokenScopeClaimFormat::Standard`, or remove the
   temporary override to use the default. Keep legacy validation enabled.
4. Wait at least the maximum lifetime of every access token issued before the
   switch, including any configured validation clock skew. Refresh-token TTL
   is not the relevant window because refreshed sessions receive newly issued
   access tokens.
5. Reject legacy claims on the issuer's local validation path and every
   independent resource server:

   ```rust
   let config = config.with_legacy_scope_claims(LegacyScopeClaims::Reject);

   let validator = AccessTokenValidator::builder()
       // issuer, audience, and public-key configuration
       .legacy_scope_claims(LegacyScopeClaims::Reject)
       .build()?;
   ```

`AuthService::new` rejects the incoherent combination of legacy issuance and
legacy rejection. Issuance and validation are separate controls so a rolling
deployment can move forward without accepting new legacy tokens indefinitely.

### Validation behavior

In the default migration mode:

- `scope` alone is accepted;
- `scopes` alone is accepted;
- both claims are accepted only when they describe the same set, regardless
  of order or duplicates; and
- conflicting dual claims are rejected as an invalid access token.

`LegacyScopeClaims::Reject` rejects every token containing `scopes`, including
an empty array or an equivalent dual claim. Standard `scope` uses exactly one
ASCII space as its delimiter. Empty tokens, repeated delimiters, tabs,
newlines, non-ASCII values, quotes, backslashes, control characters, excessive
counts, and oversized values fail closed. The exported constants describe the
enforced count and byte limits.

### Rollback

If a consumer cannot read the standard claim, restore
`AccessTokenScopeClaimFormat::LegacyArray` on issuers and keep
`LegacyScopeClaims::Accept` on every validator. This affects only newly issued
access tokens; there is no storage migration to reverse. Existing standard
tokens continue to validate while legacy acceptance is enabled. Once the
consumer is fixed, repeat the staged switch and expiry window before enabling
strict rejection.

See [Access-token scope claims](docs/access-token-scope-claims.md) for the full
wire contract, security bounds, deployment inventory, and acceptance checks.

## 0.12.0 to 0.13.0: provider-neutral operation assurance

This change is additive and opt-in. Existing calls to
`RecentMfaPolicy::evaluate`, existing session/storage rows, ordinary refresh,
and `step_up_session` continue to behave as before. No database migration is
required.

### Before: route-local policy and message handling

```rust
policy.evaluate(&user, clock.as_ref())?;
// Each resource separately chose how to expose a denial.
```

### After: stable requirement and server-authored evaluation

```rust
let policy_id = AssurancePolicyId::new("interactive.recent-auth")?;
let requirement = AssuranceRequirement::new(policy_id.clone());

let mut policies = AssurancePolicySet::new();
policies.insert(policy_id, policy);

let evaluation = policies.evaluate(&requirement, user.as_ref(), clock.as_ref());
if let Some(code) = evaluation.state.graphql_extension_code() {
    return Err(graphql_error_with_code(code));
}
```

The server evaluation time comes from one read of the injected clock. A
satisfied result carries typed `AuthenticatedAt` and inclusive
`SatisfiedUntil` values. Unknown policy IDs fail closed as `FORBIDDEN`; absent
users are `UNAUTHENTICATED`; assurance failures are `STEP_UP_REQUIRED` with a
detailed `AssuranceDenialCode`.

### Staged adoption

1. Define stable policy IDs and populate an `AssurancePolicySet` beside the
   existing `RecentMfaPolicy` configuration.
2. Expose `SessionAssuranceStatus` only if clients need advisory step-up UX.
   Do not expose `AuthPayload`, token claims, raw provider responses, or stored
   refresh records as status.
3. Convert one protected resource at a time to `AssuranceRequirement` and
   `AssuranceEvaluation`. Keep server-side evaluation immediately before the
   protected work.
4. Map `AssuranceEvaluationState::graphql_extension_code()` into the transport
   error. Retain detailed denial codes for bounded telemetry; stop matching
   human-readable messages.
5. After every protected resource is classified, enable any host-level
   completeness gate. Client manifests remain advisory.

Hosts may continue using provider-neutral evidence including password plus
TOTP, verified OIDC reauthentication, WebAuthn, or a host-defined method and
context. The host still verifies all external evidence before calling
`step_up_session`. Ordinary refresh is never a substitute: it rotates
credentials but preserves the original authentication time and satisfaction
deadline.

### Compatibility and rollback

The new public types do not change default enforcement, serialized session
shape, refresh-store traits, or token claims. Legacy sessions without assurance
still refresh and fail only at an opted-in assurance policy. To roll back,
remove requirement evaluation from the affected resources and restore their
prior direct `RecentMfaPolicy::evaluate` calls; stored sessions and refresh
tokens need no rewrite. During rollback, remove any client expectation that an
advisory status or manifest authorizes execution.

## 0.11.0 to 0.12.0: bound list-valued `acrs` step-up

Use the new typed request only when the host has an exact provider context to
request and a separate local allowlist/mapping for the returned evidence:

```rust
let options = OidcAuthorizationOptions {
    prompt: vec![OidcPrompt::Login],
    max_age: Some(300),
    acr_values: Vec::new(),
    id_token_claims: vec![
        OidcIdTokenClaimRequest::EssentialAuthTime,
        OidcIdTokenClaimRequest::EssentialAcrs {
            value: "c1".to_string(),
        },
    ],
};
let expected = options.validate()?;
```

This produces one standard OIDC `claims` parameter whose ID-token member asks
for essential `auth_time` and essential list-valued `acrs` using the singular
exact `value` form. The callback independently enforces fresh `auth_time` and
requires the validated `acrs` list to contain `c1`. The exact match is returned
as `OidcAuthorizationOutcome.matched_acrs`; the host must still call
`require_bound_policy`, allowlist/map the context, and apply its own endpoint
authorization and current-session rules.

Policies that request `acrs` use stored representation version 2. Existing
version 1 policies remain valid only without the new field, so in-flight 0.11
requests keep their behavior. Legacy/default callbacks and mismatched policies
cannot satisfy a route expecting the version 2 policy. No OAuth state store
trait or schema change is required when the policy is already stored as the
document/JSON representation. Typed relational representations must add the
optional exact `essential_acrs_value` and retain the version.

`OidcIdTokenClaimRequest` has a new enum variant and
`OidcAuthorizationOutcome` has a new public field. Update exhaustive matches
and outcome struct literals. Do not replace this request with `acr_values` or
standard `EssentialAcr`: those represent standard scalar `acr`, not provider
list-valued `acrs`.

Tests prove serialization, binding, validation, and redaction boundaries only.
Live provider challenge behavior, returned evidence, local mapping, endpoint
approval, activation, and revocation remain deployment gates.

## 0.10.0 to 0.11.0: atomic durable rate-limit attempts

Version 0.11 replaces the split rate-limit read/save contract with versioned
compare-and-swap. This prevents concurrent service instances from reading
attempt count `n` and both replacing it with `n + 1`.

### Store API migration

`find_auth_rate_limit_state` now returns
`Option<AuthRateLimitSnapshot>`. Replace `save_auth_rate_limit_state` with
`compare_exchange_auth_rate_limit_state`, and make clear conditional:

```rust
async fn compare_exchange_auth_rate_limit_state(
    &self,
    key: &AuthRateLimitKey,
    expected_revision: Option<Uuid>,
    replacement: AuthRateLimitSnapshot,
) -> AuthResult<bool>;

async fn clear_auth_rate_limit_state(
    &self,
    key: &AuthRateLimitKey,
    expected_revision: Option<Uuid>,
) -> AuthResult<bool>;
```

With no expected revision, compare-exchange succeeds only for an absent key.
With a revision, it succeeds only for an exact match. Conflict returns
`Ok(false)` without mutation. Conditional clear follows the same rule. The
service generates a fresh UUID for every replacement, recomputes the state
transition after conflict, and never falls back to split replacement.

`AuthRateLimitState` itself is unchanged. Durable stores need a UUID revision
column or equivalent value stored atomically beside it. Backfill every existing
row with a distinct revision before deploying the 0.11 writer. JSON/document
stores may wrap the existing state as:

```json
{
  "state": { "existing": "AuthRateLimitState fields" },
  "revision": "one unique UUID per committed version"
}
```

For SQLite, use a write transaction or conditional insert/update that tests the
stored revision; the unique full key resolves first-insert races. For
PostgreSQL, use `SELECT ... FOR UPDATE`, a conditional update, or an upsert
whose update predicate matches the expected revision. Clear must delete only
the matching revision. Do not implement compare-exchange as a read followed by
an unconditional upsert.

### Service and clock behavior

Existing `AuthService::new` and `new_with_rate_limit_store` remain available
and use `SystemClock`. Deterministic tests can use:

```rust
let auth = AuthService::new_with_rate_limit_store_and_clock(
    config,
    user_store,
    refresh_store,
    rate_limit_store,
    Arc::new(FixedClock::new(now)),
)?;
```

Password-reset and login-code request admission is now linearized with its
per-key attempt write. The attempt that first activates backoff remains allowed,
matching 0.10 behavior; later concurrent requests are denied. Credential
failures always record through CAS, including failures that began before a
concurrent attempt activated lockout.

A successful credential flow receives an internal observation permit before
verification and clears only unchanged revisions afterward. If a newer failure
commits meanwhile, conditional clear returns a conflict and the newer failure
remains. Expired-state cleanup is no longer an unconditional service delete;
the next attempt resets it through CAS, and stores may delete expired rows with
their normal conditional/background cleanup.

Atomicity is per full `AuthRateLimitKey`. Principal and client buckets are
evaluated independently and are not committed as one cross-key transaction.
Store failures retain the existing safe `AUTH_SERVICE_UNAVAILABLE` public
category; backend details remain available only through internal errors.

Memory-store-only consumers need no data migration, but custom trait
implementations must update before compiling. See
[atomic abuse protection](docs/abuse-protection.md) for backend and conformance
guidance.

## 0.9.0 to 0.10.0: bound OIDC reauthentication

Existing calls to `create_authorization_request` retain their standard PKCE,
nonce, state, scope, redirect, response-type, and response-mode behavior. They
create no bound policy. Use `create_authorization_request_with_options` only for
flows that need provider-enforced recent authentication or exact standard ACR
evidence.

```rust
use agql_auth::{
    OidcAuthorizationOptions, OidcIdTokenClaimRequest, OidcPrompt,
};

let options = OidcAuthorizationOptions {
    prompt: vec![OidcPrompt::Login],
    max_age: Some(300),
    acr_values: Vec::new(),
    id_token_claims: vec![OidcIdTokenClaimRequest::EssentialAuthTime],
};
let expected = options.validate()?;
let request = provider
    .create_authorization_request_with_options(&oauth_state_store, options)
    .await?;

// At the dedicated reauthentication callback endpoint:
let outcome = provider
    .handle_callback(&oauth_state_store, callback_input)
    .await?;
outcome.authorization.require_bound_policy(&expected)?;
```

`max_age` and essential `auth_time` cause callback validation to require a
numeric signed `auth_time`. Exact max age plus configured clock skew is allowed;
one second older is denied. Future skew uses the same inclusive rule. Use
`OidcProvider::new_with_clock` for deterministic host tests.

### OAuth state storage

`OAuthLoginState` adds
`authorization_policy: Option<OidcAuthorizationPolicy>`. The
`OAuthStateStore` trait methods are unchanged. JSON/document records missing the
field deserialize as `None`; a legacy in-flight login remains a normal login and
must not be accepted by an endpoint that calls `require_bound_policy`.

Relational stores should deploy a nullable JSON/typed column reader before
enabling typed request writers:

```sql
ALTER TABLE oauth_states
    ADD COLUMN authorization_policy JSON NULL;
```

Atomic consume queries must return the optional policy with the same
pre-consumption state snapshot. Implementations constructing public records
must add `authorization_policy: None`. Unknown/corrupt versions fail closed.

### Public struct and error changes

- `OidcAuthorizationRequest.authorization_policy`
- `OAuthLoginState.authorization_policy`
- `ValidatedOidcClaims.acrs`
- `OidcLoginResult.authorization`
- `AuthError::InvalidOidcAuthorizationOptions`

These additions can require changes to exhaustive matches and struct literals,
which is why this is `0.10.0` rather than a patch release.

Do not map `prompt=login`, `max_age`, `auth_time`, provider kind, standard
scalar `acr`, or provider `acrs` to MFA implicitly. Entra `acrs` ID-token
behavior requires a separately configured and proven provider contract. See
[bound OIDC reauthentication](docs/oidc-step-up.md) for the full trust boundary,
provider limitations, and long-lived-operation guidance.

## 0.8.1 to 0.9.0: durable principal lifecycle primitives

No existing call-site, database, token, session, or serialized-record migration
is required. Version 0.9.0 adds opt-in APIs for disconnected or long-lived work.

Persist `AuthPrincipal::reference()` instead of a bearer token or a cloned
roles/scopes snapshot. Implement `CurrentPrincipalResolver` in the host using
its authoritative session/token and membership stores. Before every protected
operation, resolve the reference and use only the roles, scopes, assurance, and
status on the returned `ResolvedPrincipal`.

`PrincipalReference` and `PurposeBoundGrantReference` are identifiers and
bindings, not authorization proofs. Resolver authorization remains mandatory,
and implementations must fail closed when current authority cannot be loaded.

`AuthorizationDecision` is structurally unchanged. Calling
`with_invocation(...)` now produces a `LinkedAuthorizationDecision` wrapper so
hosts can correlate authorization and application audits without changing the
actor or granting authority.

## 0.8.0 to 0.8.1: omitted optional JWT claims

No source, configuration, or storage migration is required. `0.8.1` changes
only locally issued JWT serialization: unset optional top-level claims are
omitted instead of encoded as JSON `null`.

Hosts should not manufacture an `nbf` value to work around the `0.8.0` output.
When no not-before constraint is intended, the standards-conforming payload has
no `nbf` member. When `nbf` is present, it remains a NumericDate and existing
injected-clock/leeway validation applies unchanged.

Existing short-lived `0.8.0` tokens may continue to decode in compatible
consumers, but strict resource servers can reject their `"nbf": null` member.
Upgrade the issuer to `0.8.1` and let those tokens expire normally; no refresh
record or key migration is needed.

## 0.7 to 0.8: session assurance continuity

`0.8` adds authoritative session assurance without changing the
`RefreshTokenStore` trait methods. Existing issuance methods remain available
and issue no authoritative assurance unless the supplied `SessionContext`
contains one.

### Host code

Replace ad hoc MFA booleans or access-token-only claim plumbing with:

```rust
use agql_auth::{
    AuthMethod, MfaAcceptance, RefreshableTokenMetadata, SessionAssurance,
};

let assurance = SessionAssurance::new(
    verified_authentication_time,
    ["pwd", "otp"],
    Some(host_accepted_acr),
    Some("my-provider-policy-v1".to_string()),
    MfaAcceptance::Satisfied,
)?;

let payload = auth
    .issue_assured_user_session(
        user_id,
        roles,
        scopes,
        AuthMethod::Oidc,
        assurance,
        RefreshableTokenMetadata::default(),
        client_metadata,
    )
    .await?;
```

For OIDC, read `ValidatedOidcClaims.auth_time`, `.amr`, and `.acr` inside your
`ClaimsMapper`. Return `MappedClaims { assurance: Some(...) }` only after local
policy accepts the provider values. A missing value, `NoopClaimsMapper`, and
`MicrosoftClaimsMapper` all leave MFA unsatisfied.

### Refresh storage migration

`StoredRefreshToken` adds `refreshable_metadata: Option<RefreshableTokenMetadata>`.
`SessionContext`, already stored in the refresh record, adds optional
`assurance`. JSON/document stores can deploy the new reader first: both fields
use Serde defaults and missing values become `None`.

For relational stores, add nullable JSON columns (or equivalent typed columns):

```sql
ALTER TABLE refresh_tokens
    ADD COLUMN refreshable_metadata JSON NULL;

-- If session context is decomposed rather than stored as JSON, also add
-- nullable assurance timestamp, AMR, ACR, context, and MFA-acceptance fields.
```

Do not backfill old rows with the migration time. Leave assurance `NULL`.
Legacy sessions continue refreshing normally, but an opted-in
`RecentMfaPolicy` denies them until a genuine step-up occurs.

The store trait signatures did not change. Implementations that construct
`StoredRefreshToken` literals must add `refreshable_metadata: None`. This public
record and `MappedClaims`/`ValidatedOidcClaims` field addition is the reason for
the `0.7` to `0.8` SemVer bump.

### Refresh metadata decision

Only tenant ID, organization ID, actor, and correlation ID are refreshable.
Assurance is sourced from `SessionContext.assurance`. A new `jti`, expiry, and
purpose are generated for every access token. `cnf`, resource type/ID, and
arbitrary additional claims are not propagated because their validity may be
specific to one sender, resource, or token.

### Recent-MFA guard

```rust
use agql_auth::{AssuranceMatchMode, RecentMfaPolicy};
use time::Duration;

let policy = RecentMfaPolicy {
    maximum_age: Duration::minutes(10),
    clock_skew: Duration::seconds(30),
    allowed_amr: vec!["otp".into(), "hwk".into()],
    allowed_acr: vec!["urn:example:loa:2".into()],
    match_mode: AssuranceMatchMode::Any,
};

policy.evaluate(&authenticated_user, &clock).map_err(|denial| {
    // Return denial.code().as_str() and denial.public_message() to the client.
    // Send denial.internal_detail() only to protected server diagnostics.
    denial
})?;
```

At the exact maximum-age or future-skew boundary, the policy allows. One second
beyond either boundary denies. Missing/inconsistent claims and checked-time
overflow deny safely.

See [session assurance](docs/session-assurance.md) for trust boundaries,
step-up, and long-lived connection guidance.

## 0.6 to 0.7

Upgrade recipe:

1. Upgrade the `agql-auth` pin to `0.7`.
2. Run `cargo build`.
3. Fix each compile error against the old-to-new table below.
4. Run your auth and authorization tests.
5. If you opt into hierarchical matching, run the golden vectors in this file
   against your host scope catalog.

## Compatibility Posture

`0.7` is a deliberate resource-server and authorization release. The default
runtime behavior remains exact scope matching. Hierarchical matching,
super-scopes, access-token-only grants, combined JWT/API-token injection, and
channel guards are opt-in APIs.

## Breaking-Change Classification

| Area | Classification | Default behavior |
|------|----------------|------------------|
| Existing `AuthService` construction | No structural break | unchanged |
| Existing `AuthUser::has_scope` helpers | No behavioral break | exact matching |
| Existing `RequireScope` guards without `AuthRuntime` | No behavioral break | exact matching |
| Previous MFA Rust enum type name | Structural/API break | rename to `MfaFactor`; serialized claims unchanged |
| `AuthUser` struct construction | Structural/API break | add `token_claims: Default::default()` |
| GraphQL `ErrorExtensions` message text | Behavioral hardening | safe public message only; use `public_code()` |
| Access-token-only / custom access TTL | Behavioral bound | must be `<= AuthConfig::max_access_token_ttl` (24h default) |
| Hierarchical bare `*` wildcard | Behavioral opt-in | deny unless `allow_universal_wildcard = true` |
| `AccessTokenValidator` HS256 validation | Behavioral guard on new API | rejected unless `accept_hs256(true)` |
| `HierarchicalScopeMatch` | Behavioral opt-in | not used unless configured; exact remains default |
| `super_scopes` | Behavioral opt-in | empty by default |
| `CombinedAuth` token order | Behavioral opt-in | JWT-shaped first; expired JWT never falls back |
| `ChannelIdentity` / WebSocket reauth hooks | Additive | host-owned channel verify + optional status checks |

No product scope names, tenant IDs, cookie policy, HTTP routing, SQL, or
certificate parsing is introduced by this release.

## Old To New API Table

| 0.6 pattern | 0.7 replacement |
|-------------|-----------------|
| Previous MFA `Totp` enum path | `MfaFactor::Totp` |
| Construct `AuthService` in every resource server only to validate JWTs | `AccessTokenValidator::builder()` |
| Share HS256 secret with resource servers | Prefer `rs256_public_pem` or `jwks_json`; use `accept_hs256(true)` only deliberately |
| Manually decode access-token claims with `jsonwebtoken` | `AccessTokenValidator::authenticate_bearer` |
| Manually inject a user JWT or API token on one endpoint | `CombinedAuth::new(&validator_or_auth, &api_tokens).inject_http_auth(...)` |
| Exact-only guard semantics | unchanged by default |
| Host-specific wildcard checks in resolvers | `HierarchicalScopeMatch` plus `AuthRuntime` |
| Issue session then revoke/ignore refresh token for short-lived grants | `AuthService::issue_access_token_only` |
| Ad-hoc channel metadata in request data | `ChannelIdentity` plus `RequireChannelScheme` |

## Before And After: MFA Type Rename

After:

```rust
use agql_auth::MfaFactor;

let methods = vec![MfaFactor::Totp];
```

Only the Rust type name changed. The `SessionContext` JSON claim still uses the
same `mfa.methods` field and `Totp` variant value.

## Before And After: Resource Server Validation

Before, resource servers often needed issuer stores or hand-rolled JWT decode:

```rust
let user = auth_service.authenticate_bearer(authorization_header)?;
```

After:

```rust
use agql_auth::AccessTokenValidator;

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .rs256_public_pem(public_key_pem)
    .key_id("auth-key-2026-07")
    .build()?;

let user = validator.authenticate_bearer(authorization_header)?;
```

## Before And After: Combined User Or API Token

Before:

```rust
let request = auth.inject_http_auth(request, authorization_header).await?;
let request = api_tokens
    .inject_http_auth(request, authorization_header, metadata)
    .await?;
```

After:

```rust
use agql_auth::CombinedAuth;

let request = CombinedAuth::new(&validator, &api_tokens)
    .inject_http_auth(request, authorization_header, metadata)
    .await?;
```

Use `RequirePrincipalScope` and `principal_from_ctx` for resolvers that accept
either credential type.

## Before And After: Access-Token-Only Grant

Before:

```rust
let payload = auth
    .issue_session_for_user_with_scopes(user_id, roles, scopes, session, metadata)
    .await?;
auth.logout(&payload.refresh_token, true).await?;
```

After:

```rust
use agql_auth::AccessTokenOnlyRequest;
use time::Duration;

let grant = auth
    .issue_access_token_only(
        AccessTokenOnlyRequest::new(user_id, roles, scopes, session)
            .with_ttl(Duration::minutes(30)),
    )
    .await?;
```

This path never writes a refresh-token row. TTL must be positive and not exceed
`AuthConfig::max_access_token_ttl` (default 24 hours). Issued tokens include a
unique `jti` and `purpose = access_token`.

## Hierarchical Scope Matching

Exact matching remains the default:

```rust
assert!(user.has_scope("orders.read"));
assert!(!user.has_scope("orders.*"));
```

Opt in explicitly:

```rust
use std::sync::Arc;
use agql_auth::{HierarchicalScopeMatch, HierarchicalScopeOptions};

let matcher = Arc::new(HierarchicalScopeMatch::new(
    HierarchicalScopeOptions::default().with_super_scopes(["platform.admin"]),
)?);

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .rs256_public_pem(public_key_pem)
    .scope_matcher(matcher)
    .build()?;
```

### Golden Vectors

Canonical vectors are published in
[`testdata/scope_match_golden.json`](testdata/scope_match_golden.json).

| # | Granted | Required | Expected |
|---|---------|----------|----------|
| 1 | `a.b.c.d` | `a.b.c.d` | allow |
| 2 | `a.b.c.read` | `a.b.c.write` | deny |
| 3 | `a.b.*` | `a.b.c` | allow |
| 4 | `a.b.*` | `a.b.c.d` | allow |
| 5 | `a.b.*` | `a.bc.d` | deny |
| 6 | `a.b.*` | `a.b` | deny |
| 7 | `*` | `anything.at.all` | deny (default) |
| 8 | `a.b*` | `a.bc` | allow |
| 9 | `a.*.d` | `a.c.d` | allow |
| 10 | `a.*.d` | `a.c.x.d` | deny |
| 11 | `a.*.d` | `a.d` | deny |
| 12 | `a.b.*.read` | `a.b.c.write` | deny |
| 13 | `a.b.*.read` | `a.b.c.read` | allow |
| 14 | `a.b.*` | `a.b.*` | allow |
| 15 | `a.b.*` | `a.b.*.read` | allow |
| 16 | `x.*` | `y.b.c` | deny |
| 17 | `a.b.c.read` | `a.*.c.read` | deny |
| 18 | `a.b.c.d` | `a.b.c.d.e` | deny |
| 19 | empty granted set | `a.b.c` | deny |
| 20 | `a.b.c.read` | `a.b.c.read.extra` | deny |

Bare `*` is denied unless `allow_universal_wildcard = true`. Super-scopes remain
empty unless configured.

## Public GraphQL Errors

Before:

```text
message included OIDC/store internal detail strings
```

After:

```rust
assert_eq!(err.public_code(), "AUTH_SERVICE_UNAVAILABLE");
assert_eq!(err.public_message(), "authentication service unavailable");
// GraphQL ErrorExtensions uses only public_message + code
```

## AuthUser Construction

Add the new field (or rely on struct update / default in tests):

```rust
AuthUser {
    user_id,
    session_id,
    roles,
    scopes,
    session,
    token_claims: Default::default(),
}
```

## Access-Token-Only TTL Bound

Custom TTLs must be `<= AuthConfig::max_access_token_ttl` (default 24 hours).

## Channel Identity

`ChannelIdentity` is a bag for host-verified channel data:

```rust
use agql_auth::{ChannelIdentity, RequireChannelScheme};

let request = request.data(ChannelIdentity::new("mtls", "device-1"));

#[Object]
impl Mutation {
    #[graphql(guard = "RequireChannelScheme::new(\"mtls\")")]
    async fn device_action(&self) -> bool {
        true
    }
}
```

The host owns all channel verification.

## WebSocket Reauthorization Expectations

`0.7` does not take over your subscription transport. Hosts should:

1. Authenticate `connection_init` with
   `AccessTokenValidator::authenticate_connection_init_value` (or
   `AuthService::authenticate_connection_init_value`).
2. Treat missing connection-init credentials as unauthenticated and invalid
   tokens as fail-closed (never as anonymous).
3. Optionally implement `TokenStatusChecker` for session/`jti`/principal
   revocation on high-risk operations or periodic checks.
4. Use `ReauthorizationPolicy::next_deadline` with
   `AuthUser.token_claims.expires_at` to schedule reauthorization.
5. Keep the default failure mode fail-closed
   (`StatusCheckFailureMode::FailClosed`).

See [WebSocket reauthorization](docs/websocket-reauthorization.md).
