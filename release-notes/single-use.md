# Stream `single-use`: release notes for 0.27.0

Covers login challenges, password reset, API tokens, model redaction, principal
references and delegation, and session assurance.

## #27 / AUTH-13: login-challenge verification with an expected principal and channel

`verify_login_challenge_for` takes a `LoginChallengeExpectation` (principal
and/or channel, compared exactly). A challenge created for another principal or
channel fails with `InvalidLoginChallenge`, the same error and side effects as
an unknown challenge ID. The check runs on the first read, before any attempt is
admitted or the code is hashed. The mismatch is therefore no oracle, and nobody
can spend the holder's attempts by submitting the challenge under another
principal. The reserved record is compared field by field with that snapshot,
so atomic admission is unchanged.

This is a new method, not a breaking change. The unbound methods stay correct
for the documented passwordless flow, where the challenge itself fixes the
principal and the host uses `verified.principal`. Breaking them would buy those
hosts nothing and would break every caller, including other streams' new tests.
The docs now steer second-factor and step-up flows to the bound method.

- **Added:** `AuthService::verify_login_challenge_for` and
  `LoginChallengeExpectation` (`for_principal`, `for_channel`, `with_principal`,
  `with_channel`, accessors).
- **Security:** a challenge issued to another principal or channel can be
  refused before it consumes an attempt.

## AUTH-14: password-reset type, sibling invalidation, no store-less issuance

Reset tokens must carry `typ: "password_reset"`; `typ: None` is refused. Issuing
a token invalidates the user's other outstanding reset tokens, and consuming one
invalidates the rest, through a new required store method. Store-less issuance
is now impossible rather than merely documented. An unrecorded token can never
be consumed, so it could only ever pass `authenticate_password_reset_token`,
which is repeatable until expiry. That is exactly the misuse to prevent.
`authenticate_password_reset_token` stays as a validation-only pre-check.

`consume_password_reset_token_with_metadata` carries an
`// INTEGRATION:` comment where it should call the `sessions` stream's new
`AuthService` method that revokes all of a user's refresh families.

- **Security:** reset tokens without the reset `typ` are refused.
- **Security:** only the newest reset token of a user can be consumed, and
  consuming one invalidates the user's other tokens.
- **Breaking:** `issue_password_reset_token` is now `async` and takes the store:
  `issue_password_reset_token(&store, user_id)` (one-hour TTL).
- **Breaking:** `issue_password_reset_token_with_ttl` is removed; use
  `issue_password_reset_token_with_store(&store, user_id, ttl)`.
- **Breaking:** `PasswordResetTokenStore` gains the required method
  `invalidate_password_reset_tokens_for_user(user_id, keep_token_id, invalidated_at) -> AuthResult<u64>`.
  `consume_password_reset_token` must return `false` for invalidated records.

## AUTH-22: redacting `Debug` on model types

`StoredUser` (`password_hash`), `StoredLoginChallenge` (`code_hash`),
`StoredRefreshToken` (`token_hash`), `StoredApiToken` (`token_hash`) and
`IssuedLoginChallenge` (`code`) now use manual `Debug` impls that print
`[redacted]` for those fields. The sweep of every public type found one more
leak: `GraphqlRefreshCookieDirective::Set` printed the raw refresh token. The
carriers that were already redacted (`AuthPayload`, `AccessTokenOnlyGrant`,
`PasswordResetToken`, `IssuedApiToken`, `IssuedPurposeToken`, `TotpSecret`,
`TotpProvisioning`, configs, OIDC/OAuth2 tokens and PKCE values) are pinned by
tests. The private `RawOidcIdTokenClaims` in `oidc.rs` (oidc stream) derives
`Debug` with a nonce; nonces are not secrets after use, so it is left as is.
Serialization is unchanged.

- **Security:** `Debug` no longer prints login codes, code/password/token
  hashes, or the refresh token in a cookie directive.
- **Breaking (minor):** the five types and `GraphqlRefreshCookieDirective` no
  longer *derive* `Debug`. They still implement it, so nothing breaks unless a
  host asserted on the exact `Debug` text.

## AUTH-23 and #38: API-token audience/resource, best-effort touch, bulk revocation

`ApiTokenService::with_expected_audience(aud)` and
`with_expected_resource(type, id)` declare what the service authenticates for.
A token issued for another audience or resource fails as `InvalidApiToken`,
whatever its revocation or expiry state, so a foreign token is simply unknown
here. A service with no declared audience refuses audience-bound tokens,
because it cannot show it is that audience. A service with no declared resource
accepts resource-bound tokens and carries the binding on the principal, as
before. Issuance refuses a blank audience and a half-set resource binding.

`touch_api_token` is best effort: an error no longer fails authentication and
goes to an optional `ApiTokenTouchObserver` (`with_touch_observer`). I chose a
hook over a field on the principal so that the principal stays a pure
authorization value and hosts can alert without inspecting every request.

`revoke_api_tokens_for_principal` / `_for_resource` defaults now return
`AuthError::InvalidConfiguration` instead of `Ok(0)`. They stay provided
methods, so stores without bulk support still compile, but the operation can no
longer silently do nothing.

- **Security:** API-token authentication enforces the stored audience and the
  configured resource.
- **Fixed:** a failed last-used update no longer fails API-token
  authentication.
- **Added:** `ApiTokenService::with_expected_audience`,
  `with_expected_resource`, `with_touch_observer`, the `ApiTokenTouchObserver`
  trait, and a `Debug` impl for `ApiTokenService`.
- **Breaking:** audience-bound tokens are refused unless the service declares
  that audience with `with_expected_audience`.
- **Breaking:** the default bulk revocation methods return
  `InvalidConfiguration` (public code `INVALID_CONFIGURATION`) instead of
  `Ok(0)`.
- **Breaking:** `issue_token` refuses `audience: Some("")`/whitespace and a
  resource type without an ID or the reverse (`InvalidConfiguration`).

## AUTHX-2: resolving a delegation reference is bounded by the delegated token

A `session_bound_delegation` `PrincipalReference` now carries
`grant_ceiling: Option<DelegationGrantCeiling>` (roles, scopes, authorization
roles, `auth_time`), populated by `AuthPrincipal::reference()`.
`ResolvedPrincipal::new` requires it and, for a delegation, returns a delegated
view of the resolved parent rather than the parent itself:

- grants are intersected exactly with the ceiling;
- token ID, actor, resource, operation and correlation come from the reference;
- the grant kind stays delegation, so the view cannot manage the session or
  prepare a further delegation;
- expiry is the earlier of the token's and the parent's;
- the parent's assurance is kept only for the same `auth_time`;
- custom additional claims are dropped.

`principal()` and `into_principal()` therefore never exceed the delegated
token. Matching and `revalidate_sensitive_principal` still use the raw parent
internally. The contradictory `docs/principal-lifecycle.md` text is rewritten.

- **Security:** a job that persists a narrowly delegated token's reference and
  later authorizes with the resolved principal no longer gains the parent
  session's full authority.
- **Added:** `DelegationGrantCeiling`, `PrincipalReference::grant_ceiling`.
- **Breaking:** delegation references without `grant_ceiling` (any persisted
  before 0.27) fail to resolve with `Forbidden`.
- **Breaking:** `ResolvedPrincipal::principal()` for a delegation is the
  narrowed delegated view (delegation grant kind, reduced grants, possibly no
  assurance), not the parent session.

## #41 / AUTHX-12 and the `step_up_session` half of #34: assurance policy edges

`step_up_session` refuses an empty methods list with `InvalidConfiguration`
before rotating. `RecentMfaPolicy` denies accepted MFA that records no method
(`ASSURANCE_METHOD_NOT_ALLOWED`, which the existing tests already pinned for
configured allowlists). It normalizes `allowed_amr` and the new `required_amr`
like session methods, so `"TOTP"` matches; an empty entry is a policy error.
It gains `required_amr` (all-of, always required) and `required_context`
(exact match against `SessionAssurance.context`). The WebSocket
`TokenStatusChecker` sample now shows an authoritative lookup instead of
`Ok(TokenStatus::Active)`.

- **Security:** a step-up without methods no longer satisfies a policy with
  empty allowlists.
- **Fixed:** policy AMR allowlists match case- and whitespace-insensitively,
  like session methods.
- **Added:** `RecentMfaPolicy::required_amr`, `required_context`,
  `RecentMfaPolicy::new(maximum_age)`.
- **Breaking:** `RecentMfaPolicy` struct literals need the two new fields (or
  `..RecentMfaPolicy::new(age)`).
- **Breaking:** `step_up_session` with no methods returns
  `InvalidConfiguration`.

## AUTH-5 follow-up: general session-bound delegation requires an enabled parent

`prepare_session_bound_access_token_only` and
`issue_session_bound_access_token_only` now call
`require_enabled_delegation_parent` on every path, not only the fixed-audience
facade. A missing parent fails with `Forbidden` and a disabled parent with
`UserDisabled`. The facade's duplicate call was removed; it relies on the
owner's check.

- **Security:** a disabled or deleted user can no longer receive a
  session-bound delegated token through the general path.
- **Breaking:** delegation now requires the parent in `UserStore`
  (`find_user_by_id`).

## #38 bullet: store contracts say "must"

`TotpReplayStore::consume_totp_step` must insert the
`(principal_id, factor_id, step)` tuple atomically against a unique constraint
and return `true` only for the inserting call. The docs note that `NULL`
factor IDs do not collide, and give an `INSERT ... ON CONFLICT DO NOTHING`
example. `link_external_identity` must enforce `(provider_name,
external_subject)` uniqueness with a constraint, return `Err` on a concurrent
duplicate, and never re-point a link. `PasswordResetTokenStore` documents its
consume/invalidate statements. `ApiTokenStore` documents best-effort touch and
exact binding persistence.

- **Fixed:** store-trait docs state the required atomicity with example
  statements.

## Migration notes for host applications

- **Password-reset store implementors:** implement
  `invalidate_password_reset_tokens_for_user`. Persist `user_id` from
  `insert_password_reset_token`, add an `invalidated_at` column (or
  equivalent), and make `consume_password_reset_token` return `false` for
  invalidated rows.

  ```sql
  UPDATE password_reset_tokens SET invalidated_at = ?
  WHERE user_id = ? AND (? IS NULL OR id <> ?)
    AND consumed_at IS NULL AND invalidated_at IS NULL;
  ```

  Never return `Ok` without invalidating.
- **Password-reset callers:** replace `issue_password_reset_token(user_id)` /
  `issue_password_reset_token_with_ttl(user_id, ttl)` with
  `issue_password_reset_token(&store, user_id).await` /
  `issue_password_reset_token_with_store(&store, user_id, ttl).await`.
  Validation-only resets are no longer possible. Tokens without
  `typ: "password_reset"` are refused; every token the crate issued already has
  it.
- **API-token services:** if you issue tokens `with_audience(a)`, configure each
  authenticating service with `.with_expected_audience(a)?`, or those tokens
  fail as `InvalidApiToken`. Optionally add `.with_expected_resource(t, id)?`
  for single-resource services and `.with_touch_observer(...)` for monitoring.
  Stop treating a touch error as an authentication failure.
- **API-token store implementors:** if you rely on bulk revocation, override
  both methods. Calls on a store without an override now return
  `InvalidConfiguration` rather than `Ok(0)`. Existing overrides are
  unaffected.
- **Delegation references:** references to `session_bound_delegation`
  principals persisted before 0.27 have no `grant_ceiling` and no longer
  resolve, so re-create them from the delegated principal. Code that read the
  parent's authority from `ResolvedPrincipal::principal()` for a delegation now
  receives the narrowed delegated view. `PrincipalReference` struct literals
  need `grant_ceiling: None` (or a ceiling for delegations).
- **Delegation issuers:** the parent user must exist and be enabled in the
  `UserStore` for `prepare_`/`issue_session_bound_access_token_only`. A host
  whose `UserStore` does not hold delegating users must add them, or delegation
  fails with `Forbidden`.
- **Assurance policies:** add `required_amr: vec![]` and
  `required_context: None` to `RecentMfaPolicy` literals (or build from
  `RecentMfaPolicy::new`). Sessions whose accepted MFA records no method no
  longer satisfy any policy. Policies whose `allowed_amr` used upper case now
  match. An empty `allowed_amr`/`required_amr` entry makes evaluation
  `FORBIDDEN` (`ASSURANCE_POLICY_ERROR`). Callers of `step_up_session` must
  pass at least one method.
- **Exhaustive matches / error codes:** no `AuthError` variants or public
  codes were added or removed.
- **`Debug` output:** the redacted types print `[redacted]` for secret
  fields. Update any snapshot that compared their `Debug` text.
- **TOTP replay and external-identity store implementors:** verify the stated
  atomicity (unique constraint, single statement). The trait signatures are
  unchanged.
