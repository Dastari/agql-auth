# Authentication Primitives And Complete Host Flows

Low-level helpers are independently usable building blocks. A successful return
proves only the contract below, not a complete browser login, MFA enrollment,
password change, authorization policy or global revocation. Host-specific calls
in the snippets are explicitly application-owned interfaces, not `agql-auth` APIs.

| Primitive | What succeeds | What the host must still establish |
| --- | --- | --- |
| `issue_verified_user_session*`, `issue_session_for_user*`, `issue_assured_user_session` | Sign/persist the supplied host-accepted local grant; validate supported structure | Actual credential/evidence verification, current enabled identity, authorized roles/scopes/assurance, channel/session binding, refresh authority |
| `issue_access_token_only` | Issue a bounded sessionless JWT without a refresh row | Verified subject/grants, resource/sender/operation enforcement; no active browser session is created |
| `verify_totp_code` | Code matches the supplied secret and trusted time window | Factor ownership, attempt limits, replay consumption, enrollment/session/MFA state |
| `verify_totp_code_for_principal` | Matching code plus configured principal/client abuse controls | Replay consumption, factor ownership and resulting session/MFA state |
| `verify_totp_code_with_replay_store_and_metadata` | Matching code, configured abuse controls, atomic first use of the stored step | Correct factor/secret/session binding, durable shared replay store, accepted MFA policy and state transition |
| `authenticate_password_reset_token` | Valid signed claims, purpose and expiry at validation | Store lookup/one-time consumption, attempt admission, current account, password update and revocation |
| Optional `ApiTokenStore::revoke_api_tokens_for_*` | Adapter-specific bulk action; default returns `Ok(0)` without changes | Known supported override, authorized target, durable completion and online checks for already accepted principals |

## Bound challenge to current user session

Use the principal from the consumed immutable challenge, rather than a separate
client-selected user ID. Read current user state and grants, then call the
trusted-host issuer. The same sequence is compile-checked in the Rustdoc for
`AuthService::issue_verified_user_session_with_scopes`.

```rust
let verified = auth.verify_login_challenge_with_metadata(
    &challenge_store, challenge_id, submitted_code, metadata.clone(),
).await?;
let user = users.find_user_by_principal(&verified.principal).await?
    .ok_or(AuthError::InvalidCredentials)?;
if user.disabled { return Err(AuthError::UserDisabled); }
let payload = auth.issue_verified_user_session_with_scopes(
    user.id, user.roles, user.scopes, AuthMethod::EmailCode, metadata,
).await?;
```

Before issuing/delivering the challenge, the host applies request admission,
normalization, delivery and anti-enumeration policy. Configure
`with_refresh_grant_authority` before using host-issued refreshable sessions;
refresh must read current host authority and never widen the original grant.
An auth-method label alone does not prove MFA. Failure after consumption requires
a fresh challenge. Hosts own cookies, CSRF/channel binding and browser session
handling. This sequence observes authority at its reads; use host transaction or
session-version fencing if a concurrent disable/grant change must atomically
prevent later issuance. See [challenge/recovery flows](recovery-mfa-and-challenges.md)
and [session assurance](session-assurance.md).

## TOTP step-up bound to the existing session

The `host.*` operations below must authenticate the current session, load a
confirmed factor owned by that principal, and check that the submitted refresh
token belongs to that exact session. None is implied by successful TOTP math.

```rust
let session = host.require_current_authenticated_session().await?;
let factor = host.load_confirmed_factor_for_session(&session).await?;
host.require_refresh_token_for_exact_session(&session, refresh_token).await?;
auth.verify_totp_code_with_replay_store_and_metadata(
    &replay_store, &session.user_id, Some(&factor.id), &factor.secret,
    submitted_code, factor.options, clock.now(), metadata.clone(),
).await?;
let accepted_step_up = host.accept_mfa_for_exact_session(&session, &factor).await?;
let payload = auth.step_up_session(
    refresh_token, accepted_step_up, metadata, &clock,
).await?;
```

`accepted_step_up` is a genuine host decision containing the accepted methods,
ACR/context, not a client-provided flag. `step_up_session` rotates the selected
refresh token and records the trusted clock time; replay consumption alone does
not change assurance. Use a shared atomic replay store and configured durable
rate limits across workers. Enrollment remains a separate authenticated,
confirmed host workflow; protect pending and enrolled secrets. A failure after
step consumption can require a fresh code. See [MFA recovery](recovery-mfa-and-challenges.md#totp)
and [step-up semantics](session-assurance.md#step-up).

## One-time reset through password update and revocation

Request initiation first uses `should_process_password_reset_request`; preserve
silent-success behavior and send nothing on `Ok(false)`. Persist issuance with
`issue_password_reset_token_with_store`. At completion:

```rust
host.enforce_new_password_policy(new_password)?;
let verified = auth.consume_password_reset_token_with_metadata(
    &reset_store, submitted_token, metadata,
).await?;
// Only an admitted, consumed reset reaches expensive password work.
// Host-owned bounded CPU worker; the explicit auth.hash_password helper blocks.
let new_hash = host.hash_password_with_bounded_worker(new_password).await?;
host.apply_password_reset_and_required_revocations(
    &verified.user_id, verified.expires_at, new_hash,
).await?;
```

The final host operation must check current account/expiry and implement the
password write plus required session/refresh/API-token revocation policy using
its transaction or fencing boundary. The token consume does not perform those
writes or clear already accepted JWTs. If a later write fails, the token may
already be consumed: fail closed and provide a fresh reset/recovery path, not a
validation-only retry. Transport/CSRF controls and session status checks remain
host responsibilities. See [password reset](recovery-mfa-and-challenges.md#password-reset)
and [store contracts](storage-traits.md#password-reset).

## Bulk revocation with an explicit adapter capability

Both optional API-token bulk methods default to `Ok(0)`. Zero cannot distinguish
an unsupported no-op from a supported operation with no matching active tokens.
Require a known implemented, tested durable adapter before exposing “revoke all”:

```rust
host.require_authorized_bulk_target(&subject, &principal_kind).await?;
host.require_tested_bulk_revocation_capability()?;
let affected = api_store.revoke_api_tokens_for_principal(
    &subject, &principal_kind, clock.now(), reason,
).await?;
host.record_completed_revocation(affected).await?;
```

The capability gate is trusted deployment/adapter configuration, never a client
assertion or an inference from the returned count. Otherwise use a host-owned
complete enumeration plus required per-token `revoke_api_token` workflow, with
creation/race fencing as needed. Resource bulk revocation has the same contract.
This does not revoke user sessions or already cached principals. Immediate
sensitive-operation/connection denial requires authoritative
`TokenStatusChecker`/`CurrentPrincipalResolver` checks; see
[principal lifecycle](principal-lifecycle.md) and
[WebSocket reauthorization](websocket-reauthorization.md).
