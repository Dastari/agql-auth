# Recovery, Login Challenges, And MFA

`agql-auth` includes primitives for recovery and step-up flows without taking
over delivery, UI, or persistence. Read the
[primitive-versus-complete-flow contracts](secure-primitive-flows.md) before
using a helper as an application security boundary.

## Password Reset

Password reset tokens are signed local JWTs with a `password_reset` purpose and
a token ID. To make them one-time use, pair them with `PasswordResetTokenStore`.

```rust
use time::Duration;

let issued = auth
    .issue_password_reset_token_with_store(
        &reset_store,
        user_id,
        Duration::hours(1),
    )
    .await?;

send_reset_email(&issued.token).await?;
```

When the token is submitted:

```rust
let verified = auth
    .consume_password_reset_token_with_metadata(
        &reset_store,
        submitted_token,
        client_metadata,
    )
    .await?;
```

`authenticate_password_reset_token` only validates claims and does not consult
or consume a stored token ID, check revocation, or count attempts. It cannot by
itself authorize a one-time reset. After consumption succeeds, the host checks
current account/expiry, updates the password hash and implements required
session/token revocation with transaction/fencing and recovery if a later write
fails. See the [complete reset sequence](secure-primitive-flows.md#one-time-reset-through-password-update-and-revocation).

## Login Challenges

Login challenges support short numeric codes for email, SMS, or similar flows.
The crate generates the code, stores only a password hash of that code, tracks
attempts, and consumes the challenge once. Each verification first reserves an
attempt atomically in the store. The cap includes all admitted guesses and
cancelled work, preventing concurrent callers from sharing the last available
attempt. Failed or expired attempts never create verified authority. The service
uses system UTC by default; `with_login_challenge_clock` installs a separate
trusted clock aligned with your challenge store.

```rust
use agql_auth::LoginChallengeOptions;

let challenge = auth
    .create_login_challenge(
        &challenge_store,
        "alice@example.com",
        LoginChallengeOptions::default(),
    )
    .await?;

deliver_code(&challenge.code).await?;
```

Verification consumes the challenge:

```rust
let verified = auth
    .verify_login_challenge_with_metadata(
        &challenge_store,
        challenge_id,
        submitted_code,
        client_metadata,
    )
    .await?;
```

The host decides what verified challenges can do. For example, the host can
issue a local session with `AuthMethod::EmailCode`:

```rust
use agql_auth::{AuthError, AuthMethod, ClientMetadata};

// The consumed challenge fixes the principal; request-selected user IDs/grants do not.
let user = users.find_user_by_principal(&verified.principal).await?
    .ok_or(AuthError::InvalidCredentials)?;
if user.disabled { return Err(AuthError::UserDisabled); }
let payload = auth.issue_verified_user_session_with_scopes(
    user.id, user.roles, user.scopes, AuthMethod::EmailCode,
    ClientMetadata::default(),
).await?;
```

Configure host refresh authority before issuing a refreshable host grant. This
issuer does not verify credentials or read the user store itself; see the
[complete challenge-to-session contract](secure-primitive-flows.md#bound-challenge-to-current-user-session).

## TOTP

The TOTP helpers generate secrets, build provisioning URIs, and verify codes.
The host stores the user's TOTP secret and owns enrollment UI.

```rust
use agql_auth::TotpOptions;
use time::OffsetDateTime;

let secret = auth.generate_totp_secret(20)?;
let provisioning = auth.build_totp_provisioning(
    &secret,
    "Example App",
    "alice@example.com",
    TotpOptions::default(),
)?;
```

Keep a newly provisioned secret pending until the host's authenticated enrollment
confirmation succeeds. Generating/provisioning a secret does not enroll a factor
or establish MFA. Verification below uses an existing confirmed factor loaded
for the authenticated user, not the just-generated secret.

`verify_totp_code` is stateless and has no attempt limiter.
`verify_totp_code_for_principal` adds configured abuse controls but still permits
replay. Neither changes enrollment or session assurance. Production flows
should prefer `verify_totp_code_with_replay_store_and_metadata`, which records
the accepted time step through `TotpReplayStore`, rejects the same step on
reuse, and applies per-principal/per-client abuse protection:

```rust
// Host-owned lookup must enforce confirmed enrollment and user/session ownership.
let stored_secret = host.load_confirmed_totp_secret(user_id, "primary").await?;
auth.verify_totp_code_with_replay_store_and_metadata(
    &totp_replay_store,
    user_id,
    Some("primary"),
    &stored_secret,
    submitted_code,
    TotpOptions::default(),
    OffsetDateTime::now_utc(),
    client_metadata,
).await?;
```

A successful replay-safe check still does not establish factor ownership or
update session assurance. Bind the stored factor and submitted refresh token to
the exact authenticated session, apply host MFA policy, then call
`step_up_session`. See the [complete bound step-up sequence](secure-primitive-flows.md#totp-step-up-bound-to-the-existing-session).
Do not infer MFA from an auth-method label or a client-supplied flag.

## Delivery And Persistence

The crate intentionally does not send email or SMS and does not store MFA
enrollment records. Host services should:

- call `should_process_password_reset_request` and
  `should_process_login_code_request` before user lookup or email delivery;
  `Ok(false)` means preserve silent-success semantics but do not send email
- pass `ClientMetadata` to verification/consumption helpers when possible
- keep challenge admission and one-time consume operations atomic
- expire unused records
- avoid logging reset tokens or login codes
- revoke existing sessions when local policy requires it

Credential throttling returns `AuthError::AuthThrottled` during exponential
backoff and `AuthError::AuthLocked` during temporary lockout. Password-reset
and login-code request helpers suppress those errors and return `Ok(false)` so
the host can avoid revealing whether the principal exists.

`Debug` output for issued reset tokens, TOTP secrets/provisioning URIs, local
auth payloads, OIDC token responses, and issued API tokens redacts raw secret
material. Serialization still contains the actual values when those structs are
intentionally returned by the host.
