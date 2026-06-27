# Recovery, Login Challenges, And MFA

`agql-auth` includes primitives for recovery and step-up flows without taking
over delivery, UI, or persistence.

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
    .consume_password_reset_token(&reset_store, submitted_token)
    .await?;
```

After consumption succeeds, the host updates the user's password hash and
handles any local session-revocation policy.

## Login Challenges

Login challenges support short numeric codes for email, SMS, or similar flows.
The crate generates the code, stores only a password hash of that code, tracks
attempts, and consumes the challenge once.

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
    .verify_login_challenge(&challenge_store, challenge_id, submitted_code)
    .await?;
```

The host decides what verified challenges can do. For example, the host can
issue a local session with `AuthMethod::EmailCode`:

```rust
use agql_auth::{AuthMethod, ClientMetadata};

let payload = auth
    .issue_verified_user_session(
        local_user_id,
        roles,
        AuthMethod::EmailCode,
        ClientMetadata::default(),
    )
    .await?;
```

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

auth.verify_totp_code(
    &secret.base32_secret,
    submitted_code,
    TotpOptions::default(),
    OffsetDateTime::now_utc(),
)?;
```

After a successful step-up challenge, the host can issue a new local session
with `SessionContext` showing `AuthMethod::TotpStepUp` or update local session
state according to its own policy.

## Delivery And Persistence

The crate intentionally does not send email or SMS and does not store MFA
enrollment records. Host services should:

- rate-limit challenge creation and verification
- keep one-time consume operations atomic
- expire unused records
- avoid logging reset tokens or login codes
- revoke existing sessions when local policy requires it
