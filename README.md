# agql-auth

A reusable authentication library for `async-graphql` applications.

## Scope

This crate provides:

- Argon2 password hashing and verification
- short-lived JWT access tokens
- rotated opaque refresh tokens
- database-agnostic storage traits
- password-reset token issuance and verification primitives
- one-time login challenge and code primitives
- TOTP secret generation, provisioning, and verification primitives
- `async-graphql` request context helpers
- `async-graphql` guards for auth and roles
- WebSocket `connection_init` authentication support

## Core Types

- `AuthService<U, R>`
- `UserStore`
- `RefreshTokenStore`
- `PasswordResetTokenStore`
- `LoginChallengeStore`
- `AuthUser`
- `AuthPayload`
- `PasswordResetToken`
- `IssuedLoginChallenge`
- `StoredLoginChallenge`
- `TotpSecret`
- `TotpProvisioning`
- `RequireAuth`
- `RequireAnyRole`
- `RequireAllRoles`

## Recovery And MFA Primitives

Password reset:

- issue JWT-backed password-reset tokens
- verify token signature and expiry
- optionally enforce one-time use through `PasswordResetTokenStore`

Login challenges:

- create short-lived one-time codes for email or SMS delivery
- store only the hashed code in application storage
- verify codes with expiry, attempt, and replay protection through `LoginChallengeStore`

TOTP:

- generate new shared secrets
- build `otpauth://` provisioning URIs
- verify codes with configurable digits, period, and skew window

## Intended Integration

HTTP GraphQL:

- read bearer token or cookie at the transport layer
- validate with `AuthService`
- insert `AuthUser` into `async_graphql::Request`

Subscriptions:

- read `connection_init.payload`
- authenticate with `authenticate_connection_init_value`
- merge returned `async_graphql::Data` into subscription context

Application-owned storage and policy:

- implement `UserStore` and `RefreshTokenStore` using your application persistence layer
- implement `PasswordResetTokenStore` if reset tokens must be one-time use
- implement `LoginChallengeStore` to persist hashed login codes, attempt counters, and consume state
- keep SMTP, SMS, UI flows, ORM entities, and business policy in the consuming application

## Migration Note

Consuming apps can keep existing login, refresh, logout, and GraphQL auth wiring unchanged.

To use the new recovery and challenge primitives:

- add app-owned persistence implementations for `PasswordResetTokenStore` and `LoginChallengeStore`
- call the new `AuthService` helpers from your password-reset, email-code, or SMS-code workflows
- store TOTP enrollment state in the application, not in `agql-auth`

## Status

This crate is focused on reusable auth primitives and `async-graphql` integration. It does not own your application's database schema, ORM entities, transport bootstrap, email delivery, SMS delivery, or app-specific authorization policy.

## License

License not selected yet.
