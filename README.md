# agql-auth

Reusable authentication primitives for Rust services built with `async-graphql`.

`agql-auth` gives host applications the hard parts of authentication without taking over the application's database, HTTP framework, ORM, cookie policy, or authorization model. It issues local application sessions, validates requests, and exposes database-agnostic traits so the host keeps control of persistence and business policy.

## What It Provides

- Argon2 password hashing and password login
- Short-lived JWT access tokens and rotated opaque refresh tokens
- Long-lived opaque API/service tokens for server-to-server calls
- HS256 compatibility mode and RS256 signing with JWKS export
- Roles, scopes, and typed session context in access-token claims
- Microsoft Entra ID / OIDC authorization-code + PKCE login
- Host-controlled external user provisioning and account linking
- Password reset tokens, one-time login challenges, and TOTP primitives
- `async-graphql` request injection and guards
- Storage traits instead of built-in database assumptions

## Install

```toml
[dependencies]
agql-auth = "0.6"
```

## Basic Usage

Create the service with your user and refresh-token stores:

```rust
use std::sync::Arc;
use agql_auth::{AuthConfig, AuthService};

let auth = AuthService::new(
    AuthConfig::new(std::env::var("JWT_SECRET")?),
    Arc::new(user_store),
    Arc::new(refresh_token_store),
)?;
```

HS256 secrets must be at least 32 bytes in `0.6.0`. Use a random secret from a
secret manager; prefer RS256 when routers or other services validate tokens.

Issue a local session with password login:

```rust
use agql_auth::ClientMetadata;

let payload = auth
    .login(
        "alice@example.com",
        "correct horse battery staple",
        ClientMetadata {
            ip_address: Some("203.0.113.10".to_string()),
            user_agent: Some("example-client".to_string()),
        },
    )
    .await?;

// payload.access_token is the short-lived local JWT.
// payload.refresh_token is an opaque rotated refresh token.
```

Authenticate an `async-graphql` request:

```rust
let request = auth
    .inject_http_auth(graphql_request, bearer_or_cookie_token.as_deref())
    .await?;
```

Use guards in GraphQL resolvers:

```rust
use agql_auth::{RequireAnyRole, RequireScope};

#[Object]
impl Query {
    #[graphql(guard = "RequireAnyRole::new([\"Admin\", \"Operator\"])")]
    async fn admin_view(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireScope::new(\"users.read\")")]
    async fn users(&self) -> Vec<User> {
        Vec::new()
    }
}
```

## RS256 And JWKS

For services that need routers or other systems to validate local `agql-auth` tokens without sharing a symmetric secret, configure RS256 signing:

```rust
use std::sync::Arc;
use agql_auth::{AuthConfig, AuthService};

let auth = AuthService::new(
    AuthConfig::with_rs256_pem(
        std::env::var("JWT_PRIVATE_KEY_PEM")?,
        std::env::var("JWT_PUBLIC_KEY_PEM")?,
        "auth-key-2026-06",
    ),
    Arc::new(user_store),
    Arc::new(refresh_token_store),
)?;
```

Expose public keys through your host framework:

```rust
async fn jwks(auth: &AuthService<AppUserStore, AppRefreshTokenStore>)
    -> agql_auth::AuthResult<serde_json::Value>
{
    auth.jwks()
}
```

See [JWT signing and JWKS](docs/jwt-signing-and-jwks.md).

## API And Service Tokens

Use `ApiTokenService` for long-lived server-to-server credentials. API tokens
are opaque, prefixed strings; `agql-auth` stores only their SHA-256 hash and
returns the raw token once.

```rust
use std::sync::Arc;
use agql_auth::{
    ApiTokenIssueRequest, ApiTokenPrincipalKind, ApiTokenService, ClientMetadata,
};
use time::Duration;

let api_tokens = ApiTokenService::new(Arc::new(api_token_store));

let issued = api_tokens
    .issue_token(
        ApiTokenIssueRequest::new(
            "inventory sync",
            "svc-inventory",
            ApiTokenPrincipalKind::service(),
            Duration::days(365),
        )
        .with_scopes(["inventory.read", "inventory.write"])
        .with_audience("graphql-api"),
    )
    .await?;

let principal = api_tokens
    .authenticate_bearer(
        &format!("Bearer {}", issued.token),
        ClientMetadata::default(),
    )
    .await?;
```

See [API and service tokens](docs/api-service-tokens.md).

## Microsoft Login

`agql-auth` supports Microsoft Entra ID login through OIDC authorization-code flow with PKCE. After Microsoft ID-token validation and host-controlled user resolution, the library issues a normal local `AuthPayload`; Microsoft access tokens do not become your app session tokens.

```rust
use std::sync::Arc;
use agql_auth::{MicrosoftEntraConfig, OidcProvider};

let mut entra = MicrosoftEntraConfig::single_tenant(
    "00000000-0000-0000-0000-000000000000",
    std::env::var("MICROSOFT_CLIENT_ID")?,
    "https://app.example.com/auth/microsoft/callback",
);
entra.client_secret = Some(std::env::var("MICROSOFT_CLIENT_SECRET")?);

let microsoft = OidcProvider::new(
    entra.into_oidc_provider_config()?,
    Arc::new(app_oidc_http_client),
)?;
```

See [Microsoft Entra OIDC](docs/microsoft-entra-oidc.md).

## Documentation

- [Getting started](docs/getting-started.md)
- [Storage traits](docs/storage-traits.md)
- [Authorization, scopes, and guards](docs/authorization.md)
- [API and service tokens](docs/api-service-tokens.md)
- [JWT signing and JWKS](docs/jwt-signing-and-jwks.md)
- [Microsoft Entra OIDC](docs/microsoft-entra-oidc.md)
- [Recovery, login challenges, and MFA](docs/recovery-mfa-and-challenges.md)

## 0.6.0 Migration Notes

- `RefreshTokenStore` implementers must add atomic `rotate_refresh_token`.
- HS256 secrets shorter than 32 bytes are rejected at `AuthService::new`.
- `ValidatedOidcClaims.not_before` is now `Option<OffsetDateTime>`.
- OIDC config includes discovery-cache TTL, forced-JWKS-refresh cooldown, and
  additional trusted audiences for multi-audience ID tokens.
- `AuthConfig.jwt_signing` is authoritative; `jwt_secret` remains a legacy
  mirror field and should not be mutated directly.
- Access tokens now include `purpose = "access_token"`; `0.6.x` still accepts
  legacy access tokens without that claim.
- TOTP replay protection is available through `TotpReplayStore`.
- Unsupported authorization schemes such as `Basic abc` are rejected by bearer
  parsing. Raw token strings are still accepted.

## Design Boundaries

`agql-auth` intentionally does not own:

- database schema or migrations
- HTTP routing, cookies, or CORS
- email/SMS delivery
- UI flows
- application-specific user provisioning policy
- business authorization beyond roles, scopes, and guard helpers

The host application implements those pieces around the reusable primitives.
