# agql-auth

Reusable authentication primitives for Rust services built with `async-graphql`.

`agql-auth` gives host applications the hard parts of authentication without taking over the application's database, HTTP framework, ORM, cookie policy, or authorization model. It issues local application sessions, validates requests, and exposes database-agnostic traits so the host keeps control of persistence and business policy.

## What It Provides

- Argon2 password hashing and password login
- Short-lived JWT access tokens and rotated opaque refresh tokens
- Store-free access-token validation for resource servers
- Long-lived opaque API/service tokens for server-to-server calls
- HS256 compatibility mode and RS256 signing with JWKS export
- Roles, scopes, and typed session context in access-token claims
- Exact scope matching by default with opt-in hierarchical matching
- Microsoft Entra ID / OIDC authorization-code + PKCE login
- Host-controlled external user provisioning and account linking
- Password reset tokens, one-time login challenges, and TOTP primitives
- Rate limiting, exponential backoff, and temporary lockout for auth flows
- Short-lived typed purpose JWTs with explicit audience validation
- Access-token-only grants without refresh-token storage
- Combined user JWT or API-token principal injection
- Host-verified channel identity request data and guards
- `async-graphql` request injection and guards
- Storage traits instead of built-in database assumptions

## Install

```toml
[dependencies]
agql-auth = "0.7"
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

`AuthService::new` uses an in-memory abuse-protection store. Production
multi-instance apps should provide a durable `AuthRateLimitStore`:

```rust
let auth = AuthService::new_with_rate_limit_store(
    config,
    Arc::new(user_store),
    Arc::new(refresh_token_store),
    Arc::new(rate_limit_store),
)?;
```

HS256 secrets must be at least 32 bytes. Use a random secret from a
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

Exact scope matching remains the default. To opt into hierarchical matching for
guards, configure a matcher and inject it with your auth path:

```rust
use std::sync::Arc;
use agql_auth::{HierarchicalScopeMatch, HierarchicalScopeOptions};

let auth = auth.with_scope_matcher(Arc::new(HierarchicalScopeMatch::new(
    HierarchicalScopeOptions {
        super_scopes: vec!["platform.admin".to_string()],
        ..Default::default()
    },
)));
```

See [Scope matching](docs/scope-matching.md).

Hosts that verify channel credentials outside the crate can attach
`ChannelIdentity` and use `RequireChannelScheme`:

```rust
use agql_auth::{ChannelIdentity, RequireChannelScheme};

let request = request.data(ChannelIdentity::new("mtls", "device-1"));
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

Validate the same access tokens in a resource server without user or refresh
stores:

```rust
use agql_auth::AccessTokenValidator;

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .rs256_public_pem(std::env::var("JWT_PUBLIC_KEY_PEM")?)
    .key_id("auth-key-2026-07")
    .build()?;

let user = validator.authenticate_bearer(authorization_header)?;
```

See [Resource servers](docs/resource-servers.md).

Use purpose tokens for short-lived, non-session grants:

```rust
use agql_auth::{PurposeTokenIssueRequest, PurposeTokenValidation};
use serde_json::json;
use time::Duration;

let issued = auth.issue_purpose_token(
    PurposeTokenIssueRequest::new(
        user_id,
        "capture_upload",
        "capture-upload-clients",
        Duration::minutes(15),
    )
    .with_session_id(session_id)
    .with_claim("collectionId", json!(collection_id)),
)?;

let grant = auth.authenticate_purpose_token(
    &issued.token,
    PurposeTokenValidation::new("capture_upload", "capture-upload-clients"),
)?;
```

Issue a user-shaped access token without a refresh-token row:

```rust
use agql_auth::{AccessTokenOnlyRequest, AuthMethod, SessionContext};
use time::Duration;

let grant = auth
    .issue_access_token_only(AccessTokenOnlyRequest {
        user_id: "device-user-1".to_string(),
        roles: vec!["Device".to_string()],
        scopes: vec!["devices.read".to_string()],
        session: SessionContext::for_auth_method(AuthMethod::ServiceToken),
        ttl: Some(Duration::minutes(30)),
    })
    .await?;
```

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

Accept either a user JWT or an API token on one endpoint:

```rust
use agql_auth::CombinedAuth;

let request = CombinedAuth::new(&validator, &api_tokens)
    .inject_http_auth(graphql_request, authorization_header, metadata)
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
- [Resource servers](docs/resource-servers.md)
- [Scope matching](docs/scope-matching.md)
- [Access-token-only grants](docs/access-token-only.md)
- [Multi-tenant claims](docs/multi-tenant-claims.md)
- [Key rotation and JWKS](docs/key-rotation.md)
- [API and service tokens](docs/api-service-tokens.md)
- [WebSocket reauthorization](docs/websocket-reauthorization.md)
- [Public error codes](docs/public-error-codes.md)
- [JWT signing and JWKS](docs/jwt-signing-and-jwks.md)
- [Microsoft Entra OIDC](docs/microsoft-entra-oidc.md)
- [Recovery, login challenges, and MFA](docs/recovery-mfa-and-challenges.md)
- [Session assurance and recent MFA](docs/session-assurance.md)
- [Migration guide](MIGRATION.md)

## 0.8.1 Interoperability Note

`0.8.1` is an output-only interoperability patch: unset optional JWT claims,
including `nbf`, are omitted rather than serialized as JSON `null`. Hosts do
not need to set `nbf` unless a genuine not-before constraint is intended. There
are no public API or storage migrations from `0.8.0`.

## 0.8.0 Migration Notes

- OIDC assurance claims are exposed as typed evidence but do not satisfy local
  MFA until the host mapper explicitly accepts them.
- Refresh rotation preserves authoritative `auth_time`, normalized AMR, ACR,
  MFA acceptance, and an explicitly safe metadata subset.
- Refresh stores must accept the optional `refreshable_metadata` field and the
  optional assurance nested in `SessionContext`; legacy rows remain valid.
- Use `RecentMfaPolicy` with an injected clock for recent-MFA enforcement.
- See [MIGRATION.md](MIGRATION.md) for the `0.7` to `0.8` migration.

## 0.7.0 Migration Notes

- Exact scope matching remains the default.
- Hierarchical scope matching is opt-in through `AuthRuntime`,
  `AuthService::with_scope_matcher`, or `AccessTokenValidatorBuilder::scope_matcher`.
- Resource servers should use `AccessTokenValidator` instead of constructing
  `AuthService` just to validate JWTs.
- Use `CombinedAuth` for endpoints that accept either user JWTs or API tokens.
- Use `issue_access_token_only` for short-lived JWT grants that must not create
  refresh-token rows.
- Use `ChannelIdentity` only after the host has verified the channel.
- See [MIGRATION.md](MIGRATION.md) for old-to-new API mappings and behavioral
  compatibility notes.

## Design Boundaries

`agql-auth` intentionally does not own:

- database schema or migrations
- HTTP routing, cookies, or CORS
- email/SMS delivery
- UI flows
- application-specific user provisioning policy
- business authorization beyond roles, scopes, and guard helpers

The host application implements those pieces around the reusable primitives.
