# Getting Started

`agql-auth` provides authentication primitives that can be embedded in a host
service. The crate owns password hashing, token issuance, refresh-token
rotation, request authentication, and GraphQL guard helpers. The host owns the
database schema, HTTP routes, cookie/session transport, user provisioning, and
application-specific authorization policy.

## Core Flow

Most applications start with three pieces:

- an `AuthConfig`
- a `UserStore` implementation
- a `RefreshTokenStore` implementation

```rust
use std::sync::Arc;

use agql_auth::{AuthConfig, AuthService};

let auth = AuthService::new(
    AuthConfig::new(std::env::var("JWT_SECRET")?),
    Arc::new(user_store),
    Arc::new(refresh_token_store),
)?;
```

`AuthService::new` uses an in-memory abuse-protection store. That is fine for
tests and single-process development. Production services should implement
`AuthRateLimitStore` and pass it to `AuthService::new_with_rate_limit_store`:

```rust
let auth = AuthService::new_with_rate_limit_store(
    config,
    Arc::new(user_store),
    Arc::new(refresh_token_store),
    Arc::new(rate_limit_store),
)?;
```

`AuthConfig::new(secret)` preserves the legacy HS256 signing behavior. For new
deployments where other services or routers need to validate tokens, prefer
RS256. HS256 secrets must be at least 32 bytes. See
[JWT signing and JWKS](jwt-signing-and-jwks.md).

## Password Login

The host stores users using its own schema and returns `StoredUser` from
`UserStore`. Password hashes should be created with the same service:

```rust
let password_hash = auth.hash_password("correct horse battery staple")?;
```

On login, `agql-auth` verifies the password, issues a short-lived JWT access
token, stores a hashed refresh token through `RefreshTokenStore`, and returns
an `AuthPayload`.

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
```

The access token is the local application token. The refresh token is opaque and
should be stored by the client according to the host service's security model,
for example in an HTTP-only cookie.

## Refresh And Logout

Refresh tokens are rotated on every successful refresh. The host store should
persist only the token hash from `StoredRefreshToken`, never the raw refresh
token. `RefreshTokenStore::rotate_refresh_token` must make rotation atomic so
two concurrent refreshes cannot both succeed.

```rust
let next_payload = auth.refresh(refresh_token, metadata).await?;
```

If a revoked refresh token is reused, `agql-auth` treats that as replay and asks
the store to revoke the token family.

Logout revokes either one refresh token or the whole family:

```rust
auth.logout(refresh_token, false).await?; // one token
auth.logout(refresh_token, true).await?;  // token family
```

Logout does not revoke already-issued stateless access tokens. They remain
valid until `exp`, so keep access-token lifetimes short and add host-side
session checks for high-risk operations if immediate revocation is required.

## Authenticating Requests

For HTTP GraphQL requests, extract the bearer token from the request headers or
your cookie layer and inject the authenticated user into the `async-graphql`
request.

```rust
let request = auth
    .inject_http_auth(graphql_request, bearer_or_cookie_token.as_deref())
    .await?;
```

Resolvers can then use `AuthUser` directly:

```rust
use agql_auth::auth_user_from_ctx;

let user = auth_user_from_ctx(ctx)?;
```

For WebSocket connection initialization payloads, use:

```rust
let data = auth.authenticate_connection_init_value(connection_init_json)?;
```

Attach the returned `async_graphql::Data` to the subscription connection using
the transport framework you own.

If your GraphQL auth mutations return refresh tokens in payloads and your HTTP
layer moves those tokens into cookies, use
`graphql_refresh_cookie_directive` with selected schema field names rather than
client-chosen operation names:

```rust
use agql_auth::{
    GraphqlRefreshCookieConfig, GraphqlTopLevelField,
    graphql_refresh_cookie_directive,
};

let config = GraphqlRefreshCookieConfig::new(
    ["authLogin", "authLoginWithCode", "authRefreshSession"],
    ["authLogout", "authLogoutAllSessions"],
);
let fields = [GraphqlTopLevelField::with_response_key(
    "authLogin",
    "CustomLoginAlias",
)];

if let Some(directive) =
    graphql_refresh_cookie_directive(&mut graphql_response, &fields, &config)
{
    apply_cookie_policy(directive)?;
}
```

The helper extracts `refreshToken` and `refreshTokenExpiresAt`, optionally
blanks `refreshToken` in the GraphQL response, and leaves cookie name/path,
SameSite, Secure, and Max-Age formatting to the host.

## Issuing Sessions For Verified Users

When the host has already verified the user through another trusted flow, such
as an OIDC callback or a one-time login code, it can issue a normal local
session directly:

```rust
use agql_auth::AuthMethod;

let payload = auth
    .issue_verified_user_session_with_scopes(
        user_id,
        vec!["Member".to_string()],
        vec!["orders.read".to_string()],
        AuthMethod::Oidc,
        metadata,
    )
    .await?;
```

This still uses the same local access-token and refresh-token model as password
login.

## Server-To-Server Tokens

Use `ApiTokenService` when another backend service or machine needs long-lived
access without a user refresh-token session. These tokens are opaque, hashed in
storage, and authenticate to `ApiTokenPrincipal` instead of `AuthUser`.

```rust
use std::sync::Arc;

use agql_auth::{ApiTokenIssueRequest, ApiTokenPrincipalKind, ApiTokenService};
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
        .with_scopes(["inventory.read"]),
    )
    .await?;
```

See [API and service tokens](api-service-tokens.md).

## Host Responsibilities

`agql-auth` intentionally does not provide:

- migrations or database schema
- HTTP routes, cookies, CORS, or CSRF policy
- email, SMS, or authenticator-app UI
- business-specific user provisioning
- provider-token encryption or persistence

Those boundaries keep the crate reusable across frameworks and storage layers.
