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

Durable rate-limit stores implement versioned compare-and-swap and conditional
clear; a split read followed by an unconditional upsert is not multi-instance
safe. See [atomic abuse protection](abuse-protection.md). Tests that need exact
window/backoff boundaries can use
`AuthService::new_with_rate_limit_store_and_clock` with `FixedClock`.

`AuthConfig::new(secret)` preserves the legacy HS256 signing behavior. For new
deployments where other services or routers need to validate tokens, prefer
RS256. HS256 secrets must be at least 32 bytes. See
[JWT signing and JWKS](jwt-signing-and-jwks.md) and
[Resource servers](resource-servers.md).

Version 0.14 emits access-token scopes as a standard space-delimited `scope`
string. Validators accept the older `scopes` array during a rolling migration.
Read [Access-token scope claims](access-token-scope-claims.md) before upgrading
any deployment whose consumers decode JWT payloads directly.

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
the store to revoke the token family. Hosts whose clients can lose a response after
commit, such as browsers, can opt in to a short
[refresh reuse grace](refresh-reuse-grace.md).

Sign-out revokes the whole token family. Use this form:

```rust
auth.logout(refresh_token, true).await?;
```

`logout(refresh_token, false)` revokes only the presented token while it is the
family's live token. A token that rotation already superseded, or supersedes
during the call, is treated as a reuse signal and revokes the whole family, so a
successor held by someone else cannot outlive the sign-out.

Rotation never extends a session past `AuthConfig::max_session_lifetime`, measured
from the session's first issuance (90 days by default; `None` lets rotation slide
indefinitely). Each replacement expires at the earlier of `refresh_token_ttl` from
rotation and that deadline, which the record carries in `session_expires_at`.

When you disable a user, change or reset a password, or offer "sign out everywhere",
revoke every refresh family of the user:

```rust
use agql_auth::RefreshTokenRevocationReason;

auth.revoke_user_sessions(&user_id, RefreshTokenRevocationReason::AdminRevoked)
    .await?;
```

Refresh already refuses a disabled user, but without this a re-enabled user's old
sessions would work again, and a password change would leave other sessions alive.

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

The helper extracts `session.refreshToken` and `session.refreshTokenExpiresAt`
and leaves cookie name/path, SameSite, Secure, and Max-Age formatting to the host.
It returns `Set` only when both fields are selected under their schema names, also
when another field of the request failed, and `Clear` only for a response without
errors.

Whenever an issuing field is selected, the helper also removes raw refresh tokens
from the body, whatever the response shape: aliased fields, nested selections, an
omitted expiry and partial errors included. Run it on every response, including
error responses. `sanitize_response = false` turns this off for clients that must
read the token from the body. To keep the token out of the body by construction,
leave `refreshToken` out of the schema and set the cookie from the resolver, for
example with `async_graphql::Context::insert_http_header`.

## Issuing Sessions For Verified Users

For OIDC and OAuth 2.0 logins prefer `OidcProvider::login_with_callback` and
`OAuth2Provider::login_with_callback`: they bind the callback to the initiating
browser, re-read the provisioned user and refuse a missing or disabled account
before issuing a session. See [Microsoft Entra OIDC](microsoft-entra-oidc.md)
and [OAuth 2.0 userinfo providers](oauth2-userinfo-providers.md).

When the host has already verified the user through another trusted flow, such
as a one-time login code, it can issue a normal local session directly. These
methods do not load the user: the host must check that the account exists and
is enabled first.

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
