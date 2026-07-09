# API And Service Tokens

`agql-auth` supports long-lived opaque API tokens for server-to-server calls.
They are separate from user sessions:

- user sessions use short-lived local JWT access tokens plus rotated refresh tokens
- API/service tokens are opaque bearer credentials stored by hash
- API/service tokens authenticate to an `ApiTokenPrincipal`
- `AuthPrincipal` can represent either an `AuthUser` or an `ApiTokenPrincipal`

Use API tokens when another backend service, machine, or integration needs to
call an API without a user refresh-token session.

## Why Opaque Tokens

Long-lived JWTs are hard to revoke and can leak authorization decisions into a
token that may remain valid for months. API tokens in `agql-auth` are opaque,
high-entropy strings. The host stores only a SHA-256 hash, can revoke the
stored record, can set an expiry, and can track last-used metadata.

The default generated prefix is `agql_api_`. It is intentionally not JWT-like
and generated tokens contain no period separators. Use
`ApiTokenService::with_prefix` if the host wants a different prefix.

## Storage

Implement `ApiTokenStore` in the host application. The stored record includes:

- token ID
- token hash only
- display name
- subject
- principal kind
- scopes
- optional audience
- optional generic resource type and ID
- creation, expiry, last-used, and revocation timestamps
- optional IP address and user-agent metadata

The library does not provide a database schema. The host decides indexes,
constraints, encryption strategy for any surrounding metadata, and operational
policy.

## Issuing A One-Year Token

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
        .with_audience("graphql-api")
        .with_resource("integration", "inventory")
        .with_metadata(ClientMetadata {
            ip_address: Some("203.0.113.10".to_string()),
            user_agent: Some("admin-console".to_string()),
        }),
    )
    .await?;

// Show issued.token once. Persist only the StoredApiToken written by the store.
```

`IssuedApiToken` redacts the raw token in `Debug` output, but serialization
still contains the raw token so the host can intentionally return it once.

## Authenticating A Bearer Header

```rust
let principal = api_tokens
    .authenticate_bearer(
        authorization_header,
        ClientMetadata {
            ip_address: Some(client_ip.to_string()),
            user_agent: user_agent.map(str::to_string),
        },
    )
    .await?;

assert!(principal.has_scope("inventory.read"));
```

`authenticate_bearer` accepts values with or without the `Bearer ` prefix,
rejects unknown, expired, and revoked tokens, and updates last-used metadata
after successful authentication.

## async-graphql Integration

For GraphQL requests that should accept API-token principals, inject the token
through `ApiTokenService`:

```rust
let request = api_tokens
    .inject_http_auth(graphql_request, bearer_header.as_deref(), metadata)
    .await?;
```

Resolvers can read a generic principal:

```rust
use agql_auth::principal_from_ctx;

let principal = principal_from_ctx(ctx)?;
let subject = principal.subject();
```

Generic principal guards work for either user sessions or API-token principals:

```rust
use agql_auth::{RequirePrincipal, RequirePrincipalScope};

#[Object]
impl Query {
    #[graphql(guard = "RequirePrincipal::new()")]
    async fn viewer(&self) -> Viewer {
        // ...
    }

    #[graphql(guard = "RequirePrincipalScope::new(\"inventory.read\")")]
    async fn inventory(&self) -> Vec<Item> {
        // ...
    }
}
```

Existing user-only helpers and guards still require `AuthUser` and remain
unchanged.

## Combined User JWT Or API Token

Use `CombinedAuth` when one GraphQL endpoint should accept either a user access
JWT or an opaque API token:

```rust
use agql_auth::CombinedAuth;

let request = CombinedAuth::new(&access_token_validator, &api_tokens)
    .inject_http_auth(graphql_request, authorization_header, metadata)
    .await?;
```

The injector tries JWT-shaped tokens first. Expired JWTs return
`AuthError::AccessTokenExpired` and never fall back to API-token
authentication. Invalid JWTs only fall back when the token matches the API
token prefix. On success the request contains one `AuthPrincipal`, plus the
specific `AuthUser` or `ApiTokenPrincipal`.

## Access-Token-Only Grants

Use `AuthService::issue_access_token_only` for short-lived user-shaped JWTs
that should not create refresh-token rows:

```rust
use agql_auth::{AccessTokenOnlyRequest, AuthMethod, SessionContext};
use time::Duration;

let grant = auth
    .issue_access_token_only(AccessTokenOnlyRequest {
        user_id: "device-user-1".to_string(),
        roles: vec!["Device".to_string()],
        scopes: vec!["devices.read".to_string(), "devices.write".to_string()],
        session: SessionContext::for_auth_method(AuthMethod::ServiceToken),
        ttl: Some(Duration::minutes(30)),
    })
    .await?;
```

Use API tokens for long-lived, revocable service credentials. Use
access-token-only grants for short-lived JWTs that need the same validation path
as user sessions but no refresh-token session.

## Authorization Policy

`agql-auth` stores and exposes generic scopes, optional audience, and optional
resource binding. It does not decide what those values mean. Host applications
own concrete authorization policy, resource lookup, rate limiting, audit
logging, and token lifecycle workflows.
